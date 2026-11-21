// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package casbin

// Scenario construction, matcher reading and policy diffing for the impact
// preview.

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/casbin/casbin/v3/model"
)

// ImpactSnapshot is one side of a preview: a model definition plus a policy.
type ImpactSnapshot struct {
	// Model is the model definition. The preview copies it and never mutates
	// the caller's copy.
	Model model.Model
	// Policy is the rule set in file order. Rules whose ptype starts with "g"
	// are grouping rules, all others are authorization rules.
	Policy []ImpactRule
}

// ImpactRule is one policy line: a ptype and its fields.
type ImpactRule struct {
	PType string
	Rule  []string
}

// impactScenario is a loaded, ready-to-evaluate policy.
type impactScenario struct {
	model model.Model
	// rules is the policy in the order it was supplied.
	rules []ImpactRule
	// positions maps a ptype+rule key to the supplied position of the rule.
	positions map[string]rulePosition
	// tokens caches the policy tokens of each ptype.
	tokens map[string][]string
	// roleColumns caches how many positional fields each grouping definition
	// has (user, role and, for domain models, the domain).
	roleColumns map[string]int

	enf *Enforcer
}

type rulePosition struct {
	index int
	rule  ImpactRule
}

func sectionOfPType(ptype string) string {
	if strings.HasPrefix(ptype, "g") {
		return "g"
	}
	return "p"
}

func ruleKey(ptype string, rule []string) string {
	return ptype + "\x00" + strings.Join(rule, "\x00")
}

func (r ImpactRule) key() string { return ruleKey(r.PType, r.Rule) }

// buildScenario validates and loads a snapshot into a throwaway enforcer.
func buildScenario(s ImpactSnapshot) (*impactScenario, *Failure) {
	if s.Model == nil {
		return nil, &Failure{Stage: "model", Message: "no model supplied"}
	}
	m := s.Model.Copy()
	m.ClearPolicy()

	sc := &impactScenario{
		model:       m,
		positions:   map[string]rulePosition{},
		tokens:      map[string][]string{},
		roleColumns: map[string]int{},
	}

	for _, supplied := range s.Policy {
		ptype := supplied.PType
		if ptype == "" {
			return nil, &Failure{Stage: "rule", Message: "rule has an empty policy type"}
		}
		sec := sectionOfPType(ptype)
		ast, ok := m[sec][ptype]
		if !ok {
			return nil, &Failure{
				Stage:   "rule",
				PType:   ptype,
				Rule:    &RuleRef{Section: sec, PType: ptype, Rule: append([]string(nil), supplied.Rule...)},
				Message: fmt.Sprintf("policy type %q is not defined in the model", ptype),
			}
		}
		if sec == "p" && len(supplied.Rule) != len(ast.Tokens) {
			return nil, &Failure{
				Stage:   "rule",
				PType:   ptype,
				Rule:    &RuleRef{Section: sec, PType: ptype, Rule: append([]string(nil), supplied.Rule...)},
				Message: fmt.Sprintf("rule has %d fields but %q expects %d", len(supplied.Rule), ptype, len(ast.Tokens)),
			}
		}
		if sec == "g" && len(supplied.Rule) < len(ast.Tokens) {
			return nil, &Failure{
				Stage:   "rule",
				PType:   ptype,
				Rule:    &RuleRef{Section: sec, PType: ptype, Rule: append([]string(nil), supplied.Rule...)},
				Message: fmt.Sprintf("rule has %d fields but %q expects at least %d", len(supplied.Rule), ptype, len(ast.Tokens)),
			}
		}
		rule := append([]string(nil), supplied.Rule...)
		if err := m.AddPolicy(sec, ptype, rule); err != nil {
			return nil, &Failure{
				Stage:   "rule",
				PType:   ptype,
				Rule:    &RuleRef{Section: sec, PType: ptype, Rule: append([]string(nil), supplied.Rule...)},
				Message: err.Error(),
			}
		}
		sc.rules = append(sc.rules, ImpactRule{PType: ptype, Rule: rule})
	}

	counts := map[string]int{}
	for _, r := range sc.rules {
		if _, exists := sc.positions[r.key()]; !exists {
			sc.positions[r.key()] = rulePosition{index: counts[r.PType], rule: r}
		}
		counts[r.PType]++
	}

	if err := m.SortPoliciesByPriority(); err != nil {
		return nil, &Failure{Stage: "policy", Message: err.Error()}
	}
	if err := m.SortPoliciesBySubjectHierarchy(); err != nil {
		return nil, &Failure{Stage: "policy", Message: err.Error()}
	}

	for ptype, ast := range m["p"] {
		sc.tokens[ptype] = append([]string(nil), ast.Tokens...)
	}
	// Grouping definitions are positional: (user, role[, domain]). Their token
	// names are placeholders ("_"), so they are read by position instead.
	for ptype, ast := range m["g"] {
		sc.roleColumns[ptype] = len(ast.Tokens)
	}

	enf, err := NewEnforcer(m)
	if err != nil {
		return nil, &Failure{Stage: "model", Message: err.Error()}
	}
	enf.EnableAutoSave(false)
	if err := enf.BuildRoleLinks(); err != nil {
		return nil, &Failure{Stage: "policy", Message: err.Error()}
	}
	if err := m.BuildConditionalRoleLinks(enf.condRmMap); err != nil {
		return nil, &Failure{Stage: "policy", Message: err.Error()}
	}
	sc.enf = enf
	return sc, nil
}

// refOf returns the RuleRef of a rule as it exists in this scenario.
func (s *impactScenario) refOf(r ImpactRule) RuleRef {
	index := -1
	if pos, ok := s.positions[r.key()]; ok {
		index = pos.index
	}
	return RuleRef{
		Section: sectionOfPType(r.PType),
		PType:   r.PType,
		Index:   index,
		Rule:    append([]string(nil), r.Rule...),
	}
}

// fieldIndex resolves a semantic column of a ptype: "sub", "dom", "obj",
// "act", "eft" or "priority". Grouping definitions are positional: column 0 is
// the user (subject), column 1 the role (object) and column 2, when present,
// the domain. It returns false when the column is absent.
func (s *impactScenario) fieldIndex(ptype, name string) (int, bool) {
	if strings.HasPrefix(ptype, "g") {
		columns, ok := s.roleColumns[ptype]
		if !ok {
			return -1, false
		}
		switch name {
		case "sub":
			return 0, true
		case "obj":
			return 1, columns > 1
		case "dom":
			return 2, columns > 2
		}
		return -1, false
	}
	tokens, ok := s.tokens[ptype]
	if !ok {
		return -1, false
	}
	want := ptype + "_" + name
	for i, tok := range tokens {
		if tok == want {
			return i, true
		}
	}
	return -1, false
}

func (s *impactScenario) field(ptype string, rule []string, name string) string {
	idx, ok := s.fieldIndex(ptype, name)
	if !ok || idx >= len(rule) {
		return ""
	}
	return rule[idx]
}

// requestTokens returns the request token names (without the "r_" prefix).
func (s *impactScenario) requestTokens() []string {
	ast, ok := s.model["r"]["r"]
	if !ok {
		return nil
	}
	out := make([]string, 0, len(ast.Tokens))
	for _, tok := range ast.Tokens {
		out = append(out, tokenName(tok))
	}
	return out
}

func (s *impactScenario) matcherValue() string {
	ast, ok := s.model["m"]["m"]
	if !ok {
		return ""
	}
	return ast.Value
}

func (s *impactScenario) roleTypes() map[string]bool {
	out := map[string]bool{}
	for ptype := range s.model["g"] {
		out[ptype] = true
	}
	return out
}

func tokenName(token string) string {
	if i := strings.IndexByte(token, '_'); i >= 0 {
		return token[i+1:]
	}
	return token
}

// snapshotFromEnforcer reads the enforcer's model and policy without mutating
// the enforcer.
func snapshotFromEnforcer(e *Enforcer) (ImpactSnapshot, error) {
	if e == nil || e.model == nil {
		return ImpactSnapshot{}, errors.New("impact: enforcer has no model")
	}
	snap := ImpactSnapshot{Model: e.model.Copy()}
	for _, sec := range []string{"p", "g"} {
		ptypes := make([]string, 0, len(e.model[sec]))
		for ptype := range e.model[sec] {
			ptypes = append(ptypes, ptype)
		}
		sort.Strings(ptypes)
		for _, ptype := range ptypes {
			for _, rule := range e.model[sec][ptype].Policy {
				snap.Policy = append(snap.Policy, ImpactRule{PType: ptype, Rule: append([]string(nil), rule...)})
			}
		}
	}
	return snap, nil
}

// fingerprint digests the scenario's rules; it is how a caller proves the live
// policy did not change across the preview.
func (s *impactScenario) fingerprint() string {
	lines := make([]string, 0, len(s.rules))
	for _, r := range s.rules {
		lines = append(lines, r.key())
	}
	sort.Strings(lines)
	h := sha256.New()
	for _, l := range lines {
		h.Write([]byte(l))
		h.Write([]byte{'\n'})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// impactDiff is one rule-level change.
type impactDiff struct {
	change  ChangeKind
	rule    RuleRef
	ptype   string
	section string
}

// computeDiff returns the symmetric difference between two policies in a
// deterministic order.
func computeDiff(cur, cand *impactScenario) []impactDiff {
	curKeys := map[string]ImpactRule{}
	for _, r := range cur.rules {
		curKeys[r.key()] = r
	}
	candKeys := map[string]ImpactRule{}
	for _, r := range cand.rules {
		candKeys[r.key()] = r
	}

	var out []impactDiff
	for k, r := range candKeys {
		if _, ok := curKeys[k]; ok {
			continue
		}
		out = append(out, impactDiff{change: ChangeAdded, rule: cand.refOf(r), ptype: r.PType, section: sectionOfPType(r.PType)})
	}
	for k, r := range curKeys {
		if _, ok := candKeys[k]; ok {
			continue
		}
		out = append(out, impactDiff{change: ChangeRemoved, rule: cur.refOf(r), ptype: r.PType, section: sectionOfPType(r.PType)})
	}

	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.section != b.section {
			return a.section < b.section
		}
		if a.ptype != b.ptype {
			return a.ptype < b.ptype
		}
		if a.change != b.change {
			return a.change < b.change
		}
		if a.rule.Index != b.rule.Index {
			return a.rule.Index < b.rule.Index
		}
		return strings.Join(a.rule.Rule, "\x00") < strings.Join(b.rule.Rule, "\x00")
	})
	return out
}

// subsetSnapshot derives the policy that results from applying exactly the
// changes at the given diff indexes.
//
// It starts from the candidate ordering, which is authoritative for models
// whose priority is the rule order itself: reverting an addition deletes the
// rule, and reverting a removal re-inserts the rule at the position it held in
// the base policy relative to the other surviving rules. Starting from the
// base and appending additions would silently move every added rule to the
// end, which changes implicit-priority models.
func subsetSnapshot(base, candidate ImpactSnapshot, diffs []impactDiff, kept []int) ImpactSnapshot {
	keep := make(map[int]bool, len(kept))
	for _, i := range kept {
		keep[i] = true
	}

	basePos := make(map[string]int, len(base.Policy))
	for i, r := range base.Policy {
		if _, ok := basePos[r.key()]; !ok {
			basePos[r.key()] = i
		}
	}

	// Rules to delete from the candidate view, and rules to restore.
	drop := map[string]bool{}
	var restore []ImpactRule
	for i, d := range diffs {
		if keep[i] {
			continue
		}
		key := ruleKey(d.ptype, d.rule.Rule)
		switch d.change {
		case ChangeAdded:
			drop[key] = true
		case ChangeRemoved:
			restore = append(restore, ImpactRule{PType: d.ptype, Rule: append([]string(nil), d.rule.Rule...)})
		}
	}

	out := ImpactSnapshot{Model: base.Model.Copy(), Policy: make([]ImpactRule, 0, len(candidate.Policy)+len(restore))}
	for _, r := range candidate.Policy {
		if drop[r.key()] {
			continue
		}
		out.Policy = append(out.Policy, r)
	}

	// Restore removed rules at their base position. A restored rule goes
	// immediately before the first surviving rule that came after it in the
	// base policy; otherwise it is appended.
	restorePos := make([]int, len(restore))
	for i, r := range restore {
		restorePos[i] = basePos[r.key()]
	}
	sort.SliceStable(restore, func(i, j int) bool { return restorePos[i] < restorePos[j] })

	for i, restored := range restore {
		insertAt := len(out.Policy)
		for j, existing := range out.Policy {
			if p, ok := basePos[existing.key()]; ok && p > restorePos[i] {
				insertAt = j
				break
			}
		}
		out.Policy = append(out.Policy, ImpactRule{})
		copy(out.Policy[insertAt+1:], out.Policy[insertAt:])
		out.Policy[insertAt] = restored
	}
	return out
}

// matcherInfo is the static reading of the matcher expression.
type matcherInfo struct {
	// fieldFn maps a policy field name (obj, act, dom, ...) to the relation
	// that binds it to the request: "==", "keyMatch", "g:g2", ...
	fieldFn map[string]string
	// subjectG / objectG are the role definitions used for those fields.
	subjectG string
	objectG  string
	// hostFunctions lists call names that are neither built-ins nor role
	// definitions; their semantics are unknown to a static preview.
	hostFunctions []string
	// usesEval is true when the matcher calls eval(), i.e. rule text is only
	// interpreted at request time.
	usesEval bool
	// usesAttr is true when the matcher (or an eval rule) dereferences a
	// request attribute such as r.sub.Age.
	usesAttr bool
}

var (
	fnCallRe     = regexp.MustCompile(`\b([A-Za-z][A-Za-z0-9_]*)\(\s*r\d*_([A-Za-z0-9_]+)\s*,\s*p\d*_([A-Za-z0-9_]+)\s*\)`)
	equalityRe   = regexp.MustCompile(`\br\d*_([A-Za-z0-9_]+)\s*==\s*p\d*_([A-Za-z0-9_]+)\b`)
	attrAccessRe = regexp.MustCompile(`\b[pr]\d*_[A-Za-z0-9_]+\.[A-Za-z0-9_]+`)
	// unableToAccessRe reads the attribute name out of govaluate's
	// "Unable to access 'Age', ..." error.
	unableToAccessRe = regexp.MustCompile(`Unable to access '([^']+)'`)
	evalCallRe       = regexp.MustCompile(`\beval\(`)
	builtinSet       = map[string]bool{"keyMatch": true, "keyGet": true, "keyMatch2": true, "keyGet2": true, "keyMatch3": true, "keyGet3": true, "keyMatch4": true, "keyMatch5": true, "regexMatch": true, "ipMatch": true, "globMatch": true}
)

func analyseMatcher(sc *impactScenario) matcherInfo {
	info := matcherInfo{fieldFn: map[string]string{}}
	value := sc.matcherValue()
	info.usesEval = evalCallRe.MatchString(value)
	info.usesAttr = attrAccessRe.MatchString(value)

	gtypes := sc.roleTypes()
	for _, match := range fnCallRe.FindAllStringSubmatch(value, -1) {
		fn, rField, pField := match[1], match[2], match[3]
		if gtypes[fn] {
			info.fieldFn[pField] = "g:" + fn
			if rField == "sub" {
				info.subjectG = fn
			}
			if rField == "obj" {
				info.objectG = fn
			}
			continue
		}
		if builtinSet[fn] {
			info.fieldFn[pField] = fn
			continue
		}
		info.hostFunctions = append(info.hostFunctions, fn)
	}
	for _, match := range equalityRe.FindAllStringSubmatch(value, -1) {
		if _, ok := info.fieldFn[match[2]]; !ok {
			info.fieldFn[match[2]] = "=="
		}
	}
	info.hostFunctions = dedupeSorted(info.hostFunctions)
	return info
}

// requestShape maps request token positions to their semantics and maps each
// policy column to the request position it compares against.
type requestShape struct {
	names []string
	// cols[ptype][i] is the request position policy column i compares with, or
	// -1 when the column is not a request field (eft, priority, rule text).
	cols map[string][]int
	sub  int
	dom  int
	obj  int
	act  int
}

func newRequestShape(sc *impactScenario) requestShape {
	shape := requestShape{
		names: sc.requestTokens(),
		cols:  map[string][]int{},
		sub:   -1, dom: -1, obj: -1, act: -1,
	}
	seen := map[string]int{}
	for i, name := range shape.names {
		if _, ok := seen[name]; !ok {
			seen[name] = i
		}
	}
	shape.sub = pick(seen, "sub", 0)
	shape.obj = pick(seen, "obj", -1)
	shape.act = pick(seen, "act", -1)
	shape.dom = pick(seen, "dom", -1)
	// Conventional fallbacks for models with non-standard token names.
	if shape.sub < 0 {
		shape.sub = 0
	}
	if shape.obj < 0 && len(shape.names) > 1 {
		shape.obj = 1
	}
	if shape.act < 0 && len(shape.names) > 2 {
		shape.act = 2
	}

	for ptype, tokens := range sc.tokens {
		cols := make([]int, len(tokens))
		for i, tok := range tokens {
			name := tokenName(tok)
			cols[i] = -1
			if pos, ok := seen[name]; ok {
				cols[i] = pos
			}
		}
		shape.cols[ptype] = cols
	}
	return shape
}

func pick(seen map[string]int, name string, fallback int) int {
	if v, ok := seen[name]; ok {
		return v
	}
	return fallback
}
