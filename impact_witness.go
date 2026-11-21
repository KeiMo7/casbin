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

// Witness derivation for the impact preview.
//
// A witness is a concrete request evaluated against both policies. Witnesses
// are derived from policy entities, never from the request space: each one is
// anchored to a rule that changed (or to a rule that can interact with one),
// and its fields are concrete values that exercise that rule. The bounded
// products below are the only products taken.

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/casbin/casbin/v3/util"
)

const (
	// maxSubjectsPerRule caps how many subject candidates one rule
	// contributes. Subject closure is the widest dimension in practice.
	maxSubjectsPerRule = 64
	// maxValuesPerField caps concrete samples per request field.
	maxValuesPerField = 3
	// maxDomainsPerRule caps domain candidates per rule.
	maxDomainsPerRule = 8
	// maxInteractingRules caps how many sibling rules are joined with a changed
	// rule to probe deny/priority interactions.
	maxInteractingRules = 64
	// maxWitnessesPerChange caps the product taken for one changed rule.
	maxWitnessesPerChange = 1024
)

// witnessClass orders witnesses for truncation. Witnesses anchored directly at
// a changed rule are kept first, propagated role-closure witnesses next, and
// cross-rule interaction witnesses last: when the budget bites, the preview
// keeps the witnesses most likely to be decisive.
type witnessClass int

const (
	classChangedRule witnessClass = iota
	classRoleClosure
	classInteraction
)

type impactWitness struct {
	request []interface{}
	key     string
	class   witnessClass
	// source names the change that anchored the witness.
	source string
}

// witnessSet accumulates witnesses keyed by request, keeping the best class.
type witnessSet struct {
	byKey map[string]*impactWitness
	// capped counts witnesses dropped by a per-rule cap, for the report.
	capped []string
}

func newWitnessSet() *witnessSet {
	return &witnessSet{byKey: map[string]*impactWitness{}}
}

func (w *witnessSet) add(class witnessClass, source string, req []interface{}) {
	key := requestKey(req)
	if existing, ok := w.byKey[key]; ok {
		if class < existing.class {
			existing.class = class
			existing.source = source
		}
		return
	}
	w.byKey[key] = &impactWitness{
		request: append([]interface{}(nil), req...),
		key:     key,
		class:   class,
		source:  source,
	}
}

// ordered returns the witnesses in truncation order: class, then request key.
func (w *witnessSet) ordered() []*impactWitness {
	out := make([]*impactWitness, 0, len(w.byKey))
	for _, v := range w.byKey {
		out = append(out, v)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].class != out[j].class {
			return out[i].class < out[j].class
		}
		return out[i].key < out[j].key
	})
	return out
}

// deriveWitnesses builds the witness set for a diff.
func deriveWitnesses(cur, cand *impactScenario, diffs []impactDiff, matcher matcherInfo, shape requestShape) *witnessSet {
	set := newWitnessSet()
	for _, d := range diffs {
		if d.section == "p" {
			deriveFromPolicyChange(set, d, cur, cand, matcher, shape)
		} else {
			deriveFromGroupingChange(set, d, cur, cand, matcher, shape)
		}
	}
	return set
}

// deriveFromPolicyChange builds witnesses anchored at one changed p rule.
func deriveFromPolicyChange(set *witnessSet, d impactDiff, cur, cand *impactScenario, matcher matcherInfo, shape requestShape) {
	source := string(d.change) + " " + d.rule.String()
	rule := ImpactRule{PType: d.ptype, Rule: d.rule.Rule}

	subjects := subjectCandidates(rule, cur, cand, matcher, shape)
	objects, _ := objectSamples(rule, cur, cand, matcher)
	actions := fieldSamples(rule, cur, cand, matcher, "act")
	domains := domainCandidates(rule, cur, cand, shape)

	emitted := 0
	for _, dom := range domains {
		for _, sub := range subjectCandidatesForDomain(rule, subjSubject(rule, cur), dom, subjects, cur, cand, matcher) {
			for _, obj := range objects {
				for _, act := range actions {
					if emitted >= maxWitnessesPerChange {
						set.capped = append(set.capped,
							fmt.Sprintf("changed rule %s: witness product capped at %d", d.rule.String(), maxWitnessesPerChange))
						break
					}
					if req := buildRequest(shape, cur, d.ptype, d.rule.Rule, sub, dom, obj, act); req != nil {
						set.add(classChangedRule, source, req)
						emitted++
					}
				}
				if emitted >= maxWitnessesPerChange {
					break
				}
			}
			if emitted >= maxWitnessesPerChange {
				break
			}
		}
		if emitted >= maxWitnessesPerChange {
			break
		}
	}

	// Join sibling rules sharing the object/action/domain. This is where a new
	// deny rule flips a previously allowed subject, and where priority
	// inversions surface.
	for _, sib := range interactingRules(d, cur, cand, matcher) {
		sibSubjects := subjectCandidates(sib, cur, cand, matcher, shape)
		sibObjects, _ := objectSamples(sib, cur, cand, matcher)
		sibActions := fieldSamples(sib, cur, cand, matcher, "act")
		sibDomains := domainCandidates(sib, cur, cand, shape)
		for _, dom := range sibDomains {
			for _, sub := range sibSubjects {
				for _, obj := range sibObjects {
					for _, act := range sibActions {
						if req := buildRequest(shape, cur, d.ptype, d.rule.Rule, sub, dom, obj, act); req != nil {
							set.add(classInteraction, "interaction: "+source+" with "+sib.ruleString(), req)
						}
					}
				}
			}
		}
	}
}

// deriveFromGroupingChange turns one changed role link into witnesses through
// the permissions the link can now reach.
func deriveFromGroupingChange(set *witnessSet, d impactDiff, cur, cand *impactScenario, matcher matcherInfo, shape requestShape) {
	if len(d.rule.Rule) < 2 {
		return
	}
	u, r := d.rule.Rule[0], d.rule.Rule[1]
	domains := groupingDomains(d, cur, cand, shape)

	users, roles := closureOfLink(d.ptype, u, r, domains, cur, cand)
	if len(users) == 0 {
		users = []string{u}
	}
	source := "role closure through " + string(d.change) + " " + d.rule.String()

	for _, ptype := range policyTypes(cur, cand) {
		for _, p := range allPolicyRules(cur, cand, ptype) {
			rule := ImpactRule{PType: ptype, Rule: p}
			pSub := cur.field(ptype, p, "sub")
			if pSub == "" {
				continue
			}
			reachesRole := containsString(roles, pSub)
			// A rule attached to one of the users is affected directly.
			reachesUser := containsString(users, pSub)
			if !reachesRole && !reachesUser {
				continue
			}
			objects, _ := objectSamples(rule, cur, cand, matcher)
			actions := fieldSamples(rule, cur, cand, matcher, "act")
			for _, dom := range ruleDomains(rule, domains, cur, shape) {
				for _, sub := range users {
					for _, obj := range objects {
						for _, act := range actions {
							if req := buildRequest(shape, cur, ptype, p, sub, dom, obj, act); req != nil {
								set.add(classRoleClosure, source, req)
							}
						}
					}
				}
			}
		}
	}

	// A changed resource-role link moves concrete resources into (or out of)
	// the role's permissions; those resources are witnesses for every rule
	// attached to the role.
	if matcher.objectG != d.ptype {
		return
	}
	objects := resourceObjects(d.ptype, u, domains, cur, cand)
	if len(objects) == 0 {
		objects = []string{u}
	}
	for _, ptype := range policyTypes(cur, cand) {
		for _, p := range allPolicyRules(cur, cand, ptype) {
			rule := ImpactRule{PType: ptype, Rule: p}
			pObj := cur.field(ptype, p, "obj")
			if pObj == "" || !containsString(roles, pObj) {
				continue
			}
			subs := subjectCandidates(rule, cur, cand, matcher, shape)
			actions := fieldSamples(rule, cur, cand, matcher, "act")
			for _, dom := range ruleDomains(rule, domains, cur, shape) {
				for _, sub := range subs {
					for _, obj := range objects {
						for _, act := range actions {
							if req := buildRequest(shape, cur, ptype, p, sub, dom, obj, act); req != nil {
								set.add(classRoleClosure, source, req)
							}
						}
					}
				}
			}
		}
	}
}

// genericSubject is used when a model has no subject column at all (for
// example an eval()-only policy): the request still needs a value there, and
// any plain string behaves the same way for the purpose of the preview.
const genericSubject = "alice"

// subjectCandidates returns the subjects worth evaluating for a rule: its own
// subject plus, when the subject field is a role, the implicit users of that
// role in either scenario.
func subjectCandidates(rule ImpactRule, cur, cand *impactScenario, matcher matcherInfo, shape requestShape) []string {
	sub := cur.field(rule.PType, rule.Rule, "sub")
	if sub == "" {
		// No subject column: fall back to every subject the policies mention,
		// or to one representative value when they mention none.
		panorama := subjectUniverse(cur, cand)
		if len(panorama) == 0 {
			panorama = []string{genericSubject}
		}
		return limitStrings(panorama, maxSubjectsPerRule)
	}
	out := []string{sub}
	if matcher.subjectG == "" {
		return dedupeSorted(out)
	}
	for _, sc := range []*impactScenario{cur, cand} {
		rm := sc.enf.GetNamedRoleManager(matcher.subjectG)
		if rm == nil {
			continue
		}
		for _, dom := range allDomains(cur, cand, shape) {
			if users, err := rm.GetImplicitUsers(sub, dom); err == nil {
				out = append(out, users...)
			}
		}
	}
	return limitStrings(dedupeSorted(out), maxSubjectsPerRule)
}

// subjectUniverse collects every value that appears in a subject position:
// policy subjects, grouping users and grouping roles.
func subjectUniverse(cur, cand *impactScenario) []string {
	var out []string
	for _, sc := range []*impactScenario{cur, cand} {
		if sc == nil {
			continue
		}
		for ptype, ast := range sc.model["p"] {
			idx, ok := sc.fieldIndex(ptype, "sub")
			if !ok {
				continue
			}
			for _, rule := range ast.Policy {
				if idx < len(rule) {
					out = append(out, rule[idx])
				}
			}
		}
		for ptype, ast := range sc.model["g"] {
			cols, ok := sc.fieldIndex(ptype, "sub")
			if !ok {
				continue
			}
			objCol, hasObj := sc.fieldIndex(ptype, "obj")
			for _, rule := range ast.Policy {
				if cols < len(rule) {
					out = append(out, rule[cols])
				}
				if hasObj && objCol < len(rule) {
					out = append(out, rule[objCol])
				}
			}
		}
	}
	return dedupeSorted(out)
}

// subjectCandidatesForDomain keeps subjects that actually carry the rule's
// subject in this domain, so domains and subjects do not multiply blindly.
func subjectCandidatesForDomain(rule ImpactRule, own string, dom string, candidates []string, cur, cand *impactScenario, matcher matcherInfo) []string {
	if dom == "" || matcher.subjectG == "" {
		return candidates
	}
	out := []string{own}
	for _, sc := range []*impactScenario{cur, cand} {
		rm := sc.enf.GetNamedRoleManager(matcher.subjectG)
		if rm == nil {
			continue
		}
		for _, sub := range candidates {
			if ok, _ := rm.HasLink(sub, own, dom); ok {
				out = append(out, sub)
			}
		}
	}
	return limitStrings(dedupeSorted(out), maxSubjectsPerRule)
}

func subjSubject(rule ImpactRule, sc *impactScenario) string {
	return sc.field(rule.PType, rule.Rule, "sub")
}

// objectSamples returns concrete object values that exercise the rule's object
// field, including concrete resources that reach a role-valued object.
func objectSamples(rule ImpactRule, cur, cand *impactScenario, matcher matcherInfo) ([]string, []string) {
	value := fieldEither(rule, "obj", cur, cand)
	if value == "" {
		return []string{""}, nil
	}
	var out []string
	var notes []string
	samples, note := samplesFor(matcher.fieldFn["obj"], value)
	out = append(out, samples...)
	if note != "" {
		notes = append(notes, note)
	}
	if matcher.objectG != "" {
		for _, sc := range []*impactScenario{cur, cand} {
			rm := sc.enf.GetNamedRoleManager(matcher.objectG)
			if rm == nil {
				continue
			}
			for _, dom := range allDomainValues(cur, cand) {
				if users, err := rm.GetImplicitUsers(value, dom); err == nil {
					out = append(out, users...)
				}
			}
		}
	}
	return limitStrings(dedupeSorted(out), maxValuesPerField), notes
}

// fieldSamples returns concrete request values for one policy field.
func fieldSamples(rule ImpactRule, cur, cand *impactScenario, matcher matcherInfo, name string) []string {
	value := fieldEither(rule, name, cur, cand)
	if value == "" {
		return []string{""}
	}
	samples, _ := samplesFor(matcher.fieldFn[name], value)
	return limitStrings(dedupeSorted(samples), maxValuesPerField)
}

// fieldEither reads a policy column from whichever scenario defines the ptype;
// the candidate can introduce a definition the current policy does not have.
func fieldEither(rule ImpactRule, name string, cur, cand *impactScenario) string {
	if v := cur.field(rule.PType, rule.Rule, name); v != "" {
		return v
	}
	return cand.field(rule.PType, rule.Rule, name)
}

// allDomainValues returns every distinct domain value in either policy.
func allDomainValues(cur, cand *impactScenario) []string {
	set := map[string]bool{}
	for _, sc := range []*impactScenario{cur, cand} {
		if sc == nil {
			continue
		}
		for _, r := range sc.rules {
			if v := sc.field(r.PType, r.Rule, "dom"); v != "" {
				set[v] = true
			}
		}
	}
	if len(set) == 0 {
		return []string{""}
	}
	out := make([]string, 0, len(set))
	for d := range set {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

// domainCandidates returns the domains to probe for a rule: its own domain plus
// every domain in either policy, so a misplaced rule is witnessed.
func domainCandidates(rule ImpactRule, cur, cand *impactScenario, shape requestShape) []string {
	if shape.dom < 0 {
		return []string{""}
	}
	domains := allDomains(cur, cand, shape)
	if own := cur.field(rule.PType, rule.Rule, "dom"); own != "" {
		domains = append(domains, own)
	}
	return limitStrings(dedupeSorted(domains), maxDomainsPerRule)
}

func groupingDomains(d impactDiff, cur, cand *impactScenario, shape requestShape) []string {
	if shape.dom < 0 {
		return []string{""}
	}
	if own := cur.field(d.ptype, d.rule.Rule, "dom"); own != "" {
		return []string{own}
	}
	return allDomains(cur, cand, shape)
}

func ruleDomains(rule ImpactRule, fallback []string, cur *impactScenario, shape requestShape) []string {
	if shape.dom < 0 {
		return []string{""}
	}
	if own := cur.field(rule.PType, rule.Rule, "dom"); own != "" {
		out := append([]string{own}, fallback...)
		return limitStrings(dedupeSorted(out), maxDomainsPerRule)
	}
	return fallback
}

// buildRequest assembles a request in request-token order.
func buildRequest(shape requestShape, cur *impactScenario, ptype string, rule []string, sub, dom, obj, act string) []interface{} {
	if len(shape.names) == 0 {
		return nil
	}
	req := make([]interface{}, len(shape.names))
	for i := range req {
		req[i] = ""
	}
	set := func(pos int, v string) {
		if pos >= 0 && pos < len(req) {
			req[pos] = v
		}
	}
	set(shape.sub, sub)
	set(shape.dom, dom)
	set(shape.obj, obj)
	set(shape.act, act)

	// Fill any request field this rule maps to that was not chosen above, so
	// models with extra request tokens (resource, tenant, ...) still compare
	// the rule's own value there.
	cols := shape.cols[ptype]
	for pi, pos := range cols {
		if pi >= len(rule) || pos < 0 || pos >= len(req) {
			continue
		}
		if req[pos] == "" {
			req[pos] = rule[pi]
		}
	}
	return req
}

func allDomains(cur, cand *impactScenario, shape requestShape) []string {
	if shape.dom < 0 {
		return []string{""}
	}
	set := map[string]bool{}
	for _, sc := range []*impactScenario{cur, cand} {
		if sc == nil {
			continue
		}
		for _, r := range sc.rules {
			if v := sc.field(r.PType, r.Rule, "dom"); v != "" {
				set[v] = true
			}
		}
	}
	out := make([]string, 0, len(set))
	for d := range set {
		out = append(out, d)
	}
	sort.Strings(out)
	if len(out) == 0 {
		return []string{""}
	}
	return out
}

func policyTypes(cur, cand *impactScenario) []string {
	set := map[string]bool{}
	for _, sc := range []*impactScenario{cur, cand} {
		for ptype := range sc.model["p"] {
			set[ptype] = true
		}
	}
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// allPolicyRules returns the union of a ptype's rules in both scenarios,
// de-duplicated and ordered.
func allPolicyRules(cur, cand *impactScenario, ptype string) [][]string {
	seen := map[string]bool{}
	var out [][]string
	for _, sc := range []*impactScenario{cur, cand} {
		ast, ok := sc.model["p"][ptype]
		if !ok {
			continue
		}
		for _, r := range ast.Policy {
			key := strings.Join(r, "\x00")
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, append([]string(nil), r...))
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		return strings.Join(out[i], "\x00") < strings.Join(out[j], "\x00")
	})
	return out
}

// interactingRules returns the rules that share a changed rule's object, action
// and domain and could therefore interact with it.
func interactingRules(d impactDiff, cur, cand *impactScenario, matcher matcherInfo) []ImpactRule {
	obj := cur.field(d.ptype, d.rule.Rule, "obj")
	act := cur.field(d.ptype, d.rule.Rule, "act")
	dom := cur.field(d.ptype, d.rule.Rule, "dom")
	sub := cur.field(d.ptype, d.rule.Rule, "sub")
	objFn := matcher.fieldFn["obj"]

	var out []ImpactRule
	seen := map[string]bool{}
	for _, ptype := range policyTypes(cur, cand) {
		for _, p := range allPolicyRules(cur, cand, ptype) {
			key := ruleKey(ptype, p)
			if seen[key] {
				continue
			}
			if !fieldRelates(objFn, cur.field(ptype, p, "obj"), obj) {
				continue
			}
			if other := cur.field(ptype, p, "act"); other != act && !fieldRelates(matcher.fieldFn["act"], other, act) {
				continue
			}
			if other := cur.field(ptype, p, "dom"); dom != "" && other != "" && other != dom {
				continue
			}
			if cur.field(ptype, p, "sub") == sub {
				continue
			}
			seen[key] = true
			out = append(out, ImpactRule{PType: ptype, Rule: p})
			if len(out) >= maxInteractingRules {
				return out
			}
		}
	}
	return out
}

func (r ImpactRule) ruleString() string {
	return r.PType + ", " + strings.Join(r.Rule, ", ")
}

func fieldRelates(fn, value, pattern string) bool {
	if value == pattern {
		return true
	}
	if fn == "" || fn == "==" || strings.HasPrefix(fn, "g:") {
		return false
	}
	return matchByFn(fn, value, pattern)
}

// closureOfLink returns the subjects and roles affected by one grouping link,
// including transitive reach in either scenario.
func closureOfLink(ptype, u, r string, domains []string, cur, cand *impactScenario) ([]string, []string) {
	users := []string{u}
	roles := []string{r}
	for _, sc := range []*impactScenario{cur, cand} {
		rm := sc.enf.GetNamedRoleManager(ptype)
		if rm == nil {
			continue
		}
		for _, dom := range domains {
			if implicit, err := rm.GetImplicitUsers(u, dom); err == nil {
				users = append(users, implicit...)
			}
			if implicit, err := rm.GetImplicitRoles(r, dom); err == nil {
				roles = append(roles, implicit...)
			}
		}
	}
	return limitStrings(dedupeSorted(users), maxSubjectsPerRule), dedupeSorted(roles)
}

// resourceObjects returns the concrete resources affected by a resource-role
// link in either scenario.
func resourceObjects(ptype, u string, domains []string, cur, cand *impactScenario) []string {
	objects := []string{u}
	for _, sc := range []*impactScenario{cur, cand} {
		rm := sc.enf.GetNamedRoleManager(ptype)
		if rm == nil {
			continue
		}
		for _, dom := range domains {
			if implicit, err := rm.GetImplicitUsers(u, dom); err == nil {
				objects = append(objects, implicit...)
			}
		}
	}
	return limitStrings(dedupeSorted(objects), maxValuesPerField)
}

func containsString(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

func dedupeSorted(in []string) []string {
	set := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, v := range in {
		if set[v] {
			continue
		}
		set[v] = true
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func limitStrings(in []string, limit int) []string {
	if limit <= 0 || len(in) <= limit {
		return in
	}
	return in[:limit]
}

// samplesFor turns a policy field value into concrete request values that
// satisfy fn(value). It returns a note when the pattern could not be sampled
// faithfully.
func samplesFor(fn, value string) ([]string, string) {
	if fn == "" || fn == "==" || strings.HasPrefix(fn, "g:") {
		return []string{value}, ""
	}
	var candidates []string
	switch fn {
	case "keyMatch", "keyMatch2", "keyMatch3", "keyMatch4", "keyMatch5":
		candidates = concretizeKey(value)
	case "globMatch":
		candidates = concretizeGlob(value)
	case "regexMatch":
		candidates = concretizeRegex(value)
	case "ipMatch":
		candidates = concretizeIP(value)
	default:
		return []string{value}, ""
	}
	var out []string
	for _, c := range candidates {
		if matchByFn(fn, c, value) {
			out = append(out, c)
		}
	}
	if len(out) == 0 {
		return []string{value}, fmt.Sprintf("pattern %q could not be instantiated; only the literal was probed", value)
	}
	return out, ""
}

func matchByFn(fn, value, pattern string) bool {
	switch fn {
	case "keyMatch":
		return util.KeyMatch(value, pattern)
	case "keyMatch2":
		return util.KeyMatch2(value, pattern)
	case "keyMatch3":
		return util.KeyMatch3(value, pattern)
	case "keyMatch4":
		return util.KeyMatch4(value, pattern)
	case "keyMatch5":
		return util.KeyMatch5(value, pattern)
	case "globMatch":
		matched, err := util.GlobMatch(value, pattern)
		return err == nil && matched
	case "regexMatch":
		return util.RegexMatch(value, pattern)
	case "ipMatch":
		return util.IPMatch(value, pattern)
	}
	return false
}

func concretizeKey(pattern string) []string {
	if !strings.ContainsAny(pattern, "*:{}") {
		return []string{pattern}
	}
	v := strings.ReplaceAll(pattern, "/*", "/x")
	v = strings.ReplaceAll(v, "*", "x")
	for {
		i := strings.IndexByte(v, ':')
		if i < 0 {
			break
		}
		j := i + 1
		for j < len(v) && isVarChar(v[j]) {
			j++
		}
		v = v[:i] + "1" + v[j:]
	}
	for {
		i := strings.IndexByte(v, '{')
		j := strings.IndexByte(v, '}')
		if i < 0 || j < i {
			break
		}
		v = v[:i] + "1" + v[j+1:]
	}
	if v == pattern {
		return []string{pattern}
	}
	return []string{v, v + "b"}
}

func isVarChar(b byte) bool {
	return b == '_' || b == '-' || b == '.' || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

func concretizeGlob(pattern string) []string {
	if !strings.ContainsAny(pattern, "*?[]{}") {
		return []string{pattern}
	}
	v := strings.ReplaceAll(pattern, "**", "x/y")
	v = strings.ReplaceAll(v, "*", "x")
	v = strings.ReplaceAll(v, "?", "a")
	if i := strings.IndexByte(v, '['); i >= 0 {
		if j := strings.IndexByte(v[i:], ']'); j >= 0 {
			inner := v[i+1 : i+j]
			repl := "a"
			if k := strings.IndexByte(inner, '-'); k > 0 {
				repl = inner[:k]
			} else if len(inner) > 0 && inner[0] != '!' && inner[0] != '^' {
				repl = inner[:1]
			}
			v = v[:i] + repl + v[i+j+1:]
		}
	}
	if i := strings.IndexByte(v, '{'); i >= 0 {
		if j := strings.IndexByte(v[i:], '}'); j >= 0 {
			alts := strings.Split(v[i+1:i+j], ",")
			v = v[:i] + alts[0] + v[i+j+1:]
		}
	}
	return []string{v}
}

func concretizeRegex(pattern string) []string {
	v, ok := sampleRegex(pattern)
	if !ok {
		return nil
	}
	return []string{v}
}

// sampleRegex produces one string that matches the regular expression for the
// common shapes used in policy patterns. It refuses constructs it cannot
// sample (lookarounds, backreferences); those fall back to the literal.
func sampleRegex(pattern string) (string, bool) {
	var b strings.Builder
	i := 0
	lastAtom := ""
	for i < len(pattern) {
		atom, next, done := regexAtom(pattern, i, &b, lastAtom)
		if done {
			return "", false
		}
		if atom == "|" {
			return b.String(), b.Len() > 0
		}
		if atom != "" {
			lastAtom = atom
		}
		i = next
	}
	if b.Len() == 0 {
		return "", false
	}
	return b.String(), true
}

// regexAtom consumes one construct of the pattern starting at i, appending its
// sample to b when it contributes a character. It returns the atom written (for
// quantifier repeats), the next index, and whether the pattern is unsupported.
// A returned atom of "|" ends the first alternative.
func regexAtom(pattern string, i int, b *strings.Builder, lastAtom string) (string, int, bool) {
	c := pattern[i]
	switch c {
	case '^', '$':
		return "", i + 1, false
	case '(':
		if strings.HasPrefix(pattern[i:], "(?:") {
			return "", i + 3, false
		}
		if strings.HasPrefix(pattern[i:], "(?") {
			return "", 0, true
		}
		return "", i + 1, false
	case ')':
		return "", i + 1, false
	case '|':
		return "|", i + 1, false
	case '[':
		j := strings.IndexByte(pattern[i:], ']')
		if j < 0 {
			return "", 0, true
		}
		repl := sampleRegexClass(pattern[i+1 : i+j])
		b.WriteString(repl)
		return repl, i + j + 1, false
	case '\\':
		if i+1 >= len(pattern) {
			return "", 0, true
		}
		repl := regexClassSample(pattern[i+1])
		b.WriteString(repl)
		return repl, i + 2, false
	case '.':
		b.WriteByte('x')
		return "x", i + 1, false
	case '*', '+':
		if b.Len() == 0 {
			b.WriteByte('x')
			return "x", i + 1, false
		}
		return "", i + 1, false
	case '?':
		return "", i + 1, false
	case '{':
		next := applyRepeat(pattern, i, b, lastAtom)
		if next == 0 {
			return "", 0, true
		}
		return "", next, false
	default:
		if !isRegexLiteral(c) {
			return "", 0, true
		}
		b.WriteByte(c)
		return string(c), i + 1, false
	}
}

// applyRepeat consumes a {n} quantifier, repeating the last atom n-1 more
// times. It returns the index just past the quantifier, or 0 when the pattern
// is unsupported.
func applyRepeat(pattern string, i int, b *strings.Builder, lastAtom string) int {
	j := strings.IndexByte(pattern[i:], '}')
	if j < 0 {
		return 0
	}
	n, ok := parseRepeat(pattern[i+1 : i+j])
	if !ok {
		return 0
	}
	if lastAtom == "" {
		lastAtom = "x"
		b.WriteString(lastAtom)
	}
	for k := 1; k < n; k++ {
		b.WriteString(lastAtom)
	}
	return i + j + 1
}

// sampleRegexClass returns one character that the character class inner
// accepts.
func sampleRegexClass(inner string) string {
	if len(inner) > 0 && (inner[0] == '!' || inner[0] == '^') {
		inner = inner[1:]
	}
	if len(inner) == 0 {
		return "a"
	}
	if inner[0] == '\\' && len(inner) > 1 {
		return regexClassSample(inner[1])
	}
	if inner[0] == '-' {
		return "a"
	}
	return string(inner[0])
}

func regexClassSample(c byte) string {
	switch c {
	case 'd':
		return "1"
	case 'w', 'D', 'S':
		return "a"
	case 's':
		return " "
	case 'W':
		return "-"
	case 'b':
		return ""
	}
	return string(c)
}

func isRegexLiteral(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
		c == '/' || c == '-' || c == '_' || c == ' ' || c == '.' || c == ','
}

func parseRepeat(s string) (int, bool) {
	if i := strings.IndexByte(s, ','); i >= 0 {
		s = s[:i]
	}
	if s == "" {
		return 1, true
	}
	v := 0
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
		v = v*10 + int(s[i]-'0')
		if v > 64 {
			return 0, false
		}
	}
	if v == 0 {
		return 1, true
	}
	return v, true
}

func concretizeIP(value string) []string {
	if _, cidr, err := net.ParseCIDR(value); err == nil {
		return []string{cidr.IP.String()}
	}
	if net.ParseIP(value) != nil {
		return []string{value}
	}
	return nil
}
