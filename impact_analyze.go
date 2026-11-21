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

// Impact analysis: evaluation, attribution and truncation.
//
// Every witness is evaluated against a throwaway enforcer for the current
// policy and one for the candidate policy. A confirmed flip is attributed to an
// irreducible subset of the diff: the analysis drops changes one at a time and
// keeps a removal only when the flip survives it, so every rule that remains
// is necessary. When a decision cannot be reached — a rule reads request
// attributes, the matcher calls a host function, a role link carries a runtime
// condition — the witness goes to the uncertain population and is never
// counted as allowed or denied.

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/casbin/casbin/v3/model"
)

// DefaultImpactWitnessLimit is the default budget of witness requests. It
// keeps a preview inside a narrow change window while still covering every
// changed rule.
const DefaultImpactWitnessLimit = 8000

// defaultCauseSearch caps greedy minimisation steps per flip.
const defaultCauseSearch = 128

// minMinimiseBudget and maxMinimiseBudget bound the total number of greedy
// minimisation steps for one preview, so that a large diff over many flips
// cannot push the preview outside its change window. When the budget runs out
// the remaining flips cite the full diff, which is a sufficient (not minimal)
// cause, and say so.
const (
	minMinimiseBudget = 256
	maxMinimiseBudget = 8192
)

// ImpactOptions tunes a preview.
type ImpactOptions struct {
	// WitnessLimit caps how many witnesses are evaluated. When the derived set
	// is larger, the excess is dropped in the documented order and reported as
	// a Truncation. Zero means DefaultImpactWitnessLimit; a negative value
	// disables the cap.
	WitnessLimit int
	// MaxCauseSearch caps the greedy minimisation steps per flip. Zero means
	// 128. When the diff needs more steps the cited causes are then a proven
	// superset — never a wrong subset — and the Explanation says so.
	MaxCauseSearch int
	// RoleMatching, when set, tells the preview which name-matching functions
	// the live enforcer has installed on its role managers. Those functions
	// live on the enforcer, not in the model, so the preview cannot recover
	// them from a snapshot. Leave nil when the enforcer uses none.
	RoleMatching RoleMatchingInfo
}

// RoleMatchingInfo describes the name-matching functions installed on the role
// managers of the enforcer the preview runs against.
type RoleMatchingInfo struct {
	// Names are the matching-function names registered with AddNamedMatchingFunc
	// (typically "keyMatch" or "keyMatch2"). Empty means no matching function.
	Names []string
	// DomainNames are the names registered with AddNamedDomainMatchingFunc.
	DomainNames []string
}

// Incompatible reports whether the installed functions cannot be reproduced by
// a model-only preview. Every name in Names/DomainNames is a host-installed
// function, so any non-empty value is incompatible.
func (r RoleMatchingInfo) Incompatible() bool {
	return len(r.Names) > 0 || len(r.DomainNames) > 0
}

func (r RoleMatchingInfo) explain() string {
	var parts []string
	if len(r.Names) > 0 {
		parts = append(parts, "role matching function(s) "+strings.Join(r.Names, ", "))
	}
	if len(r.DomainNames) > 0 {
		parts = append(parts, "domain matching function(s) "+strings.Join(r.DomainNames, ", "))
	}
	return "the enforcer installs " + strings.Join(parts, " and ") +
		"; the preview rebuilds the policy from the model only and cannot reproduce them, " +
		"so its role closure would be computed from literal names"
}

// Impact compares the enforcer's current policy with candidate and reports
// which requests change decision. The enforcer is never modified: both sides
// are evaluated through throwaway enforcers built from copies.
//
// If the live policy changes while the preview runs, Impact returns an error
// rather than a report that no longer describes the live policy. If the
// enforcer has name-matching functions installed on its role managers, the
// preview reports a Failure: those functions are enforcer state, not model
// state, and a snapshot cannot carry them.
func (e *Enforcer) Impact(candidate ImpactSnapshot, opts ImpactOptions) (*Report, error) {
	if e == nil {
		return nil, fmt.Errorf("impact: nil enforcer")
	}
	if !opts.RoleMatching.Incompatible() {
		opts.RoleMatching = e.roleMatchingInfo()
	}
	versionBefore := e.getPolicyVersion()
	current, err := snapshotFromEnforcer(e)
	if err != nil {
		return nil, err
	}
	report, err := ComputeImpact(current, candidate, opts)
	if err != nil {
		return nil, err
	}
	if e.getPolicyVersion() != versionBefore {
		return nil, fmt.Errorf("impact: the live policy changed during the preview (policy version %d -> %d)",
			versionBefore, e.getPolicyVersion())
	}
	after, err := snapshotFromEnforcer(e)
	if err != nil {
		return nil, err
	}
	if !snapshotsEqual(current, after) {
		return nil, fmt.Errorf("impact: the live policy changed during the preview")
	}
	return report, nil
}

// roleMatchingInfo reads the name-matching functions the enforcer's role
// managers carry. The default role managers expose Match(str, pattern); the
// preview cannot know which pattern language such a function implements, so
// any observable, non-identity matching is reported as installed.
//
// A role manager with no matching function returns str == pattern only. The
// probe below exercises two pattern-shaped inputs that no literal name is
// expected to equal; when either matches, a matching function is installed.
func (e *Enforcer) roleMatchingInfo() RoleMatchingInfo {
	var info RoleMatchingInfo
	for ptype, rm := range e.rmMap {
		if rm == nil {
			continue
		}
		if !roleManagerIsIdentity(rm) {
			info.Names = append(info.Names, ptype)
		}
	}
	for ptype, crm := range e.condRmMap {
		if crm == nil {
			continue
		}
		if !roleManagerIsIdentity(crm) {
			info.Names = append(info.Names, ptype)
		}
	}
	sort.Strings(info.Names)
	return info
}

// roleManagerIsIdentity reports whether rm answers only literal equality for
// the probe patterns. The probe values are chosen so that a literal role name
// containing wildcards cannot accidentally match a different literal.
func roleManagerIsIdentity(rm interface{ Match(string, string) bool }) bool {
	const probe = "casbin-impact-probe"
	if rm.Match(probe+"/x", probe+"/*") {
		return false
	}
	if rm.Match(probe+"/x", probe+"/:id") {
		return false
	}
	return true
}

// ComputeImpact runs a preview between two self-contained snapshots.
func ComputeImpact(current, candidate ImpactSnapshot, opts ImpactOptions) (*Report, error) {
	if opts.WitnessLimit == 0 {
		opts.WitnessLimit = DefaultImpactWitnessLimit
	}
	if opts.WitnessLimit < 0 {
		opts.WitnessLimit = 0
	}
	if opts.MaxCauseSearch <= 0 {
		opts.MaxCauseSearch = defaultCauseSearch
	}
	start := time.Now()
	report := &Report{}
	if opts.RoleMatching.Incompatible() {
		// Matching functions live on the enforcer, not in the model, so a
		// model-only preview cannot reproduce them. Refuse rather than report
		// misleading conclusions computed from literal names.
		return failureReport(report, &Failure{Stage: "model", Message: opts.RoleMatching.explain()}, start), nil
	}

	cur, failure := buildScenario(current)
	if failure != nil {
		return failureReport(report, failure, start), nil
	}
	cand, failure := buildScenario(candidate)
	if failure != nil {
		return failureReport(report, failure, start), nil
	}

	report.PolicyFingerprint = cur.fingerprint()

	diff := computeDiff(cur, cand)
	for _, d := range diff {
		report.Diff = append(report.Diff, DiffEntry{Change: d.change, Rule: d.rule})
	}

	matcher := analyseMatcher(cur)
	shape := newRequestShape(cur)

	if failure := validatePatterns(cur, cand, matcher); failure != nil {
		return failureReport(report, failure, start), nil
	}

	set := deriveWitnesses(cur, cand, diff, matcher, shape)
	witnesses := set.ordered()
	report.Witnesses = len(witnesses)

	var truncation *Truncation
	if opts.WitnessLimit > 0 && len(witnesses) > opts.WitnessLimit {
		kept := witnesses[:opts.WitnessLimit]
		dropped := witnesses[opts.WitnessLimit:]
		truncation = &Truncation{
			Category: "witnesses",
			Limit:    opts.WitnessLimit,
			Kept:     len(kept),
			Dropped:  len(dropped),
			Rule: "keep changed-rule witnesses first, then role-closure witnesses, then interaction witnesses; " +
				"within a class order by request key and drop the tail",
			Omitted: summariseDropped(dropped),
		}
		witnesses = kept
	}
	for _, c := range set.capped {
		report.Uncertain = append(report.Uncertain, Uncertainty{
			Kind:       UncertainTruncated,
			Dependency: "per-rule witness cap",
			Detail:     c,
		})
	}

	conditional := conditionalEndpoints(cur, cand, matcher)
	minimiser := newMinimiser(current, candidate, cur, cand, diff, opts.MaxCauseSearch)

	for _, w := range witnesses {
		evaluateWitness(w, cur, cand, matcher, conditional, minimiser, report)
	}

	if truncation != nil {
		report.Truncation = truncation
		report.Uncertain = append(report.Uncertain, Uncertainty{
			Kind:       UncertainTruncated,
			Dependency: fmt.Sprintf("witness budget of %d", truncation.Limit),
			Detail: fmt.Sprintf("%d of %d witnesses were not evaluated; %s",
				truncation.Dropped, report.Witnesses, strings.Join(truncation.Omitted, "; ")),
		})
		report.Summary.TruncatedWitnesses = truncation.Dropped
	}

	report.Summary.Accounted = report.Summary.AllowToDeny + report.Summary.DenyToAllow +
		report.Summary.Uncertain + report.Summary.Unchanged
	report.Summary.Examined = report.Summary.Accounted

	sortFlips(report.Flips)
	sortUncertainties(report.Uncertain)
	report.DurationMillis = time.Since(start).Milliseconds()
	return report, nil
}

func failureReport(report *Report, failure *Failure, start time.Time) *Report {
	report.Failure = failure
	report.Summary = Summary{}
	report.Flips = nil
	report.Uncertain = nil
	report.Truncation = nil
	report.DurationMillis = time.Since(start).Milliseconds()
	return report
}

// evaluateWitness decides one witness and records it in exactly one
// population.
func evaluateWitness(w *impactWitness, cur, cand *impactScenario, matcher matcherInfo, conditional map[string]bool, minimiser *causeMinimiser, report *Report) {
	if dep, ok := conditionalDependency(w, cur, conditional); ok {
		report.Summary.Uncertain++
		report.Uncertain = append(report.Uncertain, Uncertainty{
			Kind:          UncertainLinkCondition,
			Request:       w.request,
			RequestString: requestString(w.request),
			Dependency:    dep,
			Detail: "the decision passes through a conditional role link whose condition function lives on the live " +
				"enforcer; the preview cannot tell whether the link is currently valid",
		})
		return
	}

	before, errBefore := cur.enf.Enforce(w.request...)
	after, errAfter := cand.enf.Enforce(w.request...)
	if errBefore != nil || errAfter != nil {
		err := errBefore
		side := "current"
		if err == nil {
			err = errAfter
			side = "candidate"
		}
		kind, dep := classifyEvaluationError(err, matcher)
		report.Summary.Uncertain++
		report.Uncertain = append(report.Uncertain, Uncertainty{
			Kind:          kind,
			Request:       w.request,
			RequestString: requestString(w.request),
			Dependency:    dep,
			Detail:        fmt.Sprintf("evaluating the %s policy failed: %v", side, err),
		})
		return
	}

	if before == after {
		report.Summary.Unchanged++
		return
	}

	direction := AllowToDeny
	if after {
		direction = DenyToAllow
	}

	causes, minimized, steps := minimiser.minimise(w, after)
	if len(causes) == 0 {
		// A flip must be explained by the diff. An empty cause means the
		// preview is internally inconsistent, so it refuses to conclude.
		report.Summary.Uncertain++
		report.Uncertain = append(report.Uncertain, Uncertainty{
			Kind:          UncertainRuntimeRule,
			Request:       w.request,
			RequestString: requestString(w.request),
			Dependency:    "unattributed decision change",
			Detail:        "the decision changed but no rule in the diff explains it; treat this area as unverified",
		})
		return
	}

	explanation := fmt.Sprintf("%s because of %s", direction, joinCauses(causes))
	if !minimized {
		explanation += fmt.Sprintf(" (minimisation stopped after %d steps over %d changes; the cited set is sufficient but may not be minimal)",
			steps, len(causes))
	}
	if direction == AllowToDeny {
		report.Summary.AllowToDeny++
	} else {
		report.Summary.DenyToAllow++
	}
	report.Flips = append(report.Flips, Flip{
		Request:       w.request,
		RequestString: requestString(w.request),
		Direction:     direction,
		Causes:        causes,
		Explanation:   explanation,
	})
}

func joinCauses(causes []CauseRef) string {
	parts := make([]string, 0, len(causes))
	for _, c := range causes {
		parts = append(parts, c.String())
	}
	return strings.Join(parts, " and ")
}

// causeMinimiser attributes flips to irreducible subsets of the diff. Applied
// patches are cached by the index set they keep, so minimising many flips over
// the same diff does not rebuild the same enforcer repeatedly.
type causeMinimiser struct {
	base ImpactSnapshot
	cand ImpactSnapshot
	cur  *impactScenario
	diff []impactDiff
	// perFlip caps the greedy steps for a single flip.
	perFlip int
	// budget is the number of steps left for the whole preview.
	budget int
	// cache holds the scenario for an index subset, built on first use.
	cache map[string]*impactScenario
	// hints are earlier minimal causes, stored as rules rather than indexes so
	// that a hint stays meaningful against a different diff subset. Many flips
	// share one cause (a broad grant, a removed link), so testing a known-small
	// subset first usually finds the same cause without walking the whole diff.
	hints [][]impactDiff
}

func newMinimiser(base, cand ImpactSnapshot, cur *impactScenario, candScenario *impactScenario, diff []impactDiff, perFlip int) *causeMinimiser {
	budget := minMinimiseBudget
	if n := len(diff) * 8; n > budget {
		budget = n
	}
	if budget > maxMinimiseBudget {
		budget = maxMinimiseBudget
	}
	m := &causeMinimiser{base: base, cand: cand, cur: cur, diff: diff, perFlip: perFlip, budget: budget, cache: map[string]*impactScenario{}}
	if candScenario != nil {
		m.cache[indexKey(allIndexes(len(diff)))] = candScenario
	}
	return m
}

func allIndexes(n int) []int {
	out := make([]int, n)
	for i := range out {
		out[i] = i
	}
	return out
}

func indexKey(idx []int) string {
	var b strings.Builder
	for _, i := range idx {
		fmt.Fprintf(&b, "%d,", i)
	}
	return b.String()
}

// scenarioFor returns the scenario that results from keeping exactly the diff
// indexes in idx.
func (m *causeMinimiser) scenarioFor(idx []int) *impactScenario {
	key := indexKey(idx)
	if sc, ok := m.cache[key]; ok {
		return sc
	}
	sc, failure := buildScenario(subsetSnapshot(m.base, m.cand, m.diff, idx))
	if failure != nil {
		sc = nil
	}
	m.cache[key] = sc
	return sc
}

// minimise returns the irreducible subset of the diff that still yields the
// same decision as the full candidate, the number of steps taken, and whether
// the search completed.
//
// The search order is narrowed by activeDiff, which is a conservative filter:
// when it proposes a subset, minimisation runs on that subset (every change it
// excludes is first shown to be individually unnecessary), and only the
// changes the subject can actually reach are tested for removal. That keeps
// each flip's cost proportional to what the flip depends on instead of to the
// whole diff, while the result is verified against the real diff.
func (m *causeMinimiser) minimise(w *impactWitness, target bool) ([]CauseRef, bool, int) {
	if len(m.diff) <= 1 {
		out := make([]CauseRef, 0, len(m.diff))
		for _, d := range m.diff {
			out = append(out, CauseRef{Change: d.change, Rule: d.rule})
		}
		return out, true, 0
	}

	// Try a remembered cause first: many flips share one cause, and a known
	// small subset is cheap to confirm.
	if _, rules, ok := m.tryHints(w, target); ok {
		if idx, matched := m.indexesOf(rules); matched {
			m.rememberHint(rules)
			return causesForIndexes(m.diff, idx), true, 1
		}
	}

	// Split the diff into the changes this witness can reach and the rest.
	active := m.activeDiff(w)
	if len(active) < len(m.diff) {
		// Dropping every excluded change must leave the decision unchanged
		// before the narrowed search can be trusted. Then minimise over the
		// narrowed set.
		steps := 0
		if m.budget > 0 && steps < m.perFlip {
			m.budget--
			steps++
			if m.decides(active, w, target) {
				causes, minimized, more := m.greedy(w, target, active)
				m.rememberHintFromCauses(causes)
				return causes, minimized, steps + more
			}
		}
	}
	causes, minimized, steps := m.greedy(w, target, m.allIndexes())
	m.rememberHintFromCauses(causes)
	return causes, minimized, steps
}

// greedy removes changes one at a time while the witness keeps its target
// decision, returning the remaining changes as causes. It stops when the
// per-flip cap or the remaining budget runs out, in which case the cited set is
// sufficient but not proven minimal.
func (m *causeMinimiser) greedy(w *impactWitness, target bool, current []int) ([]CauseRef, bool, int) {
	steps := 0
	for i := 0; i < len(current); {
		if steps >= m.perFlip || m.budget <= 0 {
			return causesForIndexes(m.diff, current), false, steps
		}
		m.budget--
		steps++
		next := without(current, i)
		if m.decides(next, w, target) {
			current = next
			continue
		}
		i++
	}
	return causesForIndexes(m.diff, current), true, steps
}

func (m *causeMinimiser) rememberHintFromCauses(causes []CauseRef) {
	rules := make([]impactDiff, 0, len(causes))
	for _, c := range causes {
		rules = append(rules, impactDiff{change: c.Change, rule: c.Rule, ptype: c.Rule.PType, section: c.Rule.Section})
	}
	if len(rules) > 0 {
		m.rememberHint(rules)
	}
}

// decides reports whether applying exactly the diff at idx gives the witness
// the target decision.
func (m *causeMinimiser) decides(idx []int, w *impactWitness, target bool) bool {
	sc := m.scenarioFor(idx)
	if sc == nil {
		return false
	}
	got, err := sc.enf.Enforce(w.request...)
	return err == nil && got == target
}

func (m *causeMinimiser) allIndexes() []int { return allIndexes(len(m.diff)) }

func without(idx []int, at int) []int {
	out := make([]int, 0, len(idx)-1)
	out = append(out, idx[:at]...)
	out = append(out, idx[at+1:]...)
	return out
}

func causesForIndexes(diff []impactDiff, idx []int) []CauseRef {
	out := make([]CauseRef, 0, len(idx))
	for _, i := range idx {
		d := diff[i]
		out = append(out, CauseRef{Change: d.change, Rule: d.rule})
	}
	return out
}

// tryHints looks for a remembered cause that still flips the witness.
func (m *causeMinimiser) tryHints(w *impactWitness, target bool) ([]CauseRef, []impactDiff, bool) {
	for _, rules := range m.hints {
		if m.budget <= 0 {
			return nil, nil, false
		}
		idx, ok := m.indexesOf(rules)
		if !ok {
			continue
		}
		m.budget--
		if m.decides(idx, w, target) {
			return causesForIndexes(m.diff, idx), rules, true
		}
	}
	return nil, nil, false
}

// indexesOf maps a set of rules back to positions in m.diff. Every rule must
// be present; a hint that mentions a rule absent from this diff does not
// apply.
func (m *causeMinimiser) indexesOf(rules []impactDiff) ([]int, bool) {
	out := make([]int, 0, len(rules))
	for _, want := range rules {
		found := false
		for i, d := range m.diff {
			if d.change == want.change && d.section == want.section &&
				d.ptype == want.ptype && d.rule.key() == want.rule.key() {
				out = append(out, i)
				found = true
				break
			}
		}
		if !found {
			return nil, false
		}
	}
	return out, true
}

// activeDiff returns the indexes of diffs whose rule mentions a value the
// witness can reach: the request's own values, or any role the subject holds,
// or (for a grouping change) a link endpoint the subject already reaches. The
// filter is conservative: it is only allowed to exclude a change when that
// change provably cannot reach this witness.
func (m *causeMinimiser) activeDiff(w *impactWitness) []int {
	related := map[string]bool{}
	for _, v := range w.request {
		related[fmt.Sprint(v)] = true
	}
	sub := ""
	if len(w.request) > 0 {
		sub = fmt.Sprint(w.request[0])
	}
	if sub != "" {
		for _, sc := range []*impactScenario{m.cur, m.diffScenario()} {
			if sc == nil {
				continue
			}
			for ptype := range sc.model["g"] {
				rm := sc.enf.GetNamedRoleManager(ptype)
				if rm == nil {
					continue
				}
				if roles, err := rm.GetImplicitRoles(sub); err == nil {
					for _, r := range roles {
						related[r] = true
					}
				}
			}
		}
	}
	// A grouping change can move a subject that reaches the link's first
	// endpoint in *either* scenario: a chain that exists only in the candidate
	// (the very link being added) is exactly the common case.
	reaches := map[int]bool{}
	for i, d := range m.diff {
		if d.section != "g" || sub == "" || len(d.rule.Rule) < 2 {
			continue
		}
		if m.subjectReaches(sub, d, d.rule.Rule[0]) {
			reaches[i] = true
		}
	}

	var out []int
	for i, d := range m.diff {
		if reaches[i] {
			out = append(out, i)
			continue
		}
		for _, field := range d.rule.Rule {
			if related[field] {
				out = append(out, i)
				break
			}
		}
	}
	return out
}

// subjectReaches reports whether sub equals target or inherits target in
// either scenario, both with the full diff and with the diff's other changes
// reverted. The second check is what makes a link that is added by this very
// diff count as reachable.
func (m *causeMinimiser) subjectReaches(sub string, d impactDiff, target string) bool {
	if sub == target {
		return true
	}
	checks := []*impactScenario{m.cur, m.diffScenario()}
	for _, sc := range checks {
		if sc == nil {
			continue
		}
		if m.hasLinkIn(sc, sub, d.ptype, target) {
			return true
		}
	}
	// The link itself, or a longer chain through other changed links, records
	// the connection only in the patched views. Ask the candidate for the
	// subject's implicit roles too; GetImplicitRoles respects domain-less role
	// trees, which is where deep inheritance lives.
	if sc := m.diffScenario(); sc != nil {
		if rm := sc.enf.GetNamedRoleManager(d.ptype); rm != nil {
			if roles, err := rm.GetImplicitRoles(sub); err == nil && containsString(roles, target) {
				return true
			}
		}
	}
	return false
}

func (m *causeMinimiser) hasLinkIn(sc *impactScenario, sub, ptype, target string) bool {
	rm := sc.enf.GetNamedRoleManager(ptype)
	if rm == nil {
		return false
	}
	for _, dom := range allDomainValues(sc, nil) {
		if ok, err := rm.HasLink(sub, target, dom); err == nil && ok {
			return true
		}
	}
	return false
}

// diffScenario is the candidate scenario when the cache holds it.
func (m *causeMinimiser) diffScenario() *impactScenario {
	return m.cache[indexKey(allIndexes(len(m.diff)))]
}

// rememberHint keeps the smallest causes seen so far, up to a handful, for the
// next witness to try first.
func (m *causeMinimiser) rememberHint(rules []impactDiff) {
	for _, h := range m.hints {
		if sameDiffSet(h, rules) {
			return
		}
	}
	m.hints = append(m.hints, append([]impactDiff(nil), rules...))
	if len(m.hints) > 8 {
		worst := 0
		for i, h := range m.hints {
			if len(h) > len(m.hints[worst]) {
				worst = i
			}
		}
		m.hints = append(m.hints[:worst], m.hints[worst+1:]...)
	}
}

func sameDiffSet(a, b []impactDiff) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].change != b[i].change || a[i].ptype != b[i].ptype || a[i].rule.key() != b[i].rule.key() {
			return false
		}
	}
	return true
}

// classifyEvaluationError maps an enforcement error to an uncertainty kind.
func classifyEvaluationError(err error, matcher matcherInfo) (UncertaintyKind, string) {
	msg := err.Error()
	if strings.Contains(msg, "Undefined function") {
		name := strings.TrimPrefix(msg, "Undefined function ")
		if len(matcher.hostFunctions) > 0 {
			name = matcher.hostFunctions[0]
		}
		return UncertainMatcherFunction, fmt.Sprintf("host matcher function %q", name)
	}
	if strings.Contains(msg, "Unable to access") || strings.Contains(msg, "is not a struct or map") {
		attr := "request attribute access"
		if m := unableToAccessRe.FindStringSubmatch(msg); len(m) == 2 {
			attr = fmt.Sprintf("request attribute %q", m[1])
		}
		return UncertainRuntimeRule, attr
	}
	return UncertainRuntimeRule, msg
}

// conditionalEndpoints collects every subject that sits below a conditional
// role link: if such a subject's decision traverses the link, the preview
// cannot know whether the link is valid.
func conditionalEndpoints(cur, cand *impactScenario, matcher matcherInfo) map[string]bool {
	out := map[string]bool{}
	ptypes := []string{}
	if matcher.subjectG != "" {
		ptypes = append(ptypes, matcher.subjectG)
	}
	if matcher.objectG != "" && matcher.objectG != matcher.subjectG {
		ptypes = append(ptypes, matcher.objectG)
	}
	for _, ptype := range ptypes {
		for _, sc := range []*impactScenario{cur, cand} {
			ast, ok := sc.model["g"][ptype]
			if !ok || len(ast.ParamsTokens) == 0 {
				continue
			}
			for _, rule := range ast.Policy {
				if len(rule) <= len(ast.Tokens) {
					continue
				}
				user := rule[0]
				out[user] = true
				rm := sc.enf.GetNamedRoleManager(ptype)
				if rm == nil {
					continue
				}
				for _, dom := range allDomains(cur, cand, newRequestShape(sc)) {
					if users, err := rm.GetImplicitUsers(user, dom); err == nil {
						for _, u := range users {
							out[u] = true
						}
					}
				}
			}
		}
	}
	return out
}

// conditionalDependency reports whether the witness's subject lies below a
// conditional link.
func conditionalDependency(w *impactWitness, cur *impactScenario, conditional map[string]bool) (string, bool) {
	if len(conditional) == 0 || len(w.request) == 0 {
		return "", false
	}
	sub := fmt.Sprint(w.request[0])
	if !conditional[sub] {
		return "", false
	}
	return fmt.Sprintf("conditional role link below subject %q", sub), true
}

// validatePatterns refuses to run when a policy pattern cannot be parsed. A
// malformed pattern is reported against the rule that carries it, never
// silently treated as "matches nothing".
func validatePatterns(cur, cand *impactScenario, matcher matcherInfo) *Failure {
	for _, sc := range []*impactScenario{cur, cand} {
		ptypes := make([]string, 0, len(sc.model["p"]))
		for ptype := range sc.model["p"] {
			ptypes = append(ptypes, ptype)
		}
		sort.Strings(ptypes)
		for _, ptype := range ptypes {
			ast := sc.model["p"][ptype]
			for _, rule := range ast.Policy {
				for i, tok := range ast.Tokens {
					if i >= len(rule) {
						continue
					}
					name := tokenName(tok)
					if matcher.fieldFn[name] != "regexMatch" {
						continue
					}
					if _, err := regexp.Compile(rule[i]); err != nil {
						ref := sc.refOf(ImpactRule{PType: ptype, Rule: rule})
						return &Failure{
							Stage:   "rule",
							PType:   ptype,
							Rule:    &ref,
							Message: fmt.Sprintf("invalid regular expression in field %q: %v", name, err),
						}
					}
				}
			}
		}
	}
	return nil
}

// summariseDropped describes the areas of the request space a truncation left
// unexamined.
func summariseDropped(dropped []*impactWitness) []string {
	type bucket struct {
		class  witnessClass
		source string
		count  int
	}
	byKey := map[string]*bucket{}
	for _, w := range dropped {
		key := fmt.Sprintf("%d\x00%s", w.class, w.source)
		b, ok := byKey[key]
		if !ok {
			b = &bucket{class: w.class, source: w.source}
			byKey[key] = b
		}
		b.count++
	}
	buckets := make([]*bucket, 0, len(byKey))
	for _, b := range byKey {
		buckets = append(buckets, b)
	}
	sort.SliceStable(buckets, func(i, j int) bool {
		if buckets[i].class != buckets[j].class {
			return buckets[i].class < buckets[j].class
		}
		return buckets[i].source < buckets[j].source
	})
	out := make([]string, 0, len(buckets)+1)
	for _, b := range buckets {
		out = append(out, fmt.Sprintf("%s: %d witness(es) from %s", classLabel(b.class), b.count, b.source))
		if len(out) >= 16 {
			out = append(out, "and further groups not listed")
			break
		}
	}
	return out
}

func classLabel(c witnessClass) string {
	switch c {
	case classChangedRule:
		return "changed rule"
	case classRoleClosure:
		return "role closure"
	case classInteraction:
		return "interaction"
	}
	return "unknown"
}

func snapshotsEqual(a, b ImpactSnapshot) bool {
	if len(a.Policy) != len(b.Policy) {
		return false
	}
	index := map[string]int{}
	for i, r := range b.Policy {
		index[r.key()] = i
	}
	for _, r := range a.Policy {
		if _, ok := index[r.key()]; !ok {
			return false
		}
	}
	return true
}

// _ keeps the model import meaningful for callers that only use types from
// this file; it is compiled away.
var _ model.Model
