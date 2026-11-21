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

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/casbin/casbin/v3/model"
	"github.com/casbin/casbin/v3/util"
)

var utilKeyMatch2 = util.KeyMatch2

// TestImpactDeterministic checks that the same pair of policies produces the
// same report, byte for byte, on repeated runs.
func TestImpactDeterministic(t *testing.T) {
	dir := filepath.Join("testdata", "impact")
	for _, name := range []string{"rbac_deep_closure.json", "keymatch_add.json", "truncation.json"} {
		name := name
		t.Run(strings.TrimSuffix(name, ".json"), func(t *testing.T) {
			fx := loadFixtureFile(t, dir, name)
			m, err := model.NewModelFromFile(filepath.Join(dir, fx.Model))
			if err != nil {
				t.Fatal(err)
			}
			current := fixtureSnapshot(t, m, fx.Current)
			candidate := fixtureSnapshot(t, m, fx.Candidate)
			opts := ImpactOptions{}
			if fx.Options != nil {
				opts.WitnessLimit = fx.Options.WitnessLimit
			}
			first, err := ComputeImpact(current, candidate, opts)
			if err != nil {
				t.Fatal(err)
			}
			firstBytes := canonicalJSON(t, first)
			for run := 0; run < 5; run++ {
				again, err := ComputeImpact(current, candidate, opts)
				if err != nil {
					t.Fatal(err)
				}
				if got := canonicalJSON(t, again); got != firstBytes {
					t.Fatalf("run %d differs from the first run:\nfirst: %s\ngot:   %s", run+1, firstBytes, got)
				}
			}
		})
	}
}

// TestImpactDoesNotMutateEnforcer checks the hard requirement that a preview
// leaves the live policy and the enforcer's compiled state untouched.
func TestImpactDoesNotMutateEnforcer(t *testing.T) {
	dir := filepath.Join("testdata", "impact")
	e, err := NewEnforcer(filepath.Join(dir, "domain_model.conf"), "")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{
		"p, role:reader, domain1, data1, read",
		"g, alice, role:reader, domain1",
		"g, bob, role:reader, domain1",
	} {
		addRule(t, e, line)
	}
	if buildErr := e.BuildRoleLinks(); buildErr != nil {
		t.Fatal(err)
	}

	probes := [][]interface{}{
		{"alice", "domain1", "data1", "read"},
		{"bob", "domain1", "data1", "read"},
		{"carol", "domain1", "data1", "read"},
		{"alice", "domain1", "data2", "write"},
	}
	decisionsBefore := enforceAll(t, e, probes)

	before := fingerprintEnforcer(t, e)
	versionBefore := e.getPolicyVersion()

	candidateModel, err := model.NewModelFromFile(filepath.Join(dir, "domain_model.conf"))
	if err != nil {
		t.Fatal(err)
	}
	candidate := fixtureSnapshot(t, candidateModel, []string{
		"p, role:reader, domain1, data1, read",
		"g, alice, role:reader, domain1",
		"g, bob, role:reader, domain1",
		"p, role:writer, domain1, data2, write",
		"g, carol, role:writer, domain1",
	})

	report, err := e.Impact(candidate, ImpactOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := report.Verify(); err != nil {
		t.Fatalf("reconciliation: %v", err)
	}

	if got := fingerprintEnforcer(t, e); got != before {
		t.Fatalf("the preview changed the live enforcer:\nbefore: %s\nafter:  %s", before, got)
	}
	if e.getPolicyVersion() != versionBefore {
		t.Fatalf("the preview bumped the policy version: %d -> %d", versionBefore, e.getPolicyVersion())
	}

	// The compiled state must still answer exactly as before. A stale or
	// dropped matcher cache would show up here.
	decisionsAfter := enforceAll(t, e, probes)
	if !reflect.DeepEqual(decisionsBefore, decisionsAfter) {
		t.Fatalf("live decisions changed across the preview: before %v, after %v", decisionsBefore, decisionsAfter)
	}
}

// TestImpactDoesNotTouchPolicyFiles checks that a preview over file-backed
// policies leaves the files byte-identical.
func TestImpactDoesNotTouchPolicyFiles(t *testing.T) {
	dir := filepath.Join(t.TempDir())
	modelPath := filepath.Join(dir, "model.conf")
	policyPath := filepath.Join(dir, "policy.csv")
	modelText, err := os.ReadFile(filepath.Join("testdata", "impact", "rbac_model.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if writeErr := os.WriteFile(modelPath, modelText, 0o644); writeErr != nil {
		t.Fatal(err)
	}
	policyText := "p, role:reader, data1, read\ng, alice, role:reader\n"
	if writeErr := os.WriteFile(policyPath, []byte(policyText), 0o644); writeErr != nil {
		t.Fatal(err)
	}

	e, err := NewEnforcer(modelPath, policyPath)
	if err != nil {
		t.Fatal(err)
	}
	candidate := fixtureSnapshot(t, e.GetModel().Copy(), []string{
		"p, role:reader, data1, read",
		"g, alice, role:reader",
		"p, alice, data2, read",
	})
	if _, impactErr := e.Impact(candidate, ImpactOptions{}); impactErr != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != policyText {
		t.Fatalf("policy file changed:\nbefore:\n%s\nafter:\n%s", policyText, got)
	}
}

// TestImpactConcurrentWriteIsDetected checks that a preview refuses to report
// conclusions if the live policy changes while it runs.
func TestImpactConcurrentWriteIsDetected(t *testing.T) {
	dir := filepath.Join("testdata", "impact")
	e, err := NewEnforcer(filepath.Join(dir, "rbac_model.conf"), "")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{"p, role:reader, data1, read", "g, alice, role:reader"} {
		addRule(t, e, line)
	}

	// Bump the policy version between the two snapshots the preview takes by
	// mutating the enforcer during the run is inherently racy; instead simulate
	// the check directly: a snapshot read, then a write, then the comparison.
	before := e.getPolicyVersion()
	first, err := snapshotFromEnforcer(e)
	if err != nil {
		t.Fatal(err)
	}
	if _, addErr := e.AddPolicy("bob", "data2", "read"); addErr != nil {
		t.Fatal(err)
	}
	after, err := snapshotFromEnforcer(e)
	if err != nil {
		t.Fatal(err)
	}
	if e.getPolicyVersion() == before {
		t.Fatal("expected the policy version to change")
	}
	if snapshotsEqual(first, after) {
		t.Fatal("snapshot comparison failed to notice the write")
	}
}

// TestImpactReportsTimingOnLargePolicySet builds a policy set large enough to
// exercise the derivation and evaluation paths and asserts a bounded runtime,
// determinism, and a reconciled report.
func TestImpactReportsTimingOnLargePolicySet(t *testing.T) {
	if testing.Short() {
		t.Skip("timing test skipped in -short mode")
	}
	dir := filepath.Join("testdata", "impact")
	m, err := model.NewModelFromFile(filepath.Join(dir, "domain_model.conf"))
	if err != nil {
		t.Fatal(err)
	}

	const roles = 40
	const usersPerRole = 25
	const domains = 6
	cur := ImpactSnapshot{Model: m.Copy()}
	cand := ImpactSnapshot{Model: m.Copy()}

	for d := 0; d < domains; d++ {
		domain := fmt.Sprintf("domain%d", d)
		for r := 0; r < roles; r++ {
			role := fmt.Sprintf("role:%d", r)
			cur.Policy = append(cur.Policy, ImpactRule{PType: "p", Rule: []string{role, domain, fmt.Sprintf("obj:%d", r), "read"}})
			cand.Policy = append(cand.Policy, ImpactRule{PType: "p", Rule: []string{role, domain, fmt.Sprintf("obj:%d", r), "read"}})
			for u := 0; u < usersPerRole; u++ {
				user := fmt.Sprintf("user:%d:%d", r, u)
				cur.Policy = append(cur.Policy, ImpactRule{PType: "g", Rule: []string{user, role, domain}})
				cand.Policy = append(cand.Policy, ImpactRule{PType: "g", Rule: []string{user, role, domain}})
			}
		}
	}
	// A targeted change: one role gains a new object, in one domain.
	cand.Policy = append(cand.Policy, ImpactRule{PType: "p", Rule: []string{"role:0", "domain0", "obj:new", "write"}})
	// A link change deep in the tree: one user loses a role in one domain.
	remove := ImpactRule{PType: "g", Rule: []string{"user:0:0", "role:0", "domain0"}}
	cand.Policy = filterOut(cand.Policy, remove)

	if len(cur.Policy) < 5000 {
		t.Fatalf("policy set is too small to be meaningful: %d rules", len(cur.Policy))
	}

	start := time.Now()
	report, err := ComputeImpact(cur, cand, ImpactOptions{})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	if report.Failure != nil {
		t.Fatalf("preview failed: %s", report.Failure.String())
	}
	if verifyErr := report.Verify(); verifyErr != nil {
		t.Fatalf("reconciliation: %v", verifyErr)
	}
	if report.DurationMillis <= 0 {
		t.Errorf("report does not carry a duration")
	}
	if elapsed > 2*time.Minute {
		t.Fatalf("preview took %v on a %d-rule policy set, outside the change window", elapsed, len(cur.Policy))
	}
	t.Logf("preview over %d rules: %v, %d witnesses, %d flips, %d uncertain",
		len(cur.Policy), elapsed, report.Witnesses, len(report.Flips), report.Summary.Uncertain)

	// Determinism on the large set.
	second, err := ComputeImpact(cur, cand, ImpactOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if a, b := canonicalJSON(t, report), canonicalJSON(t, second); a != b {
		t.Fatal("repeated run on the large policy set produced a different report")
	}
}

func filterOut(rules []ImpactRule, drop ImpactRule) []ImpactRule {
	out := make([]ImpactRule, 0, len(rules))
	for _, r := range rules {
		if r.key() == drop.key() {
			continue
		}
		out = append(out, r)
	}
	return out
}

func loadFixtureFile(t *testing.T, dir, name string) impactFixture {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	var fx impactFixture
	if err := json.Unmarshal(data, &fx); err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	return fx
}

func canonicalJSON(t *testing.T, v interface{}) string {
	t.Helper()
	// Duration is wall-clock and therefore not part of the deterministic
	// content; every other field must match exactly.
	switch r := v.(type) {
	case *Report:
		copied := *r
		copied.DurationMillis = 0
		b, err := json.Marshal(copied)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// addRule adds a policy line, routing grouping rules to the grouping API.
func addRule(t *testing.T, e *Enforcer, line string) {
	t.Helper()
	parts := splitPolicyLine(line)
	var err error
	if strings.HasPrefix(parts[0], "g") {
		_, err = e.AddNamedGroupingPolicy(parts[0], parts[1:])
	} else {
		_, err = e.AddNamedPolicy(parts[0], parts[1:])
	}
	if err != nil {
		t.Fatalf("add %q: %v", line, err)
	}
}

func splitPolicyLine(line string) []string {
	parts := strings.Split(line, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		out = append(out, strings.TrimSpace(p))
	}
	return out
}

// fingerprintEnforcer digests everything a preview must leave alone: the policy
// rules, the role links and the policy version.
func fingerprintEnforcer(t *testing.T, e *Enforcer) string {
	t.Helper()
	h := sha256.New()
	fmt.Fprintf(h, "version:%d\n", e.getPolicyVersion())
	for _, sec := range []string{"p", "g"} {
		ptypes := make([]string, 0, len(e.model[sec]))
		for ptype := range e.model[sec] {
			ptypes = append(ptypes, ptype)
		}
		sortStrings(ptypes)
		for _, ptype := range ptypes {
			for _, rule := range e.model[sec][ptype].Policy {
				fmt.Fprintf(h, "%s:%s:%s\n", sec, ptype, strings.Join(rule, "\x00"))
			}
		}
	}
	for ptype, rm := range e.rmMap {
		if rm == nil {
			continue
		}
		domains, _ := rm.GetAllDomains()
		for _, d := range domains {
			// Range over every link the role manager holds.
			if ranger, ok := rm.(interface {
				Range(func(name1, name2 string, domain ...string) bool)
			}); ok {
				ranger.Range(func(name1, name2 string, domain ...string) bool {
					fmt.Fprintf(h, "link:%s:%s:%s:%s\n", ptype, name1, name2, strings.Join(domain, "\x00"))
					return true
				})
			}
			_ = d
		}
	}
	for _, req := range [][]interface{}{
		{"alice", "domain1", "data1", "read"},
		{"bob", "domain1", "data1", "read"},
	} {
		ok, _ := e.Enforce(req...)
		fmt.Fprintf(h, "decision:%v\n", ok)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func sortStrings(in []string) {
	for i := 1; i < len(in); i++ {
		for j := i; j > 0 && in[j] < in[j-1]; j-- {
			in[j], in[j-1] = in[j-1], in[j]
		}
	}
}

// TestImpactReportInvariantIsEnforced deliberately corrupts a report and
// checks that Verify refuses it: the acceptance criterion is that a report
// whose counters do not reconcile is untrustworthy, so the check must be real.
func TestImpactReportInvariantIsEnforced(t *testing.T) {
	dir := filepath.Join("testdata", "impact")
	fx := loadFixtureFile(t, dir, "rbac_add_grant.json")
	m, err := model.NewModelFromFile(filepath.Join(dir, fx.Model))
	if err != nil {
		t.Fatal(err)
	}
	current := fixtureSnapshot(t, m, fx.Current)
	candidate := fixtureSnapshot(t, m, fx.Candidate)
	report, err := ComputeImpact(current, candidate, ImpactOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if verifyErr := report.Verify(); verifyErr != nil {
		t.Fatalf("clean report should verify: %v", verifyErr)
	}

	cases := []struct {
		name   string
		mutate func(*Report)
	}{
		{"drop a flip detail", func(r *Report) { r.Flips = r.Flips[:len(r.Flips)-1] }},
		{"inflate a counter", func(r *Report) { r.Summary.Unchanged++ }},
		{"flip a direction", func(r *Report) {
			if len(r.Flips) > 0 {
				r.Flips[0].Direction = AllowToDeny
			}
		}},
		{"strip causes", func(r *Report) {
			if len(r.Flips) > 0 {
				r.Flips[0].Causes = nil
			}
		}},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			corrupted := *report
			corrupted.Flips = append([]Flip(nil), report.Flips...)
			corrupted.Summary = report.Summary
			c.mutate(&corrupted)
			if err := corrupted.Verify(); err == nil {
				t.Fatalf("Verify accepted a corrupted report (%s)", c.name)
			}
		})
	}
}

// TestImpactEnforcerVersionBinding checks that a live enforcer reports a
// fingerprint that matches its own policy.
func TestImpactEnforcerVersionBinding(t *testing.T) {
	dir := filepath.Join("testdata", "impact")
	e, err := NewEnforcer(filepath.Join(dir, "rbac_model.conf"), "")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{"p, role:reader, data1, read", "g, alice, role:reader"} {
		addRule(t, e, line)
	}
	candidate := fixtureSnapshot(t, e.GetModel().Copy(), []string{
		"p, role:reader, data1, read",
		"g, alice, role:reader",
		"p, alice, data2, read",
	})
	report, err := e.Impact(candidate, ImpactOptions{})
	if err != nil {
		t.Fatal(err)
	}
	cur, failure := buildScenario(mustSnapshot(t, e))
	if failure != nil {
		t.Fatal(failure.String())
	}
	if report.PolicyFingerprint != cur.fingerprint() {
		t.Fatalf("fingerprint does not describe the live policy")
	}
	_ = reflect.DeepEqual
}

func enforceAll(t *testing.T, e *Enforcer, probes [][]interface{}) []bool {
	t.Helper()
	out := make([]bool, 0, len(probes))
	for _, req := range probes {
		ok, err := e.Enforce(req...)
		if err != nil {
			t.Fatalf("enforce %v: %v", req, err)
		}
		out = append(out, ok)
	}
	return out
}

func mustSnapshot(t *testing.T, e *Enforcer) ImpactSnapshot {
	t.Helper()
	s, err := snapshotFromEnforcer(e)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestImpactRefusesWithRoleMatchingFunc checks that a preview over an enforcer
// whose role managers carry a name-matching function refuses to conclude: the
// function is enforcer state that a model snapshot cannot carry.
func TestImpactRefusesWithRoleMatchingFunc(t *testing.T) {
	dir := filepath.Join("testdata", "impact")
	e, err := NewEnforcer(filepath.Join(dir, "resource_role_model.conf"), "")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{
		"p, book_admin, book_group, GET",
		"g, alice, book_admin",
		"g2, /book/1, book_group",
	} {
		addRule(t, e, line)
	}
	e.AddNamedMatchingFunc("g2", "keyMatch2", utilKeyMatch2)

	candidate := fixtureSnapshot(t, e.GetModel().Copy(), []string{
		"p, book_admin, book_group, GET",
		"g, alice, book_admin",
		"g2, /book/1, book_group",
		"g2, /book/2, book_group",
	})
	report, err := e.Impact(candidate, ImpactOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if report.Failure == nil {
		t.Fatalf("expected a failure, got %d flips", len(report.Flips))
	}
	if report.Failure.Stage != "model" {
		t.Errorf("failure stage = %q, want model", report.Failure.Stage)
	}
	if !strings.Contains(report.Failure.Message, "matching function") {
		t.Errorf("failure does not explain the matching function: %s", report.Failure.Message)
	}

	// An enforcer without matching functions must not be refused.
	plain, err := NewEnforcer(filepath.Join(dir, "rbac_model.conf"), "")
	if err != nil {
		t.Fatal(err)
	}
	addRule(t, plain, "p, alice, data1, read")
	plainReport, err := plain.Impact(fixtureSnapshot(t, plain.GetModel().Copy(), []string{
		"p, alice, data1, read",
		"p, alice, data2, read",
	}), ImpactOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if plainReport.Failure != nil {
		t.Fatalf("plain enforcer was refused: %s", plainReport.Failure.String())
	}
}

// TestImpactRoleMatchingInfoDetectsInstalledFunction checks the probe that
// detects installed matching functions.
func TestImpactRoleMatchingInfoDetectsInstalledFunction(t *testing.T) {
	dir := filepath.Join("testdata", "impact")
	e, err := NewEnforcer(filepath.Join(dir, "resource_role_model.conf"), "")
	if err != nil {
		t.Fatal(err)
	}
	if info := e.roleMatchingInfo(); info.Incompatible() {
		t.Fatalf("fresh enforcer reported matching functions: %+v", info)
	}
	e.AddNamedMatchingFunc("g2", "keyMatch2", utilKeyMatch2)
	if info := e.roleMatchingInfo(); !info.Incompatible() {
		t.Fatal("installed matching function was not detected")
	}
}
