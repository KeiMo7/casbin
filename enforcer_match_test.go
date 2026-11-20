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
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/casbin/casbin/v3/effector"
	"github.com/casbin/casbin/v3/model"
)

// newDiagnosticsEnforcer builds a model whose matcher invokes every matcher
// family under test against the policy fields, so a policy row can carry an
// invalid pattern for any of them.
func newDiagnosticsEnforcer(t *testing.T) *Enforcer {
	t.Helper()

	m, err := model.NewModelFromString(`
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && keyMatch2(r.obj, p.obj) && regexMatch(r.act, p.act)
`)
	if err != nil {
		t.Fatalf("NewModelFromString: %v", err)
	}

	e, err := NewEnforcer(m)
	if err != nil {
		t.Fatalf("NewEnforcer: %v", err)
	}
	return e
}

// TestInvalidPatternDoesNotPoisonDecision is acceptance case 1: an invalid
// pattern mixed with valid rules still yields a usable decision and names the
// offending rule.
func TestInvalidPatternDoesNotPoisonDecision(t *testing.T) {
	e := newDiagnosticsEnforcer(t)
	if _, err := e.AddPolicy("alice", "/data/*", "(GET"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.AddPolicy("alice", "/data/:id", "GET"); err != nil {
		t.Fatal(err)
	}

	outcome, err := e.EnforceWithDiagnostics("alice", "/data/42", "GET")
	if err != nil {
		t.Fatalf("EnforceWithDiagnostics: %v", err)
	}
	if !outcome.Allowed {
		t.Error("the valid rule should still allow the request")
	}
	if len(outcome.Diagnostics) != 1 {
		t.Fatalf("diagnostics = %+v, want exactly the bad rule", outcome.Diagnostics)
	}
	diagnostic := outcome.Diagnostics[0]
	if diagnostic.PolicyIndex != 0 || diagnostic.Policy[2] != "(GET" ||
		diagnostic.Matcher != "regexMatch" || diagnostic.Kind != "syntax" {
		t.Errorf("unexpected diagnostic: %+v", diagnostic)
	}
	if outcome.Explains == nil || len(outcome.Explains) != 3 || outcome.Explains[2] != "GET" {
		t.Errorf("explains = %v, want the matched valid rule expressed as before", outcome.Explains)
	}

	// Plain Enforce agrees with EnforceWithDiagnostics and does not error.
	allowed, err := e.Enforce("alice", "/data/42", "GET")
	if err != nil {
		t.Fatalf("Enforce: %v", err)
	}
	if allowed != outcome.Allowed {
		t.Errorf("Enforce = %t, EnforceWithDiagnostics = %t", allowed, outcome.Allowed)
	}
	if stats := e.MatchStats(); stats.PatternErrors != 2 {
		// One per decision: EnforceWithDiagnostics and Enforce each evaluated
		// the bad rule once.
		t.Errorf("PatternErrors = %d, want 2", stats.PatternErrors)
	}
}

// TestMatcherErrorIsNotMismatch is acceptance case 10: an invalid pattern is
// reported as a problem, while a normal miss is silent.
func TestMatcherErrorIsNotMismatch(t *testing.T) {
	e := newDiagnosticsEnforcer(t)
	if _, err := e.AddPolicy("alice", "/data/:id", "GET"); err != nil {
		t.Fatal(err)
	}

	outcome, err := e.EnforceWithDiagnostics("alice", "/other/1", "GET")
	if err != nil {
		t.Fatalf("a simple miss must not error: %v", err)
	}
	if outcome.Allowed {
		t.Error("the request should be denied")
	}
	if len(outcome.Diagnostics) != 0 {
		t.Errorf("a miss must not produce diagnostics: %+v", outcome.Diagnostics)
	}
	if stats := e.MatchStats(); stats.PatternErrors != 0 {
		t.Errorf("a miss must not be counted as a pattern error: %d", stats.PatternErrors)
	}
}

// TestNonPatternMatcherErrorStillFails pins the boundary of the degradation:
// only pattern errors degrade. A type error in the expression is still
// reported, so callers keep seeing genuine failures.
func TestNonPatternMatcherErrorStillFails(t *testing.T) {
	e, err := NewEnforcer("examples/abac_rule_model.conf", "examples/abac_rule_policy.csv")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := e.Enforce("alice", "data1", "read", nil); err == nil {
		t.Error("a non-pattern matcher error should still be returned")
	}
}

// TestBatchEnforceKeepsStructure pins section four's requirement that a batch
// with a bad rule keeps returning the same shape.
func TestBatchEnforceKeepsStructure(t *testing.T) {
	e := newDiagnosticsEnforcer(t)
	if _, err := e.AddPolicy("alice", "/data/*", "(GET"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.AddPolicy("alice", "/data/:id", "GET"); err != nil {
		t.Fatal(err)
	}

	results, err := e.BatchEnforce([][]interface{}{
		{"alice", "/data/1", "GET"},
		{"bob", "/data/2", "GET"},
	})
	if err != nil {
		t.Fatalf("BatchEnforce: %v", err)
	}
	if len(results) != 2 || !results[0] || results[1] {
		t.Errorf("BatchEnforce = %v, want [true false]", results)
	}
}

// TestEnforceTimeoutReturnsExplicitFailure covers section three's requirement
// that an over-budget decision fails with a clear signal.
func TestEnforceTimeoutReturnsExplicitFailure(t *testing.T) {
	e := newDiagnosticsEnforcer(t)

	// A deliberately slow matcher over many rules produces a decision that
	// genuinely outlives a small bound, so the mid-run deadline check is what
	// fires rather than the first rule.
	rules := make([][]string, 0, 400)
	for i := 0; i < 400; i++ {
		rules = append(rules, []string{fmt.Sprintf("alice%d", i), "/data/1", "GET"})
	}
	if _, err := e.AddPolicies(rules); err != nil {
		t.Fatal(err)
	}
	e.AddFunction("slowMatch", func(args ...interface{}) (interface{}, error) {
		time.Sleep(200 * time.Microsecond)
		return false, nil
	})

	const matcher = "slowMatch(r.sub, p.sub)"

	e.SetEnforceTimeout(2 * time.Millisecond)
	outcome, err := e.EnforceWithMatcherAndDiagnostics(matcher, "alice", "/data/1", "GET")
	if err == nil || !errors.Is(err, ErrEnforceTimeout) {
		t.Fatalf("err = %v, want ErrEnforceTimeout", err)
	}
	if !outcome.TimedOut {
		t.Error("TimedOut should be set")
	}
	if outcome.Allowed {
		t.Error("a timed-out decision should not be reported as allowed")
	}
	if stats := e.MatchStats(); stats.Timeouts == 0 {
		t.Error("the timeout should be counted")
	}

	// The same request under a bound it can meet succeeds.
	e.SetEnforceTimeout(-1)
	if _, err := e.EnforceWithMatcherAndDiagnostics(matcher, "alice", "/data/1", "GET"); err != nil {
		t.Errorf("with the default bound the request should succeed: %v", err)
	}
}

// TestEnforceTimeoutKeepsMatchedExplain covers section 3.3: a timed-out
// decision keeps a rule that matched before the deadline in the explanation.
func TestEnforceTimeoutKeepsMatchedExplain(t *testing.T) {
	// This effector records the first matched rule as the explanation but
	// keeps the decision indeterminate, so evaluation continues past the
	// first match and can then run into the deadline.
	m, err := model.NewModelFromString(`
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = slowMatch(r.obj, p.obj)
`)
	if err != nil {
		t.Fatal(err)
	}
	e, err := NewEnforcer(m)
	if err != nil {
		t.Fatal(err)
	}
	e.eft = &firstMatchEffector{}

	e.AddFunction("slowMatch", func(args ...interface{}) (interface{}, error) {
		time.Sleep(200 * time.Microsecond)
		return true, nil
	})

	rules := make([][]string, 0, 400)
	for i := 0; i < 400; i++ {
		rules = append(rules, []string{fmt.Sprintf("alice%d", i), "/data/1", "GET"})
	}
	if _, err := e.AddPolicies(rules); err != nil {
		t.Fatal(err)
	}

	e.SetEnforceTimeout(2 * time.Millisecond)
	outcome, err := e.EnforceWithDiagnostics("alice", "/data/1", "GET")
	if err == nil || !errors.Is(err, ErrEnforceTimeout) {
		t.Fatalf("err = %v, want ErrEnforceTimeout", err)
	}
	if outcome.Allowed {
		t.Error("a timed-out decision should not be reported as allowed")
	}
	if len(outcome.Explains) == 0 || outcome.Explains[0] != "alice0" {
		t.Errorf("explains = %v, want the first matched rule", outcome.Explains)
	}
}

// firstMatchEffector records the first matched rule and otherwise stays
// indeterminate, forcing the enforcer to keep evaluating.
type firstMatchEffector struct{}

func (e *firstMatchEffector) MergeEffects(expr string, effects []effector.Effect, matches []float64, policyIndex int, policyLength int) (effector.Effect, int, error) {
	explainIndex := -1
	for i := 0; i <= policyIndex; i++ {
		if matches[i] != 0 {
			explainIndex = i
			break
		}
	}
	return effector.Indeterminate, explainIndex, nil
}

// TestEnforceTimeoutZeroDisables pins that the bound is opt-out.
func TestEnforceTimeoutZeroDisables(t *testing.T) {
	e := newDiagnosticsEnforcer(t)
	e.SetEnforceTimeout(0)
	if got := e.EnforceTimeout(); got != 0 {
		t.Errorf("EnforceTimeout() = %v, want 0", got)
	}
	e.SetEnforceTimeout(-1)
	if got := e.EnforceTimeout(); got != DefaultEnforceTimeout {
		t.Errorf("EnforceTimeout() = %v, want %v", got, DefaultEnforceTimeout)
	}
}

// TestExplainUnchangedForValidPatterns pins that valid decisions keep the same
// explanation as before.
func TestExplainUnchangedForValidPatterns(t *testing.T) {
	e, err := NewEnforcer("examples/keymatch_model.conf", "examples/keymatch_policy.csv")
	if err != nil {
		t.Fatal(err)
	}

	allowed, explains, err := e.EnforceEx("alice", "/alice_data/resource1", "GET")
	if err != nil {
		t.Fatalf("EnforceEx: %v", err)
	}
	if !allowed {
		t.Error("expected access to be allowed")
	}
	if len(explains) == 0 || !strings.HasPrefix(explains[1], "/alice_data/") {
		t.Errorf("explains = %v, want the historical matched-rule form", explains)
	}
}
