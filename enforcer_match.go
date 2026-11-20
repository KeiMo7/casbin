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
	"sync/atomic"
	"time"

	"github.com/casbin/casbin/v3/util"
)

// DefaultEnforceTimeout bounds one call to Enforce. It is checked between
// policy rules, so a single matcher invocation is not preempted; the built-in
// regexp engine is linear-time, so the un-preemptible part stays small. The
// value is deliberately far above any normal policy evaluation and exists to
// stop one pathological decision from stalling a whole batch. Set it to 0 with
// SetEnforceTimeout to disable the bound.
const DefaultEnforceTimeout = 5 * time.Second

// enforceTimeoutCheckInterval is how many policy rules pass between two
// deadline checks. Reading the clock on every rule is measurable on large
// policies; checking every 16 rules still keeps overshoot to a small fraction
// of the limit while adding a clock read to well under 1/16 of the hot path.
const enforceTimeoutCheckInterval = 16

// ErrEnforceTimeout is returned when a decision exceeds the configured time
// bound. The error wraps this sentinel, so callers can test it with errors.Is.
var ErrEnforceTimeout = errors.New("enforce exceeded its time limit")

// MatcherDiagnostic describes one policy rule whose matcher reported an
// invalid pattern. It is a configuration problem, not a normal mismatch: the
// rule is treated as a non-match, the rest of the policy is still evaluated,
// and the decision remains usable.
type MatcherDiagnostic struct {
	// PType is the policy section of the rule, for example "p".
	PType string `json:"ptype"`
	// PolicyIndex is the rule's position in that section.
	PolicyIndex int `json:"policyIndex"`
	// Policy is a copy of the rule.
	Policy []string `json:"policy"`
	// Matcher is the built-in matcher name, for example "regexMatch".
	Matcher string `json:"matcher"`
	// Pattern is the offending pattern, exactly as it appeared in the rule.
	Pattern string `json:"pattern"`
	// Kind classifies the failure, for example "syntax" or "misplaced-star".
	Kind util.MatchErrorKind `json:"kind"`
	// Reason is the parser's own message, suitable for logs.
	Reason string `json:"reason"`
}

// EnforceOutcome is the result of EnforceWithDiagnostics. The boolean decision
// and the explanation keep exactly the meaning they have in EnforceEx; the
// remaining fields are additional information.
type EnforceOutcome struct {
	// Allowed is the same decision Enforce returns.
	Allowed bool
	// Explains holds the same matched rule EnforceEx reports.
	Explains []string
	// Diagnostics lists every rule skipped because of an invalid pattern.
	Diagnostics []MatcherDiagnostic
	// TimedOut is true when the decision was cut short by the time bound.
	TimedOut bool
	// Elapsed is the wall-clock time spent on the decision.
	Elapsed time.Duration
}

// MatchStats is a snapshot of the enforcer's matcher-level counters.
type MatchStats struct {
	// PatternErrors counts rules skipped because of an invalid pattern. The
	// count is per rule evaluation, not per distinct pattern.
	PatternErrors uint64
	// Timeouts counts decisions that exceeded the time bound.
	Timeouts uint64
}

// SetEnforceTimeout sets the per-decision time bound. Zero disables it. A
// negative value restores DefaultEnforceTimeout. The bound applies to calls
// made after it is set; it is safe to change concurrently with enforcement.
func (e *Enforcer) SetEnforceTimeout(d time.Duration) {
	if d < 0 {
		d = DefaultEnforceTimeout
	}
	atomic.StoreInt64(&e.enforceTimeoutNanos, int64(d))
}

// EnforceTimeout returns the configured per-decision time bound.
func (e *Enforcer) EnforceTimeout() time.Duration {
	return time.Duration(atomic.LoadInt64(&e.enforceTimeoutNanos))
}

func (e *Enforcer) recordPatternError() {
	atomic.AddUint64(&e.patternErrors, 1)
}

func (e *Enforcer) recordTimeout() {
	atomic.AddUint64(&e.timeouts, 1)
}

func (e *Enforcer) patternErrorCount() uint64 {
	return atomic.LoadUint64(&e.patternErrors)
}

func (e *Enforcer) timeoutCount() uint64 {
	return atomic.LoadUint64(&e.timeouts)
}

// MatchStats returns the current matcher counters.
func (e *Enforcer) MatchStats() MatchStats {
	return MatchStats{
		PatternErrors: e.patternErrorCount(),
		Timeouts:      e.timeoutCount(),
	}
}

// EnforceWithDiagnostics evaluates a request like Enforce and additionally
// reports every policy rule that was skipped because its pattern is invalid.
//
// An invalid pattern never aborts the decision: the rule is recorded as a
// non-match, the diagnostic is collected when this entry is used, and the
// other rules still decide the result. Errors that are not pattern errors,
// such as a type error in the matcher or a missing ABAC attribute, are still
// returned as errors.
func (e *Enforcer) EnforceWithDiagnostics(rvals ...interface{}) (EnforceOutcome, error) {
	return e.enforceWithDiagnostics("", rvals...)
}

// EnforceWithMatcherAndDiagnostics is EnforceWithDiagnostics with a custom
// matcher, like EnforceWithMatcher.
func (e *Enforcer) EnforceWithMatcherAndDiagnostics(matcher string, rvals ...interface{}) (EnforceOutcome, error) {
	return e.enforceWithDiagnostics(matcher, rvals...)
}

func (e *Enforcer) enforceWithDiagnostics(matcher string, rvals ...interface{}) (EnforceOutcome, error) {
	var explains []string
	var diagnostics []MatcherDiagnostic

	start := time.Now()
	allowed, err := e.enforceWithOptions(matcher, &explains, &diagnostics, rvals...)
	outcome := EnforceOutcome{
		Allowed:     allowed,
		Explains:    explains,
		Diagnostics: diagnostics,
		Elapsed:     time.Since(start),
	}
	if errors.Is(err, ErrEnforceTimeout) {
		outcome.TimedOut = true
	}
	if outcome.Explains == nil {
		outcome.Explains = []string{}
	}
	return outcome, err
}

// matchDiagnostic converts a matcher error into a diagnostic. It reports false
// when err is not an invalid-pattern error, in which case the caller must
// propagate err instead of degrading the rule.
func matchDiagnostic(ptype string, policyIndex int, policy []string, err error) (MatcherDiagnostic, bool) {
	matchErr := util.AsMatchError(err)
	if matchErr == nil {
		return MatcherDiagnostic{}, false
	}

	rule := make([]string, len(policy))
	copy(rule, policy)

	return MatcherDiagnostic{
		PType:       ptype,
		PolicyIndex: policyIndex,
		Policy:      rule,
		Matcher:     matchErr.Matcher,
		Pattern:     matchErr.Pattern,
		Kind:        matchErr.Kind,
		Reason:      matchErr.Error(),
	}, true
}

// timeoutError builds the error returned when a decision exceeds its bound.
func timeoutError(limit time.Duration, evaluated int) error {
	return fmt.Errorf("%w: stopped after %d rules (limit %s)", ErrEnforceTimeout, evaluated, limit)
}
