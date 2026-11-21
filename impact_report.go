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

// Policy-change impact preview: types and report shape.
//
// The preview answers one question: if this policy is replaced by that one,
// whose access decision changes? It does so by deriving a bounded set of
// witness requests from the policy entities, evaluating each witness against
// both policies with a real enforcer, and attributing every confirmed change
// to the minimal set of added or removed rules that causes it.
//
// The report separates three populations, and they never mix:
//
//	confirmed flips  (AllowToDeny  + DenyToAllow)
//	uncertain        (runtime-dependent, not statically decidable)
//	unchanged        (examined, provably same decision)
//
// Summary.Accounted must equal Summary.Examined and must equal the sum of the
// three populations; Report.Verify enforces it. A report that fails this
// invariant is not trustworthy and callers must not use it to approve a
// change.

import (
	"fmt"
	"sort"
	"strings"
)

// ChangeKind classifies how a rule differs between the two policies.
type ChangeKind string

const (
	// ChangeAdded marks a rule present only in the candidate policy.
	ChangeAdded ChangeKind = "added"
	// ChangeRemoved marks a rule present only in the current policy.
	ChangeRemoved ChangeKind = "removed"
)

// RuleRef identifies one rule of one policy. Index is 0-based and follows the
// order in which the rule was supplied, so a report points at the caller's
// line.
type RuleRef struct {
	// Section is "p" for authorization rules or "g" for grouping rules.
	Section string `json:"section"`
	// PType is the named definition, e.g. "p" or "g2".
	PType string `json:"ptype"`
	// Index is the position of the rule within its named definition.
	Index int `json:"index"`
	// Rule is a copy of the rule fields, without the ptype prefix.
	Rule []string `json:"rule"`
}

// String renders the rule as the policy line it came from.
func (r RuleRef) String() string {
	return r.PType + ", " + strings.Join(r.Rule, ", ")
}

// key is a stable identity independent of position.
func (r RuleRef) key() string {
	return r.Section + "\x00" + r.PType + "\x00" + strings.Join(r.Rule, "\x00")
}

// FlipDir is the direction of a decision change.
type FlipDir string

const (
	// AllowToDeny marks a request that used to be allowed and is now denied.
	AllowToDeny FlipDir = "allow->deny"
	// DenyToAllow marks a request that used to be denied and is now allowed.
	DenyToAllow FlipDir = "deny->allow"
)

// Flip is one witness request whose decision changed.
type Flip struct {
	// Request is the witness request in request-token order.
	Request []interface{} `json:"request"`
	// RequestString is the display and identity form of Request.
	RequestString string `json:"request_string"`
	// Direction is allow->deny or deny->allow.
	Direction FlipDir `json:"direction"`
	// Causes is the minimal set of changes that explains the flip. It is
	// irreducible: dropping any single member from the diff makes the flip
	// disappear.
	Causes []CauseRef `json:"causes"`
	// Explanation is a one-line summary naming the deciding rules.
	Explanation string `json:"explanation"`
}

// CauseRef is one policy change that participates in a minimal cause.
type CauseRef struct {
	Change ChangeKind `json:"change"`
	Rule   RuleRef    `json:"rule"`
}

func (c CauseRef) String() string {
	return string(c.Change) + " " + c.Rule.String()
}

// UncertaintyKind classifies why something cannot be decided statically.
type UncertaintyKind string

const (
	// UncertainRuntimeRule: the decision depends on a rule whose value is only
	// known at request time, e.g. an eval() expression such as r.sub.Age > 18.
	UncertainRuntimeRule UncertaintyKind = "runtime-rule"
	// UncertainLinkCondition: the decision depends on a role link whose
	// validity is decided by a condition function installed on the enforcer
	// (for example a time window).
	UncertainLinkCondition UncertaintyKind = "link-condition"
	// UncertainMatcherFunction: the matcher calls a function registered by the
	// host application rather than a built-in, so its semantics are unknown.
	UncertainMatcherFunction UncertaintyKind = "matcher-function"
	// UncertainTruncated: the witness budget cut this area of the request
	// space; it was not examined at all.
	UncertainTruncated UncertaintyKind = "truncated"
)

// Uncertainty is something the preview refuses to decide.
type Uncertainty struct {
	Kind          UncertaintyKind `json:"kind"`
	Request       []interface{}   `json:"request,omitempty"`
	RequestString string          `json:"request_string,omitempty"`
	// Dependency names what the outcome depends on.
	Dependency string `json:"dependency"`
	// Rule, when set, is the rule that introduces the dependency.
	Rule *RuleRef `json:"rule,omitempty"`
	// Detail says why this is uncertain and what would resolve it.
	Detail string `json:"detail"`
}

// Summary holds the reconciled counts. Every examined witness appears in
// exactly one population.
type Summary struct {
	// Examined is the number of witnesses that were evaluated.
	Examined int `json:"examined"`
	// AllowToDeny and DenyToAllow count confirmed flips by direction.
	AllowToDeny int `json:"allow_to_deny"`
	DenyToAllow int `json:"deny_to_allow"`
	// Uncertain counts witnesses that could not be decided.
	Uncertain int `json:"uncertain"`
	// Unchanged counts witnesses whose decision was identical.
	Unchanged int `json:"unchanged"`
	// Accounted is the sum of the four populations above.
	Accounted int `json:"accounted"`
	// TruncatedWitnesses is the number of derived witnesses dropped by the
	// budget. They are not part of Examined.
	TruncatedWitnesses int `json:"truncated_witnesses"`
}

// DiffEntry is one rule-level difference between the two policies.
type DiffEntry struct {
	Change ChangeKind `json:"change"`
	Rule   RuleRef    `json:"rule"`
}

// Truncation describes a budget cut, including what was not examined.
type Truncation struct {
	// Category names the dimension that was cut; currently always "witnesses".
	Category string `json:"category"`
	// Limit is the configured budget.
	Limit int `json:"limit"`
	// Kept and Dropped count the witnesses retained and discarded.
	Kept    int `json:"kept"`
	Dropped int `json:"dropped"`
	// Rule is the pruning rule that chose which witnesses to keep.
	Rule string `json:"rule"`
	// Omitted describes the areas of the request space that were dropped.
	Omitted []string `json:"omitted"`
}

// Failure records why the preview refused to conclude. When Failure is set the
// report carries no flips and no "no impact" claim: a policy that cannot be
// parsed is never evidence of safety.
type Failure struct {
	// Stage is "model", "policy", "rule" or "runtime".
	Stage string `json:"stage"`
	// PType is the named definition involved, when applicable.
	PType string `json:"ptype,omitempty"`
	// Index is the offending rule's position, when the failure is rule-level.
	Index int `json:"index,omitempty"`
	// Rule is the offending rule, when the failure is rule-level.
	Rule *RuleRef `json:"rule,omitempty"`
	// Message is the underlying error.
	Message string `json:"message"`
}

func (f Failure) String() string {
	var b strings.Builder
	b.WriteString(f.Stage)
	if f.PType != "" {
		b.WriteString("/")
		b.WriteString(f.PType)
	}
	switch {
	case f.Rule != nil:
		b.WriteString(": at rule ")
		b.WriteString(f.Rule.String())
		if f.Message != "" {
			b.WriteString(": ")
			b.WriteString(f.Message)
		}
	case f.Message != "":
		b.WriteString(": ")
		b.WriteString(f.Message)
	}
	return b.String()
}

// Report is the outcome of one preview.
type Report struct {
	Summary Summary `json:"summary"`
	// Diff lists every rule added or removed, ordered deterministically.
	Diff []DiffEntry `json:"diff"`
	// Flips lists every confirmed decision change, ordered deterministically.
	Flips []Flip `json:"flips"`
	// Uncertain lists everything that could not be decided statically.
	Uncertain []Uncertainty `json:"uncertainties"`
	// Truncation is set when the witness budget was exceeded.
	Truncation *Truncation `json:"truncation,omitempty"`
	// Failure is set when the preview refused to produce conclusions.
	Failure *Failure `json:"failure,omitempty"`
	// DurationMillis is the wall-clock cost of the preview.
	DurationMillis int64 `json:"duration_millis"`
	// Witnesses is the number of candidate requests derived from the policies.
	Witnesses int `json:"witnesses"`
	// PolicyFingerprint digests the current policy as read before the run; a
	// caller can re-read the policy afterwards and compare.
	PolicyFingerprint string `json:"policy_fingerprint,omitempty"`
}

// OK reports whether the preview produced conclusions.
func (r *Report) OK() bool { return r.Failure == nil }

// Verify checks the reconciliation invariant and the shape of the detail
// lists. It returns an error on the first mismatch. Callers approving a change
// must call Verify.
func (r *Report) Verify() error {
	if r.Failure != nil {
		return fmt.Errorf("preview failed at stage %s: %s", r.Failure.Stage, r.Failure.String())
	}
	s := r.Summary
	sum := s.AllowToDeny + s.DenyToAllow + s.Uncertain + s.Unchanged
	if sum != s.Accounted {
		return fmt.Errorf("flip, uncertain and unchanged counters add up to %d, summary accounts for %d", sum, s.Accounted)
	}
	if s.Accounted != s.Examined {
		return fmt.Errorf("summary accounts for %d witnesses but %d were examined", s.Accounted, s.Examined)
	}
	if got := len(r.Flips); got != s.AllowToDeny+s.DenyToAllow {
		return fmt.Errorf("%d flip details do not match %d flips in the summary", got, s.AllowToDeny+s.DenyToAllow)
	}
	allowDeny, denyAllow := 0, 0
	for _, f := range r.Flips {
		switch f.Direction {
		case AllowToDeny:
			allowDeny++
		case DenyToAllow:
			denyAllow++
		default:
			return fmt.Errorf("flip %s has unknown direction %q", f.RequestString, f.Direction)
		}
		if len(f.Causes) == 0 {
			return fmt.Errorf("flip %s cites no cause", f.RequestString)
		}
	}
	if allowDeny != s.AllowToDeny || denyAllow != s.DenyToAllow {
		return fmt.Errorf("flip directions do not match the summary: %d/%d vs %d/%d",
			allowDeny, denyAllow, s.AllowToDeny, s.DenyToAllow)
	}
	uncertain := 0
	for _, u := range r.Uncertain {
		if u.Kind == UncertainTruncated {
			continue
		}
		uncertain++
	}
	if uncertain != s.Uncertain {
		return fmt.Errorf("%d uncertainty details do not match %d uncertain witnesses", uncertain, s.Uncertain)
	}
	if r.Truncation != nil {
		if r.Truncation.Kept+r.Truncation.Dropped != r.Witnesses {
			return fmt.Errorf("truncation kept %d and dropped %d witnesses, but %d were derived",
				r.Truncation.Kept, r.Truncation.Dropped, r.Witnesses)
		}
		if r.Truncation.Dropped != s.TruncatedWitnesses {
			return fmt.Errorf("truncation dropped %d witnesses but summary reports %d",
				r.Truncation.Dropped, s.TruncatedWitnesses)
		}
	} else if s.TruncatedWitnesses != 0 {
		return fmt.Errorf("summary reports %d truncated witnesses without a truncation record", s.TruncatedWitnesses)
	}
	if s.Examined != s.Accounted {
		return fmt.Errorf("accounting invariant broken: examined %d, accounted %d", s.Examined, s.Accounted)
	}
	return nil
}

func sortFlips(flips []Flip) {
	sort.SliceStable(flips, func(i, j int) bool {
		if flips[i].RequestString != flips[j].RequestString {
			return flips[i].RequestString < flips[j].RequestString
		}
		return flips[i].Direction < flips[j].Direction
	})
}

func sortUncertainties(items []Uncertainty) {
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].Kind != items[j].Kind {
			return items[i].Kind < items[j].Kind
		}
		if items[i].RequestString != items[j].RequestString {
			return items[i].RequestString < items[j].RequestString
		}
		if items[i].Dependency != items[j].Dependency {
			return items[i].Dependency < items[j].Dependency
		}
		return items[i].Detail < items[j].Detail
	})
}

// requestKey renders a request so that it can be used as a map key and in a
// sort order. Values are quoted so that an empty value cannot collide with a
// literal one.
func requestKey(req []interface{}) string {
	var b strings.Builder
	for i, v := range req {
		if i > 0 {
			b.WriteByte('\x00')
		}
		fmt.Fprintf(&b, "%q", fmt.Sprint(v))
	}
	return b.String()
}

// requestString renders a request for a human reader.
func requestString(req []interface{}) string {
	var b strings.Builder
	b.WriteByte('(')
	for i, v := range req {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "%q", fmt.Sprint(v))
	}
	b.WriteByte(')')
	return b.String()
}
