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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/casbin/casbin/v3/model"
)

// impactFixture is one policy pair under testdata/impact. Each fixture states
// the expected flips, their causes, and the expected uncertainty; the runner
// compares them item by item and checks that the report reconciles.
type impactFixture struct {
	Name      string              `json:"name"`
	Model     string              `json:"model"`
	Current   []string            `json:"current"`
	Candidate []string            `json:"candidate"`
	Options   *impactFixtureOpts  `json:"options,omitempty"`
	Expect    impactFixtureExpect `json:"expect"`
}

type impactFixtureOpts struct {
	WitnessLimit int `json:"witness_limit,omitempty"`
}

type impactFixtureExpect struct {
	Flips      []fixtureFlip      `json:"flips"`
	FlipCount  *int               `json:"flip_count,omitempty"`
	Unchanged  *int               `json:"unchanged,omitempty"`
	Uncertain  []fixtureUncertain `json:"uncertain,omitempty"`
	Truncation *fixtureTruncation `json:"truncation,omitempty"`
	Failure    *fixtureFailure    `json:"failure,omitempty"`
	DiffEmpty  bool               `json:"diff_empty,omitempty"`
	DiffCount  *int               `json:"diff_count,omitempty"`
}

type fixtureFlip struct {
	Request   []string       `json:"request"`
	Direction string         `json:"direction"`
	Causes    []fixtureRef   `json:"causes,omitempty"`
	CausesAny [][]fixtureRef `json:"causes_any_of,omitempty"`
}

type fixtureRef struct {
	Section string   `json:"section"`
	PType   string   `json:"ptype"`
	Rule    []string `json:"rule"`
}

type fixtureUncertain struct {
	Kind              string   `json:"kind"`
	Request           []string `json:"request,omitempty"`
	DependencyContain string   `json:"dependency_contains,omitempty"`
}

type fixtureTruncation struct {
	Limit   int `json:"limit"`
	Dropped int `json:"dropped"`
	AtLeast int `json:"at_least_omitted_groups"`
}

type fixtureFailure struct {
	Stage string   `json:"stage"`
	Rule  []string `json:"rule,omitempty"`
}

func TestImpactFixtures(t *testing.T) {
	dir := filepath.Join("testdata", "impact")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read fixtures: %v", err)
	}
	var names []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".json") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	if len(names) == 0 {
		t.Fatal("no impact fixtures found")
	}
	for _, name := range names {
		name := name
		t.Run(strings.TrimSuffix(name, ".json"), func(t *testing.T) {
			loadAndRunFixture(t, dir, filepath.Join(dir, name))
		})
	}
}

func loadAndRunFixture(t *testing.T, dir, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var fx impactFixture
	if unmarshalErr := json.Unmarshal(data, &fx); unmarshalErr != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	if fx.Name == "" {
		t.Fatalf("fixture %s has no name", path)
	}

	m, err := model.NewModelFromFile(filepath.Join(dir, fx.Model))
	if err != nil {
		t.Fatalf("load model %s: %v", fx.Model, err)
	}
	current := fixtureSnapshot(t, m, fx.Current)
	candidate := fixtureSnapshot(t, m, fx.Candidate)

	opts := ImpactOptions{}
	if fx.Options != nil {
		opts.WitnessLimit = fx.Options.WitnessLimit
	}
	report, err := ComputeImpact(current, candidate, opts)
	if err != nil {
		t.Fatalf("compute impact: %v", err)
	}

	if fx.Expect.Failure != nil {
		checkFailure(t, report, *fx.Expect.Failure)
		return
	}
	if report.Failure != nil {
		t.Fatalf("unexpected failure: %s", report.Failure.String())
	}
	if err := report.Verify(); err != nil {
		t.Fatalf("reconciliation invariant broken: %v", err)
	}

	checkDiff(t, report, fx.Expect)
	checkFlips(t, report, fx.Expect)
	checkUncertain(t, report, fx.Expect)
	if fx.Expect.Unchanged != nil && report.Summary.Unchanged != *fx.Expect.Unchanged {
		t.Errorf("unchanged = %d, want %d", report.Summary.Unchanged, *fx.Expect.Unchanged)
	}
	if fx.Expect.Truncation != nil {
		checkTruncation(t, report, *fx.Expect.Truncation)
	}
}

func fixtureSnapshot(t *testing.T, m model.Model, lines []string) ImpactSnapshot {
	t.Helper()
	snap := ImpactSnapshot{Model: m.Copy()}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ",")
		fields := make([]string, 0, len(parts))
		for _, f := range parts {
			fields = append(fields, strings.TrimSpace(f))
		}
		if len(fields) < 2 {
			t.Fatalf("invalid policy line %q", line)
		}
		snap.Policy = append(snap.Policy, ImpactRule{PType: fields[0], Rule: fields[1:]})
	}
	return snap
}

func checkDiff(t *testing.T, report *Report, want impactFixtureExpect) {
	t.Helper()
	if want.DiffEmpty && len(report.Diff) != 0 {
		t.Errorf("diff is not empty: %v", report.Diff)
	}
	if want.DiffCount != nil && len(report.Diff) != *want.DiffCount {
		t.Errorf("diff count = %d, want %d", len(report.Diff), *want.DiffCount)
	}
}

func checkFlips(t *testing.T, report *Report, want impactFixtureExpect) {
	t.Helper()
	got := map[string]Flip{}
	for _, f := range report.Flips {
		got[f.RequestString] = f
	}

	for _, exp := range want.Flips {
		key := requestString(toInterfaces(exp.Request))
		flip, ok := got[key]
		if !ok {
			seen := make([]string, 0, len(report.Flips))
			for _, f := range report.Flips {
				seen = append(seen, f.RequestString)
			}
			t.Errorf("missing expected flip %s; got flips %v", key, seen)
			continue
		}
		delete(got, key)
		if string(flip.Direction) != exp.Direction {
			t.Errorf("flip %s direction = %s, want %s", key, flip.Direction, exp.Direction)
		}
		if len(exp.Causes) > 0 && !causesMatch(flip.Causes, exp.Causes) {
			t.Errorf("flip %s causes = %v, want %v", key, describeCauses(flip.Causes), exp.Causes)
		}
		if len(exp.CausesAny) > 0 && !causesMatchAny(flip.Causes, exp.CausesAny) {
			t.Errorf("flip %s causes = %v, want one of %v", key, describeCauses(flip.Causes), exp.CausesAny)
		}
	}

	if want.FlipCount != nil {
		if len(report.Flips) != *want.FlipCount {
			details := make([]string, 0, len(report.Flips))
			for _, f := range report.Flips {
				details = append(details, fmt.Sprintf("%s %s", f.RequestString, f.Direction))
			}
			t.Errorf("flip count = %d, want %d; flips: %v", len(report.Flips), *want.FlipCount, details)
		}
		return
	}
	if len(want.Flips) == 0 {
		for _, f := range report.Flips {
			t.Errorf("unexpected flip %s %s: %s", f.RequestString, f.Direction, f.Explanation)
		}
	}
	for key, f := range got {
		t.Errorf("unexpected additional flip %s %s", key, f.Direction)
	}
}

// causesMatch compares cause sets exactly, ignoring order.
func causesMatch(got []CauseRef, want []fixtureRef) bool {
	if len(got) != len(want) {
		return false
	}
	return causesMatchAny(got, [][]fixtureRef{want})
}

func causesMatchAny(got []CauseRef, alternatives [][]fixtureRef) bool {
	for _, want := range alternatives {
		if len(got) != len(want) {
			continue
		}
		used := make([]bool, len(got))
		all := true
		for _, w := range want {
			found := false
			for i, g := range got {
				if used[i] {
					continue
				}
				if g.Rule.PType == w.PType && g.Rule.Section == w.Section &&
					strings.Join(g.Rule.Rule, "\x00") == strings.Join(w.Rule, "\x00") {
					used[i] = true
					found = true
					break
				}
			}
			if !found {
				all = false
				break
			}
		}
		if all {
			return true
		}
	}
	return false
}

func describeCauses(causes []CauseRef) []string {
	out := make([]string, 0, len(causes))
	for _, c := range causes {
		out = append(out, fmt.Sprintf("%s %s %v", c.Change, c.Rule.PType, c.Rule.Rule))
	}
	return out
}

func checkUncertain(t *testing.T, report *Report, want impactFixtureExpect) {
	t.Helper()
	for _, exp := range want.Uncertain {
		found := false
		for _, u := range report.Uncertain {
			if string(u.Kind) != exp.Kind {
				continue
			}
			if exp.Request != nil && u.RequestString != requestString(toInterfaces(exp.Request)) {
				continue
			}
			if exp.DependencyContain != "" && !strings.Contains(u.Dependency, exp.DependencyContain) {
				continue
			}
			found = true
			break
		}
		if !found {
			seen := make([]string, 0, len(report.Uncertain))
			for _, u := range report.Uncertain {
				seen = append(seen, fmt.Sprintf("%s(%s)", u.Kind, u.Dependency))
			}
			t.Errorf("missing uncertainty %s for %v (dependency contains %q); got %v",
				exp.Kind, exp.Request, exp.DependencyContain, seen)
		}
	}
}

func checkTruncation(t *testing.T, report *Report, want fixtureTruncation) {
	t.Helper()
	if report.Truncation == nil {
		t.Fatalf("expected truncation at limit %d, got none", want.Limit)
	}
	tr := report.Truncation
	if tr.Limit != want.Limit {
		t.Errorf("truncation limit = %d, want %d", tr.Limit, want.Limit)
	}
	if tr.Dropped != want.Dropped {
		t.Errorf("truncation dropped = %d, want %d", tr.Dropped, want.Dropped)
	}
	if len(tr.Omitted) < want.AtLeast {
		t.Errorf("truncation lists %d omitted groups, want at least %d", len(tr.Omitted), want.AtLeast)
	}
	if tr.Kept+tr.Dropped != report.Witnesses {
		t.Errorf("truncation kept %d + dropped %d != %d witnesses", tr.Kept, tr.Dropped, report.Witnesses)
	}
	foundTruncatedUncertainty := false
	for _, u := range report.Uncertain {
		if u.Kind == UncertainTruncated {
			foundTruncatedUncertainty = true
		}
	}
	if !foundTruncatedUncertainty {
		t.Error("truncation is not listed among the uncertainties")
	}
}

func checkFailure(t *testing.T, report *Report, want fixtureFailure) {
	t.Helper()
	if report.Failure == nil {
		t.Fatalf("expected a failure at stage %q, got a report with %d flips", want.Stage, len(report.Flips))
	}
	if report.Failure.Stage != want.Stage {
		t.Errorf("failure stage = %q, want %q", report.Failure.Stage, want.Stage)
	}
	if len(report.Flips) != 0 {
		t.Errorf("a failed preview must not report flips; got %d", len(report.Flips))
	}
	if report.Summary.Examined != 0 {
		t.Errorf("a failed preview must not claim examined witnesses; got %d", report.Summary.Examined)
	}
	if len(want.Rule) > 0 {
		if report.Failure.Rule == nil {
			t.Fatalf("failure does not name the offending rule")
		}
		if strings.Join(report.Failure.Rule.Rule, "\x00") != strings.Join(want.Rule, "\x00") {
			t.Errorf("offending rule = %v, want %v", report.Failure.Rule.Rule, want.Rule)
		}
	}
}

func toInterfaces(in []string) []interface{} {
	out := make([]interface{}, len(in))
	for i, v := range in {
		out[i] = v
	}
	return out
}
