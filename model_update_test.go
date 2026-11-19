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
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/casbin/casbin/v3/model"
)

const hotReloadBaseModel = `[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
`

const hotReloadLooseModel = `[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj
`

func newHotReloadEnforcer(t *testing.T, text string) *Enforcer {
	t.Helper()
	m, err := model.NewModelFromString(text)
	if err != nil {
		t.Fatal(err)
	}
	e, err := NewEnforcer(m)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.AddPolicy("admin", "data1", "read"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.AddGroupingPolicy("alice", "admin"); err != nil {
		t.Fatal(err)
	}
	return e
}

func TestHotReloadModelSwitchesAtomicallyAndReportsImpact(t *testing.T) {
	e := newHotReloadEnforcer(t, hotReloadBaseModel)
	oldVersion := e.GetModelVersion()

	report, err := e.HotReloadModelFromText(
		context.Background(),
		hotReloadLooseModel,
		WithModelUpdateSampleRequests([]interface{}{"alice", "data1", "write"}),
	)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Switched {
		t.Fatal("expected model to switch")
	}
	if report.ValidationDuration <= 0 {
		t.Fatal("expected validation duration")
	}
	if report.SwitchTime.IsZero() {
		t.Fatal("expected switch timestamp")
	}
	if report.OldVersion != oldVersion || report.NewVersion == oldVersion {
		t.Fatalf("unexpected version transition: %s -> %s", report.OldVersion, report.NewVersion)
	}
	if len(report.Comparisons) == 0 {
		t.Fatal("expected before/after comparisons")
	}
	if len(report.LoosenedGrants) != 1 {
		t.Fatalf("expected one loosened grant, got %d", len(report.LoosenedGrants))
	}
	if e.GetModelVersion() != report.NewVersion {
		t.Fatal("current model version does not match report")
	}
	if len(e.GetModelAuditHistory()) != 1 {
		t.Fatal("expected a loosening audit record")
	}

	allowed, trace, err := e.EnforceWithTrace("alice", "data1", "write")
	if err != nil {
		t.Fatal(err)
	}
	if !allowed {
		t.Fatal("new matcher should allow write")
	}
	if trace.ModelVersion != report.NewVersion {
		t.Fatalf("trace version = %s, want %s", trace.ModelVersion, report.NewVersion)
	}
}

func TestHotReloadReportsTightenedExistingGrants(t *testing.T) {
	e := newHotReloadEnforcer(t, hotReloadLooseModel)
	report, err := e.HotReloadModelFromText(
		context.Background(),
		hotReloadBaseModel,
		WithModelUpdateSampleRequests([]interface{}{"alice", "data1", "write"}),
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.TightenedGrants) != 1 {
		t.Fatalf("expected one tightened grant, got %d", len(report.TightenedGrants))
	}
	grant := report.TightenedGrants[0]
	if !grant.ExistingGrant || grant.OldAllowed != true || grant.NewAllowed != false {
		t.Fatalf("unexpected tightened grant: %+v", grant)
	}
}

func TestHotReloadRejectsMissingPolicyDefinitionAndKeepsOldModel(t *testing.T) {
	text := `[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act
p2 = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
`
	e := newHotReloadEnforcer(t, text)
	if _, err := e.AddNamedPolicy("p2", "admin", "data2", "read"); err != nil {
		t.Fatal(err)
	}
	oldVersion := e.GetModelVersion()
	oldAllowed, err := e.Enforce("alice", "data1", "read")
	if err != nil || !oldAllowed {
		t.Fatalf("baseline allow failed: %v %v", oldAllowed, err)
	}

	alerts := 0
	e.SetModelUpdateAlerter(func(ModelUpdateAlert) { alerts++ })
	report, err := e.HotReloadModelFromText(context.Background(), hotReloadBaseModel)
	if err == nil {
		t.Fatal("expected policy definition mismatch")
	}
	if report.Switched {
		t.Fatal("failed update must not switch")
	}
	if !strings.Contains(err.Error(), "undefined_policy_definition") && !strings.Contains(err.Error(), "does not define") {
		t.Fatalf("error should identify the broken policy definition: %v", err)
	}
	if alerts != 1 {
		t.Fatalf("expected one alert, got %d", alerts)
	}
	if e.GetModelVersion() != oldVersion {
		t.Fatal("failed update changed the active model version")
	}
	allowed, err := e.Enforce("alice", "data1", "read")
	if err != nil || !allowed {
		t.Fatalf("old model did not keep serving: %v %v", allowed, err)
	}
}

func TestHotReloadRejectsUndefinedRoleAndResourceReference(t *testing.T) {
	text := `[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[role_names]
admin =

[resource_names]
data1 =

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
`
	e := newHotReloadEnforcer(t, text)
	badModel := strings.Replace(text, "data1 =", "data2 =", 1)
	report, err := e.HotReloadModelFromText(context.Background(), badModel)
	if err == nil {
		t.Fatal("expected undefined resource validation error")
	}
	if report.Switched {
		t.Fatal("invalid model was switched")
	}
	if !strings.Contains(err.Error(), "undefined resource") || !strings.Contains(err.Error(), "admin") {
		t.Fatalf("error should identify the policy and reference: %v", err)
	}
}

func TestHotReloadTimeoutKeepsOldModel(t *testing.T) {
	e := newHotReloadEnforcer(t, hotReloadBaseModel)
	oldVersion := e.GetModelVersion()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	report, err := e.HotReloadModelFromText(ctx, hotReloadLooseModel)
	if err == nil {
		t.Fatal("expected timeout/cancellation")
	}
	if report.Switched {
		t.Fatal("cancelled update switched")
	}
	if e.GetModelVersion() != oldVersion {
		t.Fatal("cancelled update changed model")
	}
}

func TestCachedEnforcerInvalidatesOnModelSwitch(t *testing.T) {
	m, err := model.NewModelFromString(hotReloadBaseModel)
	if err != nil {
		t.Fatal(err)
	}
	e, err := NewCachedEnforcer(m)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.AddPolicy("admin", "data1", "read"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.AddGroupingPolicy("alice", "admin"); err != nil {
		t.Fatal(err)
	}
	allowed, err := e.Enforce("alice", "data1", "write")
	if err != nil || allowed {
		t.Fatalf("baseline write = %v, %v", allowed, err)
	}

	report, err := e.HotReloadModelFromText(context.Background(), hotReloadLooseModel)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Switched {
		t.Fatal("model was not switched")
	}
	allowed, err = e.Enforce("alice", "data1", "write")
	if err != nil || !allowed {
		t.Fatalf("stale cache returned old decision: %v, %v", allowed, err)
	}
}

func TestApplyPolicyBatchIsAllOrNothing(t *testing.T) {
	e := newHotReloadEnforcer(t, hotReloadBaseModel)
	before, err := e.GetPolicy()
	if err != nil {
		t.Fatal(err)
	}

	rules := make([][]string, 50)
	for i := range rules {
		rules[i] = []string{"admin", "data" + string(rune('A'+i%26)) + string(rune('a'+i/26)), "read"}
	}
	result, err := e.ApplyPolicyBatch(context.Background(), []PolicyBatchOperation{{
		Type:    PolicyBatchAdd,
		Section: "p",
		PType:   "p",
		Rules:   rules,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if result.Applied != 50 {
		t.Fatalf("applied %d rules, want 50", result.Applied)
	}
	afterSuccess, _ := e.GetPolicy()
	if len(afterSuccess) != len(before)+50 {
		t.Fatalf("policy size = %d, want %d", len(afterSuccess), len(before)+50)
	}

	invalidBatch := [][]string{
		{"admin", "atomic-a", "read"},
		{"admin", "atomic-b", "read"},
		{"admin", "data1", "read"},
	}
	if _, err := e.ApplyPolicyBatch(context.Background(), []PolicyBatchOperation{{
		Type:    PolicyBatchAdd,
		Section: "p",
		PType:   "p",
		Rules:   invalidBatch,
	}}); err == nil {
		t.Fatal("expected duplicate rule to abort the whole batch")
	}
	afterFailure, _ := e.GetPolicy()
	if len(afterFailure) != len(afterSuccess) {
		t.Fatalf("failed batch changed policy: %d -> %d", len(afterSuccess), len(afterFailure))
	}
	allowed, err := e.Enforce("alice", "atomic-a", "read")
	if err != nil {
		t.Fatal(err)
	}
	if allowed {
		t.Fatal("failed batch leaked a partial authorization")
	}
}

func TestModelVisualizationIncludesRoleAndResourceGroups(t *testing.T) {
	text := hotReloadBaseModel + `
[role_definition]
g2 = _, _
`
	m, err := model.NewModelFromString(text)
	if err != nil {
		t.Fatal(err)
	}
	e, err := NewEnforcer(m)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = e.AddGroupingPolicy("alice", "admin")
	_, _ = e.AddNamedGroupingPolicy("g2", "data1", "data_group")

	graph, err := e.ExportModelGraph(ModelGraphMermaid)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"flowchart", "Role inheritance", "Resource groups", "alice", "data_group"} {
		if !strings.Contains(graph, want) {
			t.Fatalf("graph is missing %q:\n%s", want, graph)
		}
	}
}

func TestUnsupportedModelFormatIsRejectedWithoutSwitch(t *testing.T) {
	e := newHotReloadEnforcer(t, hotReloadBaseModel)
	oldVersion := e.GetModelVersion()
	unsupported := `[model_format]
version = 99
min_reader_version = 99

` + hotReloadBaseModel
	report, err := e.HotReloadModelFromText(context.Background(), unsupported)
	if err == nil {
		t.Fatal("expected unsupported model format")
	}
	if !errors.Is(err, ErrUnsupportedModelSyntax) {
		t.Fatalf("expected unsupported syntax classification, got %v", err)
	}
	if report.Switched || e.GetModelVersion() != oldVersion {
		t.Fatal("unsupported model format changed the active model")
	}
}

func TestUnsupportedMatcherSyntaxDegradesWithoutSwitch(t *testing.T) {
	e := newHotReloadEnforcer(t, hotReloadBaseModel)
	oldVersion := e.GetModelVersion()
	unsupported := strings.Replace(
		hotReloadBaseModel,
		"g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act",
		"g(r.sub, p.sub) && timeWindow(r.act, p.act)",
		1,
	)
	report, err := e.HotReloadModelFromText(context.Background(), unsupported)
	if err == nil {
		t.Fatal("expected unsupported matcher syntax")
	}
	if !errors.Is(err, ErrUnsupportedModelSyntax) {
		t.Fatalf("expected unsupported syntax classification, got %v", err)
	}
	if report.Switched || e.GetModelVersion() != oldVersion {
		t.Fatal("unsupported matcher changed the active model")
	}
	allowed, err := e.Enforce("alice", "data1", "read")
	if err != nil || !allowed {
		t.Fatalf("old model did not continue serving: %v %v", allowed, err)
	}
}

func TestQueriesContinueDuringHotReload(t *testing.T) {
	e := newHotReloadEnforcer(t, hotReloadBaseModel)
	var wg sync.WaitGroup
	stop := make(chan struct{})
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					allowed, err := e.Enforce("alice", "data1", "read")
					if err != nil {
						errs <- err
						return
					}
					if !allowed {
						errs <- errors.New("read was denied during switch")
						return
					}
				}
			}
		}()
	}

	for i := 0; i < 20; i++ {
		text := hotReloadBaseModel
		if i%2 == 0 {
			text = hotReloadLooseModel
		}
		if _, err := e.HotReloadModelFromText(context.Background(), text); err != nil {
			close(stop)
			wg.Wait()
			t.Fatal(err)
		}
	}
	close(stop)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}

func TestModelUpdateTimeoutOption(t *testing.T) {
	e := newHotReloadEnforcer(t, hotReloadBaseModel)
	start := time.Now()
	report, err := e.HotReloadModelFromText(
		context.Background(),
		hotReloadLooseModel,
		WithModelUpdateTimeout(time.Nanosecond),
	)
	if err == nil && report.Switched {
		t.Skip("machine completed update within one nanosecond")
	}
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if time.Since(start) > time.Second {
		t.Fatal("timeout option did not bound the update")
	}
}
