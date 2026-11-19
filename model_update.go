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
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/casbin/casbin/v3/effector"
	"github.com/casbin/casbin/v3/model"
	"github.com/casbin/casbin/v3/rbac"
	defaultrolemanager "github.com/casbin/casbin/v3/rbac/default-role-manager"
	"github.com/casbin/casbin/v3/util"
	"github.com/casbin/govaluate"
)

const (
	defaultModelUpdateTimeout = 30 * time.Second
	maxModelUpdateHistory     = 256
	maxModelAuditHistory      = 1024
)

var (
	// ErrModelUpdateRejected indicates that a candidate model was not activated.
	ErrModelUpdateRejected = errors.New("model update rejected")
	// ErrUnsupportedModelSyntax indicates syntax that this binary cannot evaluate.
	ErrUnsupportedModelSyntax = errors.New("unsupported model syntax")
)

// ModelUpdateIssue identifies a validation problem and, when applicable, the
// exact policy rule that references a missing definition.
type ModelUpdateIssue struct {
	Code       string   `json:"code"`
	Section    string   `json:"section,omitempty"`
	PolicyType string   `json:"policy_type,omitempty"`
	Reference  string   `json:"reference,omitempty"`
	Message    string   `json:"message"`
	Rule       []string `json:"rule,omitempty"`
}

// ModelUpdateError is returned for both syntax and semantic validation
// failures. Issues are intentionally structured so callers can show the exact
// broken policy rule instead of a generic load error.
type ModelUpdateError struct {
	Issues []ModelUpdateIssue
	Err    error
}

func (e *ModelUpdateError) Error() string {
	parts := make([]string, 0, len(e.Issues)+1)
	for _, issue := range e.Issues {
		parts = append(parts, issue.Message)
	}
	if e.Err != nil {
		parts = append(parts, e.Err.Error())
	}
	if len(parts) == 0 {
		return ErrModelUpdateRejected.Error()
	}
	return ErrModelUpdateRejected.Error() + ": " + strings.Join(parts, "; ")
}

func (e *ModelUpdateError) Unwrap() error {
	if e.Err != nil {
		return e.Err
	}
	return ErrModelUpdateRejected
}

// AffectedGrant is one authorization decision changed by a model update.
type AffectedGrant struct {
	Request       []interface{} `json:"request"`
	OldAllowed    bool          `json:"old_allowed"`
	NewAllowed    bool          `json:"new_allowed"`
	Change        string        `json:"change"`
	ExistingGrant bool          `json:"existing_grant"`
	OldPolicy     []string      `json:"old_policy,omitempty"`
	NewPolicy     []string      `json:"new_policy,omitempty"`
}

// ModelUpdateReport is the audit record for one attempted model update. A
// report is returned on both success and failure.
type ModelUpdateReport struct {
	StartedAt          time.Time          `json:"started_at"`
	ValidationDuration time.Duration      `json:"validation_duration"`
	SwitchTime         time.Time          `json:"switch_time"`
	SwitchDuration     time.Duration      `json:"switch_duration"`
	OldVersion         string             `json:"old_version"`
	NewVersion         string             `json:"new_version"`
	Switched           bool               `json:"switched"`
	Error              string             `json:"error,omitempty"`
	Issues             []ModelUpdateIssue `json:"issues,omitempty"`
	Warnings           []string           `json:"warnings,omitempty"`
	Comparisons        []AffectedGrant    `json:"comparisons,omitempty"`
	TightenedGrants    []AffectedGrant    `json:"tightened_grants,omitempty"`
	LoosenedGrants     []AffectedGrant    `json:"loosened_grants,omitempty"`
}

func (r ModelUpdateReport) String() string {
	status := "rejected"
	if r.Switched {
		status = "switched"
	}
	return fmt.Sprintf(
		"model update %s: %s -> %s, validation=%s, switch=%s at %s, comparisons=%d, tightened=%d, loosened=%d, error=%q",
		status,
		r.OldVersion,
		r.NewVersion,
		r.ValidationDuration,
		r.SwitchDuration,
		r.SwitchTime.Format(time.RFC3339Nano),
		len(r.Comparisons),
		len(r.TightenedGrants),
		len(r.LoosenedGrants),
		r.Error,
	)
}

// ModelAuditRecord records security-relevant consequences of a model update.
type ModelAuditRecord struct {
	At         time.Time       `json:"at"`
	Type       string          `json:"type"`
	OldVersion string          `json:"old_version"`
	NewVersion string          `json:"new_version"`
	Grants     []AffectedGrant `json:"grants,omitempty"`
}

// ModelAuditSink receives model audit records. Implementations should persist
// records durably; the enforcer also keeps an in-memory bounded history.
type ModelAuditSink interface {
	RecordModelAudit(ModelAuditRecord) error
}

// ModelAuditSinkFunc adapts a function to ModelAuditSink.
type ModelAuditSinkFunc func(ModelAuditRecord) error

func (f ModelAuditSinkFunc) RecordModelAudit(record ModelAuditRecord) error {
	return f(record)
}

// ModelUpdateAlert is emitted when a candidate update is rejected. Production
// deployments should connect this to their alerting pipeline.
type ModelUpdateAlert struct {
	At         time.Time
	Stage      string
	OldVersion string
	NewVersion string
	Err        error
}

// ModelUpdateAlerter receives failed update alerts.
type ModelUpdateAlerter func(ModelUpdateAlert)

type modelUpdateConfig struct {
	timeout      time.Duration
	samples      [][]interface{}
	auditSink    ModelAuditSink
	alerter      ModelUpdateAlerter
	validateOnly bool
}

// ModelUpdateOption configures a safe model update.
type ModelUpdateOption func(*modelUpdateConfig)

// WithModelUpdateTimeout bounds validation and commit. The old model remains
// active if the budget is exhausted.
func WithModelUpdateTimeout(timeout time.Duration) ModelUpdateOption {
	return func(cfg *modelUpdateConfig) {
		if timeout > 0 {
			cfg.timeout = timeout
		}
	}
}

// WithModelUpdateSampleRequests adds request fixtures to the before/after
// comparison. Policy-derived requests are always included.
func WithModelUpdateSampleRequests(requests ...[]interface{}) ModelUpdateOption {
	return func(cfg *modelUpdateConfig) {
		cfg.samples = append(cfg.samples, requests...)
	}
}

// WithModelUpdateAuditSink adds a durable sink for loosening audits.
func WithModelUpdateAuditSink(sink ModelAuditSink) ModelUpdateOption {
	return func(cfg *modelUpdateConfig) {
		cfg.auditSink = sink
	}
}

// WithModelUpdateAlerter overrides the enforcer-level failure alerter.
func WithModelUpdateAlerter(alerter ModelUpdateAlerter) ModelUpdateOption {
	return func(cfg *modelUpdateConfig) {
		cfg.alerter = alerter
	}
}

// WithModelUpdateValidationOnly validates and compares without switching.
func WithModelUpdateValidationOnly() ModelUpdateOption {
	return func(cfg *modelUpdateConfig) {
		cfg.validateOnly = true
	}
}

type modelCandidate struct {
	state      *enforcementState
	version    string
	samples    [][]interface{}
	comparison []AffectedGrant
}

// SetModelUpdateAlerter sets the default failure alerter.
func (e *Enforcer) SetModelUpdateAlerter(alerter ModelUpdateAlerter) {
	e.modelUpdateAlerter = alerter
}

// HotReloadModel loads and validates a model file, then atomically publishes it.
// The current model keeps serving requests until publication succeeds.
func (e *Enforcer) HotReloadModel(ctx context.Context, modelPath string, opts ...ModelUpdateOption) (*ModelUpdateReport, error) {
	text, err := readModelFile(modelPath)
	if err != nil {
		report := &ModelUpdateReport{
			StartedAt:  time.Now(),
			OldVersion: e.GetModelVersion(),
			Error:      err.Error(),
		}
		e.notifyModelUpdateFailure(ModelUpdateAlert{
			At:         time.Now(),
			Stage:      "read",
			OldVersion: report.OldVersion,
			Err:        err,
		}, modelUpdateAlerterFromOptions(opts))
		e.appendModelUpdateReport(*report)
		return report, err
	}
	return e.HotReloadModelFromText(ctx, string(text), opts...)
}

// ReloadModel is an alias for HotReloadModel.
func (e *Enforcer) ReloadModel(ctx context.Context, modelPath string, opts ...ModelUpdateOption) (*ModelUpdateReport, error) {
	return e.HotReloadModel(ctx, modelPath, opts...)
}

// HotReloadModelFromText validates and atomically publishes a model text.
func (e *Enforcer) HotReloadModelFromText(ctx context.Context, text string, opts ...ModelUpdateOption) (*ModelUpdateReport, error) {
	cfg := defaultModelUpdateConfig(opts...)
	ctx, cancel := modelUpdateContext(ctx, cfg.timeout)
	defer cancel()

	e.modelUpdateMu.Lock()
	defer e.modelUpdateMu.Unlock()

	oldState := e.currentState()
	report := &ModelUpdateReport{
		StartedAt:  time.Now(),
		OldVersion: oldState.modelVersion,
	}

	candidate, validationDuration, err := e.prepareModelCandidate(ctx, oldState, text)
	report.ValidationDuration = validationDuration
	if err != nil {
		report.Error = err.Error()
		e.rejectModelUpdate(report, cfg, "validation", err)
		return report, err
	}
	report.NewVersion = candidate.version
	candidate.samples = append(candidate.samples, cfg.samples...)

	comparisons, err := e.compareModelStates(ctx, oldState, candidate)
	if err != nil {
		report.Error = err.Error()
		e.rejectModelUpdate(report, cfg, "comparison", err)
		return report, err
	}
	report.Comparisons = comparisons
	for _, comparison := range comparisons {
		switch comparison.Change {
		case "tightened":
			if comparison.ExistingGrant {
				report.TightenedGrants = append(report.TightenedGrants, comparison)
			}
		case "loosened":
			report.LoosenedGrants = append(report.LoosenedGrants, comparison)
		}
	}

	if cfg.validateOnly {
		e.appendModelUpdateReport(*report)
		return report, nil
	}

	switchStart := time.Now()
	if err := ctx.Err(); err != nil {
		report.Error = err.Error()
		e.rejectModelUpdate(report, cfg, "switch", err)
		return report, err
	}
	if err := e.commitModelCandidate(ctx, candidate, oldState.modelGeneration); err != nil {
		report.SwitchDuration = time.Since(switchStart)
		report.Error = err.Error()
		e.rejectModelUpdate(report, cfg, "switch", err)
		return report, err
	}
	report.SwitchTime = time.Now()
	report.SwitchDuration = time.Since(switchStart)
	report.Switched = true

	if len(report.LoosenedGrants) > 0 {
		record := ModelAuditRecord{
			At:         report.SwitchTime,
			Type:       "model_update_loosened",
			OldVersion: report.OldVersion,
			NewVersion: report.NewVersion,
			Grants:     append([]AffectedGrant(nil), report.LoosenedGrants...),
		}
		e.recordModelAudit(record)
		if cfg.auditSink != nil {
			if auditErr := cfg.auditSink.RecordModelAudit(record); auditErr != nil {
				report.Warnings = append(report.Warnings, "audit sink failed: "+auditErr.Error())
			}
		}
	}

	e.appendModelUpdateReport(*report)
	return report, nil
}

// ValidateModelUpdate validates and compares a candidate without activating it.
func (e *Enforcer) ValidateModelUpdate(ctx context.Context, text string, opts ...ModelUpdateOption) (*ModelUpdateReport, error) {
	opts = append(opts, WithModelUpdateValidationOnly())
	return e.HotReloadModelFromText(ctx, text, opts...)
}

// GetModelUpdateHistory returns a copy of the bounded update history.
func (e *Enforcer) GetModelUpdateHistory() []ModelUpdateReport {
	e.modelAuditMu.RLock()
	defer e.modelAuditMu.RUnlock()
	history := make([]ModelUpdateReport, len(e.modelUpdateHistory))
	copy(history, e.modelUpdateHistory)
	return history
}

// GetModelAuditHistory returns a copy of the bounded model audit history.
func (e *Enforcer) GetModelAuditHistory() []ModelAuditRecord {
	e.modelAuditMu.RLock()
	defer e.modelAuditMu.RUnlock()
	history := make([]ModelAuditRecord, len(e.modelAuditHistory))
	copy(history, e.modelAuditHistory)
	return history
}

func defaultModelUpdateConfig(opts ...ModelUpdateOption) modelUpdateConfig {
	cfg := modelUpdateConfig{timeout: defaultModelUpdateTimeout}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	return cfg
}

func modelUpdateContext(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if parent == nil {
		parent = context.Background()
	}
	if _, ok := parent.Deadline(); ok {
		return context.WithCancel(parent)
	}
	return context.WithTimeout(parent, timeout)
}

func modelUpdateAlerterFromOptions(opts []ModelUpdateOption) ModelUpdateAlerter {
	return defaultModelUpdateConfig(opts...).alerter
}

func readModelFile(path string) ([]byte, error) {
	if path == "" {
		return nil, errors.New("model path is empty")
	}
	return os.ReadFile(path)
}

func (e *Enforcer) prepareModelCandidate(ctx context.Context, oldState *enforcementState, text string) (*modelCandidate, time.Duration, error) {
	start := time.Now()
	if err := ctx.Err(); err != nil {
		return nil, time.Since(start), err
	}

	if err := model.CheckModelCompatibility(text); err != nil {
		return nil, time.Since(start), &ModelUpdateError{
			Issues: []ModelUpdateIssue{{
				Code:    "unsupported_model_format",
				Message: err.Error(),
			}},
			Err: ErrUnsupportedModelSyntax,
		}
	}

	candidateModel, err := model.NewModelFromString(text)
	if err != nil {
		return nil, time.Since(start), &ModelUpdateError{Err: fmt.Errorf("%w: %v", ErrUnsupportedModelSyntax, err)}
	}
	if err := ctx.Err(); err != nil {
		return nil, time.Since(start), err
	}

	issues := mergePolicyIntoModel(oldState.model, candidateModel)
	declarations := parseSemanticDeclarations(text)
	issues = append(issues, validatePolicyReferenceValues(candidateModel, declarations)...)

	candidateState, stateErr := buildEnforcementState(candidateModel, cloneFunctionMap(e.fm), e.eft)
	if stateErr != nil {
		issues = append(issues, ModelUpdateIssue{
			Code:    "role_link_error",
			Message: stateErr.Error(),
		})
	}
	if len(issues) != 0 {
		return nil, time.Since(start), &ModelUpdateError{Issues: issues}
	}

	if err := validateMatchers(candidateState); err != nil {
		return nil, time.Since(start), err
	}
	candidateState.policyIndexes = clonePolicyIndexes(e.policyIndexes)
	if err := ctx.Err(); err != nil {
		return nil, time.Since(start), err
	}

	candidate := &modelCandidate{
		state:   candidateState,
		version: modelDefinitionVersion(candidateModel),
	}
	return candidate, time.Since(start), nil
}

func mergePolicyIntoModel(source model.Model, target model.Model) []ModelUpdateIssue {
	var issues []ModelUpdateIssue
	for _, section := range []string{"p", "g"} {
		sourceSection := source[section]
		targetSection := target[section]
		ptypes := make([]string, 0, len(sourceSection))
		for ptype := range sourceSection {
			ptypes = append(ptypes, ptype)
		}
		sort.Strings(ptypes)

		for _, ptype := range ptypes {
			sourceAssertion := sourceSection[ptype]
			if len(sourceAssertion.Policy) == 0 {
				continue
			}
			targetAssertion, ok := targetSection[ptype]
			if !ok {
				issues = append(issues, ModelUpdateIssue{
					Code:       "undefined_policy_definition",
					Section:    section,
					PolicyType: ptype,
					Reference:  ptype,
					Message: fmt.Sprintf(
						"%s policy %q has %d existing rule(s), but the new model does not define %s %q",
						section, ptype, len(sourceAssertion.Policy), section, ptype),
				})
				continue
			}

			for _, rule := range sourceAssertion.Policy {
				ruleCopy := append([]string(nil), rule...)
				if section == "p" && len(ruleCopy) != len(targetAssertion.Tokens) {
					issues = append(issues, ModelUpdateIssue{
						Code:       "policy_shape_mismatch",
						Section:    section,
						PolicyType: ptype,
						Message: fmt.Sprintf(
							"policy %s rule %v has %d fields, but the new definition expects %d",
							ptype, ruleCopy, len(ruleCopy), len(targetAssertion.Tokens)),
						Rule: ruleCopy,
					})
					continue
				}
				if section == "g" && len(ruleCopy) < len(targetAssertion.Tokens) {
					issues = append(issues, ModelUpdateIssue{
						Code:       "policy_shape_mismatch",
						Section:    section,
						PolicyType: ptype,
						Message: fmt.Sprintf(
							"grouping policy %s rule %v has %d fields, but the new definition requires at least %d",
							ptype, ruleCopy, len(ruleCopy), len(targetAssertion.Tokens)),
						Rule: ruleCopy,
					})
					continue
				}
				targetAssertion.Policy = append(targetAssertion.Policy, ruleCopy)
				targetAssertion.PolicyMap[strings.Join(ruleCopy, model.DefaultSep)] = len(targetAssertion.Policy) - 1
				targetAssertion.PolicyVersion++
			}
		}
	}
	return issues
}

func buildEnforcementState(m model.Model, fm model.FunctionMap, eft effector.Effector) (*enforcementState, error) {
	rmMap := make(map[string]rbac.RoleManager)
	condRmMap := make(map[string]rbac.ConditionalRoleManager)

	for ptype, assertion := range m["g"] {
		switch {
		case len(assertion.Tokens) <= 2 && len(assertion.ParamsTokens) == 0:
			assertion.RM = defaultrolemanager.NewRoleManagerImpl(10)
			rmMap[ptype] = assertion.RM
		case len(assertion.Tokens) <= 2 && len(assertion.ParamsTokens) != 0:
			assertion.CondRM = defaultrolemanager.NewConditionalRoleManager(10)
			condRmMap[ptype] = assertion.CondRM
		case len(assertion.ParamsTokens) == 0:
			assertion.RM = defaultrolemanager.NewRoleManager(10)
			rmMap[ptype] = assertion.RM
		default:
			assertion.CondRM = defaultrolemanager.NewConditionalDomainManager(10)
			condRmMap[ptype] = assertion.CondRM
		}

		if len(assertion.Tokens) > 2 && modelUsesDomainMatch(m) {
			if rm := rmMap[ptype]; rm != nil {
				rm.AddDomainMatchingFunc("g", util.KeyMatch)
			}
			if crm := condRmMap[ptype]; crm != nil {
				crm.AddDomainMatchingFunc("g", util.KeyMatch)
			}
		}
	}

	if err := m.BuildRoleLinks(rmMap); err != nil {
		return nil, err
	}
	if err := m.BuildConditionalRoleLinks(condRmMap); err != nil {
		return nil, err
	}

	return &enforcementState{
		model:           m,
		fm:              fm,
		eft:             eft,
		rmMap:           rmMap,
		condRmMap:       condRmMap,
		matcherMap:      &sync.Map{},
		policyIndexes:   &sync.Map{},
		denyCache:       &sync.Map{},
		modelVersion:    modelDefinitionVersion(m),
		modelGeneration: 0,
	}, nil
}

func modelUsesDomainMatch(m model.Model) bool {
	for _, assertion := range m["m"] {
		if strings.Contains(assertion.Value, "keyMatch(") {
			return true
		}
	}
	return false
}

func cloneFunctionMap(source model.FunctionMap) model.FunctionMap {
	return source.Clone()
}

func clonePolicyIndexes(source *sync.Map) *sync.Map {
	cloned := &sync.Map{}
	if source == nil {
		return cloned
	}
	source.Range(func(key, value interface{}) bool {
		index := value.(*policyIndex)
		cloned.Store(key, &policyIndex{
			requestKey: index.requestKey,
			policyKey:  index.policyKey,
		})
		return true
	})
	return cloned
}

func validateMatchers(state *enforcementState) error {
	functions := state.fm.GetFunctions()
	for ptype, assertion := range state.model["g"] {
		if assertion.RM != nil {
			functions[ptype] = util.GenerateGFunction(assertion.RM, true)
		}
		if assertion.CondRM != nil {
			functions[ptype] = util.GenerateConditionalGFunction(assertion.CondRM)
		}
	}
	functions["eval"] = func(arguments ...interface{}) (interface{}, error) {
		return true, nil
	}

	var issues []ModelUpdateIssue
	unsupported := false
	for mtype, assertion := range state.model["m"] {
		if _, err := govaluate.NewEvaluableExpressionWithFunctions(assertion.Value, functions); err != nil {
			unsupported = true
			issues = append(issues, ModelUpdateIssue{
				Code:       "invalid_matcher",
				Section:    "m",
				PolicyType: mtype,
				Message:    fmt.Sprintf("matcher %s is not supported: %v", mtype, err),
			})
		}
		issues = append(issues, validateTokenReferences(mtype, assertion.Value, state.model)...)
	}
	if len(issues) != 0 {
		if unsupported {
			return &ModelUpdateError{Issues: issues, Err: ErrUnsupportedModelSyntax}
		}
		return &ModelUpdateError{Issues: issues}
	}
	return nil
}

var tokenReferencePattern = regexp.MustCompile(`\b([rp][0-9]*_[A-Za-z_][A-Za-z0-9_]*)`)

func validateTokenReferences(mtype, expression string, m model.Model) []ModelUpdateIssue {
	var issues []ModelUpdateIssue
	for _, reference := range tokenReferencePattern.FindAllString(expression, -1) {
		section := reference[:1]
		ptype, token, ok := splitTokenReference(m, section, reference)
		if !ok {
			issues = append(issues, ModelUpdateIssue{
				Code:       "undefined_definition",
				Section:    section,
				PolicyType: ptype,
				Reference:  reference,
				Message:    fmt.Sprintf("matcher %s references undefined %s definition %q", mtype, section, reference),
			})
			continue
		}
		found := false
		for _, candidate := range m[section][ptype].Tokens {
			if candidate == token {
				found = true
				break
			}
		}
		if !found {
			issues = append(issues, ModelUpdateIssue{
				Code:       "undefined_reference",
				Section:    section,
				PolicyType: ptype,
				Reference:  reference,
				Message: fmt.Sprintf("matcher %s references %q, but %s %s does not define token %q",
					mtype, reference, section, ptype, token),
			})
		}
	}
	return issues
}

func splitTokenReference(m model.Model, section, reference string) (string, string, bool) {
	ptypes := make([]string, 0, len(m[section]))
	for ptype := range m[section] {
		ptypes = append(ptypes, ptype)
	}
	sort.Slice(ptypes, func(i, j int) bool {
		return len(ptypes[i]) > len(ptypes[j])
	})
	for _, ptype := range ptypes {
		prefix := ptype + "_"
		if strings.HasPrefix(reference, prefix) {
			return ptype, reference, true
		}
	}
	return "", "", false
}

type semanticDeclarations struct {
	roles     map[string]struct{}
	users     map[string]struct{}
	resources map[string]struct{}
}

func parseSemanticDeclarations(text string) semanticDeclarations {
	declarations := semanticDeclarations{
		roles:     make(map[string]struct{}),
		users:     make(map[string]struct{}),
		resources: make(map[string]struct{}),
	}
	section := ""
	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			continue
		}
		var target map[string]struct{}
		switch section {
		case "role_names", "roles":
			target = declarations.roles
		case "user_names", "users":
			target = declarations.users
		case "resource_names", "resources":
			target = declarations.resources
		default:
			continue
		}
		separator := strings.Index(line, "=")
		if separator < 0 {
			continue
		}
		key := line[:separator]
		value := line[separator+1:]
		addDeclaredNames(target, key)
		addDeclaredNames(target, value)
	}
	return declarations
}

func addDeclaredNames(target map[string]struct{}, value string) {
	for _, name := range strings.Split(value, ",") {
		name = strings.Trim(strings.TrimSpace(name), `"'`)
		if name != "" {
			target[name] = struct{}{}
		}
	}
}

func validatePolicyReferenceValues(m model.Model, declarations semanticDeclarations) []ModelUpdateIssue {
	if len(declarations.roles) == 0 && len(declarations.resources) == 0 {
		return nil
	}

	knownRoles := copyStringSet(declarations.roles)
	knownUsers := copyStringSet(declarations.users)
	knownResources := copyStringSet(declarations.resources)
	for ptype, assertion := range m["g"] {
		for _, rule := range assertion.Policy {
			if len(rule) < 2 {
				continue
			}
			if ptype == "g" {
				knownUsers[rule[0]] = struct{}{}
				knownRoles[rule[1]] = struct{}{}
			}
			if ptype == "g2" {
				knownResources[rule[0]] = struct{}{}
				knownResources[rule[1]] = struct{}{}
			}
		}
	}

	var issues []ModelUpdateIssue
	for ptype, assertion := range m["p"] {
		subjectIndex := tokenIndexBySuffix(assertion.Tokens, ptype, []string{"sub", "subject", "role"})
		resourceIndex := tokenIndexBySuffix(assertion.Tokens, ptype, []string{"obj", "object", "resource"})
		for _, rule := range assertion.Policy {
			if subjectIndex >= 0 && len(declarations.roles) > 0 && subjectIndex < len(rule) {
				value := rule[subjectIndex]
				if _, ok := knownRoles[value]; !ok {
					if _, isUser := knownUsers[value]; !isUser {
						issues = append(issues, ModelUpdateIssue{
							Code:       "undefined_role",
							Section:    "p",
							PolicyType: ptype,
							Reference:  value,
							Message: fmt.Sprintf(
								"policy %s rule %v references undefined role %q",
								ptype, rule, value),
							Rule: append([]string(nil), rule...),
						})
					}
				}
			}
			if resourceIndex >= 0 && len(declarations.resources) > 0 && resourceIndex < len(rule) {
				value := rule[resourceIndex]
				if _, ok := knownResources[value]; !ok {
					issues = append(issues, ModelUpdateIssue{
						Code:       "undefined_resource",
						Section:    "p",
						PolicyType: ptype,
						Reference:  value,
						Message: fmt.Sprintf(
							"policy %s rule %v references undefined resource %q",
							ptype, rule, value),
						Rule: append([]string(nil), rule...),
					})
				}
			}
		}
	}
	return issues
}

func tokenIndexBySuffix(tokens []string, ptype string, suffixes []string) int {
	for i, token := range tokens {
		base := strings.TrimPrefix(token, ptype+"_")
		for _, suffix := range suffixes {
			if base == suffix {
				return i
			}
		}
	}
	return -1
}

func copyStringSet(source map[string]struct{}) map[string]struct{} {
	target := make(map[string]struct{}, len(source))
	for item := range source {
		target[item] = struct{}{}
	}
	return target
}

func (e *Enforcer) compareModelStates(ctx context.Context, oldState *enforcementState, candidate *modelCandidate) ([]AffectedGrant, error) {
	requests, existing := requestsFromPolicy(oldState.model)
	requests = append(requests, candidate.samples...)
	seen := make(map[string]bool)
	for _, request := range requests {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		key := requestKey(request)
		if seen[key] {
			continue
		}
		seen[key] = true
		oldExplain := []string{}
		oldAllowed, oldErr := e.enforceWithState(oldState, "", &oldExplain, request...)
		if oldErr != nil {
			continue
		}
		newExplain := []string{}
		newAllowed, newErr := e.enforceWithState(candidate.state, "", &newExplain, request...)
		if newErr != nil {
			return nil, &ModelUpdateError{Issues: []ModelUpdateIssue{{
				Code:    "candidate_evaluation_error",
				Message: fmt.Sprintf("candidate model failed for request %v: %v", request, newErr),
			}}}
		}
		change := "unchanged"
		if oldAllowed && !newAllowed {
			change = "tightened"
		} else if !oldAllowed && newAllowed {
			change = "loosened"
		}
		comparison := AffectedGrant{
			Request:       append([]interface{}(nil), request...),
			OldAllowed:    oldAllowed,
			NewAllowed:    newAllowed,
			Change:        change,
			ExistingGrant: existing[key] || oldAllowed,
			OldPolicy:     append([]string(nil), oldExplain...),
			NewPolicy:     append([]string(nil), newExplain...),
		}
		candidate.comparison = append(candidate.comparison, comparison)
	}
	return candidate.comparison, nil
}

func requestsFromPolicy(m model.Model) ([][]interface{}, map[string]bool) {
	var requests [][]interface{}
	existing := make(map[string]bool)
	seen := make(map[string]bool)
	for ptype, pAssertion := range m["p"] {
		rtype := "r" + strings.TrimPrefix(ptype, "p")
		rAssertion := m["r"][rtype]
		if rAssertion == nil {
			continue
		}
		for _, rule := range pAssertion.Policy {
			if len(rule) != len(pAssertion.Tokens) {
				continue
			}
			request := make([]interface{}, len(rAssertion.Tokens))
			complete := true
			for i, rToken := range rAssertion.Tokens {
				pIndex := tokenIndexBySuffix(pAssertion.Tokens, ptype, []string{strings.TrimPrefix(rToken, rtype+"_")})
				if pIndex < 0 {
					complete = false
					break
				}
				request[i] = rule[pIndex]
			}
			if !complete {
				continue
			}
			key := requestKey(request)
			if seen[key] {
				continue
			}
			seen[key] = true
			requests = append(requests, request)
			existing[key] = true
		}
	}
	return requests, existing
}

func requestKey(request []interface{}) string {
	parts := make([]string, len(request))
	for i, value := range request {
		parts[i] = fmt.Sprintf("%T:%v", value, value)
	}
	return strings.Join(parts, "\x00")
}

func (e *Enforcer) commitModelCandidate(ctx context.Context, candidate *modelCandidate, expectedGeneration uint64) error {
	if e.switchGuard == nil {
		e.stateMu.Lock()
		defer e.stateMu.Unlock()
		return e.commitModelCandidateLocked(ctx, candidate, expectedGeneration)
	}
	var commitErr error
	e.switchGuard(func() {
		e.stateMu.Lock()
		defer e.stateMu.Unlock()
		commitErr = e.commitModelCandidateLocked(ctx, candidate, expectedGeneration)
	})
	return commitErr
}

func (e *Enforcer) commitModelCandidateLocked(ctx context.Context, candidate *modelCandidate, expectedGeneration uint64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	current := e.state.Load().(*enforcementState)
	if current.modelGeneration != expectedGeneration {
		return errors.New("model changed concurrently; candidate update aborted")
	}

	e.resetPolicyCaches()
	e.model = candidate.state.model
	e.fm = candidate.state.fm
	e.rmMap = candidate.state.rmMap
	e.condRmMap = candidate.state.condRmMap
	e.matcherMap = candidate.state.matcherMap
	e.policyIndexes = candidate.state.policyIndexes
	e.denyCache = &sync.Map{}
	e.modelVersion = candidate.version
	e.modelGeneration = expectedGeneration + 1
	e.bumpPolicyVersion()

	candidate.state.denyCache = e.denyCache
	candidate.state.modelGeneration = e.modelGeneration
	candidate.state.modelVersion = candidate.version
	e.state.Store(candidate.state)

	if e.cacheInvalidator != nil {
		e.cacheInvalidator()
	}
	return nil
}

func (e *Enforcer) rejectModelUpdate(report *ModelUpdateReport, cfg modelUpdateConfig, stage string, err error) {
	report.Switched = false
	var updateErr *ModelUpdateError
	if errors.As(err, &updateErr) {
		report.Issues = append([]ModelUpdateIssue(nil), updateErr.Issues...)
	}
	e.appendModelUpdateReport(*report)
	alert := ModelUpdateAlert{
		At:         time.Now(),
		Stage:      stage,
		OldVersion: report.OldVersion,
		NewVersion: report.NewVersion,
		Err:        err,
	}
	alerter := cfg.alerter
	if alerter == nil {
		alerter = e.modelUpdateAlerter
	}
	e.notifyModelUpdateFailure(alert, alerter)
}

func (e *Enforcer) notifyModelUpdateFailure(alert ModelUpdateAlert, alerter ModelUpdateAlerter) {
	if alerter != nil {
		alerter(alert)
		return
	}
	if e.modelUpdateAlerter != nil {
		e.modelUpdateAlerter(alert)
	}
}

func (e *Enforcer) appendModelUpdateReport(report ModelUpdateReport) {
	e.modelAuditMu.Lock()
	defer e.modelAuditMu.Unlock()
	e.modelUpdateHistory = append(e.modelUpdateHistory, report)
	if len(e.modelUpdateHistory) > maxModelUpdateHistory {
		e.modelUpdateHistory = append([]ModelUpdateReport(nil), e.modelUpdateHistory[len(e.modelUpdateHistory)-maxModelUpdateHistory:]...)
	}
}

func (e *Enforcer) recordModelAudit(record ModelAuditRecord) {
	e.modelAuditMu.Lock()
	defer e.modelAuditMu.Unlock()
	e.modelAuditHistory = append(e.modelAuditHistory, record)
	if len(e.modelAuditHistory) > maxModelAuditHistory {
		e.modelAuditHistory = append([]ModelAuditRecord(nil), e.modelAuditHistory[len(e.modelAuditHistory)-maxModelAuditHistory:]...)
	}
}
