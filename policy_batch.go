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
	"fmt"
	"sync"

	"github.com/casbin/casbin/v3/persist"
)

// PolicyBatchOp identifies an atomic policy batch operation.
type PolicyBatchOp string

const (
	PolicyBatchAdd    PolicyBatchOp = "add"
	PolicyBatchRemove PolicyBatchOp = "remove"
	PolicyBatchUpdate PolicyBatchOp = "update"
)

// PolicyBatchOperation is one complete operation in an all-or-nothing batch.
type PolicyBatchOperation struct {
	Type     PolicyBatchOp
	Section  string
	PType    string
	Rules    [][]string
	OldRules [][]string
}

// PolicyBatchResult describes a committed policy batch.
type PolicyBatchResult struct {
	Applied          int
	ModelVersion     string
	PolicyVersion    uint64
	AffectedRules    [][]string
	AffectedGrouping [][]string
}

// ApplyPolicyBatch validates and applies every operation on a private model
// snapshot. The live model is replaced only after all operations, role links,
// and constraint checks succeed, so readers never observe an intermediate
// policy state.
func (e *Enforcer) ApplyPolicyBatch(ctx context.Context, operations []PolicyBatchOperation) (*PolicyBatchResult, error) {
	if len(operations) == 0 {
		return &PolicyBatchResult{
			ModelVersion:  e.GetModelVersion(),
			PolicyVersion: e.getPolicyVersion(),
		}, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}

	e.modelUpdateMu.Lock()
	defer e.modelUpdateMu.Unlock()

	oldState := e.currentState()
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	candidateModel := oldState.model.Copy()
	result := &PolicyBatchResult{}
	for _, operation := range operations {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		section := operation.Section
		if section == "" {
			section = "p"
		}
		ptype := operation.PType
		if ptype == "" {
			ptype = section
		}

		switch operation.Type {
		case PolicyBatchAdd:
			if len(operation.Rules) == 0 {
				continue
			}
			hasPolicies, err := candidateModel.HasPolicies(section, ptype, operation.Rules)
			if err != nil {
				return nil, err
			}
			if hasPolicies {
				return nil, fmt.Errorf("policy batch is not atomic: %s %s already contains one of the rules", section, ptype)
			}
			affected, err := candidateModel.AddPoliciesWithAffected(section, ptype, operation.Rules)
			if err != nil {
				return nil, err
			}
			if len(affected) != len(operation.Rules) {
				return nil, fmt.Errorf("policy batch is not atomic: only %d of %d add rules are applicable", len(affected), len(operation.Rules))
			}
			if section == "p" {
				result.AffectedRules = append(result.AffectedRules, cloneRules(affected)...)
			} else {
				result.AffectedGrouping = append(result.AffectedGrouping, cloneRules(affected)...)
			}
			result.Applied += len(affected)
		case PolicyBatchRemove:
			if len(operation.Rules) == 0 {
				continue
			}
			affected, err := candidateModel.RemovePoliciesWithAffected(section, ptype, operation.Rules)
			if err != nil {
				return nil, err
			}
			if len(affected) != len(operation.Rules) {
				return nil, fmt.Errorf("policy batch is not atomic: only %d of %d remove rules exist", len(affected), len(operation.Rules))
			}
			if section == "p" {
				result.AffectedRules = append(result.AffectedRules, cloneRules(affected)...)
			} else {
				result.AffectedGrouping = append(result.AffectedGrouping, cloneRules(affected)...)
			}
			result.Applied += len(affected)
		case PolicyBatchUpdate:
			if len(operation.OldRules) != len(operation.Rules) {
				return nil, errors.New("policy batch update requires the same number of old and new rules")
			}
			updated, err := candidateModel.UpdatePolicies(section, ptype, operation.OldRules, operation.Rules)
			if err != nil {
				return nil, err
			}
			if !updated {
				return nil, fmt.Errorf("policy batch is not atomic: one or more update rules do not exist in %s %s", section, ptype)
			}
			if section == "p" {
				result.AffectedRules = append(result.AffectedRules, cloneRules(operation.Rules)...)
			} else {
				result.AffectedGrouping = append(result.AffectedGrouping, cloneRules(operation.Rules)...)
			}
			result.Applied += len(operation.Rules)
		default:
			return nil, fmt.Errorf("unsupported policy batch operation %q", operation.Type)
		}
	}

	if err := candidateModel.ValidateConstraints(); err != nil {
		return nil, err
	}
	candidateState, err := buildEnforcementState(candidateModel, e.fm.Clone(), e.eft)
	if err != nil {
		return nil, err
	}
	candidateState.policyIndexes = clonePolicyIndexes(oldState.policyIndexes)
	if err := validateMatchers(candidateState); err != nil {
		return nil, err
	}

	if e.shouldPersist() {
		if err := e.persistPolicyBatch(ctx, operations); err != nil {
			return nil, err
		}
	}

	if err := e.commitPolicyBatch(ctx, candidateState, oldState.modelGeneration, oldState.modelVersion); err != nil {
		return nil, err
	}

	result.ModelVersion = e.GetModelVersion()
	result.PolicyVersion = e.getPolicyVersion()
	return result, nil
}

// AddPoliciesAtomic is the common all-or-nothing add form.
func (e *Enforcer) AddPoliciesAtomic(rules [][]string) (bool, error) {
	result, err := e.ApplyPolicyBatch(context.Background(), []PolicyBatchOperation{{
		Type:    PolicyBatchAdd,
		Section: "p",
		PType:   "p",
		Rules:   rules,
	}})
	if err != nil {
		return false, err
	}
	return result.Applied != 0, nil
}

func (e *Enforcer) persistPolicyBatch(ctx context.Context, operations []PolicyBatchOperation) error {
	if transactional, ok := e.adapter.(persist.TransactionalAdapter); ok {
		txContext, err := transactional.BeginTransaction(ctx)
		if err != nil {
			return err
		}
		if err := applyPolicyBatchToAdapter(txContext.GetAdapter(), operations); err != nil {
			_ = txContext.Rollback()
			return err
		}
		return txContext.Commit()
	}
	return applyPolicyBatchToAdapter(e.adapter, operations)
}

func applyPolicyBatchToAdapter(adapter persist.Adapter, operations []PolicyBatchOperation) error {
	for _, operation := range operations {
		section := operation.Section
		if section == "" {
			section = "p"
		}
		ptype := operation.PType
		if ptype == "" {
			ptype = section
		}

		var err error
		switch operation.Type {
		case PolicyBatchAdd:
			if batch, ok := adapter.(persist.BatchAdapter); ok {
				err = batch.AddPolicies(section, ptype, operation.Rules)
			} else {
				for _, rule := range operation.Rules {
					if currentErr := adapter.AddPolicy(section, ptype, rule); currentErr != nil {
						err = currentErr
						break
					}
				}
			}
		case PolicyBatchRemove:
			if batch, ok := adapter.(persist.BatchAdapter); ok {
				err = batch.RemovePolicies(section, ptype, operation.Rules)
			} else {
				for _, rule := range operation.Rules {
					if currentErr := adapter.RemovePolicy(section, ptype, rule); currentErr != nil {
						err = currentErr
						break
					}
				}
			}
		case PolicyBatchUpdate:
			if updater, ok := adapter.(persist.UpdatableAdapter); ok {
				err = updater.UpdatePolicies(section, ptype, operation.OldRules, operation.Rules)
			} else {
				return fmt.Errorf("adapter does not support atomic policy updates")
			}
		}
		if err != nil && err.Error() != notImplemented {
			return err
		}
	}
	return nil
}

func (e *Enforcer) commitPolicyBatch(ctx context.Context, candidate *enforcementState, expectedGeneration uint64, expectedVersion string) error {
	commit := func() error {
		e.stateMu.Lock()
		defer e.stateMu.Unlock()

		if err := ctx.Err(); err != nil {
			return err
		}
		current := e.state.Load().(*enforcementState)
		if current.modelGeneration != expectedGeneration || current.modelVersion != expectedVersion {
			return errors.New("model changed concurrently; policy batch aborted")
		}
		if current.modelGeneration != candidate.modelGeneration && candidate.modelGeneration != 0 {
			return errors.New("policy batch candidate generation is stale")
		}

		e.model = candidate.model
		e.fm = candidate.fm
		e.rmMap = candidate.rmMap
		e.condRmMap = candidate.condRmMap
		e.matcherMap = candidate.matcherMap
		e.policyIndexes = candidate.policyIndexes
		e.denyCache = &sync.Map{}
		e.bumpPolicyVersion()

		candidate.denyCache = e.denyCache
		candidate.modelGeneration = e.modelGeneration
		candidate.modelVersion = e.modelVersion
		e.state.Store(candidate)
		if e.cacheInvalidator != nil {
			e.cacheInvalidator()
		}
		return nil
	}

	if e.switchGuard == nil {
		return commit()
	}
	var commitErr error
	e.switchGuard(func() {
		commitErr = commit()
	})
	return commitErr
}

func cloneRules(rules [][]string) [][]string {
	cloned := make([][]string, len(rules))
	for i, rule := range rules {
		cloned[i] = append([]string(nil), rule...)
	}
	return cloned
}
