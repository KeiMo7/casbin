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
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/casbin/casbin/v3/model"
)

// EnforcementTrace describes the model version used by one enforcement call.
type EnforcementTrace struct {
	Allowed         bool
	ModelVersion    string
	ModelGeneration uint64
	PolicyVersion   uint64
	Duration        time.Duration
}

// GetModelVersion returns the current immutable model version.
func (e *Enforcer) GetModelVersion() string {
	return e.currentState().modelVersion
}

// GetModelGeneration returns a monotonically increasing generation number for
// model switches. It is suitable for cache keys and audit correlation.
func (e *Enforcer) GetModelGeneration() uint64 {
	return e.currentState().modelGeneration
}

// EnforceWithTrace evaluates a request and returns the exact model version that
// produced the decision.
func (e *Enforcer) EnforceWithTrace(rvals ...interface{}) (bool, *EnforcementTrace, error) {
	state := e.currentState()
	start := time.Now()
	allowed, err := e.enforceWithState(state, "", nil, rvals...)
	return allowed, &EnforcementTrace{
		Allowed:         allowed,
		ModelVersion:    state.modelVersion,
		ModelGeneration: state.modelGeneration,
		PolicyVersion:   e.getPolicyVersion(),
		Duration:        time.Since(start),
	}, err
}

func (e *Enforcer) currentState() *enforcementState {
	if value := e.state.Load(); value != nil {
		return value.(*enforcementState)
	}

	e.stateMu.Lock()
	defer e.stateMu.Unlock()
	if value := e.state.Load(); value != nil {
		return value.(*enforcementState)
	}
	e.publishStateLocked()
	return e.state.Load().(*enforcementState)
}

func (e *Enforcer) publishState() {
	e.stateMu.Lock()
	defer e.stateMu.Unlock()
	e.publishStateLocked()
}

func (e *Enforcer) publishStateLocked() {
	if e.model == nil {
		return
	}
	if e.matcherMap == nil {
		e.matcherMap = &sync.Map{}
	}
	if e.policyIndexes == nil {
		e.policyIndexes = &sync.Map{}
	}
	if e.denyCache == nil {
		e.denyCache = &sync.Map{}
	}

	version := modelDefinitionVersion(e.model)
	generation := e.modelGeneration
	if previous := e.state.Load(); previous != nil && previous.(*enforcementState).modelVersion != version {
		generation++
	} else if previous == nil && generation == 0 {
		generation = 1
	}

	e.modelGeneration = generation
	e.modelVersion = version
	e.state.Store(&enforcementState{
		model:           e.model,
		fm:              e.fm,
		eft:             e.eft,
		rmMap:           e.rmMap,
		condRmMap:       e.condRmMap,
		matcherMap:      e.matcherMap,
		policyIndexes:   e.policyIndexes,
		denyCache:       e.denyCache,
		modelVersion:    version,
		modelGeneration: generation,
	})
}

func modelDefinitionVersion(m model.Model) string {
	hash := sha256.New()
	sections := make([]string, 0, len(m))
	for section := range m {
		sections = append(sections, section)
	}
	sort.Strings(sections)
	for _, section := range sections {
		_, _ = fmt.Fprintf(hash, "section:%s\n", section)
		ptypes := make([]string, 0, len(m[section]))
		for ptype := range m[section] {
			ptypes = append(ptypes, ptype)
		}
		sort.Strings(ptypes)
		for _, ptype := range ptypes {
			ast := m[section][ptype]
			_, _ = fmt.Fprintf(hash, "%s=%s|%s|%s\n",
				ptype, ast.Value, strings.Join(ast.Tokens, ","), strings.Join(ast.ParamsTokens, ","))
		}
	}
	return "model-" + hex.EncodeToString(hash.Sum(nil)[:12])
}

func clearSyncMap(m *sync.Map) {
	if m == nil {
		return
	}
	m.Range(func(key, _ interface{}) bool {
		m.Delete(key)
		return true
	})
}
