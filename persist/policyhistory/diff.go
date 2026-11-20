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

package policyhistory

import (
	"sort"
	"strings"
)

// AssertionDefinition is one model assertion in effect for a version. Tokens
// are stored alongside the value because they are derived from it at load time
// and re-deriving them from an already-escaped value would change the matcher.
type AssertionDefinition struct {
	Value        string         `json:"value"`
	Tokens       []string       `json:"tokens,omitempty"`
	ParamsTokens []string       `json:"paramsTokens,omitempty"`
	FieldIndex   map[string]int `json:"fieldIndex,omitempty"`
}

// ModelDefinition is the set of model assertions in effect for a version,
// keyed by section and policy type. It is enough to rebuild the model.
type ModelDefinition map[string]map[string]AssertionDefinition

// CloneModelDefinition returns a deep copy of definition.
func CloneModelDefinition(definition ModelDefinition) ModelDefinition {
	if definition == nil {
		return ModelDefinition{}
	}
	out := make(ModelDefinition, len(definition))
	for sec, assertions := range definition {
		copied := make(map[string]AssertionDefinition, len(assertions))
		for key, value := range assertions {
			value.Tokens = append([]string(nil), value.Tokens...)
			value.ParamsTokens = append([]string(nil), value.ParamsTokens...)
			fieldIndex := make(map[string]int, len(value.FieldIndex))
			for field, index := range value.FieldIndex {
				fieldIndex[field] = index
			}
			value.FieldIndex = fieldIndex
			copied[key] = value
		}
		out[sec] = copied
	}
	return out
}

// UpdatePair records that oldRule was replaced by newRule.
type UpdatePair struct {
	Section string
	PType   string
	OldRule []string
	NewRule []string
}

const ruleSep = "\x00"

func ruleKey(section, ptype string, rule []string) string {
	return section + ruleSep + ptype + ruleSep + strings.Join(rule, "\x00")
}

type indexedRule struct {
	section string
	ptype   string
	rule    []string
}

func indexSnapshot(snapshot Snapshot) (map[string]indexedRule, []string) {
	index := make(map[string]indexedRule)
	order := make([]string, 0)
	for _, set := range snapshot {
		for _, rule := range set.Rules {
			key := ruleKey(set.Section, set.PType, rule)
			if _, exists := index[key]; exists {
				continue
			}
			index[key] = indexedRule{section: set.Section, ptype: set.PType, rule: rule}
			order = append(order, key)
		}
	}
	return index, order
}

// DiffSnapshots lists the differences between two snapshots. Removed and added
// rules are always exact. Rules that were replaced are reported as updates: an
// explicit update pair wins, otherwise a removed/added pair under the same
// section and ptype that differs in a single field is treated as an update.
func DiffSnapshots(before, after Snapshot, pairs []UpdatePair) []Change {
	beforeIndex, beforeOrder := indexSnapshot(before)
	afterIndex, afterOrder := indexSnapshot(after)

	var removed []indexedRule
	var added []indexedRule
	for _, key := range beforeOrder {
		if _, ok := afterIndex[key]; !ok {
			removed = append(removed, beforeIndex[key])
		}
	}
	for _, key := range afterOrder {
		if _, ok := beforeIndex[key]; !ok {
			added = append(added, afterIndex[key])
		}
	}

	changes := make([]Change, 0, len(removed)+len(added))
	usedRemoved := make([]bool, len(removed))
	usedAdded := make([]bool, len(added))

	// Explicit pairs first, so a multi-field update is still reported as one
	// modification.
	for _, pair := range pairs {
		oldKey := ruleKey(pair.Section, pair.PType, pair.OldRule)
		newKey := ruleKey(pair.Section, pair.PType, pair.NewRule)
		if oldKey == newKey {
			// Updating a rule to itself changes nothing.
			continue
		}
		if _, ok := beforeIndex[oldKey]; !ok {
			continue
		}
		if _, ok := afterIndex[newKey]; !ok {
			continue
		}
		for i := range removed {
			if !usedRemoved[i] && matches(removed[i], pair.Section, pair.PType, pair.OldRule) {
				usedRemoved[i] = true
				break
			}
		}
		for i := range added {
			if !usedAdded[i] && matches(added[i], pair.Section, pair.PType, pair.NewRule) {
				usedAdded[i] = true
				break
			}
		}
		changes = append(changes, Change{
			Section: pair.Section,
			PType:   pair.PType,
			Action:  ActionUpdate,
			OldRule: CloneRule(pair.OldRule),
			NewRule: CloneRule(pair.NewRule),
		})
	}

	// Infer the remaining updates as single-field edits.
	for i := range removed {
		if usedRemoved[i] {
			continue
		}
		for j := range added {
			if usedAdded[j] {
				continue
			}
			if removed[i].section != added[j].section || removed[i].ptype != added[j].ptype {
				continue
			}
			if !singleFieldEdit(removed[i].rule, added[j].rule) {
				continue
			}
			usedRemoved[i] = true
			usedAdded[j] = true
			changes = append(changes, Change{
				Section: removed[i].section,
				PType:   removed[i].ptype,
				Action:  ActionUpdate,
				OldRule: CloneRule(removed[i].rule),
				NewRule: CloneRule(added[j].rule),
			})
			break
		}
	}

	for i, rule := range removed {
		if usedRemoved[i] {
			continue
		}
		changes = append(changes, Change{
			Section: rule.section,
			PType:   rule.ptype,
			Action:  ActionRemove,
			OldRule: CloneRule(rule.rule),
			Rule:    CloneRule(rule.rule),
		})
	}
	for i, rule := range added {
		if usedAdded[i] {
			continue
		}
		changes = append(changes, Change{
			Section: rule.section,
			PType:   rule.ptype,
			Action:  ActionAdd,
			NewRule: CloneRule(rule.rule),
			Rule:    CloneRule(rule.rule),
		})
	}

	SortChanges(changes)
	return changes
}

func matches(rule indexedRule, section, ptype string, want []string) bool {
	if rule.section != section || rule.ptype != ptype || len(rule.rule) != len(want) {
		return false
	}
	for i := range want {
		if rule.rule[i] != want[i] {
			return false
		}
	}
	return true
}

func singleFieldEdit(a, b []string) bool {
	if len(a) != len(b) || len(a) == 0 {
		return false
	}
	diffs := 0
	for i := range a {
		if a[i] != b[i] {
			diffs++
			if diffs > 1 {
				return false
			}
		}
	}
	return diffs == 1
}

// SortChanges orders changes deterministically by section, ptype, action and
// rule content.
func SortChanges(changes []Change) {
	sort.SliceStable(changes, func(i, j int) bool {
		a, b := changes[i], changes[j]
		if a.Section != b.Section {
			return a.Section < b.Section
		}
		if a.PType != b.PType {
			return a.PType < b.PType
		}
		if a.Action != b.Action {
			return a.Action < b.Action
		}
		return changeKey(a) < changeKey(b)
	})
}

func changeKey(change Change) string {
	parts := []string{strings.Join(change.Rule, "\x00"), strings.Join(change.OldRule, "\x00"), strings.Join(change.NewRule, "\x00")}
	return strings.Join(parts, "\x01")
}
