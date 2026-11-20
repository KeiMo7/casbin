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

// Package policyhistory stores an append-only, checksummed history of policy
// changes. The enforcer writes one version record per policy mutation; the
// records are a side channel and are never consulted by Enforce.
package policyhistory

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"time"
)

// Record kinds.
const (
	// KindInitial is the record written when history is enabled.
	KindInitial = "initial"
	// KindChange is a policy mutation performed through the management API.
	KindChange = "change"
	// KindReload is a policy reload or reconciliation that changed content.
	KindReload = "reload"
)

// Action describes what happened to a single rule in a version.
type Action string

const (
	// ActionAdd means the rule did not exist before the version.
	ActionAdd Action = "add"
	// ActionRemove means the rule existed before the version and no longer does.
	ActionRemove Action = "remove"
	// ActionUpdate means an existing rule was replaced by another one.
	ActionUpdate Action = "update"
)

// Change is one rule-level change contained in a version record.
type Change struct {
	Section string   `json:"section"`
	PType   string   `json:"ptype"`
	Action  Action   `json:"action"`
	Rule    []string `json:"rule,omitempty"`
	OldRule []string `json:"oldRule,omitempty"`
	NewRule []string `json:"newRule,omitempty"`
}

// RuleRef identifies a rule together with the section and policy type it
// belongs to.
type RuleRef struct {
	Section string   `json:"section"`
	PType   string   `json:"ptype"`
	Rule    []string `json:"rule"`
}

// RuleSet is the complete ordered rule list of one section/ptype at a version.
// Rule order is preserved because it carries priority semantics.
type RuleSet struct {
	Section string     `json:"section"`
	PType   string     `json:"ptype"`
	Rules   [][]string `json:"rules"`
}

// Snapshot is the complete policy content of a version. Rule sets are sorted by
// section and ptype so that the serialized form is deterministic.
type Snapshot []RuleSet

// VersionRecord is one immutable entry of the policy history.
type VersionRecord struct {
	Version       uint64    `json:"version"`
	ParentVersion uint64    `json:"parentVersion"`
	CreatedAt     time.Time `json:"createdAt"`
	Actor         string    `json:"actor"`
	// Kind is "initial" for the snapshot written when history is enabled,
	// "change" for a policy mutation and "reload" for a policy reload that
	// changed the content.
	Kind string `json:"kind"`
	// Message optionally explains the change.
	Message string `json:"message,omitempty"`

	Changes []Change `json:"changes"`
	// Model is the model definition in effect for this version, so that a
	// version can be replayed without depending on the current model.
	Model    ModelDefinition `json:"model"`
	Snapshot Snapshot        `json:"snapshot"`

	// PrevChecksum is the Checksum of ParentVersion. It chains the records so
	// that a rewritten record can be detected even if its own checksum is
	// recomputed.
	PrevChecksum string `json:"prevChecksum"`
	// Checksum is the SHA-256 of the canonical record payload.
	Checksum string `json:"checksum"`
}

// CloneRule returns a copy of rule.
func CloneRule(rule []string) []string {
	if rule == nil {
		return []string{}
	}
	return append([]string(nil), rule...)
}

// CloneRules returns a deep copy of rules.
func CloneRules(rules [][]string) [][]string {
	if rules == nil {
		return [][]string{}
	}
	out := make([][]string, len(rules))
	for i, rule := range rules {
		out[i] = CloneRule(rule)
	}
	return out
}

// CloneChanges returns a deep copy of changes.
func CloneChanges(changes []Change) []Change {
	if changes == nil {
		return []Change{}
	}
	out := make([]Change, len(changes))
	copy(out, changes)
	for i := range out {
		out[i].Rule = CloneRule(out[i].Rule)
		out[i].OldRule = CloneRule(out[i].OldRule)
		out[i].NewRule = CloneRule(out[i].NewRule)
	}
	return out
}

// CloneSnapshot returns a deep copy of snapshot.
func CloneSnapshot(snapshot Snapshot) Snapshot {
	if snapshot == nil {
		return Snapshot{}
	}
	out := make(Snapshot, len(snapshot))
	for i, set := range snapshot {
		out[i] = RuleSet{Section: set.Section, PType: set.PType, Rules: CloneRules(set.Rules)}
	}
	return out
}

// Normalize replaces nil slices by empty ones so that the canonical JSON form
// (and therefore the checksum) does not depend on nil versus empty slices.
func Normalize(record *VersionRecord) {
	if record.Changes == nil {
		record.Changes = []Change{}
	}
	for i := range record.Changes {
		record.Changes[i].Rule = CloneRule(record.Changes[i].Rule)
		record.Changes[i].OldRule = CloneRule(record.Changes[i].OldRule)
		record.Changes[i].NewRule = CloneRule(record.Changes[i].NewRule)
	}
	if record.Snapshot == nil {
		record.Snapshot = Snapshot{}
	}
	for i := range record.Snapshot {
		record.Snapshot[i].Rules = CloneRules(record.Snapshot[i].Rules)
	}
	if record.Model == nil {
		record.Model = ModelDefinition{}
	}
}

func recordDigest(record *VersionRecord) (string, error) {
	// Work on a deep copy: Normalize replaces slices, and it must never touch
	// the caller's record (verification may run concurrently on one record).
	payload := CloneRecord(record)
	payload.Checksum = ""
	Normalize(payload)
	data, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// SealRecord computes and stores the checksum of record.
func SealRecord(record *VersionRecord) error {
	Normalize(record)
	digest, err := recordDigest(record)
	if err != nil {
		return err
	}
	record.Checksum = digest
	return nil
}

// VerifyRecord checks that record was not modified after it was sealed.
func VerifyRecord(record *VersionRecord) error {
	if record == nil {
		return &VersionError{Version: 0, Kind: KindCorrupt, Err: errNilRecord}
	}
	if record.Checksum == "" {
		return &VersionError{Version: record.Version, Kind: KindIntegrity, Err: errMissingChecksum}
	}
	digest, err := recordDigest(record)
	if err != nil {
		return &VersionError{Version: record.Version, Kind: KindIntegrity, Err: err}
	}
	if subtle.ConstantTimeCompare([]byte(record.Checksum), []byte(digest)) != 1 {
		return &VersionError{Version: record.Version, Kind: KindIntegrity, Err: errChecksumMismatch}
	}
	return nil
}
