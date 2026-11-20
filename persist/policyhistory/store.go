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
	"sync"
)

var errDuplicateVersion = errDuplicateVersionError{}

type errDuplicateVersionError struct{}

func (errDuplicateVersionError) Error() string { return "version already exists" }

// Store is the append-only storage used for policy history. Implementations
// only ever append a record; they must never overwrite or delete one.
type Store interface {
	// Versions returns every stored version number in ascending order.
	Versions() ([]uint64, error)
	// Read returns the record stored for version. It must report a corrupted
	// record as a *VersionError with Kind KindCorrupt.
	Read(version uint64) (*VersionRecord, error)
	// Append stores a sealed record. It must fail if the version already
	// exists, so that a record can never be overwritten.
	Append(record *VersionRecord) error
}

// MemoryStore is an in-memory Store. It is the default store and serves as a
// reference implementation and a test double.
type MemoryStore struct {
	mu      sync.RWMutex
	records map[uint64]*VersionRecord
}

// NewMemoryStore creates an empty in-memory store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{records: make(map[uint64]*VersionRecord)}
}

// Versions returns the stored version numbers in ascending order.
func (s *MemoryStore) Versions() ([]uint64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return sortedVersions(s.records), nil
}

// Read returns a copy of the record stored for version.
func (s *MemoryStore) Read(version uint64) (*VersionRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	record, ok := s.records[version]
	if !ok {
		return nil, &VersionError{Version: version, Kind: KindCorrupt, Err: errMissingVersion}
	}
	return CloneRecord(record), nil
}

// Append stores a copy of record.
func (s *MemoryStore) Append(record *VersionRecord) error {
	if record == nil {
		return &VersionError{Kind: KindStorage, Err: errNilRecord}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.records[record.Version]; exists {
		return &VersionError{Version: record.Version, Kind: KindSequence, Err: errDuplicateVersion}
	}
	s.records[record.Version] = CloneRecord(record)
	return nil
}

// CloneRecord returns a deep copy of record.
func CloneRecord(record *VersionRecord) *VersionRecord {
	if record == nil {
		return nil
	}
	out := *record
	out.Changes = make([]Change, len(record.Changes))
	copy(out.Changes, record.Changes)
	for i := range out.Changes {
		out.Changes[i].Rule = CloneRule(out.Changes[i].Rule)
		out.Changes[i].OldRule = CloneRule(out.Changes[i].OldRule)
		out.Changes[i].NewRule = CloneRule(out.Changes[i].NewRule)
	}
	out.Snapshot = CloneSnapshot(record.Snapshot)
	out.Model = CloneModelDefinition(record.Model)
	return &out
}

func sortedVersions(records map[uint64]*VersionRecord) []uint64 {
	versions := make([]uint64, 0, len(records))
	for version := range records {
		versions = append(versions, version)
	}
	sort.Slice(versions, func(i, j int) bool { return versions[i] < versions[j] })
	return versions
}
