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
	"os"
	"path/filepath"
	"testing"
)

func seal(t *testing.T, record *VersionRecord) *VersionRecord {
	t.Helper()
	if err := SealRecord(record); err != nil {
		t.Fatalf("SealRecord: %v", err)
	}
	return record
}

func TestSealAndVerify(t *testing.T) {
	record := seal(t, &VersionRecord{
		Version:       1,
		ParentVersion: 0,
		Kind:          KindInitial,
		Snapshot: Snapshot{
			{Section: "p", PType: "p", Rules: [][]string{{"alice", "data1", "read"}}},
		},
	})

	if err := VerifyRecord(record); err != nil {
		t.Fatalf("VerifyRecord: %v", err)
	}

	record.Snapshot[0].Rules[0][0] = "mallory"
	err := VerifyRecord(record)
	if err == nil {
		t.Fatalf("VerifyRecord accepted a modified record")
	}
	if !IsIntegrity(err) {
		t.Fatalf("error = %v, want an integrity error", err)
	}
	if version, ok := VersionOf(err); !ok || version != 1 {
		t.Errorf("VersionOf = %d, %v; want 1, true", version, ok)
	}
}

func TestChecksumIndependentOfNilSlices(t *testing.T) {
	a := seal(t, &VersionRecord{Version: 1, Kind: KindInitial})
	b := seal(t, &VersionRecord{Version: 1, Kind: KindInitial, Changes: []Change{}, Snapshot: Snapshot{}})
	if a.Checksum != b.Checksum {
		t.Fatalf("checksums differ for equivalent records: %s != %s", a.Checksum, b.Checksum)
	}
}

func TestDiffSnapshots(t *testing.T) {
	before := Snapshot{{Section: "p", PType: "p", Rules: [][]string{
		{"alice", "data1", "read"},
		{"bob", "data2", "write"},
		{"carol", "data3", "read"},
	}}}
	after := Snapshot{{Section: "p", PType: "p", Rules: [][]string{
		{"carol", "data3", "read"},
		{"bob", "data2", "read"},
		{"dave", "data4", "read"},
	}}}

	changes := DiffSnapshots(before, after, nil)
	var added, removed, updated int
	for _, change := range changes {
		switch change.Action {
		case ActionAdd:
			added++
		case ActionRemove:
			removed++
		case ActionUpdate:
			updated++
		}
	}
	if added != 1 || removed != 1 || updated != 1 {
		t.Fatalf("changes = %+v, want 1 add, 1 remove, 1 update", changes)
	}
}

func TestDiffSnapshotsExplicitPairWins(t *testing.T) {
	before := Snapshot{{Section: "p", PType: "p", Rules: [][]string{{"alice", "data1", "read"}}}}
	after := Snapshot{{Section: "p", PType: "p", Rules: [][]string{{"bob", "data2", "write"}}}}

	changes := DiffSnapshots(before, after, []UpdatePair{{
		Section: "p",
		PType:   "p",
		OldRule: []string{"alice", "data1", "read"},
		NewRule: []string{"bob", "data2", "write"},
	}})
	if len(changes) != 1 || changes[0].Action != ActionUpdate {
		t.Fatalf("changes = %+v, want one update", changes)
	}
}

func TestFileStoreNeverOverwrites(t *testing.T) {
	dir := t.TempDir()
	store := NewFileStore(dir)

	record := seal(t, &VersionRecord{Version: 1, Kind: KindInitial})
	if err := store.Append(record); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if err := store.Append(record); err == nil {
		t.Fatalf("Append overwrote an existing version")
	}

	path := filepath.Join(dir, "00000000000000000001.json")
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(original) != mustMarshal(t, record) {
		t.Fatalf("the stored record was modified")
	}
}

func TestFileStoreReportsCorruptVersion(t *testing.T) {
	dir := t.TempDir()
	store := NewFileStore(dir)
	if err := store.Append(seal(t, &VersionRecord{Version: 1, Kind: KindInitial})); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if err := store.Append(seal(t, &VersionRecord{Version: 2, ParentVersion: 1, Kind: KindChange})); err != nil {
		t.Fatalf("Append: %v", err)
	}

	path := filepath.Join(dir, "00000000000000000002.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, err := store.Read(2)
	if err == nil || !IsCorrupt(err) {
		t.Fatalf("Read(2) error = %v, want a corrupt version error", err)
	}
	if version, _ := VersionOf(err); version != 2 {
		t.Errorf("damaged version = %d, want 2", version)
	}
	if _, err := store.Read(1); err != nil {
		t.Errorf("Read(1) failed: %v", err)
	}
}

func mustMarshal(t *testing.T, record *VersionRecord) string {
	t.Helper()
	store := NewFileStore(t.TempDir())
	dir := store.Dir()
	if err := store.Append(record); err != nil {
		t.Fatalf("Append: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "00000000000000000001.json"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return string(data)
}
