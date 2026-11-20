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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/casbin/casbin/v3/persist/policyhistory"
)

func newHistoryTestEnforcer(t *testing.T) *Enforcer {
	t.Helper()
	e, err := NewEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")
	if err != nil {
		t.Fatalf("NewEnforcer: %v", err)
	}
	return e
}

func enableHistory(t *testing.T, e *Enforcer, options ...PolicyHistoryOptions) *PolicyHistory {
	t.Helper()
	var opt PolicyHistoryOptions
	if len(options) != 0 {
		opt = options[0]
	}
	if opt.Store == nil {
		opt.Store = policyhistory.NewMemoryStore()
	}
	h, err := e.EnablePolicyHistoryWithOptions(opt)
	if err != nil {
		t.Fatalf("EnablePolicyHistoryWithOptions: %v", err)
	}
	return h
}

// TestPolicyHistoryChangeRecords covers requirement V.1: each policy mutation
// appends one version record naming the added, removed and modified rules.
func TestPolicyHistoryChangeRecords(t *testing.T) {
	e := newHistoryTestEnforcer(t)
	h := enableHistory(t, e, PolicyHistoryOptions{Actor: "ops@example.com"})

	versions, err := h.Versions()
	if err != nil {
		t.Fatalf("Versions: %v", err)
	}
	if len(versions) != 1 || versions[0] != 1 {
		t.Fatalf("initial versions = %v, want [1]", versions)
	}

	if ok, err := e.AddPolicy("carol", "data3", "read"); err != nil || !ok {
		t.Fatalf("AddPolicy = %v, %v", ok, err)
	}
	if ok, err := e.RemovePolicy("bob", "data2", "write"); err != nil || !ok {
		t.Fatalf("RemovePolicy = %v, %v", ok, err)
	}
	if ok, err := e.UpdatePolicy([]string{"alice", "data1", "read"}, []string{"alice", "data1", "write"}); err != nil || !ok {
		t.Fatalf("UpdatePolicy = %v, %v", ok, err)
	}

	versions, err = h.Versions()
	if err != nil {
		t.Fatalf("Versions: %v", err)
	}
	if len(versions) != 4 {
		t.Fatalf("versions = %v, want 4 entries", versions)
	}
	for i, version := range versions {
		if version != uint64(i+1) {
			t.Fatalf("versions = %v, want 1..%d", versions, len(versions))
		}
	}

	assertChanges := func(version uint64, action policyhistory.Action, rule []string) {
		t.Helper()
		record, err := h.Record(version)
		if err != nil {
			t.Fatalf("Record(%d): %v", version, err)
		}
		if record.Actor != "ops@example.com" {
			t.Errorf("version %d actor = %q, want ops@example.com", version, record.Actor)
		}
		if record.CreatedAt.IsZero() {
			t.Errorf("version %d has no timestamp", version)
		}
		for _, change := range record.Changes {
			if change.Action != action {
				continue
			}
			candidate := change.NewRule
			if action == policyhistory.ActionRemove {
				candidate = change.OldRule
			}
			if utilArrayEquals(candidate, rule) {
				return
			}
		}
		t.Errorf("version %d has no %s change for %v: %+v", version, action, rule, record.Changes)
	}
	assertChanges(2, policyhistory.ActionAdd, []string{"carol", "data3", "read"})
	assertChanges(3, policyhistory.ActionRemove, []string{"bob", "data2", "write"})
	assertChanges(4, policyhistory.ActionUpdate, []string{"alice", "data1", "write"})

	record, err := h.Record(4)
	if err != nil {
		t.Fatalf("Record(4): %v", err)
	}
	if len(record.Changes) != 1 || record.Changes[0].Action != policyhistory.ActionUpdate {
		t.Fatalf("version 4 changes = %+v, want one update", record.Changes)
	}
	if !utilArrayEquals(record.Changes[0].OldRule, []string{"alice", "data1", "read"}) {
		t.Errorf("version 4 old rule = %v", record.Changes[0].OldRule)
	}
	if !utilArrayEquals(record.Changes[0].NewRule, []string{"alice", "data1", "write"}) {
		t.Errorf("version 4 new rule = %v", record.Changes[0].NewRule)
	}
}

// TestPolicyHistoryNoOpMutationRecordsNothing checks that a mutation that did
// not change anything does not consume a version number.
func TestPolicyHistoryNoOpMutationRecordsNothing(t *testing.T) {
	e := newHistoryTestEnforcer(t)
	h := enableHistory(t, e)

	if ok, err := e.AddPolicy("alice", "data1", "read"); err != nil || ok {
		t.Fatalf("duplicate AddPolicy = %v, %v; want false, nil", ok, err)
	}
	if ok, err := e.UpdatePolicy([]string{"alice", "data1", "read"}, []string{"alice", "data1", "read"}); err != nil || !ok {
		t.Fatalf("self UpdatePolicy = %v, %v; want true, nil", ok, err)
	}
	versions, err := h.Versions()
	if err != nil {
		t.Fatalf("Versions: %v", err)
	}
	if len(versions) != 1 {
		t.Fatalf("versions = %v, want only the initial version", versions)
	}
}

// TestPolicyHistorySnapshotAndDiff covers requirements I.2 and I.5.
func TestPolicyHistorySnapshotAndDiff(t *testing.T) {
	e := newHistoryTestEnforcer(t)
	h := enableHistory(t, e)

	if _, err := e.AddPolicy("carol", "data3", "read"); err != nil {
		t.Fatalf("AddPolicy: %v", err)
	}
	if _, err := e.RemovePolicy("bob", "data2", "write"); err != nil {
		t.Fatalf("RemovePolicy: %v", err)
	}
	if _, err := e.UpdatePolicy([]string{"alice", "data1", "read"}, []string{"alice", "data1", "list"}); err != nil {
		t.Fatalf("UpdatePolicy: %v", err)
	}

	snapshot, err := h.Snapshot(1)
	if err != nil {
		t.Fatalf("Snapshot(1): %v", err)
	}
	rules := snapshotRules(snapshot, "p", "p")
	if !containsRule(rules, []string{"alice", "data1", "read"}) || !containsRule(rules, []string{"bob", "data2", "write"}) {
		t.Fatalf("version 1 snapshot = %v", rules)
	}

	diff, err := h.Diff(1, 4)
	if err != nil {
		t.Fatalf("Diff(1,4): %v", err)
	}
	if len(diff.Added) != 1 || !utilArrayEquals(diff.Added[0].NewRule, []string{"carol", "data3", "read"}) {
		t.Errorf("added = %+v", diff.Added)
	}
	if len(diff.Removed) != 1 || !utilArrayEquals(diff.Removed[0].OldRule, []string{"bob", "data2", "write"}) {
		t.Errorf("removed = %+v", diff.Removed)
	}
	if len(diff.Modified) != 1 || !utilArrayEquals(diff.Modified[0].OldRule, []string{"alice", "data1", "read"}) ||
		!utilArrayEquals(diff.Modified[0].NewRule, []string{"alice", "data1", "list"}) {
		t.Errorf("modified = %+v", diff.Modified)
	}
}

// TestPolicyHistoryReplayMatchesLiveEnforce covers requirements I.4 and V.4: a
// historical version recomputes the same verdicts that Enforce produced then.
func TestPolicyHistoryReplayMatchesLiveEnforce(t *testing.T) {
	e := newHistoryTestEnforcer(t)
	h := enableHistory(t, e)

	requests := [][]interface{}{
		{"alice", "data1", "read"},
		{"bob", "data2", "write"},
		{"carol", "data3", "read"},
		{"alice", "data1", "write"},
	}
	live := make([]bool, len(requests))
	for i, request := range requests {
		allowed, err := e.Enforce(request...)
		if err != nil {
			t.Fatalf("Enforce: %v", err)
		}
		live[i] = allowed
	}

	// Change the policy after the decisions were taken.
	if _, err := e.UpdatePolicy([]string{"bob", "data2", "write"}, []string{"bob", "data2", "read"}); err != nil {
		t.Fatalf("UpdatePolicy: %v", err)
	}
	if _, err := e.AddPolicy("carol", "data3", "read"); err != nil {
		t.Fatalf("AddPolicy: %v", err)
	}

	results, err := h.Replay(1, requests...)
	if err != nil {
		t.Fatalf("Replay(1): %v", err)
	}
	if len(results) != len(requests) {
		t.Fatalf("Replay returned %d results, want %d", len(results), len(requests))
	}
	for i, result := range results {
		if result.Allowed != live[i] {
			t.Errorf("request %v replayed as %v, live decision was %v", result.Request, result.Allowed, live[i])
		}
		if result.Version != 1 {
			t.Errorf("result version = %d, want 1", result.Version)
		}
	}

	// The current version replays to the current live decisions.
	latest, err := h.Latest()
	if err != nil {
		t.Fatalf("Latest: %v", err)
	}
	replayedLatest, err := h.Replay(latest, requests...)
	if err != nil {
		t.Fatalf("Replay(%d): %v", latest, err)
	}
	for _, result := range replayedLatest {
		allowed, err := e.Enforce(result.Request...)
		if err != nil {
			t.Fatalf("Enforce: %v", err)
		}
		if result.Allowed != allowed {
			t.Errorf("request %v replayed as %v, current Enforce is %v", result.Request, result.Allowed, allowed)
		}
	}
}

// TestPolicyHistoryAttribution covers requirement I.3: a decision names the
// version and the rules that produced it.
func TestPolicyHistoryAttribution(t *testing.T) {
	e := newHistoryTestEnforcer(t)
	h := enableHistory(t, e)
	if _, err := e.AddPolicy("carol", "data3", "read"); err != nil {
		t.Fatalf("AddPolicy: %v", err)
	}

	attributor := NewAttributor(e)
	attribution, err := attributor.Evaluate("carol", "data3", "read")
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	latest, err := h.Latest()
	if err != nil {
		t.Fatalf("Latest: %v", err)
	}
	if attribution.Version != latest {
		t.Errorf("attributed version = %d, want %d", attribution.Version, latest)
	}
	if !attribution.Allowed {
		t.Fatalf("expected the request to be allowed")
	}
	if len(attribution.MatchedRules) != 1 || !utilArrayEquals(attribution.MatchedRules[0].Rule, []string{"carol", "data3", "read"}) {
		t.Errorf("matched rules = %+v", attribution.MatchedRules)
	}

	denied, err := attributor.Evaluate("dave", "data9", "read")
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if denied.Allowed {
		t.Fatalf("expected the request to be denied")
	}
	if len(denied.MatchedRules) != 0 {
		t.Errorf("denied request matched rules = %+v", denied.MatchedRules)
	}
}

// TestPolicyHistoryConcurrentWrites covers requirement V.2: concurrent policy
// changes produce no duplicate version and lose no record.
func TestPolicyHistoryConcurrentWrites(t *testing.T) {
	e := newHistoryTestEnforcer(t)
	h := enableHistory(t, e)

	const workers = 8
	const perWorker = 5

	var wg sync.WaitGroup
	errs := make(chan error, workers*perWorker)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				rule := []string{fmt.Sprintf("user-%d-%d", worker, i), "data", "read"}
				if _, err := e.AddPolicy(rule); err != nil {
					errs <- err
					return
				}
			}
		}(w)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent AddPolicy: %v", err)
	}

	versions, err := h.Versions()
	if err != nil {
		t.Fatalf("Versions: %v", err)
	}
	want := workers*perWorker + 1
	if len(versions) != want {
		t.Fatalf("recorded %d versions, want %d", len(versions), want)
	}
	seen := make(map[uint64]bool, len(versions))
	for i, version := range versions {
		if version != uint64(i+1) {
			t.Fatalf("version sequence = %v", versions)
		}
		if seen[version] {
			t.Fatalf("duplicate version %d", version)
		}
		seen[version] = true
	}

	// Every concurrent addition is in the final version's snapshot.
	snapshot, err := h.Snapshot(versions[len(versions)-1])
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	rules := snapshotRules(snapshot, "p", "p")
	for w := 0; w < workers; w++ {
		for i := 0; i < perWorker; i++ {
			rule := []string{fmt.Sprintf("user-%d-%d", w, i), "data", "read"}
			if !containsRule(rules, rule) {
				t.Errorf("final version is missing %v", rule)
			}
		}
	}

	audit, err := h.Audit()
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if !audit.OK() {
		t.Fatalf("audit reported issues: %v", audit.Err())
	}
}

// TestPolicyHistoryDetectsTampering covers requirement V.3: a hand-edited
// version is detected and the damaged version is named.
func TestPolicyHistoryDetectsTampering(t *testing.T) {
	dir := t.TempDir()
	e := newHistoryTestEnforcer(t)
	h := enableHistory(t, e, PolicyHistoryOptions{Store: policyhistory.NewFileStore(dir)})

	if _, err := e.AddPolicy("carol", "data3", "read"); err != nil {
		t.Fatalf("AddPolicy: %v", err)
	}
	if _, err := e.AddPolicy("dave", "data4", "read"); err != nil {
		t.Fatalf("AddPolicy: %v", err)
	}

	// Tamper with version 2 on disk, leaving a valid JSON document behind so
	// the integrity check, not JSON decoding, has to catch it.
	path := filepath.Join(dir, fmt.Sprintf("%020d.json", 2))
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read version file: %v", err)
	}
	tampered := replaceAll(string(data), `"carol"`, `"mallory"`)
	if tampered == string(data) {
		t.Fatalf("test did not change the version file")
	}
	if err := os.WriteFile(path, []byte(tampered), 0o644); err != nil {
		t.Fatalf("write tampered version: %v", err)
	}

	audit, err := h.Audit()
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if audit.OK() {
		t.Fatalf("tampering was not detected")
	}

	var integrityErr *policyhistory.VersionError
	if !errors.As(audit.Issues[0], &integrityErr) {
		t.Fatalf("issue = %v, want a *policyhistory.VersionError", audit.Issues[0])
	}
	if integrityErr.Version != 2 {
		t.Errorf("damaged version = %d, want 2", integrityErr.Version)
	}
	if !policyhistory.IsIntegrity(audit.Issues[0]) {
		t.Errorf("issue kind = %v, want integrity", integrityErr.Kind)
	}
	if version, ok := policyhistory.VersionOf(audit.Issues[0]); !ok || version != 2 {
		t.Errorf("VersionOf = %d, %v; want 2, true", version, ok)
	}

	// The other versions stay readable.
	if _, err := h.Record(1); err != nil {
		t.Errorf("version 1 became unreadable: %v", err)
	}
	if _, err := h.Record(3); err != nil {
		t.Errorf("version 3 became unreadable: %v", err)
	}
	if err := h.Verify(2); err == nil {
		t.Errorf("Verify(2) accepted the tampered record")
	}
}

// TestPolicyHistoryDetectsCorruptVersion covers requirement III.1: a truncated
// version file is reported by number and the rest of the history still reads.
func TestPolicyHistoryDetectsCorruptVersion(t *testing.T) {
	dir := t.TempDir()
	e := newHistoryTestEnforcer(t)
	h := enableHistory(t, e, PolicyHistoryOptions{Store: policyhistory.NewFileStore(dir)})

	if _, err := e.AddPolicy("carol", "data3", "read"); err != nil {
		t.Fatalf("AddPolicy: %v", err)
	}
	if _, err := e.AddPolicy("dave", "data4", "read"); err != nil {
		t.Fatalf("AddPolicy: %v", err)
	}

	path := filepath.Join(dir, fmt.Sprintf("%020d.json", 3))
	if err := os.WriteFile(path, []byte(`{"version": 3, "snapsh`), 0o644); err != nil {
		t.Fatalf("truncate version: %v", err)
	}

	audit, err := h.Audit()
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if audit.OK() {
		t.Fatalf("corruption was not detected")
	}
	if !policyhistory.IsCorrupt(audit.Issues[0]) {
		t.Fatalf("issue = %v, want a corrupt *policyhistory.VersionError", audit.Issues[0])
	}
	if version, _ := policyhistory.VersionOf(audit.Issues[0]); version != 3 {
		t.Errorf("damaged version = %d, want 3", version)
	}

	if _, err := h.Record(3); err == nil || !policyhistory.IsCorrupt(err) {
		t.Errorf("Record(3) error = %v, want a corrupt version error", err)
	}
	for _, version := range []uint64{1, 2} {
		if _, err := h.Record(version); err != nil {
			t.Errorf("Record(%d) failed although only version 3 is damaged: %v", version, err)
		}
	}
}

// TestPolicyHistoryRejectsSequenceGap covers requirement III.2: once the stored
// sequence has a gap, no further version is written and the break is named.
func TestPolicyHistoryRejectsSequenceGap(t *testing.T) {
	store := policyhistory.NewMemoryStore()
	e := newHistoryTestEnforcer(t)
	h := enableHistory(t, e, PolicyHistoryOptions{Store: store})

	if _, err := e.AddPolicy("carol", "data3", "read"); err != nil {
		t.Fatalf("AddPolicy: %v", err)
	}
	if _, err := e.AddPolicy("dave", "data4", "read"); err != nil {
		t.Fatalf("AddPolicy: %v", err)
	}

	// Simulate a lost record: hide version 2 while version 3 stays present.
	gapStore := &droppingStore{Store: store, drop: 2}
	// Swap the history onto a store with a gap.
	h.store = gapStore

	if _, err := e.AddPolicy("erin", "data5", "read"); err == nil {
		t.Fatalf("AddPolicy succeeded although the history has a gap")
	} else {
		var versionErr *policyhistory.VersionError
		if !errors.As(err, &versionErr) || versionErr.Kind != policyhistory.KindSequence {
			t.Fatalf("error = %v, want a sequence error", err)
		}
		if versionErr.Version != 3 {
			t.Errorf("break reported at version %d, want 3", versionErr.Version)
		}
	}

	// The rejected change was rolled back and was not recorded.
	if allowed, err := e.Enforce("erin", "data5", "read"); err != nil || allowed {
		t.Fatalf("policy change survived a rejected history append: allowed=%v err=%v", allowed, err)
	}
	versions, err := gapStore.Versions()
	if err != nil {
		t.Fatalf("Versions: %v", err)
	}
	if len(versions) != 2 {
		t.Fatalf("versions = %v, want no new record", versions)
	}
}

// TestPolicyHistoryRollsBackWhenStorageFails covers requirement III.3: when the
// history cannot be written, the policy change fails and is rolled back, so the
// two never diverge.
func TestPolicyHistoryRollsBackWhenStorageFails(t *testing.T) {
	store := policyhistory.NewMemoryStore()
	e := newHistoryTestEnforcer(t)
	h := enableHistory(t, e, PolicyHistoryOptions{Store: store})

	if _, err := e.AddPolicy("carol", "data3", "read"); err != nil {
		t.Fatalf("AddPolicy: %v", err)
	}

	failing := &failingStore{Store: store, failFrom: 3}
	h.store = failing

	ok, err := e.AddPolicy("dave", "data4", "read")
	if err == nil {
		t.Fatalf("AddPolicy succeeded although history storage failed")
	}
	if ok {
		t.Fatalf("AddPolicy reported success although history storage failed")
	}
	if allowed, err := e.Enforce("dave", "data4", "read"); err != nil || allowed {
		t.Fatalf("policy change was not rolled back: allowed=%v err=%v", allowed, err)
	}
	if allowed, err := e.Enforce("carol", "data3", "read"); err != nil || !allowed {
		t.Fatalf("rollback removed an earlier rule: allowed=%v err=%v", allowed, err)
	}

	versions, err := store.Versions()
	if err != nil {
		t.Fatalf("Versions: %v", err)
	}
	if len(versions) != 2 {
		t.Fatalf("versions = %v, want the two successful versions", versions)
	}
}

// TestPolicyHistoryKeepsEnforceUnchanged covers requirement II.4: enabling the
// history does not change the decision, its shape or the watcher flow.
func TestPolicyHistoryKeepsEnforceUnchanged(t *testing.T) {
	e := newHistoryTestEnforcer(t)
	watcher := &countingWatcher{}
	if err := e.SetWatcher(watcher); err != nil {
		t.Fatalf("SetWatcher: %v", err)
	}

	before, beforeExplain, err := e.EnforceEx("alice", "data1", "read")
	if err != nil {
		t.Fatalf("EnforceEx: %v", err)
	}

	h := enableHistory(t, e)
	if h == nil {
		t.Fatalf("history was not enabled")
	}

	after, afterExplain, err := e.EnforceEx("alice", "data1", "read")
	if err != nil {
		t.Fatalf("EnforceEx: %v", err)
	}
	if before != after {
		t.Errorf("decision changed after enabling history: %v -> %v", before, after)
	}
	if !utilArrayEquals(beforeExplain, afterExplain) {
		t.Errorf("explain changed after enabling history: %v -> %v", beforeExplain, afterExplain)
	}

	// A well-behaved history does not swallow or duplicate watcher calls.
	watcher.calls = 0
	if _, err := e.AddPolicy("carol", "data3", "read"); err != nil {
		t.Fatalf("AddPolicy: %v", err)
	}
	if watcher.calls != 1 {
		t.Errorf("watcher calls = %d, want 1", watcher.calls)
	}

	// History is a side channel: it must not appear in the decision cache key
	// inputs or the policy content returned by the management API.
	policy, err := e.GetPolicy()
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	if !containsRule(policy, []string{"carol", "data3", "read"}) {
		t.Errorf("GetPolicy = %v", policy)
	}
}

// TestPolicyHistoryFileStoreRoundTrip checks the file store's append-only
// behaviour and per-version readability.
func TestPolicyHistoryFileStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	e := newHistoryTestEnforcer(t)
	h := enableHistory(t, e, PolicyHistoryOptions{Store: policyhistory.NewFileStore(dir)})

	if _, err := e.AddPolicy("carol", "data3", "read"); err != nil {
		t.Fatalf("AddPolicy: %v", err)
	}

	versions, err := h.Versions()
	if err != nil {
		t.Fatalf("Versions: %v", err)
	}
	if len(versions) != 2 {
		t.Fatalf("versions = %v", versions)
	}

	// Reopening the same directory discovers the same history.
	reopened := policyhistory.NewFileStore(dir)
	reopenedVersions, err := reopened.Versions()
	if err != nil {
		t.Fatalf("Versions: %v", err)
	}
	if len(reopenedVersions) != len(versions) {
		t.Fatalf("reopened versions = %v, want %v", reopenedVersions, versions)
	}
	if err := reopened.Append(&policyhistory.VersionRecord{Version: versions[0]}); err == nil {
		t.Fatalf("Append overwrote an existing version")
	}
}

// TestPolicyHistoryDetectsRewrittenVersion covers the harder tampering case:
// a record is edited and its checksum recomputed, so only the next record's
// link can catch it. The rewritten version must be the one reported.
func TestPolicyHistoryDetectsRewrittenVersion(t *testing.T) {
	e := newHistoryTestEnforcer(t)
	store := policyhistory.NewMemoryStore()
	h := enableHistory(t, e, PolicyHistoryOptions{Store: store})

	if _, err := e.AddPolicy("carol", "data3", "read"); err != nil {
		t.Fatalf("AddPolicy: %v", err)
	}
	if _, err := e.AddPolicy("dave", "data4", "read"); err != nil {
		t.Fatalf("AddPolicy: %v", err)
	}

	h.store = &rewritingStore{Store: store, version: 2}

	audit, err := h.Audit()
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if audit.OK() {
		t.Fatalf("a rewritten version was not detected")
	}
	if len(audit.Issues) != 1 {
		t.Fatalf("issues = %v, want one issue", audit.Issues)
	}
	if version, _ := policyhistory.VersionOf(audit.Issues[0]); version != 2 {
		t.Errorf("reported version = %d, want the rewritten version 2", version)
	}
	if !policyhistory.IsIntegrity(audit.Issues[0]) {
		t.Errorf("issue = %v, want an integrity error", audit.Issues[0])
	}
	if !auditContains(audit.Versions, 3) {
		t.Errorf("intact version 3 is missing from the readable versions: %v", audit.Versions)
	}
}

// TestPolicyHistoryAuditReportsDamagedVersionOnce checks that an unreadable
// version is named exactly once even though the next record's chain link also
// points at it.
func TestPolicyHistoryAuditReportsDamagedVersionOnce(t *testing.T) {
	e := newHistoryTestEnforcer(t)
	store := policyhistory.NewMemoryStore()
	h := enableHistory(t, e, PolicyHistoryOptions{Store: store})

	for _, rule := range [][]string{{"carol", "data3", "read"}, {"dave", "data4", "read"}, {"erin", "data5", "read"}} {
		if _, err := e.AddPolicy(rule); err != nil {
			t.Fatalf("AddPolicy: %v", err)
		}
	}

	h.store = &droppingStore{Store: store, drop: 2}

	audit, err := h.Audit()
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if audit.OK() {
		t.Fatalf("the missing version was not reported")
	}
	if len(audit.Issues) != 1 {
		t.Fatalf("issues = %v, want exactly one issue", audit.Issues)
	}
	if !policyhistory.IsCorrupt(audit.Issues[0]) && !policyhistory.IsSequence(audit.Issues[0]) {
		t.Errorf("issue = %v, want a corrupt or sequence error naming version 2", audit.Issues[0])
	}
	if version, _ := policyhistory.VersionOf(audit.Issues[0]); version != 2 {
		t.Errorf("reported version = %d, want 2", version)
	}

	// The remaining versions stay readable.
	for _, version := range []uint64{1, 3, 4} {
		if _, err := h.Record(version); err != nil {
			t.Errorf("Record(%d) failed although only version 2 is damaged: %v", version, err)
		}
	}
}

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

type countingWatcher struct {
	calls int
}

func (w *countingWatcher) SetUpdateCallback(func(string)) error { return nil }
func (w *countingWatcher) Update() error                        { w.calls++; return nil }
func (w *countingWatcher) Close()                               {}

// droppingStore hides one version from the sequence to simulate a lost record.
type droppingStore struct {
	policyhistory.Store
	drop uint64
}

func (s *droppingStore) Versions() ([]uint64, error) {
	versions, err := s.Store.Versions()
	if err != nil {
		return nil, err
	}
	filtered := make([]uint64, 0, len(versions))
	for _, version := range versions {
		if version != s.drop {
			filtered = append(filtered, version)
		}
	}
	return filtered, nil
}

// rewritingStore edits one record and recomputes its checksum, leaving only
// the next record's link to detect the rewrite.
type rewritingStore struct {
	policyhistory.Store
	version uint64
}

func (s *rewritingStore) Read(version uint64) (*policyhistory.VersionRecord, error) {
	record, err := s.Store.Read(version)
	if err != nil {
		return nil, err
	}
	if version == s.version {
		record.Snapshot[0].Rules[0][0] = "mallory"
		if err := policyhistory.SealRecord(record); err != nil {
			return nil, err
		}
	}
	return record, nil
}

func auditContains(versions []uint64, want uint64) bool {
	for _, version := range versions {
		if version == want {
			return true
		}
	}
	return false
}

// failingStore rejects appends from a given version on.
type failingStore struct {
	policyhistory.Store
	failFrom uint64
}

func (s *failingStore) Append(record *policyhistory.VersionRecord) error {
	if record.Version >= s.failFrom {
		return errors.New("simulated storage outage")
	}
	return s.Store.Append(record)
}

func utilArrayEquals(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func replaceAll(s, old, new string) string {
	for {
		index := indexOf(s, old)
		if index < 0 {
			return s
		}
		s = s[:index] + new + s[index+len(old):]
	}
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func snapshotRules(snapshot policyhistory.Snapshot, section, ptype string) [][]string {
	for _, set := range snapshot {
		if set.Section == section && set.PType == ptype {
			return set.Rules
		}
	}
	return nil
}

func containsRule(rules [][]string, rule []string) bool {
	for _, candidate := range rules {
		if utilArrayEquals(candidate, rule) {
			return true
		}
	}
	return false
}
