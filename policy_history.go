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
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/casbin/casbin/v3/model"
	"github.com/casbin/casbin/v3/persist"
	"github.com/casbin/casbin/v3/persist/policyhistory"
	"github.com/casbin/casbin/v3/util"
)

// PolicyHistoryOptions configures a PolicyHistory.
type PolicyHistoryOptions struct {
	// Store is the append-only storage. When nil an in-memory store is used.
	Store policyhistory.Store
	// Actor is recorded on every version. It identifies who made the change.
	Actor string
}

// PolicyHistory records an append-only, checksummed history of policy changes
// and can replay a historical version. It is a side channel: enabling it does
// not change Enforce behaviour, return values or watcher notification
// semantics. Enforcement never reads the history.
type PolicyHistory struct {
	enforcer *Enforcer
	store    policyhistory.Store
	// mutex serializes every policy mutation together with its version
	// record, so that version numbers cannot repeat and no record is lost.
	mutex sync.Mutex
}

// EnablePolicyHistory starts recording policy history for the enforcer. The
// current policy is recorded as version 1, and every subsequent policy change
// made through the management API appends one version.
func (e *Enforcer) EnablePolicyHistory(store policyhistory.Store) (*PolicyHistory, error) {
	return e.EnablePolicyHistoryWithOptions(PolicyHistoryOptions{Store: store})
}

// EnablePolicyHistoryWithOptions is EnablePolicyHistory with explicit options.
func (e *Enforcer) EnablePolicyHistoryWithOptions(options PolicyHistoryOptions) (*PolicyHistory, error) {
	store := options.Store
	if store == nil {
		store = policyhistory.NewMemoryStore()
	}

	history := &PolicyHistory{enforcer: e, store: store}
	history.mutex.Lock()
	err := history.reconcile(policyhistory.KindInitial, nil, options.Actor, "history enabled")
	history.mutex.Unlock()
	if err != nil {
		return nil, err
	}

	e.historyMutex.Lock()
	e.history = history
	e.historyActor = options.Actor
	e.historyMutex.Unlock()
	return history, nil
}

// DisablePolicyHistory stops recording policy history and returns the history
// that was recording. Stored records are left untouched.
func (e *Enforcer) DisablePolicyHistory() *PolicyHistory {
	e.historyMutex.Lock()
	defer e.historyMutex.Unlock()
	previous := e.history
	e.history = nil
	return previous
}

// History returns the enabled policy history, or nil when it is disabled.
func (e *Enforcer) History() *PolicyHistory {
	e.historyMutex.RLock()
	defer e.historyMutex.RUnlock()
	return e.history
}

// SetPolicyHistoryActor sets the actor recorded on subsequent versions.
func (e *Enforcer) SetPolicyHistoryActor(actor string) {
	e.historyMutex.Lock()
	defer e.historyMutex.Unlock()
	e.historyActor = actor
}

// Store returns the underlying storage.
func (h *PolicyHistory) Store() policyhistory.Store {
	return h.store
}

// Versions lists the recorded versions from oldest to newest.
func (h *PolicyHistory) Versions() ([]uint64, error) {
	versions, err := h.store.Versions()
	if err != nil {
		return nil, err
	}
	sort.Slice(versions, func(i, j int) bool { return versions[i] < versions[j] })
	if err := checkSequence(versions); err != nil {
		return nil, err
	}
	return versions, nil
}

// Latest returns the newest recorded version, or 0 when nothing was recorded.
func (h *PolicyHistory) Latest() (uint64, error) {
	versions, err := h.Versions()
	if err != nil {
		return 0, err
	}
	if len(versions) == 0 {
		return 0, nil
	}
	return versions[len(versions)-1], nil
}

// Record returns a single version record after verifying its checksum and its
// link to the previous version. Only errors about this version, or about its
// parent, are returned: a damaged unrelated version never blocks reading.
func (h *PolicyHistory) Record(version uint64) (*policyhistory.VersionRecord, error) {
	record, err := h.store.Read(version)
	if err != nil {
		return nil, err
	}
	if err := verifyRecordChain(h.store, record); err != nil {
		return nil, err
	}
	return record, nil
}

// Snapshot returns the complete policy content of a version.
func (h *PolicyHistory) Snapshot(version uint64) (policyhistory.Snapshot, error) {
	record, err := h.Record(version)
	if err != nil {
		return nil, err
	}
	return policyhistory.CloneSnapshot(record.Snapshot), nil
}

// PolicyDiff is the difference between two versions. Added, removed and
// modified rules are listed separately.
type PolicyDiff struct {
	FromVersion uint64
	ToVersion   uint64
	Added       []policyhistory.Change
	Removed     []policyhistory.Change
	Modified    []policyhistory.Change
}

// Diff returns the rule-level differences needed to go from fromVersion to
// toVersion.
func (h *PolicyHistory) Diff(fromVersion, toVersion uint64) (*PolicyDiff, error) {
	from, err := h.Record(fromVersion)
	if err != nil {
		return nil, err
	}
	to, err := h.Record(toVersion)
	if err != nil {
		return nil, err
	}

	changes := policyhistory.DiffSnapshots(from.Snapshot, to.Snapshot, nil)
	diff := &PolicyDiff{
		FromVersion: fromVersion,
		ToVersion:   toVersion,
		Added:       []policyhistory.Change{},
		Removed:     []policyhistory.Change{},
		Modified:    []policyhistory.Change{},
	}
	for _, change := range changes {
		switch change.Action {
		case policyhistory.ActionAdd:
			diff.Added = append(diff.Added, change)
		case policyhistory.ActionRemove:
			diff.Removed = append(diff.Removed, change)
		default:
			diff.Modified = append(diff.Modified, change)
		}
	}
	return diff, nil
}

// ReplayResult pairs a request with the verdict computed from a version.
type ReplayResult struct {
	Request      []interface{}
	Version      uint64
	Allowed      bool
	MatchedRules []policyhistory.RuleRef
}

// Replay evaluates requests against the policy and model of a historical
// version. The verdict is produced by the same enforcement code path as
// Enforce, so it matches what Enforce returned when that version was current.
func (h *PolicyHistory) Replay(version uint64, requests ...[]interface{}) ([]ReplayResult, error) {
	record, err := h.Record(version)
	if err != nil {
		return nil, err
	}
	replayer, err := h.newReplayer(record)
	if err != nil {
		return nil, err
	}

	results := make([]ReplayResult, 0, len(requests))
	for _, request := range requests {
		verdict, err := replayer.evaluate(replayer.enforcer, request)
		if err != nil {
			return nil, err
		}
		results = append(results, ReplayResult{
			Request:      request,
			Version:      version,
			Allowed:      verdict.Allowed,
			MatchedRules: verdict.MatchedRules,
		})
	}
	return results, nil
}

// HistoryAudit is the result of checking every stored version.
type HistoryAudit struct {
	// Versions are the versions that could be read and verified.
	Versions []uint64
	// Issues holds one error per damaged or tampered version.
	Issues []error
}

// OK reports whether every version is readable and intact.
func (a *HistoryAudit) OK() bool {
	return len(a.Issues) == 0
}

// Err summarizes the issues, or returns nil when there are none.
func (a *HistoryAudit) Err() error {
	if len(a.Issues) == 0 {
		return nil
	}
	corrupt := &policyhistory.CorruptError{Versions: a.Versions}
	for _, issue := range a.Issues {
		var versionErr *policyhistory.VersionError
		if errors.As(issue, &versionErr) {
			corrupt.Damaged = append(corrupt.Damaged, *versionErr)
		}
	}
	return corrupt
}

// Audit reads every version, reports the damaged ones individually and keeps
// the readable ones available. A damaged version never prevents the other
// versions from being read. Each damaged version is reported once, even when
// both its own record and the next record's chain link point at it.
func (h *PolicyHistory) Audit() (*HistoryAudit, error) {
	versions, err := h.store.Versions()
	if err != nil {
		return nil, err
	}
	sort.Slice(versions, func(i, j int) bool { return versions[i] < versions[j] })

	audit := &HistoryAudit{Versions: []uint64{}, Issues: []error{}}
	// A version can be implicated two ways: its own record is unreadable or
	// fails its own checks, or a later intact record says its checksum was
	// rewritten. Collect both, then report each implicated version once.
	issues := make(map[uint64]error)
	order := make([]uint64, 0, len(versions))

	for _, version := range versions {
		record, err := h.store.Read(version)
		if err != nil {
			implicated := version
			var versionErr *policyhistory.VersionError
			if errors.As(err, &versionErr) {
				implicated = versionErr.Version
			}
			if _, exists := issues[implicated]; !exists {
				issues[implicated] = err
				order = append(order, implicated)
			}
			continue
		}

		if err := verifyRecordChain(h.store, record); err != nil {
			var versionErr *policyhistory.VersionError
			implicated := version
			if errors.As(err, &versionErr) {
				implicated = versionErr.Version
			}
			if _, exists := issues[implicated]; !exists {
				issues[implicated] = err
				order = append(order, implicated)
			}
		}
	}

	// Detect a gap in the numbering itself. A version that vanished from the
	// listing must be named even if a chain link happens not to be checked.
	next := uint64(1)
	for _, version := range versions {
		if version > next {
			if _, exists := issues[next]; !exists {
				issues[next] = &policyhistory.VersionError{
					Version: next,
					Kind:    policyhistory.KindSequence,
					Err:     fmt.Errorf("version is missing: expected %d before %d", next, version),
				}
				order = append(order, next)
			}
		}
		if version >= next {
			next = version + 1
		}
	}

	sort.Slice(order, func(i, j int) bool { return order[i] < order[j] })
	for _, version := range order {
		audit.Issues = append(audit.Issues, issues[version])
	}
	for _, version := range versions {
		if _, damaged := issues[version]; damaged {
			continue
		}
		audit.Versions = append(audit.Versions, version)
	}
	return audit, nil
}

// Verify checks the checksum and the chain link of one version.
func (h *PolicyHistory) Verify(version uint64) error {
	record, err := h.store.Read(version)
	if err != nil {
		return err
	}
	return verifyRecordChain(h.store, record)
}

func verifyRecordChain(store policyhistory.Store, record *policyhistory.VersionRecord) error {
	if err := policyhistory.VerifyRecord(record); err != nil {
		return err
	}
	if record.Version == 0 {
		return &policyhistory.VersionError{Version: record.Version, Kind: policyhistory.KindCorrupt, Err: errors.New("version 0 is not valid")}
	}
	if record.ParentVersion != record.Version-1 {
		return &policyhistory.VersionError{
			Version: record.Version,
			Kind:    policyhistory.KindSequence,
			Err:     fmt.Errorf("parent version is %d, expected %d", record.ParentVersion, record.Version-1),
		}
	}
	if record.ParentVersion == 0 {
		return nil
	}

	parent, err := store.Read(record.ParentVersion)
	if err != nil {
		// The parent is the version that is missing, so name it rather than
		// the intact record that points at it.
		return &policyhistory.VersionError{
			Version: record.ParentVersion,
			Kind:    policyhistory.KindSequence,
			Err:     fmt.Errorf("version %d refers to parent version %d, which is unavailable: %v", record.Version, record.ParentVersion, err),
		}
	}
	if parent.Checksum != record.PrevChecksum {
		// The parent's own checksum no longer matches what this version
		// recorded for it, so the parent is the version that was rewritten.
		// Report the parent, not the intact child.
		return &policyhistory.VersionError{
			Version: record.ParentVersion,
			Kind:    policyhistory.KindIntegrity,
			Err:     fmt.Errorf("checksum does not match the value recorded by version %d; the record was rewritten", record.Version),
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Attribution
// ---------------------------------------------------------------------------

// Attribution is the decision of a request together with its provenance.
type Attribution struct {
	Allowed      bool
	Version      uint64
	MatchedRules []policyhistory.RuleRef
}

// Attributor evaluates the current policy while reporting the version and the
// rules that produced the decision. It is separate from Enforce so that the
// enforcement hot path is untouched.
type Attributor struct {
	enforcer *Enforcer
	history  *PolicyHistory
}

// NewAttributor creates an Attributor for the enforcer.
func NewAttributor(e *Enforcer) *Attributor {
	return &Attributor{enforcer: e, history: e.History()}
}

// Evaluate decides a request and reports the policy version and every rule
// that matched the request.
func (a *Attributor) Evaluate(rvals ...interface{}) (Attribution, error) {
	history := a.history
	if history == nil {
		history = a.enforcer.History()
	}
	if history == nil {
		return (&replayer{}).evaluate(a.enforcer, rvals)
	}

	// Hold the history lock so the reported version is the one the decision
	// was made against.
	history.mutex.Lock()
	defer history.mutex.Unlock()

	attribution, err := (&replayer{}).evaluate(a.enforcer, rvals)
	if err != nil {
		return attribution, err
	}
	if latest, err := history.latestRecord(); err == nil && latest != nil {
		attribution.Version = latest.Version
	}
	return attribution, nil
}

// ---------------------------------------------------------------------------
// Recording hooks
// ---------------------------------------------------------------------------

// historySession captures the state before a policy mutation and records the
// resulting version after it. When history is disabled the session is inert.
// While a session is active the mutation and its version record are serialized,
// which keeps version numbers unique and ordered.
type historySession struct {
	history *PolicyHistory
	before  model.Model
	actor   string
}

// beginHistory starts a mutation session. The returned session must be handed
// to e.finishHistory exactly once. It holds PolicyHistory.mutex until then.
func (e *Enforcer) beginHistory() *historySession {
	e.historyMutex.RLock()
	history := e.history
	actor := e.historyActor
	e.historyMutex.RUnlock()
	if history == nil {
		return nil
	}

	history.mutex.Lock()
	return &historySession{history: history, before: e.model.Copy(), actor: actor}
}

// finishHistory records the version for a completed mutation and releases the
// serialization lock. When the record cannot be appended, the policy is rolled
// back, both in memory and in the adapter, so a change can never be effective
// without a matching version. The mutation's named return values are adjusted
// accordingly.
func (e *Enforcer) finishHistory(session *historySession, kind, message string, pairs *[]policyhistory.UpdatePair, ok *bool, err *error) {
	if session == nil {
		return
	}
	defer session.history.mutex.Unlock()

	// A mutation that left the policy unchanged (a no-op, or a failure before
	// anything was written) produces an empty diff and records nothing. If a
	// mutation failed after partially changing the policy, the change is real
	// and is recorded, so the history never disagrees with the live policy.
	var updatePairs []policyhistory.UpdatePair
	if pairs != nil {
		updatePairs = *pairs
	}
	snapshot := e.policySnapshot()
	changes := policyhistory.DiffSnapshots(modelPolicySnapshot(session.before), snapshot, updatePairs)
	if len(changes) == 0 {
		return
	}

	if appendErr := session.history.append(snapshot, changes, kind, message, session.actor); appendErr != nil {
		rollbackErr := e.rollbackPolicy(session.before, changes)
		if ok != nil {
			*ok = false
		}
		if err != nil {
			if rollbackErr != nil {
				*err = fmt.Errorf("policy history append failed, and rolling back the policy also failed: %v (history error: %w)", rollbackErr, appendErr)
			} else {
				*err = fmt.Errorf("policy history append failed, the policy change was rolled back: %w", appendErr)
			}
		}
	}
}

// rollbackPolicy restores the in-memory model and best-effort reverts the
// adapter writes performed by the mutation.
func (e *Enforcer) rollbackPolicy(before model.Model, changes []policyhistory.Change) error {
	e.model = before
	e.resetPolicyCaches()
	if e.autoBuildRoleLinks {
		if err := e.rebuildRoleLinks(e.model); err != nil {
			return err
		}
		if err := e.rebuildConditionalRoleLinks(e.model); err != nil {
			return err
		}
	}
	e.invalidateMatcherMap()

	if !e.shouldPersist() {
		return nil
	}
	return e.revertAdapterChanges(changes)
}

func (e *Enforcer) revertAdapterChanges(changes []policyhistory.Change) error {
	var firstErr error
	record := func(err error) {
		if err == nil || err.Error() == notImplemented {
			return
		}
		if firstErr == nil {
			firstErr = err
		}
	}

	for i := len(changes) - 1; i >= 0; i-- {
		change := changes[i]
		switch change.Action {
		case policyhistory.ActionAdd:
			record(e.adapter.RemovePolicy(change.Section, change.PType, change.NewRule))
		case policyhistory.ActionRemove:
			record(e.adapter.AddPolicy(change.Section, change.PType, change.OldRule))
		case policyhistory.ActionUpdate:
			if updatable, ok := e.adapter.(persist.UpdatableAdapter); ok {
				record(updatable.UpdatePolicy(change.Section, change.PType, change.NewRule, change.OldRule))
			} else {
				record(e.adapter.RemovePolicy(change.Section, change.PType, change.NewRule))
				record(e.adapter.AddPolicy(change.Section, change.PType, change.OldRule))
			}
		}
	}
	return firstErr
}

// recordPolicyReload appends a version when a reload changed the policy.
func (e *Enforcer) recordPolicyReload(before policyhistory.Snapshot) error {
	e.historyMutex.RLock()
	history := e.history
	actor := e.historyActor
	e.historyMutex.RUnlock()
	if history == nil {
		return nil
	}
	history.mutex.Lock()
	defer history.mutex.Unlock()
	return history.reconcile(policyhistory.KindReload, before, actor, "policy reloaded")
}

// recordClearPolicy records the effect of ClearPolicy.
func (e *Enforcer) recordClearPolicy(before policyhistory.Snapshot) error {
	e.historyMutex.RLock()
	history := e.history
	actor := e.historyActor
	e.historyMutex.RUnlock()
	if history == nil {
		return nil
	}
	history.mutex.Lock()
	defer history.mutex.Unlock()
	return history.reconcile(policyhistory.KindChange, before, actor, "policy cleared")
}

// append appends one sealed version. The caller must hold h.mutex.
func (h *PolicyHistory) append(snapshot policyhistory.Snapshot, changes []policyhistory.Change, kind, message, actor string) error {
	const maxAttempts = 8
	var lastCandidate uint64
	for attempt := 0; attempt < maxAttempts; attempt++ {
		versions, err := h.store.Versions()
		if err != nil {
			return err
		}
		if err := checkSequence(versions); err != nil {
			return err
		}

		var parent uint64
		prevChecksum := ""
		if len(versions) != 0 {
			parent = versions[len(versions)-1]
			parentRecord, err := h.store.Read(parent)
			if err != nil {
				return err
			}
			if err := policyhistory.VerifyRecord(parentRecord); err != nil {
				return err
			}
			prevChecksum = parentRecord.Checksum
		}

		record := &policyhistory.VersionRecord{
			Version:       parent + 1,
			ParentVersion: parent,
			CreatedAt:     time.Now().UTC(),
			Actor:         actor,
			Kind:          kind,
			Message:       message,
			Changes:       policyhistory.CloneChanges(changes),
			Model:         h.enforcer.modelDefinition(),
			Snapshot:      policyhistory.CloneSnapshot(snapshot),
			PrevChecksum:  prevChecksum,
		}
		if err := policyhistory.SealRecord(record); err != nil {
			return err
		}

		err = h.store.Append(record)
		if err == nil {
			return nil
		}
		if isAppendConflict(err) {
			// Another writer took the version; read the new tail and retry.
			lastCandidate = parent + 1
			continue
		}
		return err
	}
	return &policyhistory.VersionError{Version: lastCandidate, Kind: policyhistory.KindSequence, Err: errors.New("could not reserve a version number: too many concurrent appends")}
}

func isAppendConflict(err error) bool {
	var versionErr *policyhistory.VersionError
	if !errors.As(err, &versionErr) {
		return false
	}
	return versionErr.Kind == policyhistory.KindSequence
}

// reconcile records a version when the current policy differs from the last
// recorded one. It is used when history is enabled, on policy reload and on
// ClearPolicy.
func (h *PolicyHistory) reconcile(kind string, before policyhistory.Snapshot, actor, message string) error {
	snapshot := h.enforcer.policySnapshot()

	var changes []policyhistory.Change
	latest, err := h.latestRecord()
	if err != nil {
		return err
	}
	if latest != nil {
		changes = policyhistory.DiffSnapshots(latest.Snapshot, snapshot, nil)
		if len(changes) == 0 {
			return nil
		}
	} else if before != nil {
		changes = policyhistory.DiffSnapshots(before, snapshot, nil)
	}
	if changes == nil {
		changes = []policyhistory.Change{}
	}
	return h.append(snapshot, changes, kind, message, actor)
}

func (h *PolicyHistory) latestRecord() (*policyhistory.VersionRecord, error) {
	versions, err := h.store.Versions()
	if err != nil {
		return nil, err
	}
	if err := checkSequence(versions); err != nil {
		return nil, err
	}
	if len(versions) == 0 {
		return nil, nil
	}
	record, err := h.store.Read(versions[len(versions)-1])
	if err != nil {
		return nil, err
	}
	if err := policyhistory.VerifyRecord(record); err != nil {
		return nil, err
	}
	return record, nil
}

func modelDefinitionsEqual(a, b policyhistory.ModelDefinition) bool {
	return reflect.DeepEqual(a, b)
}

// ---------------------------------------------------------------------------
// Snapshots and model definitions
// ---------------------------------------------------------------------------

func (e *Enforcer) policySnapshot() policyhistory.Snapshot {
	sections := make([]string, 0, 2)
	for sec := range e.model {
		if sec == "p" || sec == "g" {
			sections = append(sections, sec)
		}
	}
	sort.Strings(sections)

	snapshot := make(policyhistory.Snapshot, 0)
	for _, sec := range sections {
		ptypes := make([]string, 0, len(e.model[sec]))
		for ptype := range e.model[sec] {
			ptypes = append(ptypes, ptype)
		}
		sort.Strings(ptypes)
		for _, ptype := range ptypes {
			ast := e.model[sec][ptype]
			if ast == nil {
				continue
			}
			snapshot = append(snapshot, policyhistory.RuleSet{
				Section: sec,
				PType:   ptype,
				Rules:   policyhistory.CloneRules(ast.Policy),
			})
		}
	}
	return snapshot
}

func modelPolicySnapshot(m model.Model) policyhistory.Snapshot {
	sections := make([]string, 0, 2)
	for sec := range m {
		if sec == "p" || sec == "g" {
			sections = append(sections, sec)
		}
	}
	sort.Strings(sections)

	snapshot := make(policyhistory.Snapshot, 0)
	for _, sec := range sections {
		ptypes := make([]string, 0, len(m[sec]))
		for ptype := range m[sec] {
			ptypes = append(ptypes, ptype)
		}
		sort.Strings(ptypes)
		for _, ptype := range ptypes {
			ast := m[sec][ptype]
			if ast == nil {
				continue
			}
			snapshot = append(snapshot, policyhistory.RuleSet{
				Section: sec,
				PType:   ptype,
				Rules:   policyhistory.CloneRules(ast.Policy),
			})
		}
	}
	return snapshot
}

func (e *Enforcer) modelDefinition() policyhistory.ModelDefinition {
	definition := make(policyhistory.ModelDefinition, len(e.model))
	for sec, assertions := range e.model {
		recorded := make(map[string]policyhistory.AssertionDefinition, len(assertions))
		for ptype, ast := range assertions {
			if ast == nil {
				continue
			}
			fieldIndex := make(map[string]int, len(ast.FieldIndexMap))
			ast.FieldIndexMutex.RLock()
			for field, index := range ast.FieldIndexMap {
				fieldIndex[field] = index
			}
			ast.FieldIndexMutex.RUnlock()
			recorded[ptype] = policyhistory.AssertionDefinition{
				Value:        ast.Value,
				Tokens:       append([]string(nil), ast.Tokens...),
				ParamsTokens: append([]string(nil), ast.ParamsTokens...),
				FieldIndex:   fieldIndex,
			}
		}
		definition[sec] = recorded
	}
	return definition
}

// buildModelFromDefinition rebuilds a model from a recorded definition.
func buildModelFromDefinition(definition policyhistory.ModelDefinition) (model.Model, error) {
	m := model.NewModel()
	for sec, assertions := range definition {
		for ptype, recorded := range assertions {
			ast := &model.Assertion{
				Key:           ptype,
				Value:         recorded.Value,
				Tokens:        append([]string(nil), recorded.Tokens...),
				ParamsTokens:  append([]string(nil), recorded.ParamsTokens...),
				PolicyMap:     make(map[string]int),
				FieldIndexMap: make(map[string]int),
			}
			for field, index := range recorded.FieldIndex {
				ast.FieldIndexMap[field] = index
			}
			if m[sec] == nil {
				m[sec] = make(model.AssertionMap)
			}
			m[sec][ptype] = ast
		}
	}
	for _, required := range [][2]string{{"r", "r"}, {"p", "p"}, {"e", "e"}, {"m", "m"}} {
		if m[required[0]] == nil || m[required[0]][required[1]] == nil {
			return nil, fmt.Errorf("recorded model is missing %s = %s", required[0], required[1])
		}
	}
	return m, nil
}

// ---------------------------------------------------------------------------
// Replayer
// ---------------------------------------------------------------------------

type replayer struct {
	enforcer *Enforcer
}

func (h *PolicyHistory) newReplayer(record *policyhistory.VersionRecord) (*replayer, error) {
	base, err := buildModelFromDefinition(record.Model)
	if err != nil {
		return nil, err
	}
	if err := loadSnapshotIntoModel(base, record.Snapshot); err != nil {
		return nil, err
	}

	source := h.enforcer
	e := &Enforcer{model: base}
	e.fm = source.fm
	e.modelPath = source.modelPath
	e.acceptJsonRequest = source.acceptJsonRequest
	e.gFunctionCache = source.gFunctionCache
	// Keep role links in sync with the recorded policy even when the source
	// enforcer had automatic link building turned off, otherwise the replay
	// would ignore the recorded grouping rules.
	e.autoBuildRoleLinks = source.autoBuildRoleLinks || len(base["g"]) != 0
	e.initialize()
	e.eft = source.eft

	if e.autoBuildRoleLinks && len(base["g"]) != 0 {
		if err := e.rebuildRoleLinks(e.model); err != nil {
			return nil, err
		}
		if err := e.rebuildConditionalRoleLinks(e.model); err != nil {
			return nil, err
		}
	}
	e.invalidateMatcherMap()
	return &replayer{enforcer: e}, nil
}

func loadSnapshotIntoModel(m model.Model, snapshot policyhistory.Snapshot) error {
	for _, set := range snapshot {
		if m[set.Section] == nil || m[set.Section][set.PType] == nil {
			return fmt.Errorf("recorded policy references section %q policy type %q which the recorded model does not define", set.Section, set.PType)
		}
		for _, rule := range set.Rules {
			if err := m.AddPolicy(set.Section, set.PType, policyhistory.CloneRule(rule)); err != nil {
				return err
			}
		}
	}
	return nil
}

// evaluate runs the request through the real enforcement path and then collects
// every rule whose matcher matched. The verdict therefore always agrees with
// Enforce.
func (r *replayer) evaluate(e *Enforcer, rvals []interface{}) (Attribution, error) {
	attribution := Attribution{MatchedRules: []policyhistory.RuleRef{}}
	if e == nil {
		return attribution, errors.New("policy history has no enforcer")
	}
	if !e.enabled {
		attribution.Allowed = true
		return attribution, nil
	}

	rType, pType, mType := "r", "p", "m"
	request := rvals
	if len(request) != 0 {
		if enforceContext, ok := request[0].(EnforceContext); ok {
			rType, pType, mType = enforceContext.RType, enforceContext.PType, enforceContext.MType
			request = request[1:]
		}
	}

	if e.model["r"] == nil || e.model["r"][rType] == nil ||
		e.model["p"] == nil || e.model["p"][pType] == nil ||
		e.model["e"] == nil || e.model["m"] == nil {
		return attribution, errors.New("policy model is incomplete")
	}

	allowed, err := e.enforce("", nil, rvals...)
	if err != nil {
		return attribution, err
	}
	attribution.Allowed = allowed

	matched, err := e.matchedRuleRefs(rType, pType, mType, request)
	if err != nil {
		return attribution, err
	}
	attribution.MatchedRules = matched
	return attribution, nil
}

// matchedRuleRefs evaluates the matcher against every policy rule and returns
// the rules that matched. It mirrors the matching part of enforce.
func (e *Enforcer) matchedRuleRefs(rType, pType, mType string, rvals []interface{}) ([]policyhistory.RuleRef, error) {
	refs := []policyhistory.RuleRef{}

	rAssertion := e.model["r"][rType]
	pAssertion := e.model["p"][pType]
	mAssertion := e.model["m"][mType]
	if rAssertion == nil || pAssertion == nil || mAssertion == nil {
		return refs, errors.New("policy model is incomplete")
	}

	expString := mAssertion.Value
	if !strings.Contains(expString, pType+"_") && !util.HasEval(expString) {
		// The matcher does not look at the policy, so no rule can be attributed.
		return refs, nil
	}

	if len(rAssertion.Tokens) != len(rvals) {
		return refs, fmt.Errorf(
			"invalid request size: expected %d, got %d, rvals: %v",
			len(rAssertion.Tokens), len(rvals), rvals)
	}

	rTokens := make(map[string]int, len(rAssertion.Tokens))
	for i, token := range rAssertion.Tokens {
		rTokens[token] = i
	}
	pTokens := make(map[string]int, len(pAssertion.Tokens))
	for i, token := range pAssertion.Tokens {
		pTokens[token] = i
	}

	if e.acceptJsonRequest {
		for i, rval := range rvals {
			if str, ok := rval.(string); ok && len(str) > 0 && (str[0] == '{' || str[0] == '[') {
				mapValue, err := util.JsonToMap(str)
				if err != nil {
					return refs, fmt.Errorf("failed to parse JSON parameter at index %d: %w", i, err)
				}
				rvals[i] = mapValue
			}
		}
	}

	parameters := enforceParameters{rTokens: rTokens, rVals: rvals, pTokens: pTokens}
	hasEval := util.HasEval(expString)
	expression, err := e.getAndStoreMatcherExpression(hasEval, expString, &parameters)
	if err != nil {
		return refs, err
	}

	for _, pvals := range pAssertion.Policy {
		if len(pAssertion.Tokens) != len(pvals) {
			return refs, fmt.Errorf(
				"invalid policy size: expected %d, got %d, pvals: %v",
				len(pAssertion.Tokens), len(pvals), pvals)
		}
		parameters.pVals = pvals
		result, err := expression.Eval(parameters)
		if err != nil {
			return refs, err
		}
		matched := false
		switch typed := result.(type) {
		case bool:
			matched = typed
		case float64:
			matched = typed != 0
		default:
			return refs, errors.New("matcher result should be bool, int or float")
		}
		if matched {
			refs = append(refs, policyhistory.RuleRef{
				Section: "p",
				PType:   pType,
				Rule:    policyhistory.CloneRule(pvals),
			})
		}
	}
	return refs, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func checkSequence(versions []uint64) error {
	for i, version := range versions {
		if version != uint64(i+1) {
			return &policyhistory.VersionError{
				Version: version,
				Kind:    policyhistory.KindSequence,
				Err:     fmt.Errorf("expected version %d, found %d", i+1, version),
			}
		}
	}
	return nil
}
