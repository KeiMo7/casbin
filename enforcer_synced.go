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
	"sync"
	"sync/atomic"
	"time"

	"github.com/casbin/govaluate"

	"github.com/casbin/casbin/v3/persist"
	"github.com/casbin/casbin/v3/rbac"
)

// SyncedEnforcer wraps Enforcer and provides synchronized access.
type SyncedEnforcer struct {
	*Enforcer
	m sync.RWMutex

	reconcileState
}

// NewSyncedEnforcer creates a synchronized enforcer via file or DB.
func NewSyncedEnforcer(params ...interface{}) (*SyncedEnforcer, error) {
	e := &SyncedEnforcer{}
	var err error
	e.Enforcer, err = NewEnforcer(params...)
	if err != nil {
		return nil, err
	}

	e.initReconcileState()
	e.appliedFingerprint = policyFingerprint(e.model)
	e.lastSyncedRevision = e.getLocalRevision()
	if v, versioned, verr := adapterStorageVersion(e.adapter); versioned && verr == nil {
		e.appliedVersion = v
		e.latestVersion = v
	}
	return e, nil
}

// GetLock return the private RWMutex lock.
func (e *SyncedEnforcer) GetLock() *sync.RWMutex {
	return &e.m
}

// GetRoleManager gets the current role manager with synchronization.
func (e *SyncedEnforcer) GetRoleManager() rbac.RoleManager {
	e.m.RLock()
	defer e.m.RUnlock()
	return e.Enforcer.GetRoleManager()
}

// GetNamedRoleManager gets the role manager for the named policy with synchronization.
func (e *SyncedEnforcer) GetNamedRoleManager(ptype string) rbac.RoleManager {
	e.m.RLock()
	defer e.m.RUnlock()
	return e.Enforcer.GetNamedRoleManager(ptype)
}

// SetRoleManager sets the current role manager with synchronization.
func (e *SyncedEnforcer) SetRoleManager(rm rbac.RoleManager) {
	e.m.Lock()
	defer e.m.Unlock()
	e.Enforcer.SetRoleManager(rm)
}

// SetNamedRoleManager sets the role manager for the named policy with synchronization.
func (e *SyncedEnforcer) SetNamedRoleManager(ptype string, rm rbac.RoleManager) {
	e.m.Lock()
	defer e.m.Unlock()
	e.Enforcer.SetNamedRoleManager(ptype, rm)
}

// IsAutoLoadingRunning check if SyncedEnforcer is auto loading policies.
//
// Deprecated: retained for compatibility; prefer IsReconcilerRunning().
func (e *SyncedEnforcer) IsAutoLoadingRunning() bool {
	return atomic.LoadInt32(&e.running) != 0
}

// IsReconcilerRunning reports whether the policy reconciler goroutine is active.
func (e *SyncedEnforcer) IsReconcilerRunning() bool {
	return atomic.LoadInt32(&e.running) != 0
}

// StartAutoLoadPolicy starts a go routine that periodically reloads the policy.
//
// Deprecated: use StartPolicyReconciler, which adds watcher-driven immediate
// convergence, monotonic version gating and bounded backoff. This method keeps
// its original semantics and signature.
func (e *SyncedEnforcer) StartAutoLoadPolicy(d time.Duration) {
	e.StartPolicyReconciler(ReconcilerConfig{Interval: d})
}

// ReconcilerConfig configures StartPolicyReconciler.
type ReconcilerConfig struct {
	// Interval is the period of the periodic reconciliation ticker. It is
	// also the initial retry delay after a failed pull (backoff grows from
	// it up to maxReconcileBackoff).
	Interval time.Duration
}

// StartPolicyReconciler starts the convergence loop: watcher notifications
// trigger an immediate reload, and a periodic ticker guarantees self-healing
// within a bounded time when notifications are lost. It is a no-op when a
// reconciler is already running.
func (e *SyncedEnforcer) StartPolicyReconciler(cfg ReconcilerConfig) {
	if !atomic.CompareAndSwapInt32(&e.running, 0, 1) {
		return
	}
	interval := cfg.Interval
	if interval <= 0 {
		interval = time.Second
	}
	e.stop = make(chan struct{})
	e.notifyCh = make(chan struct{}, 1)
	atomic.StoreInt32(&e.notificationMode, syncModeIndex(SyncModePeriodic))

	go e.reconcileLoop(interval)
}

func (e *SyncedEnforcer) reconcileLoop(interval time.Duration) {
	defer atomic.StoreInt32(&e.running, 0)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// failureTimer is kept nil while healthy: failures arm it with the
	// current backoff, success stops it.
	var failureTimer *time.Timer
	var failureC <-chan time.Time
	backoff := interval

	disarm := func() {
		if failureTimer != nil {
			failureTimer.Stop()
			failureTimer, failureC = nil, nil
		}
	}
	armBackoff := func() {
		disarm()
		failureTimer = time.NewTimer(backoff)
		failureC = failureTimer.C
	}

	for {
		select {
		case <-e.stop:
			disarm()
			atomic.StoreInt32(&e.notificationMode, syncModeIndex(SyncModeStopped))
			return
		case <-ticker.C:
			// Periodic reconciliation is the guaranteed convergence
			// backstop; drain any coalesced notification, the pull reads
			// the newest storage state anyway.
			e.drainNotify()
			outcome := e.tryReconcile("periodic")
			backoff = e.scheduleAfter(outcome, interval, backoff, armBackoff, disarm)
		case <-e.notifyCh:
			// A watcher fired: converge immediately. Multiple firings
			// before this point have coalesced into this single wake-up.
			outcome := e.tryReconcile("watcher")
			backoff = e.scheduleAfter(outcome, interval, backoff, armBackoff, disarm)
		case <-failureC:
			failureTimer, failureC = nil, nil
			outcome := e.tryReconcile("retry")
			backoff = e.scheduleAfter(outcome, interval, backoff, armBackoff, disarm)
		}
	}
}

// scheduleAfter adjusts the failure backoff based on the last outcome and
// returns the backoff to use after the next failure. Healthy states reset the
// backoff to the base interval so retries stay fast after recovery.
func (e *SyncedEnforcer) scheduleAfter(outcome reconcileOutcome, interval, backoff time.Duration,
	armBackoff, disarm func()) time.Duration {
	if outcome == outcomeFailed {
		armBackoff()
		if backoff < maxReconcileBackoff {
			backoff *= 2
			if backoff > maxReconcileBackoff {
				backoff = maxReconcileBackoff
			}
		}
		return backoff
	}
	// Up-to-date results and rejected rollbacks both mean the transport
	// works: keep the normal cadence and reset any armed backoff.
	disarm()
	return interval
}

func (e *SyncedEnforcer) drainNotify() {
	for {
		select {
		case <-e.notifyCh:
		default:
			return
		}
	}
}

// StopAutoLoadPolicy causes the convergence go routine to exit.
func (e *SyncedEnforcer) StopAutoLoadPolicy() {
	if atomic.LoadInt32(&e.running) == 0 {
		return
	}
	close(e.stop)
	// Block until the loop has actually exited so a subsequent
	// StartPolicyReconciler cannot race the old goroutine.
	for atomic.LoadInt32(&e.running) != 0 {
		time.Sleep(time.Millisecond)
	}
}

// StopPolicyReconciler is the explicit-name alias of StopAutoLoadPolicy.
func (e *SyncedEnforcer) StopPolicyReconciler() {
	e.StopAutoLoadPolicy()
}

// handleWatcherNotification is the entry point for plain Watcher callbacks.
// It coalesces notifications and wakes the reconciler; the actual pull is
// serialized through tryReconcile so callbacks never run policy application
// concurrently with each other.
func (e *SyncedEnforcer) handleWatcherNotification(string) {
	e.queueNotification(0, false)
}

// handleVersionedWatcherNotification discards notifications whose carried
// version is no newer than the applied one, then coalesces the rest. A
// discarded notification cannot represent a missed change because the applied
// version is already at or beyond it; lost newer notifications are still
// repaired by the periodic backstop.
func (e *SyncedEnforcer) handleVersionedWatcherNotification(version uint64) {
	current := atomic.LoadUint64(&e.appliedVersion)
	if version <= current {
		atomic.AddUint64(&e.staleNotificationsDropped, 1)
		return
	}
	// A notification is evidence of a newer storage state even before the
	// pull completes, so surface the lag immediately.
	for {
		latest := atomic.LoadUint64(&e.latestVersion)
		if version <= latest || atomic.CompareAndSwapUint64(&e.latestVersion, latest, version) {
			break
		}
	}
	e.queueNotification(version, true)
}

// tryReconcile is the single serialized entry point for every convergence
// attempt (watcher, periodic tick, retry and explicit LoadPolicy). It returns
// an outcome for backoff/metrics handling.
func (e *SyncedEnforcer) tryReconcile(trigger string) reconcileOutcome {
	e.reconcileMu.Lock()
	defer e.reconcileMu.Unlock()

	notifyVersion, hasNotifyVersion := e.takePendingNotification()
	now := time.Now()
	e.statsMu.Lock()
	e.lastAttempt = now
	e.statsMu.Unlock()

	storageVersion, versioned, err := adapterStorageVersion(e.adapter)
	if err != nil {
		e.recordFailure(err)
		return outcomeFailed
	}
	if versioned {
		// Monotonicity hard constraint: refuse any rollback the storage
		// might report (stale replica, restored snapshot, split brain).
		if storageVersion < atomic.LoadUint64(&e.appliedVersion) {
			// This is a policy rejection, not a transport failure: do not
			// arm the failure backoff or flip the notification mode, so
			// retries keep their normal cadence until storage catches up.
			e.statsMu.Lock()
			e.consecutiveFailures++
			e.lastErr = "storage version " + formatVersion(storageVersion, true) +
				" is older than applied version " + formatVersion(e.appliedVersion, true)
			e.statsMu.Unlock()
			return outcomeStaleRejected
		}
		if storageVersion > atomic.LoadUint64(&e.latestVersion) {
			atomic.StoreUint64(&e.latestVersion, storageVersion)
		}
		// A versioned watcher told us about a version that the storage
		// read does not yet contain: the read hit a lagging replica. Keep
		// serving the current complete state and retain the pending
		// notification so the next attempt retries it; this is not a
		// pull failure and does not arm the backoff.
		if hasNotifyVersion && notifyVersion > storageVersion {
			e.requeuePendingVersion(notifyVersion)
			return outcomeUpToDate
		}
		if storageVersion == atomic.LoadUint64(&e.appliedVersion) {
			e.recordSuccess()
			return outcomeUpToDate
		}
	}

	// Build the candidate snapshot without the write lock so in-flight
	// Enforce calls keep serving the previous complete state.
	e.m.RLock()
	newModel, loadErr := e.loadPolicyFromAdapter(e.model)
	e.m.RUnlock()
	if loadErr != nil {
		e.recordFailure(loadErr)
		return outcomeFailed
	}

	fingerprint := policyFingerprint(newModel)
	if !versioned {
		// Fingerprint ordering: identical content is a no-op only when no
		// local mutation happened since the last storage sync. Local
		// mutations (ClearPolicy, AddPolicy, ...) leave the storage as the
		// source of truth, so identical storage content must still be
		// re-applied to roll the in-memory state back to the stored state.
		locallyMutated := e.getLocalRevision() != atomic.LoadUint64(&e.lastSyncedRevision)
		if fingerprint == atomic.LoadUint64(&e.appliedFingerprint) && !locallyMutated {
			e.recordSuccess()
			return outcomeUpToDate
		}
	}

	// One atomic switch under the write lock: policy content, role
	// inheritance and all caches flip together; readers only ever see the
	// state before or the state after, never a half-applied one.
	e.m.Lock()
	if applyErr := e.applyModifiedModel(newModel); applyErr != nil {
		e.m.Unlock()
		// applyModifiedModel already rebuilds the previous role links on
		// failure, so the served state remains the last complete one.
		e.recordFailure(applyErr)
		return outcomeFailed
	}
	if versioned {
		atomic.StoreUint64(&e.appliedVersion, storageVersion)
	}
	atomic.StoreUint64(&e.appliedFingerprint, fingerprint)
	atomic.StoreUint64(&e.lastSyncedRevision, e.getLocalRevision())
	e.m.Unlock()

	e.recordSuccess()
	if trigger == "watcher" {
		atomic.StoreInt32(&e.notificationMode, syncModeIndex(SyncModeWatcher))
	} else if trigger == "periodic" || trigger == "retry" {
		// The periodic backstop delivered a convergence. If watchers were
		// previously trusted, a new version arriving only via the ticker
		// means the notification was lost: surface the degraded marker.
		atomic.StoreInt32(&e.notificationMode, syncModeIndex(SyncModePeriodic))
	}
	return outcomeApplied
}

func (e *SyncedEnforcer) recordFailure(err error) {
	e.recordFailureText(err.Error())
}

func (e *SyncedEnforcer) recordFailureText(msg string) {
	e.statsMu.Lock()
	e.consecutiveFailures++
	e.lastErr = msg
	e.statsMu.Unlock()
	// Failures mean watcher-only convergence cannot be trusted; surface
	// the periodic backstop explicitly.
	atomic.StoreInt32(&e.notificationMode, syncModeIndex(SyncModePeriodic))
}

func (e *SyncedEnforcer) recordSuccess() {
	e.statsMu.Lock()
	e.consecutiveFailures = 0
	e.lastErr = ""
	e.lastSuccessfulSync = time.Now()
	e.statsMu.Unlock()
}

// LoadPolicy reloads the policy from file/database through the version-gated,
// serialized convergence path. The signature is unchanged. On failure the
// previously served complete state is retained.
func (e *SyncedEnforcer) LoadPolicy() error {
	outcome := e.tryReconcile("explicit")
	if outcome == outcomeFailed {
		return errLastReconcileFailure(e.lastErr)
	}
	return nil
}

// LoadFilteredPolicy reloads a filtered policy from file/database.
func (e *SyncedEnforcer) LoadFilteredPolicy(filter interface{}) error {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.LoadFilteredPolicy(filter)
}

// LoadIncrementalFilteredPolicy reloads a filtered policy from file/database.
func (e *SyncedEnforcer) LoadIncrementalFilteredPolicy(filter interface{}) error {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.LoadIncrementalFilteredPolicy(filter)
}

// SavePolicy saves the current policy (usually after changed with Casbin API) back to file/database.
func (e *SyncedEnforcer) SavePolicy() error {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.SavePolicy()
}

// BuildRoleLinks manually rebuild the role inheritance relations.
func (e *SyncedEnforcer) BuildRoleLinks() error {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.BuildRoleLinks()
}

// Enforce decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (sub, obj, act).
func (e *SyncedEnforcer) Enforce(rvals ...interface{}) (bool, error) {
	e.m.RLock()
	defer e.m.RUnlock()
	return e.Enforcer.Enforce(rvals...)
}

// EnforceWithMatcher use a custom matcher to decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (matcher, sub, obj, act), use model matcher by default when matcher is "".
func (e *SyncedEnforcer) EnforceWithMatcher(matcher string, rvals ...interface{}) (bool, error) {
	e.m.RLock()
	defer e.m.RUnlock()
	return e.Enforcer.EnforceWithMatcher(matcher, rvals...)
}

// EnforceEx explain enforcement by informing matched rules.
func (e *SyncedEnforcer) EnforceEx(rvals ...interface{}) (bool, []string, error) {
	e.m.RLock()
	defer e.m.RUnlock()
	return e.Enforcer.EnforceEx(rvals...)
}

// EnforceExWithMatcher use a custom matcher and explain enforcement by informing matched rules.
func (e *SyncedEnforcer) EnforceExWithMatcher(matcher string, rvals ...interface{}) (bool, []string, error) {
	e.m.RLock()
	defer e.m.RUnlock()
	return e.Enforcer.EnforceExWithMatcher(matcher, rvals...)
}

// BatchEnforce enforce in batches.
func (e *SyncedEnforcer) BatchEnforce(requests [][]interface{}) ([]bool, error) {
	e.m.RLock()
	defer e.m.RUnlock()
	return e.Enforcer.BatchEnforce(requests)
}

// BatchEnforceWithMatcher enforce with matcher in batches.
func (e *SyncedEnforcer) BatchEnforceWithMatcher(matcher string, requests [][]interface{}) ([]bool, error) {
	e.m.RLock()
	defer e.m.RUnlock()
	return e.Enforcer.BatchEnforceWithMatcher(matcher, requests)
}

// GetAllSubjects gets the list of subjects that show up in the current policy.
func (e *SyncedEnforcer) GetAllSubjects() ([]string, error) {
	e.m.RLock()
	defer e.m.RUnlock()
	return e.Enforcer.GetAllSubjects()
}

// GetAllNamedSubjects gets the list of subjects that show up in the current named policy.
func (e *SyncedEnforcer) GetAllNamedSubjects(ptype string) ([]string, error) {
	e.m.RLock()
	defer e.m.RUnlock()
	return e.Enforcer.GetAllNamedSubjects(ptype)
}

// GetAllObjects gets the list of objects that show up in the current policy.
func (e *SyncedEnforcer) GetAllObjects() ([]string, error) {
	e.m.RLock()
	defer e.m.RUnlock()
	return e.Enforcer.GetAllObjects()
}

// GetAllNamedObjects gets the list of objects that show up in the current named policy.
func (e *SyncedEnforcer) GetAllNamedObjects(ptype string) ([]string, error) {
	e.m.RLock()
	defer e.m.RUnlock()
	return e.Enforcer.GetAllNamedObjects(ptype)
}

// GetAllActions gets the list of actions that show up in the current policy.
func (e *SyncedEnforcer) GetAllActions() ([]string, error) {
	e.m.RLock()
	defer e.m.RUnlock()
	return e.Enforcer.GetAllActions()
}

// GetAllNamedActions gets the list of actions that show up in the current named policy.
func (e *SyncedEnforcer) GetAllNamedActions(ptype string) ([]string, error) {
	e.m.RLock()
	defer e.m.RUnlock()
	return e.Enforcer.GetAllNamedActions(ptype)
}

// GetAllRoles gets the list of roles that show up in the current policy.
func (e *SyncedEnforcer) GetAllRoles() ([]string, error) {
	e.m.RLock()
	defer e.m.RUnlock()
	return e.Enforcer.GetAllRoles()
}

// GetAllNamedRoles gets the list of roles that show up in the current named policy.
func (e *SyncedEnforcer) GetAllNamedRoles(ptype string) ([]string, error) {
	e.m.RLock()
	defer e.m.RUnlock()
	return e.Enforcer.GetAllNamedRoles(ptype)
}

// GetAllUsers gets the list of users that show up in the current policy.
func (e *SyncedEnforcer) GetAllUsers() ([]string, error) {
	e.m.RLock()
	defer e.m.RUnlock()
	return e.Enforcer.GetAllUsers()
}

// GetPolicy gets all the authorization rules in the policy.
func (e *SyncedEnforcer) GetPolicy() ([][]string, error) {
	e.m.RLock()
	defer e.m.RUnlock()
	return e.Enforcer.GetPolicy()
}

// GetFilteredPolicy gets all the authorization rules in the policy, field filters can be specified.
func (e *SyncedEnforcer) GetFilteredPolicy(fieldIndex int, fieldValues ...string) ([][]string, error) {
	e.m.RLock()
	defer e.m.RUnlock()
	return e.Enforcer.GetFilteredPolicy(fieldIndex, fieldValues...)
}

// GetNamedPolicy gets all the authorization rules in the named policy.
func (e *SyncedEnforcer) GetNamedPolicy(ptype string) ([][]string, error) {
	e.m.RLock()
	defer e.m.RUnlock()
	return e.Enforcer.GetNamedPolicy(ptype)
}

// GetFilteredNamedPolicy gets all the authorization rules in the named policy, field filters can be specified.
func (e *SyncedEnforcer) GetFilteredNamedPolicy(ptype string, fieldIndex int, fieldValues ...string) ([][]string, error) {
	e.m.RLock()
	defer e.m.RUnlock()
	return e.Enforcer.GetFilteredNamedPolicy(ptype, fieldIndex, fieldValues...)
}

// GetGroupingPolicy gets all the role inheritance rules in the policy.
func (e *SyncedEnforcer) GetGroupingPolicy() ([][]string, error) {
	e.m.RLock()
	defer e.m.RUnlock()
	return e.Enforcer.GetGroupingPolicy()
}

// GetFilteredGroupingPolicy gets all the role inheritance rules in the policy, field filters can be specified.
func (e *SyncedEnforcer) GetFilteredGroupingPolicy(fieldIndex int, fieldValues ...string) ([][]string, error) {
	e.m.RLock()
	defer e.m.RUnlock()
	return e.Enforcer.GetFilteredGroupingPolicy(fieldIndex, fieldValues...)
}

// GetNamedGroupingPolicy gets all the role inheritance rules in the policy.
func (e *SyncedEnforcer) GetNamedGroupingPolicy(ptype string) ([][]string, error) {
	e.m.RLock()
	defer e.m.RUnlock()
	return e.Enforcer.GetNamedGroupingPolicy(ptype)
}

// GetFilteredNamedGroupingPolicy gets all the role inheritance rules in the policy, field filters can be specified.
func (e *SyncedEnforcer) GetFilteredNamedGroupingPolicy(ptype string, fieldIndex int, fieldValues ...string) ([][]string, error) {
	e.m.RLock()
	defer e.m.RUnlock()
	return e.Enforcer.GetFilteredNamedGroupingPolicy(ptype, fieldIndex, fieldValues...)
}

// HasPolicy determines whether an authorization rule exists.
func (e *SyncedEnforcer) HasPolicy(params ...interface{}) (bool, error) {
	e.m.RLock()
	defer e.m.RUnlock()
	return e.Enforcer.HasPolicy(params...)
}

// HasNamedPolicy determines whether a named authorization rule exists.
func (e *SyncedEnforcer) HasNamedPolicy(ptype string, params ...interface{}) (bool, error) {
	e.m.RLock()
	defer e.m.RUnlock()
	return e.Enforcer.HasNamedPolicy(ptype, params...)
}

// AddPolicy adds an authorization rule to the current policy.
// If the rule already exists, the function returns false and the rule will not be added.
// Otherwise the function returns true by adding the new rule.
func (e *SyncedEnforcer) AddPolicy(params ...interface{}) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.AddPolicy(params...)
}

// AddPolicies adds authorization rules to the current policy.
// If the rule already exists, the function returns false for the corresponding rule and the rule will not be added.
// Otherwise the function returns true for the corresponding rule by adding the new rule.
func (e *SyncedEnforcer) AddPolicies(rules [][]string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.AddPolicies(rules)
}

// AddPoliciesEx adds authorization rules to the current policy.
// If the rule already exists, the rule will not be added.
// But unlike AddPolicies, other non-existent rules are added instead of returning false directly.
func (e *SyncedEnforcer) AddPoliciesEx(rules [][]string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.AddPoliciesEx(rules)
}

// AddNamedPolicy adds an authorization rule to the current named policy.
// If the rule already exists, the function returns false and the rule will not be added.
// Otherwise the function returns true by adding the new rule.
func (e *SyncedEnforcer) AddNamedPolicy(ptype string, params ...interface{}) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.AddNamedPolicy(ptype, params...)
}

// AddNamedPolicies adds authorization rules to the current named policy.
// If the rule already exists, the function returns false for the corresponding rule and the rule will not be added.
// Otherwise the function returns true for the corresponding by adding the new rule.
func (e *SyncedEnforcer) AddNamedPolicies(ptype string, rules [][]string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.AddNamedPolicies(ptype, rules)
}

// AddNamedPoliciesEx adds authorization rules to the current named policy.
// If the rule already exists, the rule will not be added.
// But unlike AddNamedPolicies, other non-existent rules are added instead of returning false directly.
func (e *SyncedEnforcer) AddNamedPoliciesEx(ptype string, rules [][]string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.AddNamedPoliciesEx(ptype, rules)
}

// RemovePolicy removes an authorization rule from the current policy.
func (e *SyncedEnforcer) RemovePolicy(params ...interface{}) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.RemovePolicy(params...)
}

// UpdatePolicy updates an authorization rule from the current policy.
func (e *SyncedEnforcer) UpdatePolicy(oldPolicy []string, newPolicy []string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.UpdatePolicy(oldPolicy, newPolicy)
}

func (e *SyncedEnforcer) UpdateNamedPolicy(ptype string, p1 []string, p2 []string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.UpdateNamedPolicy(ptype, p1, p2)
}

// UpdatePolicies updates authorization rules from the current policies.
func (e *SyncedEnforcer) UpdatePolicies(oldPolices [][]string, newPolicies [][]string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.UpdatePolicies(oldPolices, newPolicies)
}

func (e *SyncedEnforcer) UpdateNamedPolicies(ptype string, p1 [][]string, p2 [][]string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.UpdateNamedPolicies(ptype, p1, p2)
}

func (e *SyncedEnforcer) UpdateFilteredPolicies(newPolicies [][]string, fieldIndex int, fieldValues ...string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.UpdateFilteredPolicies(newPolicies, fieldIndex, fieldValues...)
}

func (e *SyncedEnforcer) UpdateFilteredNamedPolicies(ptype string, newPolicies [][]string, fieldIndex int, fieldValues ...string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.UpdateFilteredNamedPolicies(ptype, newPolicies, fieldIndex, fieldValues...)
}

// RemovePolicies removes authorization rules from the current policy.
func (e *SyncedEnforcer) RemovePolicies(rules [][]string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.RemovePolicies(rules)
}

// RemoveFilteredPolicy removes an authorization rule from the current policy, field filters can be specified.
func (e *SyncedEnforcer) RemoveFilteredPolicy(fieldIndex int, fieldValues ...string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.RemoveFilteredPolicy(fieldIndex, fieldValues...)
}

// RemoveNamedPolicy removes an authorization rule from the current named policy.
func (e *SyncedEnforcer) RemoveNamedPolicy(ptype string, params ...interface{}) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.RemoveNamedPolicy(ptype, params...)
}

// RemoveNamedPolicies removes authorization rules from the current named policy.
func (e *SyncedEnforcer) RemoveNamedPolicies(ptype string, rules [][]string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.RemoveNamedPolicies(ptype, rules)
}

// RemoveFilteredNamedPolicy removes an authorization rule from the current named policy, field filters can be specified.
func (e *SyncedEnforcer) RemoveFilteredNamedPolicy(ptype string, fieldIndex int, fieldValues ...string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.RemoveFilteredNamedPolicy(ptype, fieldIndex, fieldValues...)
}

// HasGroupingPolicy determines whether a role inheritance rule exists.
func (e *SyncedEnforcer) HasGroupingPolicy(params ...interface{}) (bool, error) {
	e.m.RLock()
	defer e.m.RUnlock()
	return e.Enforcer.HasGroupingPolicy(params...)
}

// HasNamedGroupingPolicy determines whether a named role inheritance rule exists.
func (e *SyncedEnforcer) HasNamedGroupingPolicy(ptype string, params ...interface{}) (bool, error) {
	e.m.RLock()
	defer e.m.RUnlock()
	return e.Enforcer.HasNamedGroupingPolicy(ptype, params...)
}

// AddGroupingPolicy adds a role inheritance rule to the current policy.
// If the rule already exists, the function returns false and the rule will not be added.
// Otherwise the function returns true by adding the new rule.
func (e *SyncedEnforcer) AddGroupingPolicy(params ...interface{}) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.AddGroupingPolicy(params...)
}

// AddGroupingPolicies adds role inheritance rulea to the current policy.
// If the rule already exists, the function returns false for the corresponding policy rule and the rule will not be added.
// Otherwise the function returns true for the corresponding policy rule by adding the new rule.
func (e *SyncedEnforcer) AddGroupingPolicies(rules [][]string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.AddGroupingPolicies(rules)
}

// AddGroupingPoliciesEx adds role inheritance rules to the current policy.
// If the rule already exists, the rule will not be added.
// But unlike AddGroupingPolicies, other non-existent rules are added instead of returning false directly.
func (e *SyncedEnforcer) AddGroupingPoliciesEx(rules [][]string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.AddGroupingPoliciesEx(rules)
}

// AddNamedGroupingPolicy adds a named role inheritance rule to the current policy.
// If the rule already exists, the function returns false and the rule will not be added.
// Otherwise the function returns true by adding the new rule.
func (e *SyncedEnforcer) AddNamedGroupingPolicy(ptype string, params ...interface{}) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.AddNamedGroupingPolicy(ptype, params...)
}

// AddNamedGroupingPolicies adds named role inheritance rules to the current policy.
// If the rule already exists, the function returns false for the corresponding policy rule and the rule will not be added.
// Otherwise the function returns true for the corresponding policy rule by adding the new rule.
func (e *SyncedEnforcer) AddNamedGroupingPolicies(ptype string, rules [][]string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.AddNamedGroupingPolicies(ptype, rules)
}

// AddNamedGroupingPoliciesEx adds named role inheritance rules to the current policy.
// If the rule already exists, the rule will not be added.
// But unlike AddNamedGroupingPolicies, other non-existent rules are added instead of returning false directly.
func (e *SyncedEnforcer) AddNamedGroupingPoliciesEx(ptype string, rules [][]string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.AddNamedGroupingPoliciesEx(ptype, rules)
}

// RemoveGroupingPolicy removes a role inheritance rule from the current policy.
func (e *SyncedEnforcer) RemoveGroupingPolicy(params ...interface{}) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.RemoveGroupingPolicy(params...)
}

// RemoveGroupingPolicies removes role inheritance rules from the current policy.
func (e *SyncedEnforcer) RemoveGroupingPolicies(rules [][]string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.RemoveGroupingPolicies(rules)
}

// RemoveFilteredGroupingPolicy removes a role inheritance rule from the current policy, field filters can be specified.
func (e *SyncedEnforcer) RemoveFilteredGroupingPolicy(fieldIndex int, fieldValues ...string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.RemoveFilteredGroupingPolicy(fieldIndex, fieldValues...)
}

// RemoveNamedGroupingPolicy removes a role inheritance rule from the current named policy.
func (e *SyncedEnforcer) RemoveNamedGroupingPolicy(ptype string, params ...interface{}) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.RemoveNamedGroupingPolicy(ptype, params...)
}

// RemoveNamedGroupingPolicies removes role inheritance rules from the current named policy.
func (e *SyncedEnforcer) RemoveNamedGroupingPolicies(ptype string, rules [][]string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.RemoveNamedGroupingPolicies(ptype, rules)
}

func (e *SyncedEnforcer) UpdateGroupingPolicy(oldRule []string, newRule []string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.UpdateGroupingPolicy(oldRule, newRule)
}

func (e *SyncedEnforcer) UpdateGroupingPolicies(oldRules [][]string, newRules [][]string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.UpdateGroupingPolicies(oldRules, newRules)
}

func (e *SyncedEnforcer) UpdateNamedGroupingPolicy(ptype string, oldRule []string, newRule []string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.UpdateNamedGroupingPolicy(ptype, oldRule, newRule)
}

func (e *SyncedEnforcer) UpdateNamedGroupingPolicies(ptype string, oldRules [][]string, newRules [][]string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.UpdateNamedGroupingPolicies(ptype, oldRules, newRules)
}

// RemoveFilteredNamedGroupingPolicy removes an role inheritance rule from the current named policy, field filters can be specified.
func (e *SyncedEnforcer) RemoveFilteredNamedGroupingPolicy(ptype string, fieldIndex int, fieldValues ...string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.RemoveFilteredNamedGroupingPolicy(ptype, fieldIndex, fieldValues...)
}

// AddFunction adds a customized function.
func (e *SyncedEnforcer) AddFunction(name string, function govaluate.ExpressionFunction) {
	e.m.Lock()
	defer e.m.Unlock()
	e.Enforcer.AddFunction(name, function)
}

func (e *SyncedEnforcer) SelfAddPolicy(sec string, ptype string, rule []string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.SelfAddPolicy(sec, ptype, rule)
}

func (e *SyncedEnforcer) SelfAddPolicies(sec string, ptype string, rules [][]string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.SelfAddPolicies(sec, ptype, rules)
}

func (e *SyncedEnforcer) SelfAddPoliciesEx(sec string, ptype string, rules [][]string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.SelfAddPoliciesEx(sec, ptype, rules)
}

func (e *SyncedEnforcer) SelfRemovePolicy(sec string, ptype string, rule []string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.SelfRemovePolicy(sec, ptype, rule)
}

func (e *SyncedEnforcer) SelfRemovePolicies(sec string, ptype string, rules [][]string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.SelfRemovePolicies(sec, ptype, rules)
}

func (e *SyncedEnforcer) SelfRemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.SelfRemoveFilteredPolicy(sec, ptype, fieldIndex, fieldValues...)
}

func (e *SyncedEnforcer) SelfUpdatePolicy(sec string, ptype string, oldRule, newRule []string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.SelfUpdatePolicy(sec, ptype, oldRule, newRule)
}

func (e *SyncedEnforcer) SelfUpdatePolicies(sec string, ptype string, oldRules, newRules [][]string) (bool, error) {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.SelfUpdatePolicies(sec, ptype, oldRules, newRules)
}

// SetWatcher sets the current watcher and wires its callbacks into the
// reconciler so notifications are coalesced and version-checked instead of
// invoking uncoordinated LoadPolicy calls. The method signature is unchanged.
func (e *SyncedEnforcer) SetWatcher(watcher persist.Watcher) error {
	e.m.Lock()
	defer e.m.Unlock()
	e.watcher = watcher
	if vw, ok := watcher.(persist.VersionedWatcher); ok {
		return vw.SetVersionedUpdateCallback(e.handleVersionedWatcherNotification)
	}
	if _, ok := watcher.(persist.WatcherEx); ok {
		// WatcherEx drives its own callback registration (same contract
		// as Enforcer.SetWatcher); the reconciler can still be started
		// alongside it and its periodic backstop remains available.
		return nil
	}
	return watcher.SetUpdateCallback(e.handleWatcherNotification)
}

// LoadModel reloads the model from the model CONF file.
func (e *SyncedEnforcer) LoadModel() error {
	e.m.Lock()
	defer e.m.Unlock()
	return e.Enforcer.LoadModel()
}

// ClearPolicy clears all policy.
func (e *SyncedEnforcer) ClearPolicy() {
	e.m.Lock()
	defer e.m.Unlock()
	e.Enforcer.ClearPolicy()
}

// GetSyncState returns an observability snapshot of the convergence machinery:
// how far the instance lags, when it last synced successfully, which storage
// version is served, and whether notifications are currently usable.
func (e *SyncedEnforcer) GetSyncState() SyncState {
	applied := atomic.LoadUint64(&e.appliedVersion)
	latest := atomic.LoadUint64(&e.latestVersion)
	var lag uint64
	if latest > applied {
		lag = latest - applied
	}
	e.statsMu.RLock()
	state := SyncState{
		AppliedVersion:            applied,
		LatestVersion:             latest,
		Lag:                       lag,
		LastSuccessfulSync:        e.lastSuccessfulSync,
		LastAttempt:               e.lastAttempt,
		ConsecutiveFailures:       e.consecutiveFailures,
		LastError:                 e.lastErr,
		NotificationMode:          syncModeName(atomic.LoadInt32(&e.notificationMode)),
		NotificationsReceived:     atomic.LoadUint64(&e.notificationsReceived),
		StaleNotificationsDropped: atomic.LoadUint64(&e.staleNotificationsDropped),
		ReconcilerRunning:         atomic.LoadInt32(&e.running) != 0,
	}
	e.statsMu.RUnlock()
	return state
}

// errLastReconcileFailure wraps a recorded reconciliation failure text into an
// error for the LoadPolicy compatibility surface.
func errLastReconcileFailure(text string) error {
	if text == "" {
		return errors.New("reconciliation failed without an error message")
	}
	return errors.New(text)
}
