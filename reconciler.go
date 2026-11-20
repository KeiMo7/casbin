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
	"hash/fnv"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/casbin/casbin/v3/model"
	"github.com/casbin/casbin/v3/persist"
)

// Notification modes reported by SyncState.
const (
	// SyncModeStopped: no reconciler has been started.
	SyncModeStopped = "reconciler-stopped"
	// SyncModeWatcher: the last successful convergence was driven by a
	// watcher notification.
	SyncModeWatcher = "watcher"
	// SyncModePeriodic: watcher notifications are missing or unusable,
	// convergence is currently guaranteed by periodic reconciliation.
	SyncModePeriodic = "periodic-reconcile"
)

// maxReconcileBackoff caps the retry backoff after consecutive pull failures.
// The base interval is never raised on its own; backoff applies only to failed
// attempts and is reset immediately after a success, so it bounds retry load
// instead of masking convergence problems.
const maxReconcileBackoff = 30 * time.Second

// SyncState is an observability snapshot of the policy convergence machinery.
type SyncState struct {
	// AppliedVersion is the storage version whose policy is currently
	// served. It is 0 when the adapter does not expose versions.
	AppliedVersion uint64
	// LatestVersion is the greatest version observed on the storage.
	// Lag is how many storage versions the instance is behind; it is 0
	// when the adapter does not expose versions.
	LatestVersion uint64
	Lag           uint64
	// LastSuccessfulSync is the last time a storage state was applied
	// (or confirmed identical to the one currently served).
	LastSuccessfulSync time.Time
	// LastAttempt is the last reconciliation attempt, successful or not.
	LastAttempt time.Time
	// ConsecutiveFailures is the number of failed pulls in a row; the
	// currently served policy stays available while it is non-zero.
	ConsecutiveFailures int
	LastError           string
	// NotificationMode tells whether convergence is watcher-driven or
	// degraded to periodic reconciliation.
	NotificationMode string
	// NotificationsReceived counts watcher notifications delivered to
	// the enforcer.
	NotificationsReceived uint64
	// StaleNotificationsDropped counts notifications discarded because
	// they carried a version no newer than the applied one.
	StaleNotificationsDropped uint64
	// ReconcilerRunning reports whether StartPolicyReconciler is active.
	ReconcilerRunning bool
}

// policyFingerprint hashes the full policy content (p and g sections of every
// assertion). Loaded policies are sorted by the adapter load path, so equal
// content hashes deterministically. It is the fallback ordering signal for
// adapters that do not implement persist.VersionedAdapter.
func policyFingerprint(m model.Model) uint64 {
	h := fnv.New64a()
	writeSection := func(sec string) {
		pts := make([]string, 0, len(m[sec]))
		for ptype := range m[sec] {
			pts = append(pts, ptype)
		}
		sort.Strings(pts)
		for _, ptype := range pts {
			ast := m[sec][ptype]
			_, _ = h.Write([]byte(sec))
			_, _ = h.Write([]byte(ptype))
			// PolicyVersion and other bookkeeping must not influence the
			// fingerprint; only the rule content matters.
			for _, rule := range ast.Policy {
				for _, token := range rule {
					_, _ = h.Write([]byte(token))
					_, _ = h.Write([]byte("|"))
				}
				_, _ = h.Write([]byte("\n"))
			}
			_, _ = h.Write([]byte("\x00"))
		}
	}
	writeSection("p")
	writeSection("g")
	return h.Sum64()
}

// reconcileOutcome records what one reconciliation attempt did, for metrics.
type reconcileOutcome int

const (
	outcomeApplied reconcileOutcome = iota
	outcomeUpToDate
	outcomeStaleRejected
	outcomeFailed
)

// reconcileState holds all bookkeeping of the SyncedEnforcer convergence loop.
// It is embedded by SyncedEnforcer so the fields live in one place.
type reconcileState struct {
	// appliedVersion is the storage version of the policy currently served.
	// Only meaningful for persist.VersionedAdapter; otherwise stays 0.
	appliedVersion uint64
	// latestVersion is the highest version ever read from the storage.
	latestVersion uint64
	// appliedFingerprint is the content fingerprint of the served policy,
	// used as the ordering signal for non-versioned adapters.
	appliedFingerprint uint64
	// lastSyncedRevision is the Enforcer localRevision captured at the last
	// storage-driven application. A newer revision means local mutations
	// happened since, so an otherwise identical storage fingerprint must
	// still be applied to reconcile those mutations.
	lastSyncedRevision uint64

	// reconcileMu serializes reconciliation attempts: watcher callbacks,
	// periodic ticks and explicit LoadPolicy calls coalesce behind it
	// instead of racing each other.
	reconcileMu sync.Mutex
	running     int32
	stop        chan struct{}
	// notifyCh is capacity-1: burst notifications coalesce, none can block
	// the watcher goroutine, and at least one wake-up always survives.
	notifyCh chan struct{}

	notificationsReceived     uint64
	staleNotificationsDropped uint64
	// statsMu guards the observability fields below, which are written by
	// the reconciler goroutine (and explicit LoadPolicy calls) and read by
	// GetSyncState from arbitrary other goroutines.
	statsMu                 sync.RWMutex
	consecutiveFailures     int
	lastSuccessfulSync      time.Time
	lastAttempt             time.Time
	lastErr                 string
	notificationMode        int32 // one of SyncMode* constants (atomic)
	hasPendingNotifyVersion bool
	pendingNotifyVersion    uint64
	pendingVersionMu        sync.Mutex
}

func (rs *reconcileState) initReconcileState() {
	rs.stop = make(chan struct{})
	rs.notifyCh = make(chan struct{}, 1)
	atomic.StoreInt32(&rs.notificationMode, syncModeIndex(SyncModeStopped))
}

func syncModeIndex(mode string) int32 {
	switch mode {
	case SyncModeWatcher:
		return 1
	case SyncModePeriodic:
		return 2
	default:
		return 0
	}
}

func syncModeName(idx int32) string {
	switch idx {
	case 1:
		return SyncModeWatcher
	case 2:
		return SyncModePeriodic
	default:
		return SyncModeStopped
	}
}

// queueNotification records an optional storage version carried by a watcher
// notification and wakes the reconciliation loop. It never blocks: repeated
// notifications while one is pending coalesce into a single wake-up, and the
// highest pending version is retained.
func (rs *reconcileState) queueNotification(version uint64, hasVersion bool) {
	atomic.AddUint64(&rs.notificationsReceived, 1)
	if hasVersion {
		rs.pendingVersionMu.Lock()
		if !rs.hasPendingNotifyVersion || version > rs.pendingNotifyVersion {
			rs.pendingNotifyVersion = version
			rs.hasPendingNotifyVersion = true
		}
		rs.pendingVersionMu.Unlock()
	}
	select {
	case rs.notifyCh <- struct{}{}:
	default:
	}
}

func (rs *reconcileState) takePendingNotification() (uint64, bool) {
	rs.pendingVersionMu.Lock()
	defer rs.pendingVersionMu.Unlock()
	v, ok := rs.pendingNotifyVersion, rs.hasPendingNotifyVersion
	rs.pendingNotifyVersion, rs.hasPendingNotifyVersion = 0, false
	return v, ok
}

// requeuePendingVersion restores a notification version that could not be
// served yet (e.g. the storage read hit a lagging replica). The wake-up
// channel is deliberately not re-armed: the periodic ticker retries with the
// retained version, which avoids a hot retry loop while the replica lags.
func (rs *reconcileState) requeuePendingVersion(version uint64) {
	rs.pendingVersionMu.Lock()
	if !rs.hasPendingNotifyVersion || version > rs.pendingNotifyVersion {
		rs.pendingNotifyVersion = version
		rs.hasPendingNotifyVersion = true
	}
	rs.pendingVersionMu.Unlock()
}

// adapterStorageVersion queries the storage version when the adapter supports
// it. The boolean is false for plain adapters, in which case content
// fingerprints are the ordering signal.
func adapterStorageVersion(adapter persist.Adapter) (uint64, bool, error) {
	va, ok := adapter.(persist.VersionedAdapter)
	if !ok {
		return 0, false, nil
	}
	v, err := va.LoadPolicyVersion()
	return v, true, err
}

// formatVersion renders an optional storage version for log/metrics use.
func formatVersion(v uint64, versioned bool) string {
	if !versioned {
		return "n/a"
	}
	return strconv.FormatUint(v, 10)
}
