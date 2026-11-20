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
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/casbin/casbin/v3/model"
	"github.com/casbin/casbin/v3/persist"
	"github.com/casbin/casbin/v3/rbac"
)

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

// memoryVersionedAdapter is an in-memory, concurrency-safe, full-state
// adapter with a persistence-backed monotonic version. Every successful write
// bumps the version exactly once and atomically with the content.
type memoryVersionedAdapter struct {
	mu        sync.RWMutex
	text      string
	version   uint64
	failUntil uint32 // number of LoadPolicy calls that must fail first
	calls     uint32
}

func (a *memoryVersionedAdapter) LoadPolicy(m model.Model) error {
	call := atomic.AddUint32(&a.calls, 1)
	if f := atomic.LoadUint32(&a.failUntil); call <= f {
		return errors.New("injected storage failure")
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	for _, line := range splitNonEmptyLines(a.text) {
		if err := persist.LoadPolicyLine(line, m); err != nil {
			return err
		}
	}
	return nil
}

func (a *memoryVersionedAdapter) SavePolicy(m model.Model) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	var buf []byte
	writeSection := func(sec string) {
		for ptype, ast := range m[sec] {
			for _, rule := range ast.Policy {
				line, err := persist.PolicyLineToCsv(ptype, rule)
				if err != nil {
					panic(err)
				}
				buf = append(buf, line...)
				buf = append(buf, '\n')
			}
		}
	}
	writeSection("p")
	writeSection("g")
	a.text = string(buf)
	a.version++
	return nil
}

func (a *memoryVersionedAdapter) LoadPolicyVersion() (uint64, error) {
	call := atomic.AddUint32(&a.calls, 1)
	if f := atomic.LoadUint32(&a.failUntil); call <= f {
		return 0, errors.New("injected storage failure")
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.version, nil
}

func (a *memoryVersionedAdapter) setText(text string) uint64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.text = text
	a.version++
	return a.version
}

func (a *memoryVersionedAdapter) forceVersion(v uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.version = v
}

func (a *memoryVersionedAdapter) snapshot() (string, uint64) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.text, a.version
}

// Incremental Adapter methods: the tests drive storage through setText and
// SavePolicy, so auto-save hooks are accepted but treated as no-ops.
func (a *memoryVersionedAdapter) AddPolicy(string, string, []string) error { return nil }
func (a *memoryVersionedAdapter) RemovePolicy(string, string, []string) error {
	return nil
}
func (a *memoryVersionedAdapter) RemoveFilteredPolicy(string, string, int, ...string) error {
	return nil
}

// controllableVersionedWatcher delivers notifications explicitly and can
// simulate loss, duplication and reordering.
type controllableVersionedWatcher struct {
	mu       sync.Mutex
	callback func(uint64)
	closed   bool
}

func (w *controllableVersionedWatcher) SetUpdateCallback(func(string)) error { return nil }

func (w *controllableVersionedWatcher) SetVersionedUpdateCallback(cb func(uint64)) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.callback = cb
	return nil
}

func (w *controllableVersionedWatcher) Update() error { return nil }
func (w *controllableVersionedWatcher) Close() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.closed = true
}

func (w *controllableVersionedWatcher) emit(version uint64) {
	w.mu.Lock()
	cb := w.callback
	w.mu.Unlock()
	if cb != nil {
		cb(version)
	}
}

// plainControllableWatcher is a non-versioned Watcher for the fallback path.
type plainControllableWatcher struct {
	mu       sync.Mutex
	callback func(string)
}

func (w *plainControllableWatcher) SetUpdateCallback(cb func(string)) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.callback = cb
	return nil
}
func (w *plainControllableWatcher) Update() error { return nil }
func (w *plainControllableWatcher) Close()        {}
func (w *plainControllableWatcher) emit() {
	w.mu.Lock()
	cb := w.callback
	w.mu.Unlock()
	if cb != nil {
		cb("")
	}
}

func splitNonEmptyLines(text string) []string {
	var lines []string
	start := 0
	for i := 0; i <= len(text); i++ {
		if i == len(text) || text[i] == '\n' {
			line := text[start:i]
			if len(line) > 0 {
				lines = append(lines, line)
			}
			start = i + 1
		}
	}
	return lines
}

const testBasicModel = "examples/basic_model.conf"

func newTestSynced(t *testing.T, text string) (*SyncedEnforcer, *memoryVersionedAdapter, *controllableVersionedWatcher) {
	t.Helper()
	a := &memoryVersionedAdapter{text: text, version: 1}
	e, err := NewSyncedEnforcer(testBasicModel, a)
	if err != nil {
		t.Fatalf("NewSyncedEnforcer: %v", err)
	}
	w := &controllableVersionedWatcher{}
	if err := e.SetWatcher(w); err != nil {
		t.Fatalf("SetWatcher: %v", err)
	}
	return e, a, w
}

func waitFor(t *testing.T, timeout time.Duration, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for: %s", msg)
}

// ---------------------------------------------------------------------------
// 1. Lost notification: bounded self-healing convergence
// ---------------------------------------------------------------------------

func TestReconcile_LostNotificationConverges(t *testing.T) {
	e, a, _ := newTestSynced(t, "p, alice, data1, read\np, bob, data2, write\n")
	// 100ms interval gives an explicit upper bound of ~100ms for self-heal.
	e.StartPolicyReconciler(ReconcilerConfig{Interval: 100 * time.Millisecond})
	defer e.StopPolicyReconciler()

	ok, err := e.Enforce("alice", "data1", "read")
	if err != nil || !ok {
		t.Fatalf("initial enforce = %v, %v", ok, err)
	}

	// Storage changes, but the notification is deliberately never emitted.
	a.setText("p, alice, data1, read\np, bob, data2, write\np, carol, data3, read\n")
	start := time.Now()
	waitFor(t, time.Second, func() bool {
		res, _ := e.Enforce("carol", "data3", "read")
		return res
	}, "convergence after lost notification")
	elapsed := time.Since(start)

	state := e.GetSyncState()
	if state.AppliedVersion != state.LatestVersion || state.Lag != 0 {
		t.Fatalf("lag not cleared: %+v", state)
	}
	t.Logf("lost-notification self-heal took %v (bound = 100ms interval), applied v%d", elapsed, state.AppliedVersion)
}

// ---------------------------------------------------------------------------
// 2. Out-of-order notifications: stale versions are dropped
// ---------------------------------------------------------------------------

func TestReconcile_OutOfOrderNotificationsDropped(t *testing.T) {
	e, a, w := newTestSynced(t, "p, alice, data1, read\n")
	e.StartPolicyReconciler(ReconcilerConfig{Interval: 10 * time.Second}) // long tick: watcher is the only trigger
	defer e.StopPolicyReconciler()

	v2 := a.setText("p, alice, data1, read\np, bob, data2, write\n")
	v3 := a.setText("p, alice, data1, read\np, bob, data2, write\np, carol, data3, read\n")

	// Notifications arrive out of order: v3 first, then the stale v2.
	w.emit(v3)
	waitFor(t, time.Second, func() bool {
		res, _ := e.Enforce("carol", "data3", "read")
		return res
	}, "apply v3")

	w.emit(v2) // must be dropped without any reload
	time.Sleep(50 * time.Millisecond)

	ok, _ := e.Enforce("carol", "data3", "read")
	if !ok {
		t.Fatal("stale v2 notification overwrote v3 state")
	}
	state := e.GetSyncState()
	if state.AppliedVersion != v3 {
		t.Fatalf("applied version = %d, want %d", state.AppliedVersion, v3)
	}
	if state.StaleNotificationsDropped != 1 {
		t.Fatalf("stale drop count = %d, want 1", state.StaleNotificationsDropped)
	}
	// The stale v2 notification is dropped at the enforcer boundary and
	// never reaches the coalescing queue, so only the v3 wake-up is counted.
	if state.NotificationsReceived != 1 {
		t.Fatalf("notifications received = %d, want 1", state.NotificationsReceived)
	}
}

// ---------------------------------------------------------------------------
// 2b. Monotonicity: a storage that reports an older version is rejected
// ---------------------------------------------------------------------------

func TestReconcile_VersionRollbackRejected(t *testing.T) {
	e, a, w := newTestSynced(t, "p, alice, data1, read\np, bob, data2, write\n")
	e.StartPolicyReconciler(ReconcilerConfig{Interval: 10 * time.Second})
	defer e.StopPolicyReconciler()

	current, _ := a.snapshot()
	v2 := a.setText(current + "p, carol, data3, read\n")
	w.emit(v2)
	waitFor(t, time.Second, func() bool {
		res, _ := e.Enforce("carol", "data3", "read")
		return res
	}, "apply v2")

	// Storage "restores" an older snapshot and reports a lower version.
	a.forceVersion(1)
	a.setText("p, alice, data1, read\n")
	w.emit(1)
	time.Sleep(100 * time.Millisecond)

	ok, _ := e.Enforce("carol", "data3", "read")
	if !ok {
		t.Fatal("rolled-back storage version was applied")
	}
	if got := e.GetSyncState().AppliedVersion; got != v2 {
		t.Fatalf("applied version = %d, want stay at %d", got, v2)
	}
}

// ---------------------------------------------------------------------------
// 3/4. Concurrent change + enforce: no intermediate state, full ruleset only
// ---------------------------------------------------------------------------

func TestReconcile_ConcurrentEnforceNoIntermediateState(t *testing.T) {
	base := "p, alice, data1, read\np, bob, data2, write\n"
	a := &memoryVersionedAdapter{text: base, version: 1}
	e, err := NewSyncedEnforcer(testBasicModel, a)
	if err != nil {
		t.Fatal(err)
	}
	w := &plainControllableWatcher{}
	if err := e.SetWatcher(w); err != nil {
		t.Fatal(err)
	}
	e.StartPolicyReconciler(ReconcilerConfig{Interval: 5 * time.Millisecond})
	defer e.StopPolicyReconciler()

	// Each generation swaps two rules together: the pair (carol read, dave
	// write) must appear and disappear atomically — never exactly one.
	// Every check samples both decisions under the same read lock so a
	// generation switch between the two calls cannot masquerade as an
	// intermediate state.
	var generation uint32
	go func() {
		for i := 0; i < 40; i++ {
			g := atomic.AddUint32(&generation, 1)
			if g%2 == 1 {
				a.setText(base + "p, carol, data3, read\np, dave, data4, write\n")
			} else {
				a.setText(base)
			}
			w.emit()
			time.Sleep(2 * time.Millisecond)
		}
	}()

	stop := time.Now().Add(2 * time.Second)
	var checks uint64
	for time.Now().Before(stop) {
		// Single critical section per sample: RLock makes the two decisions
		// observe one immutable generation each.
		e.m.RLock()
		carol, err1 := e.Enforcer.Enforce("carol", "data3", "read")
		dave, err2 := e.Enforcer.Enforce("dave", "data4", "write")
		alice, err3 := e.Enforcer.Enforce("alice", "data1", "read")
		e.m.RUnlock()
		if err1 != nil || err2 != nil || err3 != nil {
			t.Fatalf("enforce errors: %v %v %v", err1, err2, err3)
		}
		if carol != dave {
			t.Fatalf("intermediate state observed: carol=%v dave=%v (half-applied ruleset)", carol, dave)
		}
		// Stable rules must remain correct throughout.
		if !alice {
			t.Fatal("stable rule regressed: alice denied")
		}
		checks++
	}
	t.Logf("observed %d locked enforce samples with zero intermediate states", checks)
}

// Multi-rule atomicity via a versioned watcher: same assertion, g + p rules.
func TestReconcile_MultiRuleAtomicSwitch(t *testing.T) {
	e, a, w := newTestSynced(t, "p, alice, data1, read\n")
	e.StartPolicyReconciler(ReconcilerConfig{Interval: 10 * time.Second})
	defer e.StopPolicyReconciler()

	// Two rules added in one storage state; readers may see neither or both.
	v := a.setText("p, alice, data1, read\np, bob, data2, write\np, carol, data3, read\n")
	w.emit(v)
	waitFor(t, time.Second, func() bool {
		bob, _ := e.Enforce("bob", "data2", "write")
		carol, _ := e.Enforce("carol", "data3", "read")
		return bob && carol
	}, "both rules visible together")
}

// ---------------------------------------------------------------------------
// 5. Decision cache never serves a conclusion computed under an older version
// ---------------------------------------------------------------------------

func TestReconcile_CacheDoesNotCrossVersions(t *testing.T) {
	a := &memoryVersionedAdapter{text: "p, alice, data1, read\n", version: 1}

	ce, err := NewCachedEnforcer(testBasicModel, a)
	if err != nil {
		t.Fatal(err)
	}
	// Drive the cached enforcer through the same convergence path manually
	// by sharing the storage adapter: bump storage, then LoadPolicy on ce.
	if ok, _ := ce.Enforce("alice", "data1", "read"); !ok {
		t.Fatal("initial cached enforce wrong")
	}
	if ok, _ := ce.Enforce("bob", "data2", "write"); ok {
		t.Fatal("bob should initially be denied")
	}

	a.setText("p, alice, data1, read\np, bob, data2, write\n")
	if err := ce.LoadPolicy(); err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	// The old denial must not survive the version switch.
	if ok, _ := ce.Enforce("bob", "data2", "write"); !ok {
		t.Fatal("cached denial from old policy survived version switch")
	}

	// And on the synced cached enforcer under concurrent reloads.
	sce, err := NewSyncedCachedEnforcer(testBasicModel, a)
	if err != nil {
		t.Fatal(err)
	}
	sce.StartPolicyReconciler(ReconcilerConfig{Interval: 5 * time.Millisecond})
	defer sce.StopPolicyReconciler()
	v2 := a.setText("p, alice, data1, read\n")
	w2 := &controllableVersionedWatcher{}
	if err := sce.SetWatcher(w2); err != nil {
		t.Fatal(err)
	}
	w2.emit(v2)
	waitFor(t, time.Second, func() bool {
		res, _ := sce.Enforce("bob", "data2", "write")
		return !res
	}, "cache converges after removal")
}

// ---------------------------------------------------------------------------
// 6. No decision oscillation for the same request during rapid changes
// ---------------------------------------------------------------------------

func TestReconcile_NoOscillationForSameRequest(t *testing.T) {
	// A single monotonic sequence of storage versions; each applied state
	// must move forward exactly once, and repeated identical requests must
	// not flip while no storage change is in flight.
	e, a, w := newTestSynced(t, "p, alice, data1, read\n")
	e.StartPolicyReconciler(ReconcilerConfig{Interval: 10 * time.Second})
	defer e.StopPolicyReconciler()
	for gen := uint64(2); gen <= 6; gen++ {
		text := "p, alice, data1, read\n"
		if gen%2 == 0 {
			text += "p, bob, data2, write\n"
		}
		v := a.setText(text)
		// Duplicate + stale notifications must not cause extra switches.
		w.emit(v)
		w.emit(v)
		w.emit(gen - 1)
		waitFor(t, time.Second, func() bool {
			return e.GetSyncState().AppliedVersion == v
		}, fmt.Sprintf("converge to v%d", v))

		first, _ := e.Enforce("bob", "data2", "write")
		for i := 0; i < 50; i++ {
			got, _ := e.Enforce("bob", "data2", "write")
			if got != first {
				t.Fatalf("decision oscillated at rest for v%d: %v -> %v", v, first, got)
			}
		}
	}
	state := e.GetSyncState()
	if state.StaleNotificationsDropped < 5 {
		t.Fatalf("expected stale drops, got %d", state.StaleNotificationsDropped)
	}
}

// ---------------------------------------------------------------------------
// 7. Observability: lag, last sync time, current version
// ---------------------------------------------------------------------------

func TestReconcile_ObservabilityState(t *testing.T) {
	e, a, w := newTestSynced(t, "p, alice, data1, read\n")
	before := time.Now()
	e.StartPolicyReconciler(ReconcilerConfig{Interval: 10 * time.Second})
	defer e.StopPolicyReconciler()

	v := a.setText("p, alice, data1, read\np, bob, data2, write\n")
	// The notification announces v2 before any pull, so the lag must be
	// observable immediately even though nothing has been applied yet.
	w.emit(v)
	waitFor(t, time.Second, func() bool {
		s := e.GetSyncState()
		return s.LatestVersion == v && s.Lag == v-s.AppliedVersion
	}, "lag visible before application")
	waitFor(t, time.Second, func() bool {
		s := e.GetSyncState()
		return s.AppliedVersion == v && s.Lag == 0
	}, "lag cleared")

	state := e.GetSyncState()
	if !state.ReconcilerRunning {
		t.Fatal("ReconcilerRunning should be true")
	}
	if state.LastSuccessfulSync.Before(before) {
		t.Fatal("LastSuccessfulSync not recorded")
	}
	if state.NotificationMode != SyncModeWatcher {
		t.Fatalf("mode = %q, want %q", state.NotificationMode, SyncModeWatcher)
	}
	t.Logf("sync state: applied=%d latest=%d lag=%d mode=%s notif=%d dropped=%d lastSync=%s",
		state.AppliedVersion, state.LatestVersion, state.Lag, state.NotificationMode,
		state.NotificationsReceived, state.StaleNotificationsDropped, state.LastSuccessfulSync.Format(time.RFC3339Nano))
}

// ---------------------------------------------------------------------------
// 8. Multi-instance eventual consistency with a bounded window
// ---------------------------------------------------------------------------

func TestReconcile_MultiInstanceEventualConsistency(t *testing.T) {
	a1 := &memoryVersionedAdapter{text: "p, alice, data1, read\n", version: 1}
	a2 := &memoryVersionedAdapter{text: "p, alice, data1, read\n", version: 1}
	a3 := &memoryVersionedAdapter{text: "p, alice, data1, read\n", version: 1}
	instances := make([]*SyncedEnforcer, 3)
	watchers := make([]*controllableVersionedWatcher, 3)
	for i, ad := range []*memoryVersionedAdapter{a1, a2, a3} {
		e, err := NewSyncedEnforcer(testBasicModel, ad)
		if err != nil {
			t.Fatal(err)
		}
		w := &controllableVersionedWatcher{}
		if err := e.SetWatcher(w); err != nil {
			t.Fatal(err)
		}
		// 80ms periodic backstop for all instances.
		e.StartPolicyReconciler(ReconcilerConfig{Interval: 80 * time.Millisecond})
		instances[i], watchers[i] = e, w
	}
	defer func() {
		for _, e := range instances {
			e.StopPolicyReconciler()
		}
	}()

	// Simulate the incident: instance 1 gets the notification, instance 2's
	// notification is lost, instance 3 gets it late/out of order.
	newText := "p, alice, data1, read\np, bob, data2, write\n"
	v := a1.setText(newText)
	a2.setText(newText)
	a3.setText(newText)
	watchers[0].emit(v)
	// instance 1: no notification
	watchers[2].emit(v - 1) // stale first
	watchers[2].emit(v)     // correct one later

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		allConverged := true
		for i, e := range instances {
			ok, _ := e.Enforce("bob", "data2", "write")
			if !ok {
				allConverged = false
			}
			if s := e.GetSyncState(); s.AppliedVersion != v {
				allConverged = false
			}
			_ = i
		}
		if allConverged {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	for i, e := range instances {
		s := e.GetSyncState()
		if s.AppliedVersion != v || s.Lag != 0 {
			t.Fatalf("instance %d did not converge within bound: %+v", i, s)
		}
		ok, _ := e.Enforce("bob", "data2", "write")
		if !ok {
			t.Fatalf("instance %d still serving old policy", i)
		}
	}
}

// ---------------------------------------------------------------------------
// 9. Restart: recovery from persistence never goes backwards
// ---------------------------------------------------------------------------

func TestReconcile_RestartRecoversLatestVersion(t *testing.T) {
	a := &memoryVersionedAdapter{
		text:    "p, alice, data1, read\np, bob, data2, write\n",
		version: 7, // storage is ahead of any fresh in-memory snapshot
	}
	e, err := NewSyncedEnforcer(testBasicModel, a)
	if err != nil {
		t.Fatal(err)
	}
	state := e.GetSyncState()
	if state.AppliedVersion != 7 {
		t.Fatalf("fresh enforcer baseline version = %d, want storage v7", state.AppliedVersion)
	}
	ok, _ := e.Enforce("bob", "data2", "write")
	if !ok {
		t.Fatal("restarted enforcer did not recover stored policy content")
	}

	// Simulate process restart: brand new enforcer on the same persistence.
	e2, err := NewSyncedEnforcer(testBasicModel, a)
	if err != nil {
		t.Fatal(err)
	}
	if s := e2.GetSyncState(); s.AppliedVersion != 7 {
		t.Fatalf("restart regressed to version %d", s.AppliedVersion)
	}
}

// ---------------------------------------------------------------------------
// 10. High-frequency concurrent change + enforce: no deadlock/livelock
// ---------------------------------------------------------------------------

func TestReconcile_HighFrequencyNoDeadlock(t *testing.T) {
	base := "p, alice, data1, read\n"
	a := &memoryVersionedAdapter{text: base, version: 1}
	e, err := NewSyncedEnforcer(testBasicModel, a)
	if err != nil {
		t.Fatal(err)
	}
	w := &plainControllableWatcher{}
	_ = e.SetWatcher(w)
	e.StartPolicyReconciler(ReconcilerConfig{Interval: 2 * time.Millisecond})
	defer e.StopPolicyReconciler()

	var writers, readers sync.WaitGroup
	stop := make(chan struct{})
	for wn := 0; wn < 4; wn++ {
		writers.Add(1)
		go func(id int) {
			defer writers.Done()
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				text := base + fmt.Sprintf("p, user%d, data%d, read\n", id, i%5)
				a.setText(text)
				w.emit()
			}
		}(wn)
	}
	for rn := 0; rn < runtime.NumCPU()*2; rn++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				if _, err := e.Enforce("alice", "data1", "read"); err != nil {
					t.Errorf("enforce error: %v", err)
					return
				}
			}
		}()
	}
	time.Sleep(3 * time.Second)
	close(stop)
	done := make(chan struct{})
	go func() {
		writers.Wait()
		readers.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("deadlock/livelock suspected: goroutines did not stop in time")
	}
	state := e.GetSyncState()
	t.Logf("high-frequency run finished: applied v%d, failures=%d, mode=%s",
		state.AppliedVersion, state.ConsecutiveFailures, state.NotificationMode)
}

// ---------------------------------------------------------------------------
// Failure/degradation 1: pull failure keeps current state, retries with cap
// ---------------------------------------------------------------------------

func TestReconcile_PullFailureKeepsStateAndRetries(t *testing.T) {
	e, a, w := newTestSynced(t, "p, alice, data1, read\n")
	e.StartPolicyReconciler(ReconcilerConfig{Interval: 20 * time.Millisecond})
	defer e.StopPolicyReconciler()

	atomic.StoreUint32(&a.failUntil, 5) // next five storage calls fail
	v := a.setText("p, alice, data1, read\np, bob, data2, write\n")
	w.emit(v)

	// Current state stays fully available while storage is failing.
	ok, _ := e.Enforce("alice", "data1", "read")
	if !ok {
		t.Fatal("current policy became unavailable during storage outage")
	}
	waitFor(t, 3*time.Second, func() bool {
		return e.GetSyncState().ConsecutiveFailures > 0
	}, "failure counted")

	// Once failures are exhausted, bounded retry converges automatically.
	waitFor(t, 3*time.Second, func() bool {
		res, _ := e.Enforce("bob", "data2", "write")
		return res && e.GetSyncState().AppliedVersion == v
	}, "retry convergence after outage")
	s := e.GetSyncState()
	if s.ConsecutiveFailures != 0 || s.LastError != "" {
		t.Fatalf("failure state not reset after recovery: %+v", s)
	}
}

// ---------------------------------------------------------------------------
// Failure/degradation 2: failed application rolls back to the complete state
// ---------------------------------------------------------------------------

// rollbackAdapter fails LoadPolicy mid-way before populating the model,
// exercising the "failed pull leaves the served state untouched" path.
type rollbackAdapter struct {
	memoryVersionedAdapter
	failNext int32
}

func (a *rollbackAdapter) LoadPolicy(m model.Model) error {
	if atomic.LoadInt32(&a.failNext) != 0 {
		atomic.StoreInt32(&a.failNext, 0)
		return errors.New("injected mid-load failure")
	}
	return a.memoryVersionedAdapter.LoadPolicy(m)
}

func (a *rollbackAdapter) LoadPolicyVersion() (uint64, error) {
	// Version probing never consumes the injected failure; only the actual
	// policy load fails, exercising the rollback path after a successful
	// version read.
	return a.memoryVersionedAdapter.LoadPolicyVersion()
}

func TestReconcile_FailedApplyRollsBack(t *testing.T) {
	ra := &rollbackAdapter{}
	ra.text = "p, alice, data1, read\n"
	ra.version = 1
	e, err := NewSyncedEnforcer(testBasicModel, ra)
	if err != nil {
		t.Fatal(err)
	}
	w := &plainControllableWatcher{}
	_ = e.SetWatcher(w)
	e.StartPolicyReconciler(ReconcilerConfig{Interval: 10 * time.Millisecond})
	defer e.StopPolicyReconciler()

	// The next pull fails mid-load: the served complete state must remain
	// untouched, and the bounded retry loop converges on its own.
	atomic.StoreInt32(&ra.failNext, 1)
	ra.setText("p, alice, data1, read\np, bob, data2, write\n")
	w.emit()
	if ok, _ := e.Enforce("alice", "data1", "read"); !ok {
		t.Fatal("previous complete state lost after failed application")
	}
	waitFor(t, 2*time.Second, func() bool {
		res, _ := e.Enforce("bob", "data2", "write")
		return res
	}, "converges after the failed attempt is retried")
}

// ---------------------------------------------------------------------------
// Failure/degradation 3: unavailable notifications degrade to periodic mode
// ---------------------------------------------------------------------------

func TestReconcile_DegradedModeMarked(t *testing.T) {
	e, a, w := newTestSynced(t, "p, alice, data1, read\n")
	e.StartPolicyReconciler(ReconcilerConfig{Interval: 30 * time.Millisecond})
	defer e.StopPolicyReconciler()

	// Watcher works first.
	v := a.setText("p, alice, data1, read\np, bob, data2, write\n")
	w.emit(v)
	waitFor(t, time.Second, func() bool {
		return e.GetSyncState().NotificationMode == SyncModeWatcher
	}, "watcher mode")

	// Notification channel goes silent: periodic reconciliation must still
	// converge and expose the degraded marker.
	v2 := a.setText("p, alice, data1, read\np, bob, data2, write\np, carol, data3, read\n")
	waitFor(t, 2*time.Second, func() bool {
		s := e.GetSyncState()
		return s.AppliedVersion == v2 && s.NotificationMode == SyncModePeriodic
	}, "periodic degraded convergence")
}

// failingRM wraps a RoleManager and fails Clear on demand so role-link
// rebuild failures can be exercised deterministically.
type failingRM struct {
	inner     rbac.RoleManager
	failClear int32
}

func (rm *failingRM) Clear() error {
	if atomic.LoadInt32(&rm.failClear) != 0 {
		return errors.New("injected role manager clear failure")
	}
	return rm.inner.Clear()
}
func (rm *failingRM) AddLink(n1, n2 string, domain ...string) error {
	return rm.inner.AddLink(n1, n2, domain...)
}
func (rm *failingRM) BuildRelationship(n1, n2 string, domain ...string) error {
	return rm.inner.BuildRelationship(n1, n2, domain...)
}
func (rm *failingRM) DeleteLink(n1, n2 string, domain ...string) error {
	return rm.inner.DeleteLink(n1, n2, domain...)
}
func (rm *failingRM) HasLink(n1, n2 string, domain ...string) (bool, error) {
	return rm.inner.HasLink(n1, n2, domain...)
}
func (rm *failingRM) GetRoles(name string, domain ...string) ([]string, error) {
	return rm.inner.GetRoles(name, domain...)
}
func (rm *failingRM) GetUsers(name string, domain ...string) ([]string, error) {
	return rm.inner.GetUsers(name, domain...)
}
func (rm *failingRM) GetImplicitRoles(name string, domain ...string) ([]string, error) {
	return rm.inner.GetImplicitRoles(name, domain...)
}
func (rm *failingRM) GetImplicitUsers(name string, domain ...string) ([]string, error) {
	return rm.inner.GetImplicitUsers(name, domain...)
}
func (rm *failingRM) GetDomains(name string) ([]string, error) { return rm.inner.GetDomains(name) }
func (rm *failingRM) GetAllDomains() ([]string, error)         { return rm.inner.GetAllDomains() }
func (rm *failingRM) PrintRoles() error                        { return rm.inner.PrintRoles() }
func (rm *failingRM) Match(s, p string) bool                   { return rm.inner.Match(s, p) }
func (rm *failingRM) AddMatchingFunc(name string, fn rbac.MatchingFunc) {
	rm.inner.AddMatchingFunc(name, fn)
}
func (rm *failingRM) AddDomainMatchingFunc(name string, fn rbac.MatchingFunc) {
	rm.inner.AddDomainMatchingFunc(name, fn)
}
func (rm *failingRM) DeleteDomain(domain string) error { return rm.inner.DeleteDomain(domain) }

func TestReconcile_RoleLinkRebuildFailureRollsBack(t *testing.T) {
	// RBAC model so a role manager exists and role links are rebuilt on
	// every convergence application.
	a := &memoryVersionedAdapter{
		text:    "p, admin, data1, read\ng, alice, admin\n",
		version: 1,
	}
	e, err := NewSyncedEnforcer("examples/rbac_model.conf", a)
	if err != nil {
		t.Fatal(err)
	}
	fr := &failingRM{inner: e.GetRoleManager()}
	e.SetRoleManager(fr)
	// Re-wire the assertion's RM pointer so model.BuildRoleLinks uses the
	// failing wrapper too.
	e.model["g"]["g"].RM = fr

	ok, err := e.Enforce("alice", "data1", "read")
	if err != nil || !ok {
		t.Fatalf("initial RBAC enforce = %v, %v", ok, err)
	}

	atomic.StoreInt32(&fr.failClear, 1)
	a.setText("p, admin, data1, read\np, admin, data2, write\ng, alice, admin\n")
	if err := e.LoadPolicy(); err == nil {
		t.Fatal("expected LoadPolicy to fail when role-link rebuild fails")
	}
	// The previous complete state must still be served, not a half-applied one.
	ok, err = e.Enforce("alice", "data1", "read")
	if err != nil || !ok {
		t.Fatalf("previous state lost after failed apply: %v, %v", ok, err)
	}

	atomic.StoreInt32(&fr.failClear, 0)
	if err := e.LoadPolicy(); err != nil {
		t.Fatalf("retry LoadPolicy: %v", err)
	}
	ok, _ = e.Enforce("alice", "data2", "write")
	if !ok {
		t.Fatal("new policy not visible after successful retry")
	}
}

// laggingReplicaAdapter simulates a stale storage replica: for a number of
// version reads it still reports the old version even though the write has
// landed, then catches up and reports the new version alongside new content.
type laggingReplicaAdapter struct {
	memoryVersionedAdapter
	lagReads int32
}

func (a *laggingReplicaAdapter) LoadPolicyVersion() (uint64, error) {
	if remaining := atomic.AddInt32(&a.lagReads, -1); remaining >= 0 {
		// Replica lag: report the previous version (current content's
		// version) while the new write is not yet visible on this replica.
		a.mu.RLock()
		defer a.mu.RUnlock()
		return a.version - 1, nil
	}
	return a.memoryVersionedAdapter.LoadPolicyVersion()
}

func TestReconcile_LaggingReplicaRetriesWithoutBackoff(t *testing.T) {
	la := &laggingReplicaAdapter{}
	la.text = "p, alice, data1, read\n"
	la.version = 2 // next write will be v3; lag reads report v2
	atomic.StoreInt32(&la.lagReads, 2)
	e, err := NewSyncedEnforcer(testBasicModel, la)
	if err != nil {
		t.Fatal(err)
	}
	w := &controllableVersionedWatcher{}
	if err := e.SetWatcher(w); err != nil {
		t.Fatal(err)
	}
	e.StartPolicyReconciler(ReconcilerConfig{Interval: 30 * time.Millisecond})
	defer e.StopPolicyReconciler()

	// Notification for v3 arrives while the replica still reports v2.
	v3 := la.setText("p, alice, data1, read\np, bob, data2, write\n")
	if v3 != 3 {
		t.Fatalf("unexpected version %d", v3)
	}
	w.emit(v3)

	// Once the replica catches up, convergence must happen at the normal
	// cadence; the served state must never have jumped to a partial view.
	waitFor(t, 2*time.Second, func() bool {
		res, _ := e.Enforce("bob", "data2", "write")
		return res && e.GetSyncState().AppliedVersion == v3
	}, "converge after replica catches up")
	if s := e.GetSyncState(); s.ConsecutiveFailures != 0 {
		t.Fatalf("lagging replica counted as transport failure: %+v", s)
	}
}

// ---------------------------------------------------------------------------
// No-regression: auto-load switch stays opt-in, no goroutine before Start
// ---------------------------------------------------------------------------
func TestReconciler_DoesNotStartAutomatically(t *testing.T) {
	e, _, _ := newTestSynced(t, "p, alice, data1, read\n")
	if e.IsReconcilerRunning() {
		t.Fatal("reconciler must not run before explicit start")
	}
	if mode := e.GetSyncState().NotificationMode; mode != SyncModeStopped {
		t.Fatalf("mode = %q, want %q", mode, SyncModeStopped)
	}
	e.StartPolicyReconciler(ReconcilerConfig{Interval: 10 * time.Millisecond})
	if !e.IsReconcilerRunning() {
		t.Fatal("reconciler not running after start")
	}
	e.StopPolicyReconciler()
	if e.IsReconcilerRunning() {
		t.Fatal("reconciler still running after stop")
	}
	// Restart works cleanly.
	e.StartPolicyReconciler(ReconcilerConfig{Interval: 10 * time.Millisecond})
	if !e.IsReconcilerRunning() {
		t.Fatal("reconciler failed to restart")
	}
	e.StopPolicyReconciler()
}
