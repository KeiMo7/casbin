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
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// BenchmarkEnforceDuringReconciliation measures steady-state Enforce
// throughput while the reconciler continuously applies new policy versions.
// Every switch is atomic, so readers never block on a half-applied policy.
func BenchmarkEnforceDuringReconciliation(b *testing.B) {
	base := "p, alice, data1, read\np, bob, data2, write\n"
	a := &memoryVersionedAdapter{text: base, version: 1}
	e, err := NewSyncedEnforcer(testBasicModel, a)
	if err != nil {
		b.Fatal(err)
	}
	w := &plainControllableWatcher{}
	if err := e.SetWatcher(w); err != nil {
		b.Fatal(err)
	}
	e.StartPolicyReconciler(ReconcilerConfig{Interval: 2 * time.Millisecond})
	defer e.StopPolicyReconciler()

	stop := make(chan struct{})
	var writerWG sync.WaitGroup
	writerWG.Add(1)
	go func() {
		defer writerWG.Done()
		i := 0
		for {
			select {
			case <-stop:
				return
			default:
			}
			a.setText(fmt.Sprintf("%sp, user%d, data%d, read\n", base, i%8, i%4))
			w.emit()
			i++
		}
	}()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if ok, err := e.Enforce("alice", "data1", "read"); err != nil || !ok {
				b.Fatalf("unexpected enforce result ok=%v err=%v", ok, err)
			}
		}
	})
	b.StopTimer()
	close(stop)
	writerWG.Wait()
}

// BenchmarkCachedEnforceDuringReconciliation measures cached decision
// throughput under continuous version switches; version-prefixed keys make
// cache invalidation atomic without Clear() contention.
func BenchmarkCachedEnforceDuringReconciliation(b *testing.B) {
	base := "p, alice, data1, read\np, bob, data2, write\n"
	a := &memoryVersionedAdapter{text: base, version: 1}
	e, err := NewSyncedCachedEnforcer(testBasicModel, a)
	if err != nil {
		b.Fatal(err)
	}
	w := &plainControllableWatcher{}
	if err := e.SetWatcher(w); err != nil {
		b.Fatal(err)
	}
	e.StartPolicyReconciler(ReconcilerConfig{Interval: 2 * time.Millisecond})
	defer e.StopPolicyReconciler()

	stop := make(chan struct{})
	var writerWG sync.WaitGroup
	writerWG.Add(1)
	go func() {
		defer writerWG.Done()
		i := 0
		for {
			select {
			case <-stop:
				return
			default:
			}
			a.setText(fmt.Sprintf("%sp, user%d, data%d, read\n", base, i%8, i%4))
			w.emit()
			i++
		}
	}()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if ok, err := e.Enforce("alice", "data1", "read"); err != nil || !ok {
				b.Fatalf("unexpected enforce result ok=%v err=%v", ok, err)
			}
		}
	})
	b.StopTimer()
	close(stop)
	writerWG.Wait()
}

// TestReconcile_ConvergenceTimeMeasurement prints measured convergence
// latency for watcher-driven and periodic self-healing paths so the bounds
// are observable in test output rather than only asserted.
func TestReconcile_ConvergenceTimeMeasurement(t *testing.T) {
	t.Run("watcher-driven", func(t *testing.T) {
		e, a, w := newTestSynced(t, "p, alice, data1, read\n")
		e.StartPolicyReconciler(ReconcilerConfig{Interval: time.Second})
		defer e.StopPolicyReconciler()

		const rounds = 20
		var total time.Duration
		var max time.Duration
		for i := 0; i < rounds; i++ {
			v := a.setText(fmt.Sprintf("p, alice, data1, read\np, user%d, data%d, read\n", i, i))
			start := time.Now()
			w.emit(v)
			waitFor(t, time.Second, func() bool {
				return atomic.LoadUint64(&e.appliedVersion) == v
			}, "watcher convergence")
			latency := time.Since(start)
			total += latency
			if latency > max {
				max = latency
			}
		}
		t.Logf("watcher-driven convergence over %d rounds: avg=%s max=%s",
			rounds, total/rounds, max)
	})

	t.Run("periodic-self-heal", func(t *testing.T) {
		for _, interval := range []time.Duration{50 * time.Millisecond, 100 * time.Millisecond} {
			e, a, _ := newTestSynced(t, "p, alice, data1, read\n")
			e.StartPolicyReconciler(ReconcilerConfig{Interval: interval})
			v := a.setText("p, alice, data1, read\np, bob, data2, write\n")
			// No notification emitted: the periodic backstop must self-heal.
			start := time.Now()
			waitFor(t, 5*time.Second, func() bool {
				return atomic.LoadUint64(&e.appliedVersion) == v
			}, "periodic convergence")
			elapsed := time.Since(start)
			e.StopPolicyReconciler()
			if elapsed > interval+200*time.Millisecond {
				t.Fatalf("self-heal took %s, exceeds bound interval %s + 200ms", elapsed, interval)
			}
			t.Logf("interval=%s measured self-heal convergence=%s (upper bound ≈ interval + one tick)",
				interval, elapsed)
		}
	})
}
