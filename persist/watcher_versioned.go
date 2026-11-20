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

package persist

// VersionedWatcher is an optional capability of a Watcher for transports that
// carry an explicit, monotonically increasing version with each change
// notification. It lets an enforcer discard out-of-order notifications before
// touching the storage instead of discovering staleness only after a reload.
//
// The callback receives the storage version of the change that triggered it.
// A plain Watcher remains fully supported: notifications without a version are
// reconciled by comparing against the storage directly.
type VersionedWatcher interface {
	Watcher
	// SetVersionedUpdateCallback registers a callback invoked with the
	// monotonically increasing version of the policy change.
	SetVersionedUpdateCallback(func(version uint64)) error
}
