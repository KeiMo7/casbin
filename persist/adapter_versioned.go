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

// VersionedAdapter is an optional capability of an Adapter: the storage layer
// itself assigns a monotonically increasing, persistence-backed version to the
// policy content. Every successful write must make LoadPolicyVersion return a
// strictly greater version than any previous state; a stale storage replica
// must never report a version lower than the one a surviving instance applied.
//
// Adapters that do not implement this interface still converge, but ordering
// can only be derived from the loaded policy content instead of an explicit
// storage version.
type VersionedAdapter interface {
	Adapter
	// LoadPolicyVersion returns the version of the policy currently held by
	// the storage. Versions are required to be monotonically increasing over
	// the sequence of successful policy writes.
	LoadPolicyVersion() (uint64, error)
}
