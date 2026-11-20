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
	"errors"
	"fmt"
)

var (
	errNilRecord        = errors.New("policy history record is nil")
	errMissingChecksum  = errors.New("policy history record has no checksum")
	errChecksumMismatch = errors.New("policy history record checksum mismatch")
	errMissingVersion   = errors.New("policy history version does not exist")
)

// ErrorKind classifies history errors so callers can react differently to a
// damaged record, an integrity violation and a sequencing violation.
type ErrorKind string

const (
	// KindCorrupt means a version exists but cannot be decoded or stored.
	KindCorrupt ErrorKind = "corrupt"
	// KindIntegrity means a version decodes but its content no longer matches
	// the checksum that was written for it.
	KindIntegrity ErrorKind = "integrity"
	// KindSequence means version numbers went backwards, skipped or repeated.
	KindSequence ErrorKind = "sequence"
	// KindStorage means the underlying history storage failed.
	KindStorage ErrorKind = "storage"
)

// VersionError is returned for every history read/write failure. It names the
// version that is at fault so that a caller can report "version N is
// unreadable" while still using the other versions.
type VersionError struct {
	Version uint64
	Kind    ErrorKind
	Err     error
}

func (e *VersionError) Error() string {
	switch e.Kind {
	case KindCorrupt:
		return fmt.Sprintf("policy history version %d is corrupt: %v", e.Version, e.Err)
	case KindIntegrity:
		return fmt.Sprintf("policy history version %d failed the integrity check: %v", e.Version, e.Err)
	case KindSequence:
		return fmt.Sprintf("policy history version sequence is broken at version %d: %v", e.Version, e.Err)
	default:
		return fmt.Sprintf("policy history storage failed at version %d: %v", e.Version, e.Err)
	}
}

func (e *VersionError) Unwrap() error {
	return e.Err
}

// IsCorrupt reports whether err is caused by an unreadable version.
func IsCorrupt(err error) bool {
	var ve *VersionError
	return errors.As(err, &ve) && ve.Kind == KindCorrupt
}

// IsIntegrity reports whether err is caused by a tampered version.
func IsIntegrity(err error) bool {
	var ve *VersionError
	return errors.As(err, &ve) && ve.Kind == KindIntegrity
}

// IsSequence reports whether err is caused by a broken version sequence.
func IsSequence(err error) bool {
	var ve *VersionError
	return errors.As(err, &ve) && ve.Kind == KindSequence
}

// VersionOf returns the version a history error refers to, if any.
func VersionOf(err error) (uint64, bool) {
	var ve *VersionError
	if errors.As(err, &ve) {
		return ve.Version, true
	}
	return 0, false
}

// CorruptError reports that one version is unreadable while the rest of the
// history can still be read. It is returned by batch readers.
type CorruptError struct {
	// Damaged lists every version that could not be read.
	Damaged []VersionError
	// Versions lists every version that could still be read.
	Versions []uint64
}

func (e *CorruptError) Error() string {
	versions := make([]uint64, len(e.Damaged))
	for i := range e.Damaged {
		versions[i] = e.Damaged[i].Version
	}
	if len(versions) == 1 {
		return fmt.Sprintf("policy history version %d is unreadable", versions[0])
	}
	return fmt.Sprintf("policy history versions %v are unreadable", versions)
}
