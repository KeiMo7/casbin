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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const versionFileSuffix = ".json"

// ErrVersionFileExists is reported by FileStore when an append would overwrite
// a version file that already exists.
var ErrVersionFileExists = errors.New("policy history version file already exists")

// FileStore keeps one file per version in a directory. A file is named
// "<version>.json" and is written with O_EXCL, so an append can never overwrite
// an existing version. The directory is the unit of history.
type FileStore struct {
	dir string
}

// NewFileStore creates a file store rooted at dir. The directory is created on
// the first append.
func NewFileStore(dir string) *FileStore {
	return &FileStore{dir: dir}
}

// Dir returns the directory the store writes to.
func (s *FileStore) Dir() string {
	return s.dir
}

// Versions lists the version files present in the directory. A file whose name
// is not a version number is ignored.
func (s *FileStore) Versions() ([]uint64, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return []uint64{}, nil
		}
		return nil, &VersionError{Kind: KindStorage, Err: err}
	}

	versions := make([]uint64, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), versionFileSuffix) {
			continue
		}
		version, err := strconv.ParseUint(strings.TrimSuffix(entry.Name(), versionFileSuffix), 10, 64)
		if err != nil {
			continue
		}
		versions = append(versions, version)
	}
	sort.Slice(versions, func(i, j int) bool { return versions[i] < versions[j] })
	return versions, nil
}

// Read decodes the record stored for version.
func (s *FileStore) Read(version uint64) (*VersionRecord, error) {
	path := s.path(version)
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, &VersionError{Version: version, Kind: KindCorrupt, Err: errMissingVersion}
		}
		return nil, &VersionError{Version: version, Kind: KindStorage, Err: err}
	}

	var record VersionRecord
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&record); err != nil {
		return nil, &VersionError{Version: version, Kind: KindCorrupt, Err: err}
	}
	Normalize(&record)
	return &record, nil
}

// Append writes record to its own file. It never overwrites: the write fails
// when the file already exists or when another writer created it first. The
// record is written to a temporary file first and then hard-linked into place,
// so a concurrent reader either sees the complete record or no record at all.
func (s *FileStore) Append(record *VersionRecord) error {
	if record == nil {
		return &VersionError{Kind: KindStorage, Err: errNilRecord}
	}
	if err := os.MkdirAll(s.dir, 0o755); err != nil {
		return &VersionError{Version: record.Version, Kind: KindStorage, Err: err}
	}

	data, err := json.Marshal(record)
	if err != nil {
		return &VersionError{Version: record.Version, Kind: KindStorage, Err: err}
	}

	temp, err := os.CreateTemp(s.dir, fmt.Sprintf(".%020d-*", record.Version))
	if err != nil {
		return &VersionError{Version: record.Version, Kind: KindStorage, Err: err}
	}
	tempPath := temp.Name()
	cleanup := func() {
		_ = temp.Close()
		_ = os.Remove(tempPath)
	}

	if _, err := temp.Write(data); err != nil {
		cleanup()
		return &VersionError{Version: record.Version, Kind: KindStorage, Err: err}
	}
	if err := temp.Sync(); err != nil {
		cleanup()
		return &VersionError{Version: record.Version, Kind: KindStorage, Err: err}
	}
	if err := temp.Close(); err != nil {
		_ = os.Remove(tempPath)
		return &VersionError{Version: record.Version, Kind: KindStorage, Err: err}
	}

	// Link atomically publishes the fully written file and fails if the
	// version already exists. Hard links keep the append-only guarantee: an
	// existing version file is never replaced.
	if err := os.Link(tempPath, s.path(record.Version)); err != nil {
		_ = os.Remove(tempPath)
		if errors.Is(err, os.ErrExist) {
			return &VersionError{Version: record.Version, Kind: KindSequence, Err: ErrVersionFileExists}
		}
		return &VersionError{Version: record.Version, Kind: KindStorage, Err: err}
	}
	_ = os.Remove(tempPath)
	return nil
}

func (s *FileStore) path(version uint64) string {
	return filepath.Join(s.dir, fmt.Sprintf("%020d%s", version, versionFileSuffix))
}
