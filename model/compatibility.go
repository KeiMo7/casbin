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

package model

import (
	"bufio"
	"fmt"
	"strconv"
	"strings"
)

// CurrentModelFormatVersion is the newest model envelope understood by this
// binary. New syntax should remain readable by old instances during a rolling
// upgrade whenever possible. A model can declare its envelope explicitly:
//
//	[model_format]
//	version = 1
//	min_reader_version = 1
//
// Readers reject newer mandatory formats cleanly instead of partially loading
// them.
const CurrentModelFormatVersion = 1

// UnsupportedModelFormatError is returned when a model requires a newer reader.
type UnsupportedModelFormatError struct {
	Version          int
	MinReaderVersion int
	Supported        int
}

func (e *UnsupportedModelFormatError) Error() string {
	return fmt.Sprintf("model format %d requires reader >= %d, this binary supports %d",
		e.Version, e.MinReaderVersion, e.Supported)
}

// CheckModelCompatibility validates the optional model_format envelope.
func CheckModelCompatibility(text string) error {
	section := ""
	version := 0
	minReaderVersion := 0
	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			continue
		}
		if section != "model_format" {
			continue
		}
		separator := strings.Index(line, "=")
		if separator < 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(line[:separator]))
		value := strings.TrimSpace(line[separator+1:])
		parsed, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("invalid model_format %s %q: %w", key, value, err)
		}
		switch key {
		case "version":
			version = parsed
		case "min_reader_version":
			minReaderVersion = parsed
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if version > CurrentModelFormatVersion || minReaderVersion > CurrentModelFormatVersion {
		return &UnsupportedModelFormatError{
			Version:          version,
			MinReaderVersion: maxInt(minReaderVersion, version),
			Supported:        CurrentModelFormatVersion,
		}
	}
	return nil
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
