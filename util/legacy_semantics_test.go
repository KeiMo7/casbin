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

package util

import (
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The legacy* functions below are the pre-change rewrite-and-match pipeline,
// kept here as the reference the new implementation must agree with on every
// legal pattern. They deliberately do no caching or validation.

func legacyRegexpMatches(key1, key2 string) bool {
	re, err := regexp.Compile(key2)
	if err != nil {
		return false
	}
	return re.MatchString(key1)
}

func legacyKeyMatch(key1, key2 string) bool {
	i := strings.Index(key2, "*")
	if i == -1 {
		return key1 == key2
	}
	if len(key1) > i {
		return key1[:i] == key2[:i]
	}
	return key1 == key2[:i]
}

// legacySegmentMatch mirrors the baseline pipeline for one matcher dialect:
// the token regexp and replacement match builtin_operators.go as it stood
// before this change.
func legacySegmentMatch(key1, key2 string, tokenRe *regexp.Regexp, replacement string, namedTokens bool) bool {
	key2 = strings.ReplaceAll(key2, "/*", "/.*")

	if namedTokens {
		i := 0
		tokens := []string{}
		key2 = tokenRe.ReplaceAllStringFunc(key2, func(s string) string {
			tokens = append(tokens, s[1:len(s)-1])
			group := "(?P<casbinToken" + strconv.Itoa(i) + ">[^/]+)"
			i++
			return group
		})
		re, err := regexp.Compile("^" + key2 + "$")
		if err != nil {
			return false
		}
		matches := re.FindStringSubmatch(key1)
		if matches == nil {
			return false
		}
		values := map[string]string{}
		for i, token := range tokens {
			name := "casbinToken" + strconv.Itoa(i)
			match := matches[re.SubexpIndex(name)]
			if _, ok := values[token]; !ok {
				values[token] = match
			}
			if values[token] != match {
				return false
			}
		}
		return true
	}

	key2 = tokenRe.ReplaceAllString(key2, replacement)
	re, err := regexp.Compile("^" + key2 + "$")
	if err != nil {
		return false
	}
	return re.MatchString(key1)
}

func TestLegalPatternsMatchLegacySemantics(t *testing.T) {
	keyMatch2Re := regexp.MustCompile(`:[^/]+`)
	keyMatch3Re := regexp.MustCompile(`\{[^/]+\}`)
	keyMatch4Re := regexp.MustCompile(`{([^/]+)}`)
	keyMatch5Re := regexp.MustCompile(`\{[^/]+\}`)

	keys := []string{
		"/foo", "/foo/bar", "/foo/bar/baz", "/foobar", "/",
		"/alice_data/resource1", "/alice_data2/42/using/99",
		"/parent/123/child/123", "/parent/123/child/456",
		"/proxy/myid/res/res2", "/book/1/2/3/4/5",
		"/a/123/child/123", "/123/x/123", "", "GET", "POST",
	}
	patterns := []string{
		"", "/foo", "/foo/*", "/foo*", "/*", "/:id", "/:id/all",
		"/alice_data/:resource", "/alice_data2/:id/using/:resId",
		"/{id}", "/{id}/all", "/parent/{id}/child/{id}",
		"/parent/{id}/child/{another_id}", "/(a|b)/{id}/child/{id}",
		"/{id}/(x|y)/{id}", "/proxy/{id}/*", "/book/*", "/book/:id",
		"/pen/:id", "/book2/{id}",
	}

	for _, key := range keys {
		for _, pattern := range patterns {
			if got, want := KeyMatch2(key, pattern), legacySegmentMatch(key, pattern, keyMatch2Re, "$1[^/]+$2", false); got != want {
				t.Errorf("KeyMatch2(%q, %q) = %t, legacy = %t", key, pattern, got, want)
			}
			if got, want := KeyMatch3(key, pattern), legacySegmentMatch(key, pattern, keyMatch3Re, "$1[^/]+$2", false); got != want {
				t.Errorf("KeyMatch3(%q, %q) = %t, legacy = %t", key, pattern, got, want)
			}
			if got, want := KeyMatch4(key, pattern), legacySegmentMatch(key, pattern, keyMatch4Re, "", true); got != want {
				t.Errorf("KeyMatch4(%q, %q) = %t, legacy = %t", key, pattern, got, want)
			}
			if got, want := KeyMatch5(key, pattern), legacySegmentMatch(key, pattern, keyMatch5Re, "$1[^/]+$2", false); got != want {
				t.Errorf("KeyMatch5(%q, %q) = %t, legacy = %t", key, pattern, got, want)
			}
			if got, want := RegexMatch(key, pattern), legacyRegexpMatches(key, pattern); got != want {
				t.Errorf("RegexMatch(%q, %q) = %t, legacy = %t", key, pattern, got, want)
			}
			if got, want := KeyMatch(key, pattern), legacyKeyMatch(key, pattern); got != want {
				t.Errorf("KeyMatch(%q, %q) = %t, legacy = %t", key, pattern, got, want)
			}
		}
	}
}
