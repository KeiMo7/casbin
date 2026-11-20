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
	"errors"
	"strings"
	"testing"
)

// wrapperFor returns the govaluate wrapper of a built-in matcher.
func wrapperFor(matcher string) func(args ...interface{}) (interface{}, error) {
	switch matcher {
	case "keyMatch":
		return KeyMatchFunc
	case "keyGet":
		return KeyGetFunc
	case "keyMatch2":
		return KeyMatch2Func
	case "keyMatch3":
		return KeyMatch3Func
	case "keyMatch4":
		return KeyMatch4Func
	case "keyMatch5":
		return KeyMatch5Func
	case "regexMatch":
		return RegexMatchFunc
	case "globMatch":
		return GlobMatchFunc
	default:
		panic("unknown matcher " + matcher)
	}
}

// TestMatchEntriesAgree pins the contract between the two public faces of each
// matcher: for the same (key1, key2), the bool entry and the wrapper entry
// agree on the match, and the wrapper reports a pattern error exactly when
// MatchPattern does.
func TestMatchEntriesAgree(t *testing.T) {
	type testCase struct {
		key1 string
		key2 string
	}
	cases := []testCase{
		// valid patterns
		{"/foo/bar", "/foo/*"},
		{"/resource1", "/:resource"},
		{"/resource1", "/{resource}"},
		{"/parent/123/child/123", "/parent/{id}/child/{id}"},
		{"/foo/bar", "/foo/bar"},
		{"/topic/1", "^/topic/[0-9]+$"},
		{"/foo/bar", "/foo/*"},
		// invalid patterns
		{"/foo/bar", "/foo/(bar"},
		{"/foo/bar", "/foo/[bar"},
		{"/foo/bar", "/foo/*bar"},
		{"GET", "(GET"},
		{"/topic/edit/1", "/topic/edit/[0-9"},
		{"/foo/bar", "/foo/[a-"},
		{"/x", "/x/[z-a]"},
	}

	for _, matcher := range []string{"keyMatch", "keyMatch2", "keyMatch3", "keyMatch4", "keyMatch5", "regexMatch", "globMatch"} {
		wrapper := wrapperFor(matcher)
		for _, tc := range cases {
			result := MatchPattern(matcher, tc.key1, tc.key2)

			wrapperRes, wrapperErr := wrapper(tc.key1, tc.key2)
			wrapperMatched, _ := wrapperRes.(bool)

			if wrapperMatched != result.Matched {
				t.Errorf("%s(%q, %q): wrapper matched=%t, MatchPattern matched=%t",
					matcher, tc.key1, tc.key2, wrapperMatched, result.Matched)
			}
			if (wrapperErr != nil) != (result.Err != nil) {
				t.Errorf("%s(%q, %q): wrapper err=%v, MatchPattern err=%v",
					matcher, tc.key1, tc.key2, wrapperErr, result.Err)
			}
			if result.Err != nil {
				if result.Matched {
					t.Errorf("%s(%q, %q): an invalid pattern must match nothing", matcher, tc.key1, tc.key2)
				}
				if !errors.Is(wrapperErr, ErrInvalidPattern) {
					t.Errorf("%s(%q, %q): wrapper error %v does not wrap ErrInvalidPattern", matcher, tc.key1, tc.key2, wrapperErr)
				}
				if result.Err.Matcher != matcher || result.Err.Pattern != tc.key2 || result.Err.Kind == "" {
					t.Errorf("%s(%q, %q): incomplete MatchError %+v", matcher, tc.key1, tc.key2, result.Err)
				}
			}
		}
	}
}

func TestInvalidPatternIsMachineReadable(t *testing.T) {
	result := MatchPattern("regexMatch", "GET", "(GET")
	if result.OK() || result.Err == nil {
		t.Fatal("expected a pattern error")
	}
	if result.Err.Kind != MatchErrorSyntax {
		t.Errorf("kind = %q, want %q", result.Err.Kind, MatchErrorSyntax)
	}
	if result.Err.Matcher != "regexMatch" || result.Err.Pattern != "(GET" {
		t.Errorf("unexpected MatchError: %+v", result.Err)
	}
	if result.Class != PatternRegex {
		t.Errorf("class = %q, want %q", result.Class, PatternRegex)
	}

	err := MatchPattern("nope", "a", "b").Err
	if err == nil || err.Kind != MatchErrorUnsupported {
		t.Errorf("unknown matcher should yield MatchErrorUnsupported, got %+v", err)
	}
}

// TestMidSegmentStarIsRejected covers the rule that a '*' only acts as a
// wildcard when it occupies a whole path segment.
func TestMidSegmentStarIsRejected(t *testing.T) {
	for _, matcher := range []string{"keyMatch2", "keyMatch3", "keyMatch4", "keyMatch5"} {
		result := MatchPattern(matcher, "/foo/bar", "/foo/*bar")
		if result.Matched {
			t.Errorf("%s: mid-segment star must not match", matcher)
		}
		if result.Err == nil || result.Err.Kind != MatchErrorMisplacedStar {
			t.Errorf("%s: got %+v, want MatchErrorMisplacedStar", matcher, result.Err)
		}
	}

	// A whole-segment star still works.
	for _, matcher := range []string{"keyMatch2", "keyMatch3", "keyMatch4", "keyMatch5"} {
		if result := MatchPattern(matcher, "/foo/bar", "/foo/*"); !result.Matched || !result.OK() {
			t.Errorf("%s: /foo/* should still match /foo/bar, got %+v", matcher, result)
		}
	}

	// A star inside a bracket expression is a regexp class, not a wildcard.
	if result := MatchPattern("keyMatch2", "/x/*", "/x/[*]"); !result.Matched || !result.OK() {
		t.Errorf("a star inside a class should be valid, got %+v", result)
	}
}

// TestSegmentPlaceholderBoundaries covers placeholder segment boundaries: a
// placeholder stands for exactly one non-empty segment.
func TestSegmentPlaceholderBoundaries(t *testing.T) {
	type testCase struct {
		matcher string
		key1    string
		key2    string
		want    bool
	}
	cases := []testCase{
		// ':' placeholders (KeyMatch2)
		{"keyMatch2", "/foo//bar", "/foo/:id/bar", false},
		{"keyMatch2", "/foo/x/bar", "/foo/:id/bar", true},
		{"keyMatch2", "/foo/x/y/bar", "/foo/:id/bar", false},
		{"keyMatch2", "/foo/x", "/foo/:", false},
		{"keyMatch2", "/foo/x", "/foo/", false},
		// '{}' placeholders (KeyMatch3/4)
		{"keyMatch3", "/foo//bar", "/foo/{id}/bar", false},
		{"keyMatch3", "/foo/x/bar", "/foo/{id}/bar", true},
		{"keyMatch3", "/foo/x/y/bar", "/foo/{id}/bar", false},
		{"keyMatch3", "/foo/x", "/foo/{}", false},
		{"keyMatch4", "/parent//child/", "/parent/{id}/child/{id}", false},
		{"keyMatch4", "/parent/1/child/1", "/parent/{id}/child/{id}", true},
	}
	for _, tc := range cases {
		if got := MatchPattern(tc.matcher, tc.key1, tc.key2).Matched; got != tc.want {
			t.Errorf("%s(%q, %q) = %t, want %t", tc.matcher, tc.key1, tc.key2, got, tc.want)
		}
	}
}

// TestBracketBoundaries covers unclosed and malformed bracket expressions in
// each matcher family that reads them.
func TestBracketBoundaries(t *testing.T) {
	type testCase struct {
		matcher string
		key1    string
		key2    string
		kind    MatchErrorKind
	}
	cases := []testCase{
		{"keyMatch2", "/foo/1", "/foo/[0-9", MatchErrorSyntax},
		{"keyMatch3", "/foo/1", "/foo/{id}/[0-9", MatchErrorSyntax},
		{"keyMatch4", "/foo/1", "/foo/{id}/[0-9", MatchErrorSyntax},
		{"keyMatch5", "/foo/1", "/foo/{id}/[0-9", MatchErrorSyntax},
		{"regexMatch", "/foo/1", "/foo/[0-9", MatchErrorSyntax},
		{"globMatch", "/foo/1", "/foo/[0-9", MatchErrorSyntax},
	}
	for _, tc := range cases {
		result := MatchPattern(tc.matcher, tc.key1, tc.key2)
		if result.Matched {
			t.Errorf("%s(%q, %q): unclosed bracket must not match", tc.matcher, tc.key1, tc.key2)
		}
		if result.Err == nil || result.Err.Kind != tc.kind {
			t.Errorf("%s(%q, %q): got %+v, want kind %q", tc.matcher, tc.key1, tc.key2, result.Err, tc.kind)
		}
	}

	// A well-formed class matches and reports no error.
	if result := MatchPattern("regexMatch", "/foo/1", "/foo/[0-9]"); !result.Matched || !result.OK() {
		t.Errorf("valid class should match, got %+v", result)
	}
}

func TestPatternBounds(t *testing.T) {
	tooLong := strings.Repeat("a", MaxPatternLength+1)
	for _, matcher := range []string{"keyMatch", "keyMatch2", "keyMatch3", "keyMatch4", "keyMatch5", "regexMatch", "globMatch"} {
		result := MatchPattern(matcher, tooLong, tooLong)
		if result.Matched || result.Err == nil || result.Err.Kind != MatchErrorTooLong {
			t.Errorf("%s: too-long pattern must be rejected before the fast path, got %+v", matcher, result)
		}
	}

	// Build a star-free pattern with too many segments: a '*' in it would
	// legitimately take the wildcard path before the bound is checked.
	manySegments := "/" + strings.TrimSuffix(strings.Repeat("a/", MaxPatternSegments+1), "/")
	result := MatchPattern("keyMatch2", "/a", manySegments)
	if result.Matched || result.Err == nil || result.Err.Kind != MatchErrorTooManySegments {
		t.Errorf("got %+v, want MatchErrorTooManySegments", result)
	}

	// The empty pattern and a pattern made of repeated segments stay stable.
	// An empty pattern is a valid (if useless) pattern and only matches "".
	if result := MatchPattern("keyMatch2", "", ""); !result.Matched || !result.OK() {
		t.Errorf("empty pattern should match only the empty key, got %+v", result)
	}
	repeated := strings.Repeat("/a", 512)
	if result := MatchPattern("keyMatch2", repeated, repeated); !result.Matched || !result.OK() {
		t.Errorf("repeated segments should match themselves, got %+v", result)
	}
}

// TestPatternCacheParsesOnce asserts that the same pattern is compiled once
// and reused across many decisions.
func TestPatternCacheParsesOnce(t *testing.T) {
	SetPatternCacheCapacity(patternCacheMax)
	t.Cleanup(func() { SetPatternCacheCapacity(patternCacheMax) })

	const pattern = "/cache/test/:id"

	_, missesBefore, _, ok := PatternCacheStats("keyMatch2")
	if !ok {
		t.Fatal("expected stats for keyMatch2")
	}

	for i := 0; i < 100; i++ {
		if !KeyMatch2("/cache/test/42", pattern) {
			t.Fatal("pattern should match")
		}
	}

	hits, misses, size, _ := PatternCacheStats("keyMatch2")
	if misses-missesBefore != 1 {
		t.Errorf("pattern parsed %d times, want exactly 1", misses-missesBefore)
	}
	if hits == 0 {
		t.Error("expected cache hits on repeated use")
	}
	if size == 0 {
		t.Error("expected the pattern to be retained")
	}
}

// TestPatternCacheIsBounded asserts that the cache never grows past its bound
// and that eviction does not change decisions.
func TestPatternCacheIsBounded(t *testing.T) {
	const capacity = 8
	SetPatternCacheCapacity(capacity)
	t.Cleanup(func() { SetPatternCacheCapacity(patternCacheMax) })

	// Insert far more distinct patterns than the cache can hold.
	for i := 0; i < capacity*10; i++ {
		pattern := "/bounded/" + strings.Repeat("x", i+1)
		if !KeyMatch2(pattern, pattern) {
			t.Fatalf("pattern %d should match its own key", i+1)
		}
	}

	_, _, size, _ := PatternCacheStats("keyMatch2")
	if size > capacity {
		t.Errorf("cache size = %d, exceeds bound %d", size, capacity)
	}

	// Eviction must not change answers: the evicted patterns are recompiled.
	for i := 0; i < capacity*10; i++ {
		pattern := "/bounded/" + strings.Repeat("x", i+1)
		if !KeyMatch2(pattern, pattern) {
			t.Errorf("pattern %d stopped matching after eviction", i+1)
		}
	}
}

// TestPatternCacheConcurrentUse exercises the cache from many goroutines so
// the FIFO bookkeeping and sync.Map reads stay consistent under load.
func TestPatternCacheConcurrentUse(t *testing.T) {
	SetPatternCacheCapacity(16)
	t.Cleanup(func() { SetPatternCacheCapacity(patternCacheMax) })

	done := make(chan struct{})
	for g := 0; g < 8; g++ {
		go func(g int) {
			defer func() { done <- struct{}{} }()
			for i := 0; i < 500; i++ {
				pattern := "/concurrent/" + strings.Repeat("x", (i+g)%40+1)
				if !KeyMatch2(pattern, pattern) {
					t.Errorf("pattern %q stopped matching under concurrency", pattern)
					return
				}
				KeyMatch2("/concurrent/1", "/concurrent/:id")
			}
		}(g)
	}
	for g := 0; g < 8; g++ {
		<-done
	}

	if _, _, size, _ := PatternCacheStats("keyMatch2"); size > 16 {
		t.Errorf("cache size = %d, exceeds bound 16", size)
	}
}

// TestPatternErrorTextIsPreserved guards the historical wrapper error text so
// existing log parsing keeps working.
func TestPatternErrorTextIsPreserved(t *testing.T) {
	_, err := RegexMatchFunc("GET", "(GET")
	if err == nil || !strings.Contains(err.Error(), "regexMatch: error parsing regexp: missing closing ): `(GET`") {
		t.Errorf("wrapper error = %v, want the historical text", err)
	}

	_, err = KeyMatch2Func("/foo/bar", "/foo/(bar")
	if err == nil || !strings.Contains(err.Error(), "keyMatch2: error parsing regexp: missing closing ): `^/foo/(bar$`") {
		t.Errorf("wrapper error = %v, want the historical text", err)
	}
}
