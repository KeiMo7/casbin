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
	"fmt"
	"strings"
)

// The built-in matchers have two public faces: a bool function such as
// KeyMatch2 and a govaluate wrapper such as KeyMatch2Func. The bool face has
// nowhere to report a malformed pattern, so it answers "no match" and carries
// on. The wrapper face reports the same "no match" plus a *MatchError. The two
// faces share one implementation, so for every (key1, key2) pair the bool they
// return is identical; the wrapper merely adds the error. MatchPattern is the
// machine-readable entry that exposes both facts at once.
//
// Pattern grammar boundaries, by matcher family:
//
//   - KeyMatch / KeyGet treat the first '*' in key2 as a raw prefix marker.
//     This is the historical contract of those two functions: the star is not
//     segment-aware ("/foo*" matches "/foobar"). They are left unchanged.
//
//   - KeyMatch2/3/4/5 and KeyGet2/3 split key2 on '/'. A '*' is a wildcard
//     only when it occupies a whole segment ("/foo/*", "/*", or a leading
//     '*' segment). A '*' with a non-empty suffix inside its segment
//     (for example "/foo/*bar" or "/foo/a*bar") has no path-segment meaning
//     and is rejected with MatchErrorMisplacedStar instead of being turned
//     into a regexp prefix. This is the one deliberate narrowing of the old
//     behaviour: such a star used to act as a regexp quantifier on the
//     preceding atom. Write the intent explicitly instead, e.g. "/foo/.*bar".
//     A trailing '*' in a segment ("/foo*") and a star that quantifies a
//     regexp atom at the end of a segment ("/foo/.*", "/foo/(a|b)*") are
//     accepted and keep their historical meaning.
//
//   - ':' placeholders (KeyMatch2/KeyGet2) and '{...}' placeholders
//     (KeyMatch3/4/5, KeyGet3) stand for exactly one non-empty path segment.
//     They never match an empty segment, so "/foo//bar" does not match
//     "/foo/:id/bar".
//
//   - '[...]' bracket expressions are regexp character classes in the
//     segment matchers and in regexMatch, and glob classes in globMatch. In
//     every case the bracket is part of the pattern language of that matcher.
//     An unclosed bracket is a syntax error: the bool face says "no match"
//     and the wrapper face returns a syntax MatchError.
//
//   - RegexMatch compiles key2 as an unanchored Go regexp (MatchString), so
//     a regexp can match inside key1. This is the historical behaviour and is
//     preserved. Use '^' and '$' in the pattern to anchor it.
//
//   - GlobMatch delegates to doublestar: '*' and '?' stay inside one path
//     segment, while '**' crosses segments. Mid-segment stars are legitimate
//     glob syntax and are not rejected.
//
// Bounds: every pattern is checked against MaxPatternLength and
// MaxPatternSegments before it reaches the regexp compiler or the cache.
// A pattern over a bound is a configuration error (MatchError), never a
// panic and never a reason to fail an entire decision.

const (
	// MaxPatternLength is the largest pattern, in bytes, that the built-in
	// matchers accept. It comfortably exceeds any real policy pattern while
	// keeping the cost of one pattern bounded when policies come from an
	// external, possibly hostile, source.
	MaxPatternLength = 64 * 1024

	// MaxPatternSegments is the largest number of '/'-separated segments a
	// segment matcher accepts. It bounds the number of capture groups that a
	// single pattern can create.
	MaxPatternSegments = 4096
)

// ErrInvalidPattern is the sentinel matched by every *MatchError through
// errors.Is. Use it when the only question is whether an error describes a
// malformed pattern rather than a normal mismatch.
var ErrInvalidPattern = errors.New("invalid pattern")

// MatchErrorKind classifies why a pattern was rejected. The values are stable
// strings so they can be logged, counted, or compared by machine.
type MatchErrorKind string

const (
	// MatchErrorSyntax means the pattern's own language (regexp, glob, ...)
	// rejected it.
	MatchErrorSyntax MatchErrorKind = "syntax"
	// MatchErrorTooLong means the pattern exceeds MaxPatternLength.
	MatchErrorTooLong MatchErrorKind = "too-long"
	// MatchErrorTooManySegments means the pattern has more than
	// MaxPatternSegments '/' separated segments.
	MatchErrorTooManySegments MatchErrorKind = "too-many-segments"
	// MatchErrorMisplacedStar means a '*' appears with a non-empty suffix
	// inside one path segment, where it has no segment-wildcard meaning.
	MatchErrorMisplacedStar MatchErrorKind = "misplaced-star"
	// MatchErrorUnsupported means there is no built-in matcher under the
	// requested name.
	MatchErrorUnsupported MatchErrorKind = "unsupported-matcher"
)

func (k MatchErrorKind) String() string {
	return string(k)
}

// MatchError describes a pattern that a built-in matcher refused to compile.
// It is a configuration error, not a normal mismatch: the matcher treats the
// pattern as "matches nothing" so the surrounding decision can continue, and
// callers that need to act on the problem consume this type.
//
// Error() keeps the historical text of the matcher wrappers, for example
// "regexMatch: error parsing regexp: missing closing ): `(GET`", so existing
// log parsing keeps working: the wrappers prepend "<matcher>: " and this method
// returns the cause as before. Matcher, Pattern and Kind are the new
// machine-readable fields.
type MatchError struct {
	Matcher string         // matcher name, e.g. "keyMatch2"
	Pattern string         // the original key2, before any rewriting
	Kind    MatchErrorKind // classification of the failure
	Cause   error          // underlying parser error, if any
}

// Error implements error. It describes only the failure: the matcher wrappers
// (KeyMatch2Func, ...) prepend the matcher name themselves, which keeps their
// historical message text such as "regexMatch: error parsing regexp: ...".
func (e *MatchError) Error() string {
	if e.Cause == nil {
		return fmt.Sprintf("invalid pattern (%s)", e.Kind)
	}
	return e.Cause.Error()
}

// Unwrap exposes the underlying parser error.
func (e *MatchError) Unwrap() error {
	return e.Cause
}

// Is reports whether target is ErrInvalidPattern.
func (e *MatchError) Is(target error) bool {
	return target == ErrInvalidPattern
}

// AsMatchError extracts a *MatchError from err. It returns nil when err does
// not describe an invalid pattern.
func AsMatchError(err error) *MatchError {
	var matchErr *MatchError
	if errors.As(err, &matchErr) {
		return matchErr
	}
	return nil
}

// PatternClass names the strongest pattern feature a pattern uses. It is
// informational: it lets diagnostics say which boundary rules apply to a
// pattern without re-parsing it. The order below is the precedence used when a
// pattern combines several features.
type PatternClass string

const (
	PatternLiteral     PatternClass = "literal"
	PatternPlaceholder PatternClass = "placeholder"
	PatternBracket     PatternClass = "bracket"
	PatternWildcard    PatternClass = "wildcard"
	PatternRegex       PatternClass = "regex"
	PatternGlob        PatternClass = "glob"
)

// MatchResult is the machine-consumable result of one matcher call.
//
// Matched is exactly what the bool entry (KeyMatch2, ...) returns. Err is
// exactly what the wrapper entry (KeyMatch2Func, ...) returns as its error.
// When Err is non-nil, Matched is false: an invalid pattern matches nothing.
type MatchResult struct {
	Matched bool
	Matcher string
	Pattern string
	Class   PatternClass
	Err     *MatchError
}

// OK reports whether the pattern was valid.
func (r MatchResult) OK() bool {
	return r.Err == nil
}

// MatchPattern evaluates one of the bool built-in matchers and returns the
// match result together with a structured pattern error.
//
// matcher is one of "keyMatch", "keyMatch2", "keyMatch3", "keyMatch4",
// "keyMatch5", "regexMatch", "globMatch". key2 is the pattern. Unknown matcher
// names produce MatchErrorUnsupported rather than a panic.
func MatchPattern(matcher string, key1 string, key2 string) MatchResult {
	result := MatchResult{Matcher: matcher, Pattern: key2}

	var err error
	switch matcher {
	case "keyMatch":
		result.Matched, err = keyMatch(key1, key2)
	case "keyMatch2":
		result.Matched, err = keyMatch2(key1, key2)
	case "keyMatch3":
		result.Matched, err = keyMatch3(key1, key2)
	case "keyMatch4":
		result.Matched, err = keyMatch4(key1, key2)
	case "keyMatch5":
		result.Matched, err = keyMatch5(key1, key2)
	case "regexMatch":
		result.Matched, err = regexMatch(key1, key2)
	case "globMatch":
		result.Matched, err = globMatch(key1, key2)
	default:
		err = &MatchError{Matcher: matcher, Pattern: key2, Kind: MatchErrorUnsupported}
	}

	if err != nil {
		result.Err = AsMatchError(err)
		if result.Err == nil {
			// Defensive: every built-in matcher reports MatchError, but never
			// let an unstructured error leak through as a panic.
			result.Err = &MatchError{Matcher: matcher, Pattern: key2, Kind: MatchErrorSyntax, Cause: err}
		}
		result.Matched = false
	}

	result.Class = ClassifyPattern(matcher, key2)
	return result
}

// ClassifyPattern reports which feature class applies to pattern for matcher.
// The classification is descriptive only and never affects matching.
func ClassifyPattern(matcher string, pattern string) PatternClass {
	switch matcher {
	case "regexMatch":
		return PatternRegex
	case "globMatch":
		return classifyGlob(pattern)
	case "keyMatch2", "keyGet2":
		return classifySegmentPattern(pattern, ':')
	case "keyMatch3", "keyMatch4", "keyMatch5", "keyGet3":
		return classifySegmentPattern(pattern, '{')
	default:
		if strings.Contains(pattern, "*") {
			return PatternWildcard
		}
		return PatternLiteral
	}
}

func classifyGlob(pattern string) PatternClass {
	switch {
	case strings.ContainsAny(pattern, "[?*"):
		if strings.Contains(pattern, "[") {
			return PatternBracket
		}
		return PatternWildcard
	default:
		return PatternLiteral
	}
}

func classifySegmentPattern(pattern string, placeholder byte) PatternClass {
	hasBracket := false
	hasStar := false
	hasRegex := false
	hasPlaceholder := false

	for i := 0; i < len(pattern); i++ {
		switch pattern[i] {
		case '[':
			hasBracket = true
		case '*':
			hasStar = true
		case placeholder:
			hasPlaceholder = true
		case '(', ')', '|', '+', '?', '.', '^', '$', '\\':
			hasRegex = true
		}
	}

	switch {
	case hasRegex:
		return PatternRegex
	case hasBracket:
		return PatternBracket
	case hasStar:
		return PatternWildcard
	case hasPlaceholder:
		return PatternPlaceholder
	default:
		return PatternLiteral
	}
}

// validatePatternBounds enforces the size limits shared by every segment
// matcher. It does no work proportional to the pattern in the common case: a
// pattern shorter than MaxPatternSegments bytes cannot hold more segments than
// the limit, so the segment count is only taken when the length allows it.
func validatePatternBounds(matcher string, pattern string) *MatchError {
	if len(pattern) > MaxPatternLength {
		return &MatchError{
			Matcher: matcher,
			Pattern: pattern,
			Kind:    MatchErrorTooLong,
			Cause:   fmt.Errorf("pattern is %d bytes, exceeds the %d byte limit", len(pattern), MaxPatternLength),
		}
	}

	if len(pattern) > MaxPatternSegments {
		if segments := strings.Count(pattern, "/") + 1; segments > MaxPatternSegments {
			return &MatchError{
				Matcher: matcher,
				Pattern: pattern,
				Kind:    MatchErrorTooManySegments,
				Cause:   fmt.Errorf("pattern has %d segments, exceeds the %d segment limit", segments, MaxPatternSegments),
			}
		}
	}

	return nil
}

// validateSegmentPattern enforces the bounds and the segment-boundary star
// rule of KeyMatch2/3/4/5 and KeyGet2/3. It is evaluated once per pattern,
// before the pattern is rewritten or compiled.
func validateSegmentPattern(matcher string, pattern string) *MatchError {
	if err := validatePatternBounds(matcher, pattern); err != nil {
		return err
	}
	return validateStarBoundary(matcher, pattern)
}

// validateStarBoundary rejects a '*' that has a non-empty suffix inside its
// path segment. It is separate from validatePatternBounds so matchers can run
// the cheap bound check before their plain-pattern fast path and only do the
// scan when the pattern can actually hold a star.
func validateStarBoundary(matcher string, pattern string) *MatchError {
	// Only patterns that reach this point can carry a '*', so scanning for one
	// is O(1) for the plain-pattern fast path that keyMatchShortcut handles.
	if !strings.ContainsRune(pattern, '*') {
		return nil
	}

	for _, segment := range strings.Split(pattern, "/") {
		if at, ok := misplacedStar(segment); ok {
			return &MatchError{
				Matcher: matcher,
				Pattern: pattern,
				Kind:    MatchErrorMisplacedStar,
				Cause: fmt.Errorf(
					"'*' at byte %d of segment %q has a non-empty suffix; a wildcard must occupy a whole path segment",
					at,
					segment),
			}
		}
	}

	return nil
}

// misplacedStar finds a '*' that is neither the last character of segment nor
// inside a bracket expression or an escape. Such a star cannot be a
// path-segment wildcard; callers reject it instead of letting it act as an
// accidental regexp prefix.
func misplacedStar(segment string) (int, bool) {
	inClass := false
	escaped := false
	for i := 0; i < len(segment); i++ {
		c := segment[i]
		switch {
		case escaped:
			escaped = false
		case c == '\\':
			escaped = true
		case inClass:
			if c == ']' {
				inClass = false
			}
		case c == '[':
			inClass = true
		case c == '*':
			if i != len(segment)-1 {
				return i, true
			}
		}
	}
	return 0, false
}
