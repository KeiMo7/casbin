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
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bmatcuk/doublestar/v4"

	"github.com/casbin/casbin/v3/rbac"

	"github.com/casbin/govaluate"
)

var (
	keyMatch2Re = regexp.MustCompile(`:[^/]+`)
	keyMatch3Re = regexp.MustCompile(`\{[^/]+\}`)
	keyMatch4Re = regexp.MustCompile(`{([^/]+)}`)
	keyMatch5Re = regexp.MustCompile(`\{[^/]+\}`)
	keyGet2Re1  = regexp.MustCompile(`:[^/]+`)
	keyGet3Re1  = regexp.MustCompile(`\{[^/]+?\}`) // non-greedy match of `{...}` to support multiple {} in `/.../`
)

// regexpMetaChars is exactly the set of characters that regexp.QuoteMeta escapes.
// It is spelled out instead of calling QuoteMeta so that keyMatchShortcut never
// allocates; TestRegexpMetaChars guards the two against drifting apart.
const regexpMetaChars = `\.+*?()|[]{}^$`

// keyMatchShortcut answers KeyMatch2/3/4/5 for the two cases that need no regexp
// work at all. ok reports whether matched is the final answer; when it is false
// the caller falls through to its unchanged rewrite-and-match path.
//
// The two cases are:
//
//  1. key2 == "*", the bare wildcard used as the "all domains" key. The regexp
//     path reaches the same answer via "^*$", which only works by accident (see
//     issue #330); making it explicit is both faster and less fragile.
//
//  2. key2 is plain, i.e. it holds no regexp metacharacter and none of the
//     matcher's own pattern characters (extraChars, ":" for KeyMatch2's :param
//     dialect; the "{}" and "*" of the other matchers are already metacharacters).
//     Then "^"+key2+"$" can only match key2 itself, so key1 == key2 is the answer.
//
// Case 2 has to stay conservative because RegexMatch embeds key2 unescaped: a
// stray metacharacter makes key2 behave as a regexp, so "acme.com" does match
// "acmeXcom", and key1 == key2 is not sufficient either ("^a+b$" does not match
// "a+b"). Any such key2 keeps taking the regexp path.
//
// This matters because a DomainMatchingFunc is called O(N*D) times while building
// role links, and real deployments mostly hold concrete domains ("team/123") that
// pay for the full pipeline only to come back false.
func keyMatchShortcut(key1 string, key2 string, extraChars string) (matched bool, ok bool) {
	if key2 == "*" {
		return true, true
	}

	if !strings.ContainsAny(key2, regexpMetaChars) && !strings.ContainsAny(key2, extraChars) {
		return key1 == key2, true
	}

	return false, false
}

// compiledPattern is the fully prepared form of a matcher's key2: the regexp that
// key1 is tested against, plus the names of the pattern variables in the order
// they appear and the submatch index of each one's capture group (only
// KeyGet2/KeyGet3/KeyMatch4 use tokens).
//
// The indices are looked up by group name rather than assumed to be 1..n, because
// key2 can carry capture groups of its own, e.g. "/(a|b)/{id}".
//
// Everything in it is a pure function of key2, so it is built once per distinct
// key2 and reused afterwards. A key2 that does not compile keeps its error here,
// so it is reported on every call without being compiled again.
type compiledPattern struct {
	re     *regexp.Regexp
	tokens []string
	groups []int
	err    error
}

// tokenGroup returns the named capture group that stands in for the i-th pattern
// variable; compilePattern finds it again by tokenGroupName.
func tokenGroup(i int, expr string) string {
	return "(?P<" + tokenGroupName(i) + ">" + expr + ")"
}

func tokenGroupName(i int) string {
	return "casbinToken" + strconv.Itoa(i)
}

func compilePattern(expr string, tokens []string, matcher string, pattern string) *compiledPattern {
	re, err := regexp.Compile(expr)
	if err != nil {
		return &compiledPattern{tokens: tokens, err: newMatchError(matcher, pattern, MatchErrorSyntax, err)}
	}

	groups := make([]int, len(tokens))
	for i := range tokens {
		groups[i] = re.SubexpIndex(tokenGroupName(i))
	}

	return &compiledPattern{re: re, tokens: tokens, groups: groups}
}

// replaceTokens replaces every match of tokenRe in key2 with a numbered
// tokenGroup around expr.
func replaceTokens(key2 string, tokenRe *regexp.Regexp, expr string) string {
	i := 0
	return tokenRe.ReplaceAllStringFunc(key2, func(string) string {
		group := tokenGroup(i, expr)
		i++
		return group
	})
}

// newMatchError builds a *MatchError, stamping the original pattern.
func newMatchError(matcher string, pattern string, kind MatchErrorKind, cause error) *MatchError {
	return &MatchError{Matcher: matcher, Pattern: pattern, Kind: kind, Cause: cause}
}

// tooLongPattern is the MatchError reported when key2 exceeds MaxPatternLength.
func tooLongPattern(matcher string, pattern string) *MatchError {
	return newMatchError(matcher, pattern, MatchErrorTooLong,
		fmt.Errorf("pattern is %d bytes, exceeds the %d byte limit", len(pattern), MaxPatternLength))
}

// compiledPattern.match returns the stored pattern error, if any.
func (p *compiledPattern) match(key1 string) (bool, error) {
	if p.err != nil {
		return false, p.err
	}
	return p.re.MatchString(key1), nil
}

// patternCache memoizes compiledPattern by raw key2, one cache per matcher since
// each of them reads key2 in its own dialect. Only compiling the regexp used to be
// cached, which still left every call rebuilding the regexp source with a chain of
// ReplaceAll passes just to look it up. Keying on key2 instead makes the steady
// state a single map read.
//
// The cache is read-mostly, so reads go through sync.Map without a lock. Writes
// are serialized by mu, which also maintains a bounded FIFO of keys: once the
// cache holds patternCacheMax entries, inserting a new pattern evicts the oldest
// one. Eviction only drops a compiled result; the next use of that pattern
// recompiles it and reaches the same answer, so eviction can never change a
// decision. The bound matters because key2 can come from an external policy
// source and would otherwise grow the cache without limit.
type patternCache struct {
	// m is never copied, so reset clears it with Range+Delete instead of
	// assigning a fresh sync.Map.
	m   sync.Map // string -> *compiledPattern
	mu  sync.Mutex
	key []string // FIFO ring of cached keys
	pos int      // next slot to overwrite once full
	max int

	hits   uint64
	misses uint64
}

// patternCacheMax is the default number of distinct patterns held per matcher.
// It is deliberately generous for real policies and finite for hostile input.
const patternCacheMax = 4096

func newPatternCache(max int) *patternCache {
	if max <= 0 {
		max = patternCacheMax
	}
	return &patternCache{max: max}
}

func (c *patternCache) reset(max int) {
	if max <= 0 {
		max = patternCacheMax
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m.Range(func(k interface{}, _ interface{}) bool {
		c.m.Delete(k)
		return true
	})
	c.key = nil
	c.pos = 0
	c.max = max
	atomic.StoreUint64(&c.hits, 0)
	atomic.StoreUint64(&c.misses, 0)
}

func (c *patternCache) get(key2 string, build func(key2 string) *compiledPattern) *compiledPattern {
	if v, ok := c.m.Load(key2); ok {
		atomic.AddUint64(&c.hits, 1)
		return v.(*compiledPattern)
	}
	atomic.AddUint64(&c.misses, 1)

	p := build(key2)
	if actual, loaded := c.m.LoadOrStore(key2, p); loaded {
		return actual.(*compiledPattern)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.key) < c.max {
		c.key = append(c.key, key2)
		return p
	}

	// Full: overwrite the oldest key in the FIFO ring.
	evicted := c.key[c.pos]
	c.key[c.pos] = key2
	c.pos = (c.pos + 1) % c.max
	c.m.Delete(evicted)

	return p
}

// len returns the number of cached patterns.
func (c *patternCache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.key)
}

func (c *patternCache) stats() (hits uint64, misses uint64) {
	return atomic.LoadUint64(&c.hits), atomic.LoadUint64(&c.misses)
}

var (
	keyMatch2Cache = newPatternCache(patternCacheMax)
	keyMatch3Cache = newPatternCache(patternCacheMax)
	keyMatch4Cache = newPatternCache(patternCacheMax)
	keyMatch5Cache = newPatternCache(patternCacheMax)
	keyGet2Cache   = newPatternCache(patternCacheMax)
	keyGet3Cache   = newPatternCache(patternCacheMax)
	regexCache     = newPatternCache(patternCacheMax)
	globCache      = newPatternCache(patternCacheMax)
)

// SetPatternCacheCapacity resets every built-in pattern cache and sets the
// maximum number of distinct patterns each may retain. A non-positive value
// restores the default. Resetting is safe at any time with respect to the
// results of matching, but it clears the caches and counters, so call it
// during setup rather than concurrently with live enforcement.
func SetPatternCacheCapacity(max int) {
	for _, c := range []*patternCache{
		keyMatch2Cache, keyMatch3Cache, keyMatch4Cache, keyMatch5Cache,
		keyGet2Cache, keyGet3Cache, regexCache, globCache,
	} {
		c.reset(max)
	}
}

// PatternCacheStats reports hits, misses and the retained size, per matcher.
// It exists so callers can confirm that a batch of decisions parses each
// distinct pattern at most once.
func PatternCacheStats(matcher string) (hits uint64, misses uint64, size int, ok bool) {
	c := patternCacheFor(matcher)
	if c == nil {
		return 0, 0, 0, false
	}
	hits, misses = c.stats()
	return hits, misses, c.len(), true
}

func patternCacheFor(matcher string) *patternCache {
	switch matcher {
	case "keyMatch2":
		return keyMatch2Cache
	case "keyMatch3":
		return keyMatch3Cache
	case "keyMatch4":
		return keyMatch4Cache
	case "keyMatch5":
		return keyMatch5Cache
	case "keyGet2":
		return keyGet2Cache
	case "keyGet3":
		return keyGet3Cache
	case "regexMatch":
		return regexCache
	case "globMatch":
		return globCache
	default:
		return nil
	}
}

// validate the variadic parameter size and type as string.
func validateVariadicArgs(expectedLen int, args ...interface{}) error {
	if len(args) != expectedLen {
		return fmt.Errorf("expected %d arguments, but got %d", expectedLen, len(args))
	}

	for _, p := range args {
		_, ok := p.(string)
		if !ok {
			return errors.New("argument must be a string")
		}
	}

	return nil
}

// validate the variadic string parameter size.
func validateVariadicStringArgs(expectedLen int, args ...string) error {
	if len(args) != expectedLen {
		return fmt.Errorf("expected %d arguments, but got %d", expectedLen, len(args))
	}
	return nil
}

// KeyMatch determines whether key1 matches the pattern of key2 (similar to RESTful path), key2 can contain a *.
// For example, "/foo/bar" matches "/foo/*".
// A pattern longer than MaxPatternLength matches nothing; KeyMatchFunc reports
// it as a MatchError.
func KeyMatch(key1 string, key2 string) bool {
	matched, _ := keyMatch(key1, key2)
	return matched
}

func keyMatch(key1 string, key2 string) (bool, error) {
	if err := validatePatternBounds("keyMatch", key2); err != nil {
		return false, err
	}

	i := strings.Index(key2, "*")
	if i == -1 {
		return key1 == key2, nil
	}

	if len(key1) > i {
		return key1[:i] == key2[:i], nil
	}
	return key1 == key2[:i], nil
}

// KeyMatchFunc is the wrapper for KeyMatch.
func KeyMatchFunc(args ...interface{}) (interface{}, error) {
	if err := validateVariadicArgs(2, args...); err != nil {
		return false, fmt.Errorf("%s: %w", "keyMatch", err)
	}

	name1 := args[0].(string)
	name2 := args[1].(string)

	matched, err := keyMatch(name1, name2)
	if err != nil {
		return false, fmt.Errorf("%s: %w", "keyMatch", err)
	}
	return matched, nil
}

// KeyGet returns the matched part
// For example, "/foo/bar/foo" matches "/foo/*"
// "bar/foo" will been returned.
// A pattern longer than MaxPatternLength returns ""; KeyGetFunc reports it as a
// MatchError.
func KeyGet(key1, key2 string) string {
	value, _ := keyGet(key1, key2)
	return value
}

func keyGet(key1, key2 string) (string, error) {
	if err := validatePatternBounds("keyGet", key2); err != nil {
		return "", err
	}

	i := strings.Index(key2, "*")
	if i == -1 {
		return "", nil
	}
	if len(key1) > i {
		if key1[:i] == key2[:i] {
			return key1[i:], nil
		}
	}
	return "", nil
}

// KeyGetFunc is the wrapper for KeyGet.
func KeyGetFunc(args ...interface{}) (interface{}, error) {
	if err := validateVariadicArgs(2, args...); err != nil {
		return false, fmt.Errorf("%s: %w", "keyGet", err)
	}

	name1 := args[0].(string)
	name2 := args[1].(string)

	return KeyGet(name1, name2), nil
}

// KeyMatch2 determines whether key1 matches the pattern of key2 (similar to RESTful path), key2 can contain a *.
// For example, "/foo/bar" matches "/foo/*", "/resource1" matches "/:resource".
// An invalid pattern matches nothing; KeyMatch2Func reports it as an error.
func KeyMatch2(key1 string, key2 string) bool {
	matched, _ := keyMatch2(key1, key2)
	return matched
}

func keyMatch2(key1 string, key2 string) (bool, error) {
	if err := validatePatternBounds("keyMatch2", key2); err != nil {
		return false, err
	}
	if matched, ok := keyMatchShortcut(key1, key2, ":"); ok {
		return matched, nil
	}

	if err := validateStarBoundary("keyMatch2", key2); err != nil {
		return false, err
	}

	return keyMatch2Cache.get(key2, buildKeyMatch2).match(key1)
}

func buildKeyMatch2(key2 string) *compiledPattern {
	original := key2

	key2 = strings.ReplaceAll(key2, "/*", "/.*")

	key2 = keyMatch2Re.ReplaceAllString(key2, "$1[^/]+$2")

	return compilePattern("^"+key2+"$", nil, "keyMatch2", original)
}

// KeyMatch2Func is the wrapper for KeyMatch2.
func KeyMatch2Func(args ...interface{}) (interface{}, error) {
	if err := validateVariadicArgs(2, args...); err != nil {
		return false, fmt.Errorf("%s: %w", "keyMatch2", err)
	}

	name1 := args[0].(string)
	name2 := args[1].(string)

	matched, err := keyMatch2(name1, name2)
	if err != nil {
		return false, fmt.Errorf("%s: %w", "keyMatch2", err)
	}

	return matched, nil
}

// KeyGet2 returns value matched pattern
// For example, "/resource1" matches "/:resource"
// if the pathVar == "resource", then "resource1" will be returned.
// An invalid pattern returns ""; KeyGet2Func reports it as an error.
func KeyGet2(key1, key2 string, pathVar string) string {
	value, _ := keyGet2(key1, key2, pathVar)
	return value
}

func keyGet2(key1 string, key2 string, pathVar string) (string, error) {
	if err := validateSegmentPattern("keyGet2", key2); err != nil {
		return "", err
	}
	return extractKey(keyGet2Cache.get(key2, buildKeyGet2), key1, pathVar)
}

func extractKey(p *compiledPattern, key1 string, pathVar string) (string, error) {
	if p.err != nil {
		return "", p.err
	}

	values := p.re.FindStringSubmatch(key1)
	if values == nil {
		return "", nil
	}
	for i, key := range p.tokens {
		if pathVar == key {
			return values[p.groups[i]], nil
		}
	}
	return "", nil
}

func buildKeyGet2(key2 string) *compiledPattern {
	original := key2

	key2 = strings.ReplaceAll(key2, "/*", "/.*")

	// The ":" is dropped here so that the lookup in KeyGet2 is a plain comparison.
	tokens := keyGet2Re1.FindAllString(key2, -1)
	for i, token := range tokens {
		tokens[i] = token[1:]
	}

	key2 = replaceTokens(key2, keyGet2Re1, "[^/]+")

	return compilePattern("^"+key2+"$", tokens, "keyGet2", original)
}

// KeyGet2Func is the wrapper for KeyGet2.
func KeyGet2Func(args ...interface{}) (interface{}, error) {
	if err := validateVariadicArgs(3, args...); err != nil {
		return false, fmt.Errorf("%s: %w", "keyGet2", err)
	}

	name1 := args[0].(string)
	name2 := args[1].(string)
	key := args[2].(string)

	value, err := keyGet2(name1, name2, key)
	if err != nil {
		return "", fmt.Errorf("%s: %w", "keyGet2", err)
	}

	return value, nil
}

// KeyMatch3 determines whether key1 matches the pattern of key2 (similar to RESTful path), key2 can contain a *.
// For example, "/foo/bar" matches "/foo/*", "/resource1" matches "/{resource}".
// An invalid pattern matches nothing; KeyMatch3Func reports it as an error.
func KeyMatch3(key1 string, key2 string) bool {
	matched, _ := keyMatch3(key1, key2)
	return matched
}

func keyMatch3(key1 string, key2 string) (bool, error) {
	if err := validatePatternBounds("keyMatch3", key2); err != nil {
		return false, err
	}
	if matched, ok := keyMatchShortcut(key1, key2, ""); ok {
		return matched, nil
	}

	if err := validateStarBoundary("keyMatch3", key2); err != nil {
		return false, err
	}

	return keyMatch3Cache.get(key2, buildKeyMatch3).match(key1)
}

func buildKeyMatch3(key2 string) *compiledPattern {
	original := key2

	key2 = strings.ReplaceAll(key2, "/*", "/.*")
	key2 = keyMatch3Re.ReplaceAllString(key2, "$1[^/]+$2")

	return compilePattern("^"+key2+"$", nil, "keyMatch3", original)
}

// KeyMatch3Func is the wrapper for KeyMatch3.
func KeyMatch3Func(args ...interface{}) (interface{}, error) {
	if err := validateVariadicArgs(2, args...); err != nil {
		return false, fmt.Errorf("%s: %w", "keyMatch3", err)
	}

	name1 := args[0].(string)
	name2 := args[1].(string)

	matched, err := keyMatch3(name1, name2)
	if err != nil {
		return false, fmt.Errorf("%s: %w", "keyMatch3", err)
	}

	return matched, nil
}

// KeyGet3 returns value matched pattern
// For example, "project/proj_project1_admin/" matches "project/proj_{project}_admin/"
// if the pathVar == "project", then "project1" will be returned.
// An invalid pattern returns ""; KeyGet3Func reports it as an error.
func KeyGet3(key1, key2 string, pathVar string) string {
	value, _ := keyGet3(key1, key2, pathVar)
	return value
}

func keyGet3(key1 string, key2 string, pathVar string) (string, error) {
	if err := validateSegmentPattern("keyGet3", key2); err != nil {
		return "", err
	}
	return extractKey(keyGet3Cache.get(key2, buildKeyGet3), key1, pathVar)
}

func buildKeyGet3(key2 string) *compiledPattern {
	original := key2

	key2 = strings.ReplaceAll(key2, "/*", "/.*")

	// The surrounding "{}" is dropped here so that the lookup in KeyGet3 is a plain
	// comparison.
	tokens := keyGet3Re1.FindAllString(key2, -1)
	for i, token := range tokens {
		tokens[i] = token[1 : len(token)-1]
	}

	key2 = replaceTokens(key2, keyGet3Re1, "[^/]+?")

	return compilePattern("^"+key2+"$", tokens, "keyGet3", original)
}

// KeyGet3Func is the wrapper for KeyGet3.
func KeyGet3Func(args ...interface{}) (interface{}, error) {
	if err := validateVariadicArgs(3, args...); err != nil {
		return false, fmt.Errorf("%s: %w", "keyGet3", err)
	}

	name1 := args[0].(string)
	name2 := args[1].(string)
	key := args[2].(string)

	value, err := keyGet3(name1, name2, key)
	if err != nil {
		return "", fmt.Errorf("%s: %w", "keyGet3", err)
	}

	return value, nil
}

// KeyMatch4 determines whether key1 matches the pattern of key2 (similar to RESTful path), key2 can contain a *.
// Besides what KeyMatch3 does, KeyMatch4 can also match repeated patterns:
// "/parent/123/child/123" matches "/parent/{id}/child/{id}"
// "/parent/123/child/456" does not match "/parent/{id}/child/{id}"
// But KeyMatch3 will match both.
// An invalid pattern matches nothing; KeyMatch4Func reports it as an error.
func KeyMatch4(key1 string, key2 string) bool {
	matched, _ := keyMatch4(key1, key2)
	return matched
}

func keyMatch4(key1 string, key2 string) (bool, error) {
	if err := validatePatternBounds("keyMatch4", key2); err != nil {
		return false, err
	}
	if matched, ok := keyMatchShortcut(key1, key2, ""); ok {
		return matched, nil
	}

	if err := validateStarBoundary("keyMatch4", key2); err != nil {
		return false, err
	}

	p := keyMatch4Cache.get(key2, buildKeyMatch4)
	if p.err != nil {
		return false, p.err
	}

	matches := p.re.FindStringSubmatch(key1)
	if matches == nil {
		return false, nil
	}

	values := map[string]string{}

	for i, token := range p.tokens {
		match := matches[p.groups[i]]
		if _, ok := values[token]; !ok {
			values[token] = match
		}
		if values[token] != match {
			return false, nil
		}
	}

	return true, nil
}

func buildKeyMatch4(key2 string) *compiledPattern {
	original := key2

	key2 = strings.ReplaceAll(key2, "/*", "/.*")

	tokens := []string{}

	key2 = keyMatch4Re.ReplaceAllStringFunc(key2, func(s string) string {
		group := tokenGroup(len(tokens), "[^/]+")
		tokens = append(tokens, s[1:len(s)-1])
		return group
	})

	return compilePattern("^"+key2+"$", tokens, "keyMatch4", original)
}

// KeyMatch4Func is the wrapper for KeyMatch4.
func KeyMatch4Func(args ...interface{}) (interface{}, error) {
	if err := validateVariadicArgs(2, args...); err != nil {
		return false, fmt.Errorf("%s: %w", "keyMatch4", err)
	}

	name1 := args[0].(string)
	name2 := args[1].(string)

	matched, err := keyMatch4(name1, name2)
	if err != nil {
		return false, fmt.Errorf("%s: %w", "keyMatch4", err)
	}

	return matched, nil
}

// KeyMatch5 determines whether key1 matches the pattern of key2 (similar to RESTful path), key2 can contain a *
// For example,
// - "/foo/bar?status=1&type=2" matches "/foo/bar"
// - "/parent/child1" and "/parent/child1" matches "/parent/*"
// - "/parent/child1?status=1" matches "/parent/*".
// An invalid pattern matches nothing; KeyMatch5Func reports it as an error.
func KeyMatch5(key1 string, key2 string) bool {
	matched, _ := keyMatch5(key1, key2)
	return matched
}

func keyMatch5(key1 string, key2 string) (bool, error) {
	if err := validatePatternBounds("keyMatch5", key2); err != nil {
		return false, err
	}

	i := strings.Index(key1, "?")

	if i != -1 {
		key1 = key1[:i]
	}

	// After the query string is stripped, so that key1 is compared in the same
	// shape the regexp path would have matched.
	if matched, ok := keyMatchShortcut(key1, key2, ""); ok {
		return matched, nil
	}

	if err := validateStarBoundary("keyMatch5", key2); err != nil {
		return false, err
	}

	return keyMatch5Cache.get(key2, buildKeyMatch5).match(key1)
}

func buildKeyMatch5(key2 string) *compiledPattern {
	original := key2

	key2 = strings.ReplaceAll(key2, "/*", "/.*")
	key2 = keyMatch5Re.ReplaceAllString(key2, "$1[^/]+$2")

	return compilePattern("^"+key2+"$", nil, "keyMatch5", original)
}

// KeyMatch5Func is the wrapper for KeyMatch5.
func KeyMatch5Func(args ...interface{}) (interface{}, error) {
	if err := validateVariadicArgs(2, args...); err != nil {
		return false, fmt.Errorf("%s: %w", "keyMatch5", err)
	}

	name1 := args[0].(string)
	name2 := args[1].(string)

	matched, err := keyMatch5(name1, name2)
	if err != nil {
		return false, fmt.Errorf("%s: %w", "keyMatch5", err)
	}

	return matched, nil
}

// RegexMatch determines whether key1 matches the pattern of key2 in regular expression.
// An invalid pattern matches nothing; RegexMatchFunc reports it as an error.
func RegexMatch(key1 string, key2 string) bool {
	matched, _ := regexMatch(key1, key2)
	return matched
}

func regexMatch(key1 string, key2 string) (bool, error) {
	if err := validatePatternBounds("regexMatch", key2); err != nil {
		return false, err
	}
	return regexCache.get(key2, buildRegexMatch).match(key1)
}

func buildRegexMatch(key2 string) *compiledPattern {
	return compilePattern(key2, nil, "regexMatch", key2)
}

// RegexMatchFunc is the wrapper for RegexMatch.
func RegexMatchFunc(args ...interface{}) (interface{}, error) {
	if err := validateVariadicArgs(2, args...); err != nil {
		return false, fmt.Errorf("%s: %w", "regexMatch", err)
	}

	name1 := args[0].(string)
	name2 := args[1].(string)

	matched, err := regexMatch(name1, name2)
	if err != nil {
		return false, fmt.Errorf("%s: %w", "regexMatch", err)
	}

	return matched, nil
}

// IPMatch determines whether IP address ip1 matches the pattern of IP address ip2, ip2 can be an IP address or a CIDR pattern.
// For example, "192.168.2.123" matches "192.168.2.0/24".
// An invalid argument matches nothing; IPMatchFunc reports it as an error.
func IPMatch(ip1 string, ip2 string) bool {
	matched, _ := ipMatch(ip1, ip2)
	return matched
}

func ipMatch(ip1 string, ip2 string) (bool, error) {
	objIP1 := net.ParseIP(ip1)
	if objIP1 == nil {
		return false, fmt.Errorf("%q is not an IP address", ip1)
	}

	_, cidr, err := net.ParseCIDR(ip2)
	if err == nil {
		return cidr.Contains(objIP1), nil
	}

	objIP2 := net.ParseIP(ip2)
	if objIP2 == nil {
		return false, fmt.Errorf("%q is neither an IP address nor a CIDR", ip2)
	}

	return objIP1.Equal(objIP2), nil
}

// IPMatchFunc is the wrapper for IPMatch.
func IPMatchFunc(args ...interface{}) (interface{}, error) {
	if err := validateVariadicArgs(2, args...); err != nil {
		return false, fmt.Errorf("%s: %w", "ipMatch", err)
	}

	ip1 := args[0].(string)
	ip2 := args[1].(string)

	matched, err := ipMatch(ip1, ip2)
	if err != nil {
		return false, fmt.Errorf("%s: %w", "ipMatch", err)
	}

	return matched, nil
}

// GlobMatch determines whether key1 matches the pattern of key2 using glob pattern.
// An invalid pattern matches nothing; the returned error is a *MatchError.
func GlobMatch(key1 string, key2 string) (bool, error) {
	return globMatch(key1, key2)
}

func globMatch(key1 string, key2 string) (bool, error) {
	if err := validatePatternBounds("globMatch", key2); err != nil {
		return false, err
	}

	if p := globCache.get(key2, buildGlobMatch); p.err != nil {
		return false, p.err
	}

	return doublestar.Match(key2, key1)
}

// buildGlobMatch validates the pattern once; the validated pattern still goes
// through doublestar.Match, which does its own matching work per call.
func buildGlobMatch(key2 string) *compiledPattern {
	if !doublestar.ValidatePattern(key2) {
		return &compiledPattern{err: newMatchError("globMatch", key2, MatchErrorSyntax, doublestar.ErrBadPattern)}
	}
	return &compiledPattern{}
}

// GlobMatchFunc is the wrapper for GlobMatch.
func GlobMatchFunc(args ...interface{}) (interface{}, error) {
	if err := validateVariadicArgs(2, args...); err != nil {
		return false, fmt.Errorf("%s: %w", "globMatch", err)
	}

	name1 := args[0].(string)
	name2 := args[1].(string)

	return GlobMatch(name1, name2)
}

// GenerateGFunction is the factory method of the g(_, _[, _]) function.
// If useCache is true, results are memoized per unique argument combination for performance.
// Set useCache to false when inputs are high-cardinality (e.g. UUIDs) to avoid unbounded memory growth.
func GenerateGFunction(rm rbac.RoleManager, useCache bool) govaluate.ExpressionFunction {
	memorized := sync.Map{}
	return func(args ...interface{}) (interface{}, error) {
		// Like all our other govaluate functions, all args are strings.

		if useCache {
			// Allocate and generate a cache key from the arguments...
			total := len(args)
			for _, a := range args {
				aStr := a.(string)
				total += len(aStr)
			}
			builder := strings.Builder{}
			builder.Grow(total)
			for _, arg := range args {
				builder.WriteByte(0)
				builder.WriteString(arg.(string))
			}
			key := builder.String()

			// ...and see if we've already calculated this.
			if v, found := memorized.Load(key); found {
				return v, nil
			}

			// If not, do the calculation.
			// There are guaranteed to be exactly 2 or 3 arguments.
			name1, name2 := args[0].(string), args[1].(string)
			var v interface{}
			if rm == nil {
				v = name1 == name2
			} else if len(args) == 2 {
				v, _ = rm.HasLink(name1, name2)
			} else {
				domain := args[2].(string)
				v, _ = rm.HasLink(name1, name2, domain)
			}

			memorized.Store(key, v)
			return v, nil
		}

		// No caching path.
		name1, name2 := args[0].(string), args[1].(string)
		var v interface{}
		if rm == nil {
			v = name1 == name2
		} else if len(args) == 2 {
			v, _ = rm.HasLink(name1, name2)
		} else {
			domain := args[2].(string)
			v, _ = rm.HasLink(name1, name2, domain)
		}
		return v, nil
	}
}

// GenerateConditionalGFunction is the factory method of the g(_, _[, _]) function with conditions.
func GenerateConditionalGFunction(crm rbac.ConditionalRoleManager) govaluate.ExpressionFunction {
	return func(args ...interface{}) (interface{}, error) {
		// Like all our other govaluate functions, all args are strings.
		var hasLink bool

		name1, name2 := args[0].(string), args[1].(string)
		if crm == nil {
			hasLink = name1 == name2
		} else if len(args) == 2 {
			hasLink, _ = crm.HasLink(name1, name2)
		} else {
			domain := args[2].(string)
			hasLink, _ = crm.HasLink(name1, name2, domain)
		}

		return hasLink, nil
	}
}

// builtin LinkConditionFunc

// TimeMatchFunc is the wrapper for TimeMatch.
func TimeMatchFunc(args ...string) (bool, error) {
	if err := validateVariadicStringArgs(2, args...); err != nil {
		return false, fmt.Errorf("%s: %w", "TimeMatch", err)
	}
	return TimeMatch(args[0], args[1])
}

// TimeMatch determines whether the current time is between startTime and endTime.
// You can use "_" to indicate that the parameter is ignored.
func TimeMatch(startTime, endTime string) (bool, error) {
	now := time.Now()
	if startTime != "_" {
		if start, err := time.Parse("2006-01-02 15:04:05", startTime); err != nil {
			return false, err
		} else if !now.After(start) {
			return false, nil
		}
	}

	if endTime != "_" {
		if end, err := time.Parse("2006-01-02 15:04:05", endTime); err != nil {
			return false, err
		} else if !now.Before(end) {
			return false, nil
		}
	}

	return true, nil
}
