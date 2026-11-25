/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright 2025 Red Hat, Inc.
 *
 */
package gostack

import (
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// controlParams are query parameters that select how a collection is
// rendered rather than which members it contains. They never take part in
// attribute matching.
var controlParams = map[string]bool{
	"limit":           true,
	"marker":          true,
	"offset":          true,
	"sort":            true,
	"sort_key":        true,
	"sort_dir":        true,
	"fields":          true,
	"page_reverse":    true,
	"all_tenants":     true,
	"with_count":      true,
	"include_names":   true,
	"include_subtree": true,
	"force":           true,
	"usage":           true,
	"detail":          true,
	// Tag filters have their own set-semantics, handled separately.
	"tags":         true,
	"tags-any":     true,
	"not-tags":     true,
	"not-tags-any": true,
}

// normalizeScalar renders a stored attribute value as the string an API
// client would compare against. Booleans and numbers are matched loosely
// because clients send them as query strings ("True", "1", "10").
func normalizeScalar(v interface{}) (string, bool) {
	switch t := v.(type) {
	case nil:
		return "", true
	case string:
		return t, true
	case bool:
		return strconv.FormatBool(t), true
	case int:
		return strconv.Itoa(t), true
	case int64:
		return strconv.FormatInt(t, 10), true
	case float64:
		// JSON numbers decode as float64; render integers without a suffix.
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10), true
		}
		return strconv.FormatFloat(t, 'f', -1, 64), true
	default:
		return "", false
	}
}

// scalarEqual compares a stored value against a query string value. Booleans
// accept Python's "True"/"False" spelling, which openstacksdk emits.
func scalarEqual(stored interface{}, want string) bool {
	got, ok := normalizeScalar(stored)
	if !ok {
		return false
	}
	if got == want {
		return true
	}
	// A boolean attribute accepts Python's "True"/"False" spelling, which
	// openstacksdk emits.
	if b, ok := stored.(bool); ok {
		if parsed, err := strconv.ParseBool(strings.ToLower(want)); err == nil {
			return b == parsed
		}
	}
	// Everything else compares exactly: name and status filters are
	// case-sensitive in the real services.
	return false
}

// isUnsetValue reports whether every value for a parameter is a placeholder
// for "not set", which must not narrow the collection.
func isUnsetValue(values []string) bool {
	for _, v := range values {
		// Both spellings turn up: "None" from a bare str(None) and "none"
		// from a lower-cased boolean render.
		if v != "" && !strings.EqualFold(v, "none") && !strings.EqualFold(v, "null") {
			return false
		}
	}
	return true
}

// matchTagFilters applies Neutron's tags / tags-any / not-tags / not-tags-any
// query parameters against the object's tag list.
func matchTagFilters(obj map[string]interface{}, q url.Values) bool {
	tags := map[string]bool{}
	for _, t := range toStringSlice(obj["tags"]) {
		tags[t] = true
	}
	has := func(csv string) (all bool, any bool) {
		all = true
		for _, t := range strings.Split(csv, ",") {
			t = strings.TrimSpace(t)
			if t == "" {
				continue
			}
			if tags[t] {
				any = true
			} else {
				all = false
			}
		}
		return all, any
	}
	for _, csv := range q["tags"] {
		if all, _ := has(csv); !all {
			return false
		}
	}
	for _, csv := range q["tags-any"] {
		if _, any := has(csv); !any {
			return false
		}
	}
	for _, csv := range q["not-tags"] {
		if all, _ := has(csv); all {
			return false
		}
	}
	for _, csv := range q["not-tags-any"] {
		if _, any := has(csv); any {
			return false
		}
	}
	return true
}

// MatchesFilters reports whether obj satisfies every attribute filter in the
// query string.
//
// Only attributes the object actually carries are matched: OpenStack services
// ignore query parameters that are not attributes of the resource, and this
// keeps an unmodelled filter from silently emptying a collection. A filter
// repeated with several values matches if any of them matches, as Neutron
// does. Names in skip are never matched, for callers that handle a parameter
// themselves.
func MatchesFilters(obj map[string]interface{}, q url.Values, skip ...string) bool {
	skipped := map[string]bool{}
	for _, s := range skip {
		skipped[s] = true
	}
	for key, values := range q {
		if controlParams[key] || skipped[key] {
			continue
		}
		// openstacksdk renders an unset parameter as Python's "None"
		// (notably is_public=None, which Nova reads as "do not filter").
		if isUnsetValue(values) {
			continue
		}
		// tenant_id is Neutron's pre-Queens spelling of project_id.
		field := key
		if _, ok := obj[field]; !ok && field == "tenant_id" {
			field = "project_id"
		}
		stored, present := obj[field]
		if !present {
			continue
		}
		matched := false
		for _, want := range values {
			if scalarEqual(stored, want) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return matchTagFilters(obj, q)
}

// FilterList returns the members of list that satisfy the query's filters,
// in a stable order. The result is never nil, so it serializes as [] rather
// than null.
//
// Ordering matters: several collections are backed by a Go map, whose
// iteration order is deliberately random, and clients routinely index into
// a listing. OpenStack returns collections oldest-first, which created_at
// and then id approximate.
func FilterList(list []map[string]interface{}, q url.Values, skip ...string) []map[string]interface{} {
	out := []map[string]interface{}{}
	for _, item := range list {
		if MatchesFilters(item, q, skip...) {
			out = append(out, item)
		}
	}
	SortCollection(out)
	return out
}

// SortCollection orders a collection the way the services do: by creation
// time, falling back to id so the order is total.
func SortCollection(list []map[string]interface{}) {
	sort.SliceStable(list, func(i, j int) bool {
		ci, cj := stringOf(list[i]["created_at"]), stringOf(list[j]["created_at"])
		if ci != cj {
			return ci < cj
		}
		return stringOf(list[i]["id"]) < stringOf(list[j]["id"])
	})
}

// ApplyLimit truncates a filtered collection to the query's limit parameter.
// A missing, zero or unparseable limit returns the list unchanged.
func ApplyLimit(list []map[string]interface{}, q url.Values) []map[string]interface{} {
	raw := q.Get("limit")
	if raw == "" {
		return list
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 || n >= len(list) {
		return list
	}
	return list[:n]
}

// AsList converts a map-keyed store into a slice for filtering, applying fn
// to render each entry.
func AsList[T any](m map[string]T, render func(T) map[string]interface{}) []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(m))
	for _, v := range m {
		out = append(out, render(v))
	}
	return out
}

// QueryBool reads a boolean query parameter, accepting Python's spelling.
func QueryBool(q url.Values, key string) (value bool, present bool) {
	raw := q.Get(key)
	if raw == "" {
		return false, false
	}
	b, err := strconv.ParseBool(strings.ToLower(raw))
	if err != nil {
		return false, false
	}
	return b, true
}

// stringOf renders any attribute value as a string for comparison.
func stringOf(v interface{}) string {
	if s, ok := normalizeScalar(v); ok {
		return s
	}
	return fmt.Sprint(v)
}

// adminScope makes every listing span all projects, as it does for the
// admin role gostack's token already carries. It is off by default, where
// listings are scoped to the token's project so os-migrate's per-project
// export tests see one tenant at a time; the devstack seed profile turns it
// on, because suites written against a real cloud authenticate as admin and
// expect to list resources they created in another project.
var adminScope bool

// SetAdminScope selects whether listings span all projects.
func SetAdminScope(enabled bool) {
	adminScope = enabled
}

// strictResponses makes responses match the real services exactly where
// doing so returns *less* than gostack historically did — a summary
// listing instead of a detailed one, a creation response holding only what
// Nova sends back, a 202 where gostack used to answer 204. Clients built
// against gostack read fields and statuses the real services do not
// provide there, so this is off unless the devstack profile is selected.
var strictResponses bool

// SetStrictResponses selects whether responses are trimmed to what the
// real services return.
func SetStrictResponses(enabled bool) {
	strictResponses = enabled
}

// ShowAllProjects reports whether a listing should ignore the token's
// project scope: either because admin scope is on, or because the client
// named a project (or asked for all of them) itself.
func ShowAllProjects(q url.Values) bool {
	return adminScope || ScopeOverridden(q)
}

// ScopeOverridden reports whether the client named a project itself. gostack
// issues an admin-scoped token, so an explicit project filter has to win
// over the implicit "only my project" scoping a handler would otherwise
// apply — that is what lets a client read another project's resources.
func ScopeOverridden(q url.Values) bool {
	if _, ok := q["project_id"]; ok {
		return true
	}
	if _, ok := q["tenant_id"]; ok {
		return true
	}
	if all, ok := QueryBool(q, "all_tenants"); ok && all {
		return true
	}
	if all, ok := QueryBool(q, "all_projects"); ok && all {
		return true
	}
	return false
}
