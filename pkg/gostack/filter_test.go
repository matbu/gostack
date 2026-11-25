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
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func query(t *testing.T, raw string) url.Values {
	t.Helper()
	q, err := url.ParseQuery(raw)
	require.NoError(t, err)
	return q
}

func TestMatchesFilters(t *testing.T) {
	obj := map[string]interface{}{
		"id":          "net-1",
		"name":        "private",
		"status":      "ACTIVE",
		"shared":      false,
		"mtu":         1500,
		"project_id":  "demo",
		"description": "",
		"tags":        []interface{}{"blue", "green"},
	}

	tests := []struct {
		name  string
		query string
		want  bool
	}{
		{"no filters matches", "", true},
		{"matching name", "name=private", true},
		{"other name", "name=public", false},
		{"name is case sensitive", "name=Private", false},
		{"matching id", "id=net-1", true},
		{"integer attribute", "mtu=1500", true},
		{"wrong integer", "mtu=9000", false},
		{"python false", "shared=False", true},
		{"python true", "shared=True", false},
		{"lowercase bool", "shared=false", true},
		{"empty description matches empty filter", "description=", true},
		{"tenant_id falls back to project_id", "tenant_id=demo", true},
		{"wrong tenant_id", "tenant_id=other", false},
		{"unmodelled attribute is ignored", "flavour=chocolate", true},
		{"unset value does not narrow", "name=None", true},
		{"lowercase unset value does not narrow", "is_public=none", true},
		{"repeated filter is an or", "name=public&name=private", true},
		{"repeated filter with no match", "name=public&name=other", false},
		{"control parameter is not an attribute", "limit=1", true},
		{"tags all present", "tags=blue,green", true},
		{"tags missing one", "tags=blue,red", false},
		{"tags-any one present", "tags-any=red,green", true},
		{"not-tags excludes", "not-tags=blue,green", false},
		{"not-tags-any excludes", "not-tags-any=red,green", false},
		{"not-tags-any keeps unrelated", "not-tags-any=red", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MatchesFilters(obj, query(t, tt.query))
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestMatchesFiltersSkip(t *testing.T) {
	obj := map[string]interface{}{"id": "p1", "fixed_ips": []interface{}{}}
	// A caller that handles a parameter itself passes it in skip, and the
	// generic matcher must leave it alone.
	assert.True(t, MatchesFilters(obj, query(t, "fixed_ips=ip_address%3D1.2.3.4"), "fixed_ips"))
	assert.False(t, MatchesFilters(obj, query(t, "fixed_ips=ip_address%3D1.2.3.4")))
}

func TestFilterListIsOrderedAndNeverNil(t *testing.T) {
	list := []map[string]interface{}{
		{"id": "c", "created_at": "2026-01-03T00:00:00"},
		{"id": "a", "created_at": "2026-01-01T00:00:00"},
		{"id": "b", "created_at": "2026-01-02T00:00:00"},
	}
	got := FilterList(list, url.Values{})
	require.Len(t, got, 3)
	assert.Equal(t, []interface{}{"a", "b", "c"},
		[]interface{}{got[0]["id"], got[1]["id"], got[2]["id"]})

	// Same creation time falls back to id, so the order stays total.
	tied := []map[string]interface{}{
		{"id": "z", "created_at": "2026-01-01T00:00:00"},
		{"id": "y", "created_at": "2026-01-01T00:00:00"},
	}
	got = FilterList(tied, url.Values{})
	assert.Equal(t, "y", got[0]["id"])

	// An empty result serialises as [] rather than null.
	assert.NotNil(t, FilterList(nil, url.Values{}))
}

func TestApplyLimit(t *testing.T) {
	list := []map[string]interface{}{{"id": "1"}, {"id": "2"}, {"id": "3"}}
	assert.Len(t, ApplyLimit(list, query(t, "limit=2")), 2)
	assert.Len(t, ApplyLimit(list, query(t, "limit=0")), 3)
	assert.Len(t, ApplyLimit(list, query(t, "limit=99")), 3)
	assert.Len(t, ApplyLimit(list, query(t, "limit=nonsense")), 3)
	assert.Len(t, ApplyLimit(list, url.Values{}), 3)
}

func TestShowAllProjects(t *testing.T) {
	t.Cleanup(func() { SetAdminScope(false) })

	SetAdminScope(false)
	assert.False(t, ShowAllProjects(url.Values{}))
	assert.True(t, ShowAllProjects(query(t, "project_id=other")))
	assert.True(t, ShowAllProjects(query(t, "tenant_id=other")))
	assert.True(t, ShowAllProjects(query(t, "all_tenants=1")))
	assert.False(t, ShowAllProjects(query(t, "all_tenants=0")))

	// Admin scope widens every listing, however it was requested.
	SetAdminScope(true)
	assert.True(t, ShowAllProjects(url.Values{}))
}

func TestCompactPrefixes(t *testing.T) {
	tests := []struct {
		name string
		in   []interface{}
		want []interface{}
	}{
		{
			"adjacent halves merge into their parent",
			[]interface{}{"192.168.0.0/24", "192.168.1.0/24"},
			[]interface{}{"192.168.0.0/23"},
		},
		{
			"a contained block is absorbed",
			[]interface{}{"10.0.0.0/8", "10.1.2.0/24"},
			[]interface{}{"10.0.0.0/8"},
		},
		{
			"unrelated blocks are kept and sorted",
			[]interface{}{"192.168.4.0/24", "10.0.0.0/24"},
			[]interface{}{"10.0.0.0/24", "192.168.4.0/24"},
		},
		{
			"a single prefix is unchanged",
			[]interface{}{"192.168.0.0/24"},
			[]interface{}{"192.168.0.0/24"},
		},
		{
			"non-adjacent siblings do not merge",
			[]interface{}{"192.168.0.0/24", "192.168.2.0/24"},
			[]interface{}{"192.168.0.0/24", "192.168.2.0/24"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, compactPrefixes(tt.in))
		})
	}
}

func TestDefaultGatewayAndPools(t *testing.T) {
	// Neutron derives the gateway and the allocation pool from the CIDR,
	// and router interfaces land on that gateway address.
	assert.Equal(t, "10.10.10.1", defaultGatewayIP("10.10.10.0/24"))
	assert.Nil(t, defaultGatewayIP("not-a-cidr"))

	pools := defaultAllocationPools("10.10.10.0/24")
	require.Len(t, pools, 1)
	pool := pools[0].(map[string]interface{})
	assert.Equal(t, "10.10.10.2", pool["start"])
	assert.Equal(t, "10.10.10.254", pool["end"])
}

func TestNormalizeCIDR(t *testing.T) {
	// Neutron stores a bare address as a host route.
	assert.Equal(t, "5.6.7.8/32", normalizeCIDR("5.6.7.8"))
	assert.Equal(t, "2001:db8::1/128", normalizeCIDR("2001:db8::1"))
	assert.Equal(t, "0.0.0.0/0", normalizeCIDR("0.0.0.0/0"))
	assert.Nil(t, normalizeCIDR(nil))
}
