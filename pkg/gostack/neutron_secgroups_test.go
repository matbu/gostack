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
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newSecGroupTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	mu.Lock()
	savedGroups, savedRules := neutronSecGroups, neutronSecGroupRules
	savedGroupSeq, savedRuleSeq := secGroupSeq, secGroupRuleSeq
	neutronSecGroups = []map[string]interface{}{}
	neutronSecGroupRules = []map[string]interface{}{}
	mu.Unlock()

	mux := http.NewServeMux()
	registerNeutronSecurityGroups(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(func() {
		srv.Close()
		mu.Lock()
		neutronSecGroups, neutronSecGroupRules = savedGroups, savedRules
		secGroupSeq, secGroupRuleSeq = savedGroupSeq, savedRuleSeq
		mu.Unlock()
	})
	return srv
}

func postJSON(t *testing.T, url string, body interface{}) (int, map[string]interface{}) {
	t.Helper()
	data, err := json.Marshal(body)
	require.NoError(t, err)
	resp, err := http.Post(url, "application/json", bytes.NewReader(data))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	out := map[string]interface{}{}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	return resp.StatusCode, out
}

func getJSON(t *testing.T, url string) map[string]interface{} {
	t.Helper()
	resp, err := http.Get(url)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	out := map[string]interface{}{}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	return out
}

func createSecGroup(t *testing.T, srv *httptest.Server, name string) string {
	t.Helper()
	code, out := postJSON(t, srv.URL+"/v2.0/security-groups",
		map[string]interface{}{"security_group": map[string]interface{}{"name": name}})
	require.Equal(t, http.StatusCreated, code)
	return out["security_group"].(map[string]interface{})["id"].(string)
}

func tcp80Rule(sgID string) map[string]interface{} {
	return map[string]interface{}{"security_group_rule": map[string]interface{}{
		"security_group_id": sgID,
		"direction":         "ingress",
		"ethertype":         "IPv4",
		"protocol":          "tcp",
		"port_range_min":    80,
		"port_range_max":    80,
		"remote_ip_prefix":  "0.0.0.0/0",
	}}
}

func TestSecGroupListEmbedsRules(t *testing.T) {
	srv := newSecGroupTestServer(t)
	sgID := createSecGroup(t, srv, "web")
	otherID := createSecGroup(t, srv, "other")

	code, _ := postJSON(t, srv.URL+"/v2.0/security-group-rules", tcp80Rule(sgID))
	require.Equal(t, http.StatusCreated, code)

	groups := getJSON(t, srv.URL+"/v2.0/security-groups")["security_groups"].([]interface{})
	require.Len(t, groups, 2)
	rulesByGroup := map[string][]interface{}{}
	for _, g := range groups {
		sg := g.(map[string]interface{})
		rulesByGroup[sg["id"].(string)] = sg["security_group_rules"].([]interface{})
	}
	// Neutron gives every new group a default egress rule per address
	// family, so the explicit rule is the third one here and a group with
	// no explicit rules still has two.
	require.Len(t, rulesByGroup[sgID], 3)
	assert.Equal(t, "tcp", ruleWithProtocol(t, rulesByGroup[sgID], "tcp")["protocol"])
	assert.Len(t, rulesByGroup[otherID], 2)
	for _, raw := range rulesByGroup[otherID] {
		assert.Equal(t, "egress", raw.(map[string]interface{})["direction"])
	}
}

// ruleWithProtocol returns the single rule in rules using the given
// protocol, failing the test when there is not exactly one.
func ruleWithProtocol(t *testing.T, rules []interface{}, protocol string) map[string]interface{} {
	t.Helper()
	var found map[string]interface{}
	for _, raw := range rules {
		rule := raw.(map[string]interface{})
		if rule["protocol"] == protocol {
			require.Nil(t, found, "more than one %s rule", protocol)
			found = rule
		}
	}
	require.NotNil(t, found, "no %s rule found", protocol)
	return found
}

func TestSecGroupRuleDuplicateConflict(t *testing.T) {
	srv := newSecGroupTestServer(t)
	sgID := createSecGroup(t, srv, "web")
	rulesURL := srv.URL + "/v2.0/security-group-rules"

	code, first := postJSON(t, rulesURL, tcp80Rule(sgID))
	require.Equal(t, http.StatusCreated, code)
	firstID := first["security_group_rule"].(map[string]interface{})["id"]

	// Same rule again (protocol case differs): 409, nothing created.
	dup := tcp80Rule(sgID)
	dup["security_group_rule"].(map[string]interface{})["protocol"] = "TCP"
	code, out := postJSON(t, rulesURL, dup)
	require.Equal(t, http.StatusConflict, code)
	nerr := out["NeutronError"].(map[string]interface{})
	assert.Equal(t, "SecurityGroupRuleExists", nerr["type"])
	assert.Contains(t, nerr["message"], firstID)

	// A different port is a different rule.
	other := tcp80Rule(sgID)
	other["security_group_rule"].(map[string]interface{})["port_range_min"] = 443
	other["security_group_rule"].(map[string]interface{})["port_range_max"] = 443
	code, _ = postJSON(t, rulesURL, other)
	require.Equal(t, http.StatusCreated, code)

	// Same rule as an IPv6 rule is different too.
	v6 := tcp80Rule(sgID)
	v6["security_group_rule"].(map[string]interface{})["ethertype"] = "IPv6"
	v6["security_group_rule"].(map[string]interface{})["remote_ip_prefix"] = "::/0"
	code, created := postJSON(t, rulesURL, v6)
	require.Equal(t, http.StatusCreated, code)
	rule := created["security_group_rule"].(map[string]interface{})
	assert.Equal(t, "IPv6", rule["ethertype"])
	assert.Equal(t, "IPv6", rule["ether_type"])

	// Three explicit rules plus the two default egress rules the group was
	// created with.
	rules := getJSON(t, rulesURL+"?security_group_id="+sgID)["security_group_rules"].([]interface{})
	assert.Len(t, rules, 5)
}
