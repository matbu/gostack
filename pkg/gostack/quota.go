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
	"encoding/json"
	"net/http"
)

// novaQuotaDefaults are the per-project compute quotas devstack ships.
var novaQuotaDefaults = map[string]int{
	"instances": 10, "cores": 20, "ram": 51200, "metadata_items": 128,
	"key_pairs": 100, "server_groups": 10, "server_group_members": 10,
	"injected_files": 5, "injected_file_content_bytes": 10240,
	"injected_file_path_bytes": 255,
}

// neutronQuotaDefaults are the per-project network quotas devstack ships.
var neutronQuotaDefaults = map[string]int{
	"floatingip": 50, "network": 100, "port": 500, "rbac_policy": 10,
	"router": 10, "security_group": 10, "security_group_rule": 100,
	"subnet": 100, "subnetpool": -1,
}

// quotasFor returns the effective quota map for a project: the service
// defaults with any stored override applied. The caller must hold the mutex.
func quotasFor(store map[string]map[string]int, defaults map[string]int, projectID string) map[string]interface{} {
	out := map[string]interface{}{"id": projectID}
	for k, v := range defaults {
		out[k] = v
	}
	for k, v := range store[projectID] {
		out[k] = v
	}
	return out
}

// serveQuotaSet implements the Nova and Cinder os-quota-sets endpoint. p is
// the path from the project id onwards.
func serveQuotaSet(w http.ResponseWriter, r *http.Request, p []string,
	store map[string]map[string]int, defaults map[string]int, svc Service) {
	if len(p) == 0 {
		notFound(w, svc, "Quota set")
		return
	}
	projectID := p[0]
	// /os-quota-sets/{project}/defaults and /detail
	if len(p) == 2 && p[1] == "defaults" {
		out := map[string]interface{}{"id": projectID}
		for k, v := range defaults {
			out[k] = v
		}
		writeJSON(w, map[string]interface{}{"quota_set": out})
		return
	}

	switch r.Method {
	case http.MethodGet:
		mu.Lock()
		out := quotasFor(store, defaults, projectID)
		mu.Unlock()
		if len(p) == 2 && p[1] == "detail" {
			detailed := map[string]interface{}{"id": projectID}
			for k, v := range out {
				if k == "id" {
					continue
				}
				detailed[k] = map[string]interface{}{
					"limit": v, "in_use": 0, "reserved": 0,
				}
			}
			writeJSON(w, map[string]interface{}{"quota_set": detailed})
			return
		}
		writeJSON(w, map[string]interface{}{"quota_set": out})
	case http.MethodPut, http.MethodPost:
		var req struct {
			QuotaSet map[string]interface{} `json:"quota_set"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			badRequest(w, svc, "Invalid request body: "+err.Error())
			return
		}
		mu.Lock()
		if store[projectID] == nil {
			store[projectID] = map[string]int{}
		}
		for k, v := range req.QuotaSet {
			if k == "force" || k == "id" {
				continue
			}
			if s, ok := normalizeScalar(v); ok && s != "" {
				store[projectID][k] = parseSignedInt(s)
			}
		}
		out := quotasFor(store, defaults, projectID)
		mu.Unlock()
		writeJSON(w, map[string]interface{}{"quota_set": out})
	case http.MethodDelete:
		mu.Lock()
		delete(store, projectID)
		mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
	default:
		methodNotAllowed(w, svc, r.Method)
	}
}

// serveNeutronQuotas implements Neutron's /v2.0/quotas endpoints, which use a
// different envelope and path shape from the Nova/Cinder quota sets.
func serveNeutronQuotas(w http.ResponseWriter, r *http.Request, p []string) {
	// GET /v2.0/quotas — every project with an override.
	if len(p) == 0 {
		if r.Method != http.MethodGet {
			methodNotAllowed(w, Neutron, r.Method)
			return
		}
		mu.Lock()
		list := []map[string]interface{}{}
		for projectID := range neutronQuotas {
			list = append(list, quotasFor(neutronQuotas, neutronQuotaDefaults, projectID))
		}
		mu.Unlock()
		writeJSON(w, map[string]interface{}{"quotas": list})
		return
	}

	projectID := p[0]
	if projectID == "default" && len(p) == 1 {
		out := map[string]interface{}{"id": "default"}
		for k, v := range neutronQuotaDefaults {
			out[k] = v
		}
		writeJSON(w, map[string]interface{}{"quota": out})
		return
	}
	// /v2.0/quotas/{project}/default
	if len(p) == 2 && p[1] == "default" {
		out := map[string]interface{}{"id": projectID}
		for k, v := range neutronQuotaDefaults {
			out[k] = v
		}
		writeJSON(w, map[string]interface{}{"quota": out})
		return
	}
	// /v2.0/quotas/{project}/details.json
	if len(p) == 2 && (p[1] == "details" || p[1] == "details.json") {
		mu.Lock()
		out := quotasFor(neutronQuotas, neutronQuotaDefaults, projectID)
		mu.Unlock()
		detailed := map[string]interface{}{}
		for k, v := range out {
			if k == "id" {
				continue
			}
			detailed[k] = map[string]interface{}{"limit": v, "used": 0, "reserved": 0}
		}
		writeJSON(w, map[string]interface{}{"quota": detailed})
		return
	}

	switch r.Method {
	case http.MethodGet:
		mu.Lock()
		out := quotasFor(neutronQuotas, neutronQuotaDefaults, projectID)
		mu.Unlock()
		writeJSON(w, map[string]interface{}{"quota": out})
	case http.MethodPut:
		var req struct {
			Quota map[string]interface{} `json:"quota"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			badRequest(w, Neutron, "Invalid request body: "+err.Error())
			return
		}
		mu.Lock()
		if neutronQuotas[projectID] == nil {
			neutronQuotas[projectID] = map[string]int{}
		}
		for k, v := range req.Quota {
			if s, ok := normalizeScalar(v); ok && s != "" {
				neutronQuotas[projectID][k] = parseSignedInt(s)
			}
		}
		out := quotasFor(neutronQuotas, neutronQuotaDefaults, projectID)
		mu.Unlock()
		writeJSON(w, map[string]interface{}{"quota": out})
	case http.MethodDelete:
		mu.Lock()
		delete(neutronQuotas, projectID)
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w, Neutron, r.Method)
	}
}

// parseSignedInt parses an integer quota value, where -1 means unlimited.
func parseSignedInt(s string) int {
	neg := false
	if len(s) > 0 && (s[0] == '-' || s[0] == '+') {
		neg = s[0] == '-'
		s = s[1:]
	}
	n := atoiSafe(s)
	if neg {
		return -n
	}
	return n
}
