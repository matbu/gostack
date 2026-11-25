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
	"fmt"
	"net/http"
)

/* ============================
   Server groups
============================ */

// serveServerGroups handles /os-server-groups[/{id}].
func serveServerGroups(w http.ResponseWriter, r *http.Request, p []string, projectID string) {
	mu.Lock()
	defer mu.Unlock()

	if len(p) == 0 {
		switch r.Method {
		case http.MethodGet:
			list := AsList(serverGroups, func(g map[string]interface{}) map[string]interface{} { return g })
			writeJSON(w, map[string]interface{}{
				"server_groups": FilterList(list, r.URL.Query(), "policies", "members"),
			})
		case http.MethodPost:
			var req struct {
				ServerGroup struct {
					Name     string                 `json:"name"`
					Policy   string                 `json:"policy"`
					Policies []string               `json:"policies"`
					Rules    map[string]interface{} `json:"rules"`
				} `json:"server_group"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				badRequest(w, Nova, "Invalid request body: "+err.Error())
				return
			}
			if req.ServerGroup.Name == "" {
				badRequest(w, Nova, "Expecting to find name in server_group.")
				return
			}
			policies := req.ServerGroup.Policies
			policy := req.ServerGroup.Policy
			if policy == "" && len(policies) > 0 {
				policy = policies[0]
			}
			if len(policies) == 0 && policy != "" {
				policies = []string{policy}
			}
			rules := req.ServerGroup.Rules
			if rules == nil {
				rules = map[string]interface{}{}
			}
			id := RandomID("servergroup")
			g := map[string]interface{}{
				"id": id, "name": req.ServerGroup.Name,
				"policy": policy, "policies": policies, "rules": rules,
				"members": []interface{}{}, "project_id": projectID,
				"user_id": "demo-user", "metadata": map[string]string{},
			}
			serverGroups[id] = g
			writeJSONStatus(w, http.StatusOK, map[string]interface{}{"server_group": g})
		default:
			methodNotAllowed(w, Nova, r.Method)
		}
		return
	}

	id := p[0]
	g, ok := serverGroups[id]
	if !ok {
		notFound(w, Nova, "Server group "+id)
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, map[string]interface{}{"server_group": g})
	case http.MethodDelete:
		delete(serverGroups, id)
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w, Nova, r.Method)
	}
}

/* ============================
   Host aggregates
============================ */

// serveAggregates handles /os-aggregates[/{id}[/action|/images]].
func serveAggregates(w http.ResponseWriter, r *http.Request, p []string) {
	mu.Lock()
	defer mu.Unlock()

	if len(p) == 0 {
		switch r.Method {
		case http.MethodGet:
			list := AsList(aggregates, func(a map[string]interface{}) map[string]interface{} { return a })
			writeJSON(w, map[string]interface{}{
				"aggregates": FilterList(list, r.URL.Query(), "hosts", "metadata"),
			})
		case http.MethodPost:
			var req struct {
				Aggregate struct {
					Name      string `json:"name"`
					AvailZone string `json:"availability_zone"`
				} `json:"aggregate"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				badRequest(w, Nova, "Invalid request body: "+err.Error())
				return
			}
			if req.Aggregate.Name == "" {
				badRequest(w, Nova, "Expecting to find name in aggregate.")
				return
			}
			for _, a := range aggregates {
				if a["name"] == req.Aggregate.Name {
					apiError(w, Nova, http.StatusConflict,
						"Aggregate "+req.Aggregate.Name+" already exists.")
					return
				}
			}
			aggregateSeq++
			id := fmt.Sprintf("%d", aggregateSeq)
			meta := map[string]interface{}{}
			var az interface{}
			if req.Aggregate.AvailZone != "" {
				az = req.Aggregate.AvailZone
				meta["availability_zone"] = req.Aggregate.AvailZone
			}
			a := map[string]interface{}{
				"id": id, "uuid": RandomID("aggregate"), "name": req.Aggregate.Name,
				"availability_zone": az, "hosts": []interface{}{},
				"metadata": meta, "created_at": nowRFC3339(),
				"updated_at": nil, "deleted_at": nil, "deleted": false,
			}
			aggregates[id] = a
			writeJSONStatus(w, http.StatusOK, map[string]interface{}{"aggregate": a})
		default:
			methodNotAllowed(w, Nova, r.Method)
		}
		return
	}

	id := p[0]
	a, ok := aggregates[id]
	if !ok {
		notFound(w, Nova, "Aggregate "+id)
		return
	}

	// /os-aggregates/{id}/action — host membership and metadata updates.
	if len(p) == 2 && p[1] == "action" {
		if r.Method != http.MethodPost {
			methodNotAllowed(w, Nova, r.Method)
			return
		}
		var body map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			badRequest(w, Nova, "Invalid request body: "+err.Error())
			return
		}
		hosts := toStringSlice(a["hosts"])
		if args, ok := body["add_host"].(map[string]interface{}); ok {
			host, _ := args["host"].(string)
			for _, existing := range hosts {
				if existing == host {
					apiError(w, Nova, http.StatusConflict,
						"Cannot add host "+host+" in aggregate "+id+": host exists.")
					return
				}
			}
			a["hosts"] = append(hosts, host)
			writeJSON(w, map[string]interface{}{"aggregate": a})
			return
		}
		if args, ok := body["remove_host"].(map[string]interface{}); ok {
			host, _ := args["host"].(string)
			out := []string{}
			found := false
			for _, existing := range hosts {
				if existing == host {
					found = true
					continue
				}
				out = append(out, existing)
			}
			if !found {
				notFound(w, Nova, "Host "+host+" in aggregate "+id)
				return
			}
			a["hosts"] = out
			writeJSON(w, map[string]interface{}{"aggregate": a})
			return
		}
		if args, ok := body["set_metadata"].(map[string]interface{}); ok {
			meta, _ := a["metadata"].(map[string]interface{})
			if meta == nil {
				meta = map[string]interface{}{}
			}
			raw, _ := args["metadata"].(map[string]interface{})
			for k, v := range raw {
				// A null value removes the key, as Nova does.
				if v == nil {
					delete(meta, k)
					continue
				}
				meta[k] = v
				if k == "availability_zone" {
					a["availability_zone"] = v
				}
			}
			a["metadata"] = meta
			writeJSON(w, map[string]interface{}{"aggregate": a})
			return
		}
		badRequest(w, Nova, "Unsupported aggregate action")
		return
	}

	switch r.Method {
	case http.MethodGet:
		writeJSON(w, map[string]interface{}{"aggregate": a})
	case http.MethodPut:
		var req struct {
			Aggregate struct {
				Name      *string `json:"name"`
				AvailZone *string `json:"availability_zone"`
			} `json:"aggregate"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			badRequest(w, Nova, "Invalid request body: "+err.Error())
			return
		}
		if req.Aggregate.Name != nil {
			a["name"] = *req.Aggregate.Name
		}
		if req.Aggregate.AvailZone != nil {
			a["availability_zone"] = *req.Aggregate.AvailZone
		}
		a["updated_at"] = nowRFC3339()
		writeJSON(w, map[string]interface{}{"aggregate": a})
	case http.MethodDelete:
		delete(aggregates, id)
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w, Nova, r.Method)
	}
}

/* ============================
   Services, zones, hypervisors, limits
============================ */

// computeServices is the set of compute services gostack reports. It is
// mutable so enabling and disabling a service sticks, which is what the
// compute_service module asserts on.
var computeServices = []map[string]interface{}{
	{"id": "1", "binary": "nova-conductor", "host": "fakehost", "zone": "internal",
		"status": "enabled", "state": "up", "disabled_reason": nil,
		"forced_down": false},
	{"id": "2", "binary": "nova-scheduler", "host": "fakehost", "zone": "internal",
		"status": "enabled", "state": "up", "disabled_reason": nil,
		"forced_down": false},
	{"id": "3", "binary": "nova-compute", "host": "fakehost", "zone": "nova",
		"status": "enabled", "state": "up", "disabled_reason": nil,
		"forced_down": false},
}

// serveComputeServices handles /os-services[/{id}].
func serveComputeServices(w http.ResponseWriter, r *http.Request, p []string) {
	mu.Lock()
	defer mu.Unlock()
	for _, s := range computeServices {
		s["updated_at"] = nowRFC3339()
	}

	switch r.Method {
	case http.MethodGet:
		writeJSON(w, map[string]interface{}{
			"services": FilterList(computeServices, r.URL.Query()),
		})
	case http.MethodPut:
		if len(p) == 0 {
			badRequest(w, Nova, "Expecting a service id in the request path.")
			return
		}
		var req map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			badRequest(w, Nova, "Invalid request body: "+err.Error())
			return
		}
		// Microversion 2.53 addresses a service by id; older clients send
		// host and binary in the body instead.
		for _, s := range computeServices {
			if !computeServiceMatches(s, p[0], req) {
				continue
			}
			for k, v := range req {
				if k == "host" || k == "binary" {
					continue
				}
				s[k] = v
			}
			// The pre-2.53 endpoints carry the new status in the path
			// rather than the body.
			switch p[0] {
			case "enable":
				s["status"] = "enabled"
			case "disable", "disable-log-reason":
				s["status"] = "disabled"
			case "force-down":
				s["forced_down"] = true
			}
			// Enabling a service drops any reason it was disabled for.
			if s["status"] == "enabled" {
				s["disabled_reason"] = nil
			}
			writeJSON(w, map[string]interface{}{"service": s})
			return
		}
		notFound(w, Nova, "Service "+p[0])
	case http.MethodDelete:
		if len(p) > 0 {
			for i, s := range computeServices {
				if s["id"] == p[0] {
					computeServices = append(computeServices[:i], computeServices[i+1:]...)
					break
				}
			}
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w, Nova, r.Method)
	}
}

// computeServiceMatches reports whether a stored service is the one a PUT
// addresses, by id in the path or by host/binary in the body.
func computeServiceMatches(s map[string]interface{}, id string, req map[string]interface{}) bool {
	switch id {
	case "enable", "disable", "disable-log-reason", "force-down":
		host, _ := req["host"].(string)
		binary, _ := req["binary"].(string)
		return s["host"] == host && s["binary"] == binary
	default:
		return s["id"] == id
	}
}

// serveAvailabilityZones handles /os-availability-zone[/detail].
func serveAvailabilityZones(w http.ResponseWriter, r *http.Request, p []string) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, Nova, r.Method)
		return
	}
	zone := map[string]interface{}{
		"zoneName":  "nova",
		"zoneState": map[string]interface{}{"available": true},
		"hosts":     nil,
	}
	if len(p) == 1 && p[0] == "detail" {
		zone["hosts"] = map[string]interface{}{
			"fakehost": map[string]interface{}{
				"nova-compute": map[string]interface{}{
					"available": true, "active": true, "updated_at": nowRFC3339(),
				},
			},
		}
	}
	writeJSON(w, map[string]interface{}{"availabilityZoneInfo": []interface{}{zone}})
}

// serveHypervisors handles /os-hypervisors[/detail|/{id}].
func serveHypervisors(w http.ResponseWriter, r *http.Request, p []string) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, Nova, r.Method)
		return
	}
	hv := map[string]interface{}{
		"id": "1", "hypervisor_hostname": "fakehost", "state": "up",
		"status": "enabled", "hypervisor_type": "QEMU", "hypervisor_version": 6002000,
		"host_ip": "127.0.0.1", "vcpus": 16, "vcpus_used": 0,
		"memory_mb": 65536, "memory_mb_used": 512, "memory_mb_free": 65024,
		"local_gb": 500, "local_gb_used": 0, "free_disk_gb": 500,
		"running_vms": len(servers), "disk_available_least": 500,
		"service": map[string]interface{}{
			"id": "3", "host": "fakehost", "disabled_reason": nil,
		},
	}
	if len(p) == 1 && p[0] != "detail" && p[0] != "statistics" {
		if p[0] != "1" {
			notFound(w, Nova, "Hypervisor "+p[0])
			return
		}
		writeJSON(w, map[string]interface{}{"hypervisor": hv})
		return
	}
	if len(p) == 1 && p[0] == "statistics" {
		writeJSON(w, map[string]interface{}{"hypervisor_statistics": map[string]interface{}{
			"count": 1, "vcpus": 16, "vcpus_used": 0, "memory_mb": 65536,
			"memory_mb_used": 512, "local_gb": 500, "local_gb_used": 0,
			"running_vms": len(servers),
		}})
		return
	}
	writeJSON(w, map[string]interface{}{"hypervisors": []interface{}{hv}})
}

// serveComputeLimits handles GET /limits.
func serveComputeLimits(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, Nova, r.Method)
		return
	}
	mu.Lock()
	used := len(servers)
	mu.Unlock()
	writeJSON(w, map[string]interface{}{
		"limits": map[string]interface{}{
			"rate": []interface{}{},
			"absolute": map[string]interface{}{
				"maxTotalInstances":     novaQuotaDefaults["instances"],
				"maxTotalCores":         novaQuotaDefaults["cores"],
				"maxTotalRAMSize":       novaQuotaDefaults["ram"],
				"maxTotalKeypairs":      novaQuotaDefaults["key_pairs"],
				"maxServerMeta":         novaQuotaDefaults["metadata_items"],
				"maxServerGroups":       novaQuotaDefaults["server_groups"],
				"maxServerGroupMembers": novaQuotaDefaults["server_group_members"],
				"totalInstancesUsed":    used,
				"totalCoresUsed":        0,
				"totalRAMUsed":          0,
				"totalServerGroupsUsed": len(serverGroups),
			},
		},
	})
}
