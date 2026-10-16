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
	"log"
	"net/http"
	"time"
)

// Neutron router and security-group state.
var (
	routers              = []map[string]interface{}{}
	routerSeq            = 0
	neutronSecGroupRules = []map[string]interface{}{}
	secGroupSeq          = 1
	secGroupRuleSeq      = 0
)

func enrichRouter(rt map[string]interface{}, projectID string) {
	now := time.Now().UTC().Format(time.RFC3339)
	setDefault(rt, "admin_state_up", true)
	setDefault(rt, "status", "ACTIVE")
	setDefault(rt, "description", "")
	setDefault(rt, "revision_number", 1)
	setDefault(rt, "created_at", now)
	setDefault(rt, "updated_at", now)
	setDefault(rt, "distributed", false)
	setDefault(rt, "ha", false)
	setDefault(rt, "external_gateway_info", nil)
	setDefault(rt, "flavor_id", nil)
	setDefault(rt, "routes", []interface{}{})
	setDefault(rt, "availability_zones", []interface{}{})
	setDefault(rt, "availability_zone_hints", []interface{}{})
	setDefault(rt, "tags", []interface{}{})
	if projectID != "" {
		setDefault(rt, "project_id", projectID)
		setDefault(rt, "tenant_id", rt["project_id"])
	}
}

func enrichSecGroup(sg map[string]interface{}, projectID string) {
	now := time.Now().UTC().Format(time.RFC3339)
	setDefault(sg, "description", "")
	setDefault(sg, "revision_number", 1)
	setDefault(sg, "created_at", now)
	setDefault(sg, "updated_at", now)
	setDefault(sg, "tags", []interface{}{})
	setDefault(sg, "security_group_rules", []interface{}{})
	if projectID != "" {
		setDefault(sg, "project_id", projectID)
		setDefault(sg, "tenant_id", sg["project_id"])
	}
}

func enrichSecGroupRule(ru map[string]interface{}, projectID string) {
	now := time.Now().UTC().Format(time.RFC3339)
	setDefault(ru, "description", nil)
	setDefault(ru, "revision_number", 1)
	setDefault(ru, "created_at", now)
	setDefault(ru, "updated_at", now)
	setDefault(ru, "remote_group_id", nil)
	setDefault(ru, "remote_ip_prefix", nil)
	setDefault(ru, "protocol", nil)
	setDefault(ru, "port_range_min", nil)
	setDefault(ru, "port_range_max", nil)
	setDefault(ru, "ether_type", "IPv4")
	setDefault(ru, "direction", "ingress")
	if projectID != "" {
		setDefault(ru, "project_id", projectID)
		setDefault(ru, "tenant_id", ru["project_id"])
	}
}

func registerNeutronRouters(mux *http.ServeMux) {
	// GET and POST /v2.0/routers
	mux.HandleFunc("/v2.0/routers", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		mu.Lock()
		defer mu.Unlock()
		projectID := ProjectIDFromToken(r)

		switch r.Method {
		case http.MethodGet:
			nameFilter := r.URL.Query().Get("name")
			filtered := []map[string]interface{}{}
			for _, rt := range routers {
				enrichRouter(rt, projectID)
				if rt["project_id"] != projectID {
					continue
				}
				if nameFilter != "" {
					if n, ok := rt["name"].(string); !ok || n != nameFilter {
						continue
					}
				}
				filtered = append(filtered, rt)
			}
			writeJSON(w, map[string]interface{}{"routers": filtered})
		case http.MethodPost:
			var req struct {
				Router map[string]interface{} `json:"router"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			rt := req.Router
			routerSeq++
			rt["id"] = fmt.Sprintf("router-%d", routerSeq)
			enrichRouter(rt, projectID)
			routers = append(routers, rt)
			w.WriteHeader(http.StatusCreated)
			writeJSON(w, map[string]interface{}{"router": rt})
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	// GET/PUT/DELETE /v2.0/routers/{id} and interface add/remove.
	mux.HandleFunc("/v2.0/routers/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		mu.Lock()
		defer mu.Unlock()
		projectID := ProjectIDFromToken(r)

		parts := Parts(r.URL.Path) // ["v2.0","routers","{id}", maybe "add_router_interface"]
		if len(parts) < 3 {
			http.NotFound(w, r)
			return
		}
		id := parts[2]

		idx := -1
		for i, rt := range routers {
			if rt["id"] == id {
				idx = i
				break
			}
		}
		if idx == -1 {
			http.NotFound(w, r)
			return
		}
		rt := routers[idx]
		enrichRouter(rt, projectID)

		if handleTags(w, r, parts, rt) {
			return
		}

		// Interface add/remove: PUT /v2.0/routers/{id}/add_router_interface
		if len(parts) == 4 && r.Method == http.MethodPut {
			var body map[string]interface{}
			_ = json.NewDecoder(r.Body).Decode(&body)
			action := parts[3]
			if action == "add_router_interface" {
				subnetID, _ := body["subnet_id"].(string)
				portID, _ := body["port_id"].(string)
				networkID := ""

				// Attach by port_id: reuse the existing port (which already
				// carries its fixed_ips/subnet), as the router module does.
				if portID != "" {
					for i, p := range ports {
						if p["id"] == portID {
							p["device_id"] = id
							p["device_owner"] = "network:router_interface"
							ports[i] = p
							networkID, _ = p["network_id"].(string)
							if subnetID == "" {
								if fips, ok := p["fixed_ips"].([]interface{}); ok && len(fips) > 0 {
									if f, ok := fips[0].(map[string]interface{}); ok {
										subnetID, _ = f["subnet_id"].(string)
									}
								}
							}
						}
					}
				} else {
					// Attach by subnet_id: create the router port.
					portID = fmt.Sprintf("port-%d", len(ports)+1)
					for _, s := range subnets {
						if s["id"] == subnetID {
							networkID, _ = s["network_id"].(string)
						}
					}
					port := map[string]interface{}{
						"id":           portID,
						"network_id":   networkID,
						"device_id":    id,
						"device_owner": "network:router_interface",
						"project_id":   projectID,
						"status":       "ACTIVE",
						"fixed_ips":    []map[string]interface{}{{"subnet_id": subnetID, "ip_address": "10.0.0.1"}},
					}
					ports = append(ports, port)
				}
				writeJSON(w, map[string]interface{}{
					"id": id, "subnet_id": subnetID, "subnet_ids": []string{subnetID},
					"port_id": portID, "network_id": networkID, "tenant_id": projectID,
				})
				return
			}
			if action == "remove_router_interface" {
				subnetID, _ := body["subnet_id"].(string)
				portID, _ := body["port_id"].(string)
				for i, p := range ports {
					if p["device_id"] == id && (portID == "" || p["id"] == portID) {
						if portID == "" && subnetID != "" {
							// best-effort subnet match
							if fips, ok := p["fixed_ips"].([]map[string]interface{}); ok {
								match := false
								for _, f := range fips {
									if f["subnet_id"] == subnetID {
										match = true
									}
								}
								if !match {
									continue
								}
							}
						}
						portID, _ = p["id"].(string)
						ports = append(ports[:i], ports[i+1:]...)
						break
					}
				}
				writeJSON(w, map[string]interface{}{
					"id": id, "subnet_id": subnetID, "port_id": portID, "tenant_id": projectID,
				})
				return
			}
			http.NotFound(w, r)
			return
		}

		switch r.Method {
		case http.MethodGet:
			writeJSON(w, map[string]interface{}{"router": rt})
		case http.MethodPut:
			var req struct {
				Router map[string]interface{} `json:"router"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			for k, v := range req.Router {
				rt[k] = v
			}
			if rev, ok := rt["revision_number"].(int); ok {
				rt["revision_number"] = rev + 1
			}
			routers[idx] = rt
			writeJSON(w, map[string]interface{}{"router": rt})
		case http.MethodDelete:
			routers = append(routers[:idx], routers[idx+1:]...)
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})
}

func registerNeutronSecurityGroups(mux *http.ServeMux) {
	// GET and POST /v2.0/security-groups
	mux.HandleFunc("/v2.0/security-groups", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		mu.Lock()
		defer mu.Unlock()
		projectID := ProjectIDFromToken(r)

		switch r.Method {
		case http.MethodGet:
			nameFilter := r.URL.Query().Get("name")
			filtered := []map[string]interface{}{}
			for _, sg := range neutronSecGroups {
				enrichSecGroup(sg, projectID)
				if sg["project_id"] != projectID {
					continue
				}
				if nameFilter != "" {
					if n, ok := sg["name"].(string); !ok || n != nameFilter {
						continue
					}
				}
				filtered = append(filtered, sg)
			}
			writeJSON(w, map[string]interface{}{"security_groups": filtered})
		case http.MethodPost:
			var req struct {
				SecurityGroup map[string]interface{} `json:"security_group"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			sg := req.SecurityGroup
			secGroupSeq++
			sg["id"] = fmt.Sprintf("sg-%d", secGroupSeq)
			enrichSecGroup(sg, projectID)
			neutronSecGroups = append(neutronSecGroups, sg)
			w.WriteHeader(http.StatusCreated)
			writeJSON(w, map[string]interface{}{"security_group": sg})
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	// GET/PUT/DELETE /v2.0/security-groups/{id}
	mux.HandleFunc("/v2.0/security-groups/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		mu.Lock()
		defer mu.Unlock()
		projectID := ProjectIDFromToken(r)
		id := Parts(r.URL.Path)[2]

		idx := -1
		for i, sg := range neutronSecGroups {
			if sg["id"] == id {
				idx = i
				break
			}
		}
		if idx == -1 {
			http.NotFound(w, r)
			return
		}
		sg := neutronSecGroups[idx]
		enrichSecGroup(sg, projectID)
		if handleTags(w, r, Parts(r.URL.Path), sg) {
			return
		}
		// Attach current rules for a single-group fetch.
		rules := []map[string]interface{}{}
		for _, ru := range neutronSecGroupRules {
			if ru["security_group_id"] == id {
				rules = append(rules, ru)
			}
		}
		sg["security_group_rules"] = rules

		switch r.Method {
		case http.MethodGet:
			writeJSON(w, map[string]interface{}{"security_group": sg})
		case http.MethodPut:
			var req struct {
				SecurityGroup map[string]interface{} `json:"security_group"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			for k, v := range req.SecurityGroup {
				sg[k] = v
			}
			neutronSecGroups[idx] = sg
			writeJSON(w, map[string]interface{}{"security_group": sg})
		case http.MethodDelete:
			neutronSecGroups = append(neutronSecGroups[:idx], neutronSecGroups[idx+1:]...)
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	// GET and POST /v2.0/security-group-rules
	mux.HandleFunc("/v2.0/security-group-rules", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		mu.Lock()
		defer mu.Unlock()
		projectID := ProjectIDFromToken(r)

		switch r.Method {
		case http.MethodGet:
			sgFilter := r.URL.Query().Get("security_group_id")
			filtered := []map[string]interface{}{}
			for _, ru := range neutronSecGroupRules {
				enrichSecGroupRule(ru, projectID)
				if sgFilter != "" && ru["security_group_id"] != sgFilter {
					continue
				}
				filtered = append(filtered, ru)
			}
			writeJSON(w, map[string]interface{}{"security_group_rules": filtered})
		case http.MethodPost:
			var req struct {
				SecurityGroupRule map[string]interface{} `json:"security_group_rule"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			ru := req.SecurityGroupRule
			secGroupRuleSeq++
			ru["id"] = fmt.Sprintf("sgr-%d", secGroupRuleSeq)
			enrichSecGroupRule(ru, projectID)
			neutronSecGroupRules = append(neutronSecGroupRules, ru)
			w.WriteHeader(http.StatusCreated)
			writeJSON(w, map[string]interface{}{"security_group_rule": ru})
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	// GET/DELETE /v2.0/security-group-rules/{id}
	mux.HandleFunc("/v2.0/security-group-rules/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		mu.Lock()
		defer mu.Unlock()
		projectID := ProjectIDFromToken(r)
		id := Parts(r.URL.Path)[2]

		for i, ru := range neutronSecGroupRules {
			if ru["id"] == id {
				enrichSecGroupRule(ru, projectID)
				switch r.Method {
				case http.MethodGet:
					writeJSON(w, map[string]interface{}{"security_group_rule": ru})
				case http.MethodDelete:
					neutronSecGroupRules = append(neutronSecGroupRules[:i], neutronSecGroupRules[i+1:]...)
					w.WriteHeader(http.StatusNoContent)
				default:
					http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
				}
				return
			}
		}
		http.NotFound(w, r)
	})
}

// toStringSlice coerces an interface{} holding a list of strings into []string.
func toStringSlice(v interface{}) []string {
	out := []string{}
	switch t := v.(type) {
	case []string:
		return t
	case []interface{}:
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}

// handleTags implements the Neutron tags sub-resource for any object that
// carries a "tags" list. parts is the split request path; it handles the
// request and returns true when parts addresses .../{id}/tags[/{tag}].
// The caller must already hold the state mutex and have located obj.
func handleTags(w http.ResponseWriter, r *http.Request, parts []string, obj map[string]interface{}) bool {
	if len(parts) < 4 || parts[3] != "tags" {
		return false
	}
	tags := toStringSlice(obj["tags"])

	// .../{id}/tags
	if len(parts) == 4 {
		switch r.Method {
		case http.MethodGet:
			writeJSON(w, map[string]interface{}{"tags": tags})
		case http.MethodPut:
			var body struct {
				Tags []string `json:"tags"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			obj["tags"] = body.Tags
			writeJSON(w, map[string]interface{}{"tags": body.Tags})
		case http.MethodDelete:
			obj["tags"] = []string{}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
		return true
	}

	// .../{id}/tags/{tag}
	tag := parts[4]
	switch r.Method {
	case http.MethodGet:
		for _, t := range tags {
			if t == tag {
				w.WriteHeader(http.StatusNoContent)
				return true
			}
		}
		http.NotFound(w, r)
	case http.MethodPut:
		found := false
		for _, t := range tags {
			if t == tag {
				found = true
			}
		}
		if !found {
			tags = append(tags, tag)
		}
		obj["tags"] = tags
		w.WriteHeader(http.StatusCreated)
	case http.MethodDelete:
		out := []string{}
		for _, t := range tags {
			if t != tag {
				out = append(out, t)
			}
		}
		obj["tags"] = out
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
	return true
}

// writeJSON encodes v as a JSON response, logging on failure.
func writeJSON(w http.ResponseWriter, v interface{}) {
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("Error encoding JSON response: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}
