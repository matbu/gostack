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
	"strings"
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

// normalizeCIDR gives a bare address the prefix length Neutron adds when it
// stores a remote_ip_prefix: /32 for IPv4 and /128 for IPv6.
func normalizeCIDR(v interface{}) interface{} {
	addr, ok := v.(string)
	if !ok || addr == "" || strings.Contains(addr, "/") {
		return v
	}
	if strings.Contains(addr, ":") {
		return addr + "/128"
	}
	return addr + "/32"
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
	// The Neutron API field is "ethertype" (openstacksdk sends that); keep the
	// legacy "ether_type" key in sync with it instead of defaulting it blindly.
	setDefault(ru, "ethertype", ru["ether_type"])
	if ru["ethertype"] == nil {
		ru["ethertype"] = "IPv4"
	}
	ru["ether_type"] = ru["ethertype"]
	setDefault(ru, "direction", "ingress")
	ru["remote_ip_prefix"] = normalizeCIDR(ru["remote_ip_prefix"])
	if projectID != "" {
		setDefault(ru, "project_id", projectID)
		setDefault(ru, "tenant_id", ru["project_id"])
	}
}

// secGroupRulesFor returns the rules belonging to a security group.
func secGroupRulesFor(sgID interface{}) []map[string]interface{} {
	rules := []map[string]interface{}{}
	for _, ru := range neutronSecGroupRules {
		if ru["security_group_id"] == sgID {
			rules = append(rules, ru)
		}
	}
	return rules
}

// secGroupRuleKeyFields are the attributes Neutron compares to decide whether
// a new security group rule duplicates an existing one.
var secGroupRuleKeyFields = []string{
	"security_group_id", "direction", "ethertype", "protocol",
	"port_range_min", "port_range_max",
	"remote_ip_prefix", "remote_group_id", "remote_address_group_id",
}

func secGroupRuleKey(ru map[string]interface{}) string {
	var b strings.Builder
	for _, f := range secGroupRuleKeyFields {
		v := ru[f]
		if v == nil {
			v = ""
		}
		if s, ok := v.(string); ok && f == "protocol" {
			v = strings.ToLower(s)
		}
		fmt.Fprintf(&b, "%s=%v;", f, v)
	}
	return b.String()
}

// findDuplicateSecGroupRule returns an existing rule identical to ru, or nil.
func findDuplicateSecGroupRule(ru map[string]interface{}) map[string]interface{} {
	key := secGroupRuleKey(ru)
	for _, existing := range neutronSecGroupRules {
		if secGroupRuleKey(existing) == key {
			return existing
		}
	}
	return nil
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
			anyProject := ShowAllProjects(r.URL.Query())
			visible := []map[string]interface{}{}
			for _, rt := range routers {
				enrichRouter(rt, projectID)
				if !anyProject && rt["project_id"] != projectID {
					continue
				}
				visible = append(visible, rt)
			}
			writeJSON(w, map[string]interface{}{
				"routers": ApplyLimit(FilterList(visible, r.URL.Query(), "external_gateway_info"), r.URL.Query()),
			})
		case http.MethodPost:
			var req struct {
				Router map[string]interface{} `json:"router"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				badRequest(w, Neutron, "Invalid request body: "+err.Error())
				return
			}
			rt := req.Router
			if rt == nil {
				badRequest(w, Neutron, "Expecting to find router in request body.")
				return
			}
			routerSeq++
			rt["id"] = fmt.Sprintf("router-%d", routerSeq)
			enrichRouter(rt, projectID)
			fillExternalGateway(rt)
			routers = append(routers, rt)
			w.WriteHeader(http.StatusCreated)
			writeJSON(w, map[string]interface{}{"router": rt})
		default:
			methodNotAllowed(w, Neutron, r.Method)
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
			notFound(w, Neutron, "Router")
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
			notFound(w, Neutron, "Router "+id)
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
					gatewayIP := "10.0.0.1"
					for _, s := range subnets {
						if s["id"] == subnetID {
							networkID, _ = s["network_id"].(string)
							if gw, ok := s["gateway_ip"].(string); ok && gw != "" {
								gatewayIP = gw
							}
						}
					}
					port := map[string]interface{}{
						"id":           portID,
						"network_id":   networkID,
						"device_id":    id,
						"device_owner": "network:router_interface",
						"project_id":   projectID,
						"status":       "ACTIVE",
						"fixed_ips": []interface{}{map[string]interface{}{
							"subnet_id": subnetID, "ip_address": gatewayIP,
						}},
					}
					enrichPort(port, projectID)
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
			notFound(w, Neutron, "Router action "+action)
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
				badRequest(w, Neutron, "Invalid request body: "+err.Error())
				return
			}
			// Keep the gateway addresses already allocated: re-running an
			// update that does not name them must not hand out new ones,
			// which clients see as a spurious change.
			previousGateway, _ := rt["external_gateway_info"].(map[string]interface{})
			for k, v := range req.Router {
				rt[k] = v
			}
			carryOverGatewayIPs(rt, previousGateway)
			fillExternalGateway(rt)
			bumpRevision(rt)
			routers[idx] = rt
			writeJSON(w, map[string]interface{}{"router": rt})
		case http.MethodDelete:
			routers = append(routers[:idx], routers[idx+1:]...)
			w.WriteHeader(http.StatusNoContent)
		default:
			methodNotAllowed(w, Neutron, r.Method)
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
			anyProject := ShowAllProjects(r.URL.Query())
			visible := []map[string]interface{}{}
			for _, sg := range neutronSecGroups {
				enrichSecGroup(sg, projectID)
				if !anyProject && sg["project_id"] != projectID {
					continue
				}
				// Like Neutron, embed each group's rules in the list response
				// too (clients such as os-migrate read them from here).
				sg["security_group_rules"] = secGroupRulesFor(sg["id"])
				visible = append(visible, sg)
			}
			writeJSON(w, map[string]interface{}{
				"security_groups": ApplyLimit(FilterList(visible, r.URL.Query(), "security_group_rules"), r.URL.Query()),
			})
		case http.MethodPost:
			var req struct {
				SecurityGroup map[string]interface{} `json:"security_group"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				badRequest(w, Neutron, "Invalid request body: "+err.Error())
				return
			}
			sg := req.SecurityGroup
			if sg == nil {
				badRequest(w, Neutron, "Expecting to find security_group in request body.")
				return
			}
			secGroupSeq++
			sg["id"] = fmt.Sprintf("sg-%d", secGroupSeq)
			enrichSecGroup(sg, projectID)
			addDefaultSecGroupRules(sg, projectID)
			sg["security_group_rules"] = secGroupRulesFor(sg["id"])
			neutronSecGroups = append(neutronSecGroups, sg)
			w.WriteHeader(http.StatusCreated)
			writeJSON(w, map[string]interface{}{"security_group": sg})
		default:
			methodNotAllowed(w, Neutron, r.Method)
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
			notFound(w, Neutron, "Security group "+id)
			return
		}
		sg := neutronSecGroups[idx]
		enrichSecGroup(sg, projectID)
		if handleTags(w, r, Parts(r.URL.Path), sg) {
			return
		}
		// Attach current rules for a single-group fetch.
		sg["security_group_rules"] = secGroupRulesFor(id)

		switch r.Method {
		case http.MethodGet:
			writeJSON(w, map[string]interface{}{"security_group": sg})
		case http.MethodPut:
			var req struct {
				SecurityGroup map[string]interface{} `json:"security_group"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				badRequest(w, Neutron, "Invalid request body: "+err.Error())
				return
			}
			for k, v := range req.SecurityGroup {
				sg[k] = v
			}
			neutronSecGroups[idx] = sg
			writeJSON(w, map[string]interface{}{"security_group": sg})
		case http.MethodDelete:
			neutronSecGroups = append(neutronSecGroups[:idx], neutronSecGroups[idx+1:]...)
			remaining := []map[string]interface{}{}
			for _, ru := range neutronSecGroupRules {
				if ru["security_group_id"] != id {
					remaining = append(remaining, ru)
				}
			}
			neutronSecGroupRules = remaining
			w.WriteHeader(http.StatusNoContent)
		default:
			methodNotAllowed(w, Neutron, r.Method)
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
			visible := []map[string]interface{}{}
			for _, ru := range neutronSecGroupRules {
				enrichSecGroupRule(ru, projectID)
				visible = append(visible, ru)
			}
			writeJSON(w, map[string]interface{}{
				"security_group_rules": ApplyLimit(FilterList(visible, r.URL.Query()), r.URL.Query()),
			})
		case http.MethodPost:
			var req struct {
				SecurityGroupRule  map[string]interface{}   `json:"security_group_rule"`
				SecurityGroupRules []map[string]interface{} `json:"security_group_rules"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				badRequest(w, Neutron, "Invalid request body: "+err.Error())
				return
			}
			// Neutron also accepts a bulk create, which openstacksdk uses
			// whenever a client asks for more than one rule at a time.
			if req.SecurityGroupRule == nil && req.SecurityGroupRules != nil {
				created := []map[string]interface{}{}
				for _, ru := range req.SecurityGroupRules {
					if ru == nil {
						continue
					}
					enrichSecGroupRule(ru, projectID)
					if dup := findDuplicateSecGroupRule(ru); dup != nil {
						writeJSONStatus(w, http.StatusConflict, map[string]interface{}{
							"NeutronError": map[string]interface{}{
								"type":    "SecurityGroupRuleExists",
								"message": fmt.Sprintf("Security group rule already exists. Rule id is %v.", dup["id"]),
								"detail":  "",
							}})
						return
					}
					secGroupRuleSeq++
					ru["id"] = fmt.Sprintf("sgr-%d", secGroupRuleSeq)
					neutronSecGroupRules = append(neutronSecGroupRules, ru)
					created = append(created, ru)
				}
				writeJSONStatus(w, http.StatusCreated,
					map[string]interface{}{"security_group_rules": created})
				return
			}
			ru := req.SecurityGroupRule
			if ru == nil {
				badRequest(w, Neutron, "Expecting to find security_group_rule in request body.")
				return
			}
			enrichSecGroupRule(ru, projectID)
			// Neutron rejects a rule identical to an existing one with a 409
			// (SecurityGroupRuleExists); os-migrate relies on that to make
			// rule imports idempotent.
			if dup := findDuplicateSecGroupRule(ru); dup != nil {
				w.WriteHeader(http.StatusConflict)
				writeJSON(w, map[string]interface{}{"NeutronError": map[string]interface{}{
					"type":    "SecurityGroupRuleExists",
					"message": fmt.Sprintf("Security group rule already exists. Rule id is %v.", dup["id"]),
					"detail":  "",
				}})
				return
			}
			secGroupRuleSeq++
			ru["id"] = fmt.Sprintf("sgr-%d", secGroupRuleSeq)
			neutronSecGroupRules = append(neutronSecGroupRules, ru)
			w.WriteHeader(http.StatusCreated)
			writeJSON(w, map[string]interface{}{"security_group_rule": ru})
		default:
			methodNotAllowed(w, Neutron, r.Method)
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
					methodNotAllowed(w, Neutron, r.Method)
				}
				return
			}
		}
		notFound(w, Neutron, "Security group rule "+id)
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
			methodNotAllowed(w, Neutron, r.Method)
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
		notFound(w, Neutron, "Tag "+tag)
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
		methodNotAllowed(w, Neutron, r.Method)
	}
	return true
}

// addDefaultSecGroupRules creates the two egress rules Neutron adds to every
// new security group, one per address family. The caller must hold the mutex.
func addDefaultSecGroupRules(sg map[string]interface{}, projectID string) {
	for _, ethertype := range []string{"IPv4", "IPv6"} {
		secGroupRuleSeq++
		ru := map[string]interface{}{
			"id":                fmt.Sprintf("sgr-%d", secGroupRuleSeq),
			"security_group_id": sg["id"],
			"direction":         "egress",
			"ethertype":         ethertype,
		}
		enrichSecGroupRule(ru, projectID)
		neutronSecGroupRules = append(neutronSecGroupRules, ru)
	}
}

// fillExternalGateway completes a router's external_gateway_info the way
// Neutron does: attaching a gateway network allocates a fixed IP on one of
// its subnets, and clients read the subnet back from external_fixed_ips.
// The caller must hold the state mutex.
func fillExternalGateway(rt map[string]interface{}) {
	gw, ok := rt["external_gateway_info"].(map[string]interface{})
	if !ok || gw == nil {
		return
	}
	netID, _ := gw["network_id"].(string)
	if netID == "" {
		return
	}
	setDefault(gw, "enable_snat", true)
	fixed, _ := gw["external_fixed_ips"].([]interface{})
	if len(fixed) > 0 {
		for _, raw := range fixed {
			entry, ok := raw.(map[string]interface{})
			if !ok {
				continue
			}
			// An entry may name only an address, or only a subnet;
			// Neutron completes whichever half is missing.
			if sid, ok := entry["subnet_id"].(string); !ok || sid == "" {
				if sub := firstSubnetOf(netID); sub != "" {
					entry["subnet_id"] = sub
				}
			}
			if addr, ok := entry["ip_address"].(string); !ok || addr == "" {
				entry["ip_address"] = allocateExternalIP()
			}
		}
		rt["external_gateway_info"] = gw
		return
	}
	sub := firstSubnetOf(netID)
	if sub == "" {
		return
	}
	gw["external_fixed_ips"] = []interface{}{map[string]interface{}{
		"subnet_id": sub, "ip_address": allocateExternalIP(),
	}}
	rt["external_gateway_info"] = gw
}

// externalIPSeq numbers the addresses handed out on external networks.
var externalIPSeq = 0

// allocateExternalIP returns the next gateway address on the external net.
func allocateExternalIP() string {
	externalIPSeq++
	return fmt.Sprintf("172.24.4.%d", 100+externalIPSeq)
}

// firstSubnetOf returns the id of a network's first subnet, or "".
// The caller must hold the state mutex.
func firstSubnetOf(networkID string) string {
	for _, s := range subnets {
		if s["network_id"] == networkID {
			id, _ := s["id"].(string)
			return id
		}
	}
	return ""
}

// carryOverGatewayIPs keeps a router's previously allocated external fixed
// IPs when an update re-states the same gateway network without naming
// them. Neutron does not reallocate in that case.
// The caller must hold the state mutex.
func carryOverGatewayIPs(rt map[string]interface{}, previous map[string]interface{}) {
	if previous == nil {
		return
	}
	gw, ok := rt["external_gateway_info"].(map[string]interface{})
	if !ok || gw == nil {
		return
	}
	if gw["network_id"] != previous["network_id"] {
		return
	}
	prior, _ := previous["external_fixed_ips"].([]interface{})
	if len(prior) == 0 {
		return
	}
	current, _ := gw["external_fixed_ips"].([]interface{})
	if len(current) == 0 {
		gw["external_fixed_ips"] = prior
		return
	}
	// The update may name only the subnet; reuse the address already
	// allocated on it rather than taking a fresh one.
	for _, raw := range current {
		entry, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		if addr, ok := entry["ip_address"].(string); ok && addr != "" {
			continue
		}
		for _, rawPrior := range prior {
			priorEntry, ok := rawPrior.(map[string]interface{})
			if !ok {
				continue
			}
			if priorEntry["subnet_id"] == entry["subnet_id"] {
				entry["ip_address"] = priorEntry["ip_address"]
				break
			}
		}
	}
}
