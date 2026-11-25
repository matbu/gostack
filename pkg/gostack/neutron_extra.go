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
	"net/netip"
	"sort"
)

// neutronResource describes a Neutron collection that follows the project's
// standard CRUD shape, so the handler can be generated rather than repeated.
type neutronResource struct {
	// path is the URL segment, e.g. "address-scopes".
	path string
	// singular and plural are the JSON envelope keys, e.g. "address_scope"
	// and "address_scopes".
	singular string
	plural   string
	// store is the backing slice.
	store *[]map[string]interface{}
	// idPrefix seeds generated ids.
	idPrefix string
	// enrich fills the resource's default fields. It must be idempotent.
	enrich func(m map[string]interface{}, projectID string)
	// projectScoped hides objects belonging to other projects.
	projectScoped bool
	// subResource handles a path below the object's id, such as a trunk's
	// sub-ports. It reports whether it handled the request. The state
	// mutex is held when it runs.
	subResource func(w http.ResponseWriter, r *http.Request, parts []string, item map[string]interface{}) bool
}

// registerNeutronResource installs list/create and show/update/delete
// handlers for a standard Neutron collection.
func registerNeutronResource(mux *http.ServeMux, res neutronResource) {
	collection := func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		projectID := ProjectIDFromToken(r)

		switch r.Method {
		case http.MethodGet:
			anyProject := ShowAllProjects(r.URL.Query())
			visible := []map[string]interface{}{}
			for _, item := range *res.store {
				res.enrich(item, projectID)
				if res.projectScoped && !anyProject && item["project_id"] != projectID {
					if shared, _ := item["shared"].(bool); !shared {
						continue
					}
				}
				visible = append(visible, item)
			}
			writeJSON(w, map[string]interface{}{
				res.plural: ApplyLimit(FilterList(visible, r.URL.Query()), r.URL.Query()),
			})
		case http.MethodPost:
			var req map[string]map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				badRequest(w, Neutron, "Invalid request body: "+err.Error())
				return
			}
			item := req[res.singular]
			if item == nil {
				badRequest(w, Neutron, "Expecting to find "+res.singular+" in request body.")
				return
			}
			neutronSeq++
			item["id"] = fmt.Sprintf("%s-%d", res.idPrefix, neutronSeq)
			res.enrich(item, projectID)
			*res.store = append(*res.store, item)
			writeJSONStatus(w, http.StatusCreated, map[string]interface{}{res.singular: item})
		default:
			methodNotAllowed(w, Neutron, r.Method)
		}
	}

	mux.HandleFunc("/v2.0/"+res.path, func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.String())
		collection(w, r)
	})

	mux.HandleFunc("/v2.0/"+res.path+"/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.String())
		parts := Parts(r.URL.Path)
		if len(parts) < 3 || parts[2] == "" {
			collection(w, r)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		projectID := ProjectIDFromToken(r)
		id := parts[2]

		idx := -1
		for i, item := range *res.store {
			if item["id"] == id {
				idx = i
				break
			}
		}
		if idx == -1 {
			notFound(w, Neutron, res.singular+" "+id)
			return
		}
		item := (*res.store)[idx]
		res.enrich(item, projectID)
		if handleTags(w, r, parts, item) {
			return
		}
		if res.subResource != nil && res.subResource(w, r, parts, item) {
			return
		}

		switch r.Method {
		case http.MethodGet:
			writeJSON(w, map[string]interface{}{res.singular: item})
		case http.MethodPut:
			var req map[string]map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				badRequest(w, Neutron, "Invalid request body: "+err.Error())
				return
			}
			for k, v := range req[res.singular] {
				item[k] = v
			}
			// Re-run enrichment so fields derived from the update (such as
			// a subnet pool's compacted prefixes) stay consistent.
			res.enrich(item, projectID)
			bumpRevision(item)
			(*res.store)[idx] = item
			writeJSON(w, map[string]interface{}{res.singular: item})
		case http.MethodDelete:
			*res.store = append((*res.store)[:idx], (*res.store)[idx+1:]...)
			w.WriteHeader(http.StatusNoContent)
		default:
			methodNotAllowed(w, Neutron, r.Method)
		}
	})
}

// bumpRevision increments a Neutron object's revision_number, whatever
// numeric type it currently holds.
func bumpRevision(item map[string]interface{}) {
	switch n := item["revision_number"].(type) {
	case int:
		item["revision_number"] = n + 1
	case float64:
		item["revision_number"] = int(n) + 1
	default:
		item["revision_number"] = 1
	}
	item["updated_at"] = nowRFC3339()
}

// enrichCommon fills the metadata fields every Neutron resource carries.
func enrichCommon(m map[string]interface{}, projectID string) {
	now := nowRFC3339()
	setDefault(m, "name", "")
	setDefault(m, "description", "")
	setDefault(m, "revision_number", 1)
	setDefault(m, "created_at", now)
	setDefault(m, "updated_at", now)
	setDefault(m, "tags", []interface{}{})
	if projectID != "" {
		setDefault(m, "project_id", projectID)
		setDefault(m, "tenant_id", m["project_id"])
	}
}

// RegisterNeutronExtraHandlers registers the network resources beyond the
// core networks/subnets/ports/routers/security-groups set.
func RegisterNeutronExtraHandlers(mux *http.ServeMux) {
	registerNeutronResource(mux, neutronResource{
		path: "address-scopes", singular: "address_scope", plural: "address_scopes",
		store: &addressScopes, idPrefix: "ascope", projectScoped: true,
		enrich: func(m map[string]interface{}, projectID string) {
			enrichCommon(m, projectID)
			setDefault(m, "ip_version", 4)
			setDefault(m, "shared", false)
		},
	})

	registerNeutronResource(mux, neutronResource{
		path: "subnetpools", singular: "subnetpool", plural: "subnetpools",
		store: &subnetPools, idPrefix: "subnetpool", projectScoped: true,
		enrich: func(m map[string]interface{}, projectID string) {
			enrichCommon(m, projectID)
			setDefault(m, "prefixes", []interface{}{})
			m["prefixes"] = compactPrefixes(m["prefixes"])
			setDefault(m, "ip_version", 4)
			setDefault(m, "shared", false)
			setDefault(m, "is_default", false)
			setDefault(m, "address_scope_id", nil)
			setDefault(m, "default_prefixlen", 8)
			setDefault(m, "min_prefixlen", 8)
			setDefault(m, "max_prefixlen", 32)
			setDefault(m, "default_quota", nil)
		},
	})

	registerNeutronResource(mux, neutronResource{
		path: "segments", singular: "segment", plural: "segments",
		store: &netSegments, idPrefix: "segment",
		enrich: func(m map[string]interface{}, projectID string) {
			enrichCommon(m, projectID)
			setDefault(m, "network_type", "vlan")
			setDefault(m, "physical_network", nil)
			setDefault(m, "segmentation_id", nil)
			setDefault(m, "network_id", nil)
		},
	})

	registerNeutronResource(mux, neutronResource{
		path: "rbac-policies", singular: "rbac_policy", plural: "rbac_policies",
		store: &rbacPolicies, idPrefix: "rbac", projectScoped: true,
		enrich: func(m map[string]interface{}, projectID string) {
			// RBAC policies carry no name, description or tags.
			if projectID != "" {
				setDefault(m, "project_id", projectID)
				setDefault(m, "tenant_id", m["project_id"])
			}
			setDefault(m, "object_type", "network")
			setDefault(m, "action", "access_as_shared")
			setDefault(m, "target_tenant", "*")
			setDefault(m, "target_project_id", m["target_tenant"])
		},
	})

	registerNeutronResource(mux, neutronResource{
		path: "trunks", singular: "trunk", plural: "trunks",
		store: &trunks, idPrefix: "trunk", projectScoped: true,
		subResource: trunkSubPorts,
		enrich: func(m map[string]interface{}, projectID string) {
			enrichCommon(m, projectID)
			setDefault(m, "admin_state_up", true)
			setDefault(m, "status", "ACTIVE")
			setDefault(m, "sub_ports", []interface{}{})
			setDefault(m, "port_id", nil)
		},
	})

	registerNeutronExtensions(mux)
	registerNeutronQuotas(mux)
	registerNeutronAgents(mux)
	registerNeutronAvailabilityZones(mux)
}

// neutronExtensionList is the extension discovery document. openstacksdk
// consults it before using an optional feature, so an empty list makes the
// SDK silently skip capabilities gostack does implement.
func neutronExtensionList() []map[string]interface{} {
	aliases := []struct{ alias, name string }{
		{"address-scope", "Address scope"},
		{"agent", "agent"},
		{"availability_zone", "Availability Zone"},
		{"binding", "Port Binding"},
		{"default-subnetpools", "Default Subnetpools"},
		{"dhcp_agent_scheduler", "DHCP Agent Scheduler"},
		{"dns-integration", "DNS Integration"},
		{"external-net", "Neutron external network"},
		{"extra_dhcp_opt", "Neutron Extra DHCP opts"},
		{"extraroute", "Neutron Extra Route"},
		{"l3_agent_scheduler", "L3 Agent Scheduler"},
		{"multi-provider", "Multi Provider Network"},
		{"net-mtu", "Network MTU"},
		{"network-ip-availability", "Network IP Availability"},
		{"network_availability_zone", "Network Availability Zone"},
		{"port-security", "Port Security"},
		{"project-id", "project_id field enabled"},
		{"provider", "Provider Network"},
		{"quotas", "Quota management support"},
		{"rbac-policies", "RBAC Policies"},
		{"revision-if-match", "If-Match constraints based on revision_number"},
		{"router", "Neutron L3 Router"},
		{"router_availability_zone", "Router Availability Zone"},
		{"security-group", "security-group"},
		{"security-groups-remote-address-group", "Security group remote address group"},
		{"segment", "Segment"},
		{"service-type", "Neutron Service Type Management"},
		{"sorting", "Sorting support"},
		{"standard-attr-description", "standard-attr-description"},
		{"standard-attr-revisions", "Resource revision numbers"},
		{"standard-attr-segment", "Standard Attribute Segment Extension"},
		{"standard-attr-tag", "Tag support for resources with standard attribute"},
		{"standard-attr-timestamp", "Resource timestamps"},
		{"subnet-service-types", "Subnet service types"},
		{"subnet_allocation", "Subnet Allocation"},
		{"trunk", "Trunk Extension"},
	}
	out := make([]map[string]interface{}, 0, len(aliases))
	for _, a := range aliases {
		out = append(out, map[string]interface{}{
			"alias": a.alias, "name": a.name, "description": a.name,
			"links": []interface{}{}, "updated": "2023-01-01T00:00:00Z",
		})
	}
	return out
}

// registerNeutronExtensions implements /v2.0/extensions.
func registerNeutronExtensions(mux *http.ServeMux) {
	mux.HandleFunc("/v2.0/extensions", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.String())
		if r.Method != http.MethodGet {
			methodNotAllowed(w, Neutron, r.Method)
			return
		}
		writeJSON(w, map[string]interface{}{"extensions": neutronExtensionList()})
	})

	mux.HandleFunc("/v2.0/extensions/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.String())
		alias := segmentAt(r, 2)
		if alias == "" {
			writeJSON(w, map[string]interface{}{"extensions": neutronExtensionList()})
			return
		}
		for _, ext := range neutronExtensionList() {
			if ext["alias"] == alias {
				writeJSON(w, map[string]interface{}{"extension": ext})
				return
			}
		}
		notFound(w, Neutron, "Extension "+alias)
	})
}

// registerNeutronQuotas implements /v2.0/quotas.
func registerNeutronQuotas(mux *http.ServeMux) {
	mux.HandleFunc("/v2.0/quotas", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.String())
		serveNeutronQuotas(w, r, nil)
	})
	mux.HandleFunc("/v2.0/quotas/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.String())
		serveNeutronQuotas(w, r, Parts(r.URL.Path)[2:])
	})
}

// registerNeutronAgents implements the read-only /v2.0/agents listing.
func registerNeutronAgents(mux *http.ServeMux) {
	agent := func() map[string]interface{} {
		return map[string]interface{}{
			"id": "agent-1", "agent_type": "Open vSwitch agent", "host": "fakehost",
			"alive": true, "admin_state_up": true, "binary": "neutron-openvswitch-agent",
			"topic": "N/A", "availability_zone": nil, "description": nil,
			"started_at": nowRFC3339(), "heartbeat_timestamp": nowRFC3339(),
			"configurations": map[string]interface{}{},
		}
	}
	mux.HandleFunc("/v2.0/agents", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.String())
		if r.Method != http.MethodGet {
			methodNotAllowed(w, Neutron, r.Method)
			return
		}
		writeJSON(w, map[string]interface{}{
			"agents": FilterList([]map[string]interface{}{agent()}, r.URL.Query()),
		})
	})
	mux.HandleFunc("/v2.0/agents/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.String())
		id := segmentAt(r, 2)
		if id != "agent-1" {
			notFound(w, Neutron, "Agent "+id)
			return
		}
		writeJSON(w, map[string]interface{}{"agent": agent()})
	})
}

// registerNeutronAvailabilityZones implements /v2.0/availability_zones.
func registerNeutronAvailabilityZones(mux *http.ServeMux) {
	mux.HandleFunc("/v2.0/availability_zones", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.String())
		if r.Method != http.MethodGet {
			methodNotAllowed(w, Neutron, r.Method)
			return
		}
		list := []map[string]interface{}{
			{"name": "nova", "resource": "network", "state": "available"},
			{"name": "nova", "resource": "router", "state": "available"},
		}
		writeJSON(w, map[string]interface{}{
			"availability_zones": FilterList(list, r.URL.Query()),
		})
	})
}

// compactPrefixes normalises a subnet pool's prefix list the way Neutron
// does: it merges adjacent and contained blocks, so updating a pool that
// holds 192.168.0.0/24 with 192.168.1.0/24 yields 192.168.0.0/23. Entries
// that do not parse are kept untouched.
func compactPrefixes(v interface{}) interface{} {
	raw := toStringSlice(v)
	if len(raw) == 0 {
		return v
	}
	parsed := []netip.Prefix{}
	unparsed := []string{}
	for _, item := range raw {
		pfx, err := netip.ParsePrefix(item)
		if err != nil {
			unparsed = append(unparsed, item)
			continue
		}
		parsed = append(parsed, pfx.Masked())
	}

	// Repeatedly absorb contained blocks and merge sibling pairs until the
	// set stops shrinking.
	for {
		merged := mergePrefixesOnce(parsed)
		if len(merged) == len(parsed) {
			parsed = merged
			break
		}
		parsed = merged
	}

	sort.Slice(parsed, func(i, j int) bool {
		if parsed[i].Addr() != parsed[j].Addr() {
			return parsed[i].Addr().Less(parsed[j].Addr())
		}
		return parsed[i].Bits() < parsed[j].Bits()
	})
	out := make([]interface{}, 0, len(parsed)+len(unparsed))
	for _, pfx := range parsed {
		out = append(out, pfx.String())
	}
	for _, item := range unparsed {
		out = append(out, item)
	}
	return out
}

// mergePrefixesOnce performs a single absorb-and-merge pass over a prefix
// set, returning a set no larger than the input.
func mergePrefixesOnce(in []netip.Prefix) []netip.Prefix {
	out := []netip.Prefix{}
	used := make([]bool, len(in))
	for i, a := range in {
		if used[i] {
			continue
		}
		current := a
		for j := i + 1; j < len(in); j++ {
			if used[j] {
				continue
			}
			b := in[j]
			switch {
			case current.Overlaps(b):
				// Keep whichever block contains the other.
				if b.Bits() < current.Bits() {
					current = b
				}
				used[j] = true
			case siblingPrefixes(current, b):
				parent, _ := current.Addr().Prefix(current.Bits() - 1)
				current = parent
				used[j] = true
			}
		}
		used[i] = true
		out = append(out, current)
	}
	return out
}

// siblingPrefixes reports whether two equally sized blocks are the two
// halves of one block a bit shorter, and so can be merged into it.
func siblingPrefixes(a, b netip.Prefix) bool {
	if a.Bits() != b.Bits() || a.Bits() == 0 || a.Addr().Is4() != b.Addr().Is4() {
		return false
	}
	parentA, err := a.Addr().Prefix(a.Bits() - 1)
	if err != nil {
		return false
	}
	parentB, err := b.Addr().Prefix(b.Bits() - 1)
	if err != nil {
		return false
	}
	return parentA == parentB && a.Addr() != b.Addr()
}

// trunkSubPorts implements a trunk's sub-port endpoints:
//
//	PUT /v2.0/trunks/{id}/add_subports
//	PUT /v2.0/trunks/{id}/remove_subports
//	GET /v2.0/trunks/{id}/get_subports
//
// These take a list under "sub_ports" rather than the single object the
// generic handler expects, so the trunk resource handles them itself.
// The caller must hold the state mutex.
func trunkSubPorts(w http.ResponseWriter, r *http.Request, parts []string, trunk map[string]interface{}) bool {
	if len(parts) != 4 {
		return false
	}
	action := parts[3]
	if action != "add_subports" && action != "remove_subports" && action != "get_subports" {
		return false
	}

	existing, _ := trunk["sub_ports"].([]interface{})

	if action == "get_subports" {
		writeJSON(w, map[string]interface{}{"sub_ports": existing})
		return true
	}
	if r.Method != http.MethodPut {
		methodNotAllowed(w, Neutron, r.Method)
		return true
	}

	var req struct {
		SubPorts []map[string]interface{} `json:"sub_ports"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		badRequest(w, Neutron, "Invalid request body: "+err.Error())
		return true
	}

	if action == "add_subports" {
		for _, add := range req.SubPorts {
			portID := stringOf(add["port_id"])
			duplicate := false
			for _, raw := range existing {
				if entry, ok := raw.(map[string]interface{}); ok &&
					stringOf(entry["port_id"]) == portID {
					duplicate = true
					break
				}
			}
			if duplicate {
				apiError(w, Neutron, http.StatusConflict,
					"Port "+portID+" is already a subport of trunk "+stringOf(trunk["id"])+".")
				return true
			}
			setDefault(add, "segmentation_type", "vlan")
			existing = append(existing, add)
			// A sub-port is owned by the trunk while it is attached.
			for _, p := range ports {
				if p["id"] == portID {
					p["device_owner"] = "trunk:subport"
					p["device_id"] = trunk["id"]
				}
			}
		}
	} else {
		remove := map[string]bool{}
		for _, item := range req.SubPorts {
			remove[stringOf(item["port_id"])] = true
		}
		kept := []interface{}{}
		for _, raw := range existing {
			entry, ok := raw.(map[string]interface{})
			if !ok {
				continue
			}
			portID := stringOf(entry["port_id"])
			if !remove[portID] {
				kept = append(kept, entry)
				continue
			}
			for _, p := range ports {
				if p["id"] == portID {
					p["device_owner"] = ""
					p["device_id"] = ""
				}
			}
		}
		existing = kept
	}

	trunk["sub_ports"] = existing
	bumpRevision(trunk)
	writeJSON(w, map[string]interface{}{"trunk": trunk})
	return true
}
