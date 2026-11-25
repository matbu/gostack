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
	"strings"
)

// RegisterNeutronHandlers registers Neutron API handlers on mux.
func RegisterNeutronHandlers(mux *http.ServeMux) {
	// GET and POST /v2.0/networks
	mux.HandleFunc("/v2.0/networks", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.String())
		mu.Lock()
		defer mu.Unlock()
		tokenProject := ProjectIDFromToken(r)

		switch r.Method {
		case http.MethodGet:
			anyProject := ShowAllProjects(r.URL.Query())
			visible := []map[string]interface{}{}
			for _, n := range networks {
				enrichNetwork(n, tokenProject)
				// A project sees its own networks plus any shared or
				// external ones, as Neutron's default policy allows.
				if !anyProject && n["project_id"] != tokenProject && !networkVisible(n) {
					continue
				}
				visible = append(visible, n)
			}
			writeJSON(w, map[string]interface{}{
				"networks": ApplyLimit(FilterList(visible, r.URL.Query()), r.URL.Query()),
			})
		case http.MethodPost:
			var req struct {
				Network map[string]interface{} `json:"network"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				badRequest(w, Neutron, "Invalid request body: "+err.Error())
				return
			}
			network := req.Network
			if network == nil {
				badRequest(w, Neutron, "Expecting to find network in request body.")
				return
			}
			network["id"] = fmt.Sprintf("net-%d", len(networks)+1)
			enrichNetwork(network, tokenProject)
			networks = append(networks, network)
			writeJSONStatus(w, http.StatusCreated, map[string]interface{}{"network": network})
		default:
			methodNotAllowed(w, Neutron, r.Method)
		}
	})

	// GET/PUT/DELETE /v2.0/networks/{id} (+ /tags sub-resource)
	mux.HandleFunc("/v2.0/networks/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.String())
		parts := Parts(r.URL.Path)
		if len(parts) < 3 || parts[2] == "" {
			notFound(w, Neutron, "Network")
			return
		}
		id := parts[2]
		mu.Lock()
		defer mu.Unlock()
		projectID := ProjectIDFromToken(r)

		for i, n := range networks {
			if n["id"] != id {
				continue
			}
			enrichNetwork(n, projectID)
			if handleTags(w, r, parts, n) {
				return
			}
			// With admin scope, reading by id is not project-scoped:
			// clients fetch another project's resource by an id they
			// already hold, as an admin may. Listings stay scoped.
			if !adminScope && n["project_id"] != projectID && !networkVisible(n) {
				notFound(w, Neutron, "Network "+id)
				return
			}
			switch r.Method {
			case http.MethodDelete:
				networks = append(networks[:i], networks[i+1:]...)
				w.WriteHeader(http.StatusNoContent)
			case http.MethodPut:
				var req struct {
					Network map[string]interface{} `json:"network"`
				}
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					badRequest(w, Neutron, "Invalid request body: "+err.Error())
					return
				}
				for k, v := range req.Network {
					n[k] = v
				}
				bumpRevision(n)
				networks[i] = n
				writeJSON(w, map[string]interface{}{"network": n})
			case http.MethodGet:
				writeJSON(w, map[string]interface{}{"network": n})
			default:
				methodNotAllowed(w, Neutron, r.Method)
			}
			return
		}
		notFound(w, Neutron, "Network "+id)
	})

	// GET and POST /v2.0/subnets
	mux.HandleFunc("/v2.0/subnets", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.String())
		mu.Lock()
		defer mu.Unlock()
		projectID := ProjectIDFromToken(r)

		switch r.Method {
		case http.MethodGet:
			anyProject := ShowAllProjects(r.URL.Query())
			visible := []map[string]interface{}{}
			for _, s := range subnets {
				enrichSubnet(s, projectID)
				if !anyProject && s["project_id"] != projectID && !subnetVisible(s) {
					continue
				}
				visible = append(visible, s)
			}
			writeJSON(w, map[string]interface{}{
				"subnets": ApplyLimit(FilterList(visible, r.URL.Query()), r.URL.Query()),
			})
		case http.MethodPost:
			var req struct {
				Subnet map[string]interface{} `json:"subnet"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				badRequest(w, Neutron, "Invalid request body: "+err.Error())
				return
			}
			subnet := req.Subnet
			if subnet == nil {
				badRequest(w, Neutron, "Expecting to find subnet in request body.")
				return
			}
			if _, ok := subnet["id"]; !ok {
				subnet["id"] = fmt.Sprintf("subnet-%d", len(subnets)+1)
			}
			enrichSubnet(subnet, projectID)
			subnets = append(subnets, subnet)
			attachSubnetToNetwork(subnet)
			writeJSONStatus(w, http.StatusCreated, map[string]interface{}{"subnet": subnet})
		default:
			methodNotAllowed(w, Neutron, r.Method)
		}
	})

	// GET/PUT/DELETE /v2.0/subnets/{id}
	mux.HandleFunc("/v2.0/subnets/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.String())
		parts := Parts(r.URL.Path)
		if len(parts) < 3 || parts[2] == "" {
			notFound(w, Neutron, "Subnet")
			return
		}
		id := parts[2]
		mu.Lock()
		defer mu.Unlock()
		projectID := ProjectIDFromToken(r)

		for i, s := range subnets {
			if s["id"] != id {
				continue
			}
			enrichSubnet(s, projectID)
			if handleTags(w, r, parts, s) {
				return
			}
			if !adminScope && s["project_id"] != projectID && !subnetVisible(s) {
				notFound(w, Neutron, "Subnet "+id)
				return
			}
			switch r.Method {
			case http.MethodDelete:
				subnets = append(subnets[:i], subnets[i+1:]...)
				detachSubnetFromNetwork(s)
				w.WriteHeader(http.StatusNoContent)
			case http.MethodPut:
				var req struct {
					Subnet map[string]interface{} `json:"subnet"`
				}
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					badRequest(w, Neutron, "Invalid request body: "+err.Error())
					return
				}
				for k, v := range req.Subnet {
					s[k] = v
				}
				bumpRevision(s)
				subnets[i] = s
				writeJSON(w, map[string]interface{}{"subnet": s})
			case http.MethodGet:
				writeJSON(w, map[string]interface{}{"subnet": s})
			default:
				methodNotAllowed(w, Neutron, r.Method)
			}
			return
		}
		notFound(w, Neutron, "Subnet "+id)
	})

	// GET and POST /v2.0/ports
	mux.HandleFunc("/v2.0/ports", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.String())
		mu.Lock()
		defer mu.Unlock()
		projectID := ProjectIDFromToken(r)

		switch r.Method {
		case http.MethodGet:
			anyProject := ShowAllProjects(r.URL.Query())
			visible := []map[string]interface{}{}
			for _, p := range ports {
				enrichPort(p, projectID)
				if !anyProject && p["project_id"] != projectID {
					continue
				}
				visible = append(visible, p)
			}
			matched := FilterList(visible, r.URL.Query(), "fixed_ips")
			matched = filterByFixedIPs(matched, r.URL.Query()["fixed_ips"])
			writeJSON(w, map[string]interface{}{
				"ports": ApplyLimit(matched, r.URL.Query()),
			})
		case http.MethodPost:
			var req struct {
				Port map[string]interface{} `json:"port"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				badRequest(w, Neutron, "Invalid request body: "+err.Error())
				return
			}
			port := req.Port
			if port == nil {
				badRequest(w, Neutron, "Expecting to find port in request body.")
				return
			}
			port["id"] = fmt.Sprintf("port-%d", len(ports)+1)
			port["status"] = "ACTIVE"
			enrichPort(port, projectID)
			ports = append(ports, port)
			writeJSONStatus(w, http.StatusCreated, map[string]interface{}{"port": port})
		default:
			methodNotAllowed(w, Neutron, r.Method)
		}
	})

	// GET/PUT/DELETE /v2.0/ports/{id}
	mux.HandleFunc("/v2.0/ports/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.String())
		parts := Parts(r.URL.Path)
		if len(parts) < 3 || parts[2] == "" {
			notFound(w, Neutron, "Port")
			return
		}
		id := parts[2]
		mu.Lock()
		defer mu.Unlock()
		projectID := ProjectIDFromToken(r)

		for i, p := range ports {
			if p["id"] != id {
				continue
			}
			enrichPort(p, projectID)
			if handleTags(w, r, parts, p) {
				return
			}
			if !adminScope && p["project_id"] != projectID {
				notFound(w, Neutron, "Port "+id)
				return
			}
			switch r.Method {
			case http.MethodDelete:
				ports = append(ports[:i], ports[i+1:]...)
				w.WriteHeader(http.StatusNoContent)
			case http.MethodPut:
				var req struct {
					Port map[string]interface{} `json:"port"`
				}
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					badRequest(w, Neutron, "Invalid request body: "+err.Error())
					return
				}
				for k, v := range req.Port {
					p[k] = v
				}
				bumpRevision(p)
				ports[i] = p
				writeJSON(w, map[string]interface{}{"port": p})
			case http.MethodGet:
				writeJSON(w, map[string]interface{}{"port": p})
			default:
				methodNotAllowed(w, Neutron, r.Method)
			}
			return
		}
		notFound(w, Neutron, "Port "+id)
	})

	registerFloatingIPs(mux)
	registerNeutronRouters(mux)
	registerNeutronSecurityGroups(mux)
	RegisterNeutronExtraHandlers(mux)
}

/* ============================
   Floating IPs
============================ */

// registerFloatingIPs implements the /v2.0/floatingips collection.
func registerFloatingIPs(mux *http.ServeMux) {
	collection := func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		projectID := ProjectIDFromToken(r)

		switch r.Method {
		case http.MethodGet:
			anyProject := ShowAllProjects(r.URL.Query())
			visible := []map[string]interface{}{}
			for _, f := range floatingIPs {
				enrichFloatingIP(f, projectID)
				if !anyProject && f["project_id"] != projectID {
					continue
				}
				visible = append(visible, f)
			}
			writeJSON(w, map[string]interface{}{
				"floatingips": ApplyLimit(FilterList(visible, r.URL.Query()), r.URL.Query()),
			})
		case http.MethodPost:
			var req struct {
				FloatingIP map[string]interface{} `json:"floatingip"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				badRequest(w, Neutron, "Invalid request body: "+err.Error())
				return
			}
			f := req.FloatingIP
			if f == nil {
				badRequest(w, Neutron, "Expecting to find floatingip in request body.")
				return
			}
			netID, _ := f["floating_network_id"].(string)
			if netID == "" {
				badRequest(w, Neutron, "Expecting to find floating_network_id in floatingip.")
				return
			}
			floatingIPSeq++
			f["id"] = fmt.Sprintf("fip-%d", floatingIPSeq)
			if _, ok := f["floating_ip_address"]; !ok {
				f["floating_ip_address"] = fmt.Sprintf("172.24.4.%d", 10+floatingIPSeq)
			}
			enrichFloatingIP(f, projectID)
			bindFloatingIP(f)
			floatingIPs = append(floatingIPs, f)
			writeJSONStatus(w, http.StatusCreated, map[string]interface{}{"floatingip": f})
		default:
			methodNotAllowed(w, Neutron, r.Method)
		}
	}

	mux.HandleFunc("/v2.0/floatingips", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.String())
		collection(w, r)
	})

	mux.HandleFunc("/v2.0/floatingips/", func(w http.ResponseWriter, r *http.Request) {
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

		for i, f := range floatingIPs {
			if f["id"] != id {
				continue
			}
			enrichFloatingIP(f, projectID)
			if handleTags(w, r, parts, f) {
				return
			}
			if len(parts) >= 4 && parts[3] == "port_forwardings" {
				servePortForwardings(w, r, id, parts[4:])
				return
			}
			switch r.Method {
			case http.MethodGet:
				writeJSON(w, map[string]interface{}{"floatingip": f})
			case http.MethodPut:
				var req struct {
					FloatingIP map[string]interface{} `json:"floatingip"`
				}
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					badRequest(w, Neutron, "Invalid request body: "+err.Error())
					return
				}
				for k, v := range req.FloatingIP {
					f[k] = v
				}
				bindFloatingIP(f)
				bumpRevision(f)
				floatingIPs[i] = f
				writeJSON(w, map[string]interface{}{"floatingip": f})
			case http.MethodDelete:
				floatingIPs = append(floatingIPs[:i], floatingIPs[i+1:]...)
				w.WriteHeader(http.StatusNoContent)
			default:
				methodNotAllowed(w, Neutron, r.Method)
			}
			return
		}
		notFound(w, Neutron, "Floating IP "+id)
	})
}

// bindFloatingIP keeps the derived association fields consistent with
// port_id: Neutron fills in or clears the fixed address and status when a
// floating IP is attached or detached. The caller must hold the mutex.
func bindFloatingIP(f map[string]interface{}) {
	portID, _ := f["port_id"].(string)
	if portID == "" {
		f["port_id"] = nil
		f["fixed_ip_address"] = nil
		f["router_id"] = nil
		f["status"] = "DOWN"
		return
	}
	f["status"] = "ACTIVE"
	for _, p := range ports {
		if p["id"] != portID {
			continue
		}
		if f["fixed_ip_address"] == nil {
			if fips, ok := p["fixed_ips"].([]interface{}); ok && len(fips) > 0 {
				if first, ok := fips[0].(map[string]interface{}); ok {
					f["fixed_ip_address"] = first["ip_address"]
				}
			}
		}
		if dev, ok := p["device_id"].(string); ok && dev != "" {
			setDefault(f, "router_id", dev)
		}
		return
	}
}

// enrichFloatingIP fills the field set Neutron returns for a floating IP.
func enrichFloatingIP(f map[string]interface{}, projectID string) {
	now := nowRFC3339()
	setDefault(f, "status", "DOWN")
	setDefault(f, "description", "")
	setDefault(f, "revision_number", 1)
	setDefault(f, "created_at", now)
	setDefault(f, "updated_at", now)
	setDefault(f, "port_id", nil)
	setDefault(f, "router_id", nil)
	setDefault(f, "fixed_ip_address", nil)
	setDefault(f, "floating_ip_address", nil)
	setDefault(f, "floating_network_id", nil)
	setDefault(f, "dns_domain", "")
	setDefault(f, "dns_name", "")
	setDefault(f, "port_details", nil)
	setDefault(f, "qos_policy_id", nil)
	setDefault(f, "subnet_id", nil)
	setDefault(f, "tags", []interface{}{})
	if projectID != "" {
		setDefault(f, "project_id", projectID)
		setDefault(f, "tenant_id", f["project_id"])
	}
}

/* ============================
   Enrichment helpers
============================ */

// setDefault sets m[key]=val only if key is absent.
func setDefault(m map[string]interface{}, key string, val interface{}) {
	if _, ok := m[key]; !ok {
		m[key] = val
	}
}

// networkVisible reports whether a network is readable outside its owning
// project, which Neutron allows for shared and external networks.
func networkVisible(n map[string]interface{}) bool {
	if shared, ok := n["shared"].(bool); ok && shared {
		return true
	}
	external, ok := n["router:external"].(bool)
	return ok && external
}

// subnetVisible reports whether a subnet's network is shared or external.
func subnetVisible(s map[string]interface{}) bool {
	netID, _ := s["network_id"].(string)
	for _, n := range networks {
		if n["id"] == netID {
			return networkVisible(n)
		}
	}
	return false
}

// attachSubnetToNetwork records a new subnet on its network's subnets list.
func attachSubnetToNetwork(s map[string]interface{}) {
	netID, _ := s["network_id"].(string)
	for _, n := range networks {
		if n["id"] != netID {
			continue
		}
		list := toStringSlice(n["subnets"])
		id, _ := s["id"].(string)
		for _, existing := range list {
			if existing == id {
				return
			}
		}
		n["subnets"] = append(list, id)
		return
	}
}

// detachSubnetFromNetwork removes a deleted subnet from its network.
func detachSubnetFromNetwork(s map[string]interface{}) {
	netID, _ := s["network_id"].(string)
	id, _ := s["id"].(string)
	for _, n := range networks {
		if n["id"] != netID {
			continue
		}
		out := []string{}
		for _, existing := range toStringSlice(n["subnets"]) {
			if existing != id {
				out = append(out, existing)
			}
		}
		n["subnets"] = out
		return
	}
}

// enrichNetwork fills a network object with the full set of fields that
// openstacksdk's Network resource expects, so export/serialization never sees
// a missing (nil) list/attribute. Idempotent: only fills absent keys.
func enrichNetwork(n map[string]interface{}, projectID string) {
	now := nowRFC3339()
	setDefault(n, "name", "")
	setDefault(n, "admin_state_up", true)
	setDefault(n, "status", "ACTIVE")
	setDefault(n, "mtu", 1500)
	setDefault(n, "revision_number", 1)
	setDefault(n, "description", "")
	setDefault(n, "created_at", now)
	setDefault(n, "updated_at", now)
	setDefault(n, "shared", false)
	setDefault(n, "is_default", false)
	setDefault(n, "port_security_enabled", true)
	setDefault(n, "router:external", false)
	setDefault(n, "vlan_transparent", nil)
	setDefault(n, "dns_domain", nil)
	setDefault(n, "qos_policy_id", nil)
	setDefault(n, "provider:network_type", nil)
	setDefault(n, "provider:physical_network", nil)
	setDefault(n, "provider:segmentation_id", nil)
	setDefault(n, "ipv4_address_scope", nil)
	setDefault(n, "ipv6_address_scope", nil)
	// Lists must never be nil.
	setDefault(n, "subnets", []interface{}{})
	setDefault(n, "availability_zones", []interface{}{})
	setDefault(n, "availability_zone_hints", []interface{}{})
	setDefault(n, "segments", nil)
	setDefault(n, "tags", []interface{}{})
	if projectID != "" {
		setDefault(n, "project_id", projectID)
		setDefault(n, "tenant_id", n["project_id"])
	}
}

// enrichSubnet fills the field set Neutron returns for a subnet. Idempotent.
func enrichSubnet(s map[string]interface{}, projectID string) {
	now := nowRFC3339()
	setDefault(s, "name", "")
	setDefault(s, "status", "ACTIVE")
	setDefault(s, "ip_version", 4)
	setDefault(s, "enable_dhcp", true)
	setDefault(s, "dns_publish_fixed_ip", false)
	setDefault(s, "cidr", nil)
	// Neutron derives the gateway from the CIDR unless one is given, and
	// router interfaces are then created on that address.
	if _, ok := s["gateway_ip"]; !ok {
		if cidr, ok := s["cidr"].(string); ok && cidr != "" {
			s["gateway_ip"] = defaultGatewayIP(cidr)
		} else {
			s["gateway_ip"] = nil
		}
	}
	if _, ok := s["allocation_pools"]; !ok {
		if cidr, ok := s["cidr"].(string); ok && cidr != "" {
			s["allocation_pools"] = defaultAllocationPools(cidr)
		}
	}
	setDefault(s, "network_id", nil)
	// Arrays MUST exist (never nil).
	setDefault(s, "allocation_pools", []interface{}{})
	setDefault(s, "dns_nameservers", []interface{}{})
	setDefault(s, "host_routes", []interface{}{})
	setDefault(s, "service_types", []interface{}{})
	setDefault(s, "tags", []interface{}{})
	// Nullable fields Neutron always returns.
	setDefault(s, "ipv6_address_mode", nil)
	setDefault(s, "ipv6_ra_mode", nil)
	setDefault(s, "segment_id", nil)
	setDefault(s, "subnetpool_id", nil)
	setDefault(s, "revision_number", 1)
	setDefault(s, "description", "")
	setDefault(s, "created_at", now)
	setDefault(s, "updated_at", now)
	setDefault(s, "router:external", false)
	if projectID != "" {
		setDefault(s, "project_id", projectID)
		setDefault(s, "tenant_id", s["project_id"])
	}
}

// enrichPort fills the field set Neutron returns for a port. openstacksdk
// compares most of these to decide whether a port needs updating, so a
// missing key reads as a change and breaks idempotency. Idempotent.
func enrichPort(p map[string]interface{}, projectID string) {
	now := nowRFC3339()
	setDefault(p, "name", "")
	setDefault(p, "status", "DOWN")
	setDefault(p, "admin_state_up", true)
	setDefault(p, "description", "")
	setDefault(p, "revision_number", 1)
	setDefault(p, "created_at", now)
	setDefault(p, "updated_at", now)
	setDefault(p, "device_id", "")
	setDefault(p, "device_owner", "")
	setDefault(p, "mac_address", "fa:16:3e:00:00:01")
	setDefault(p, "network_id", nil)
	setDefault(p, "port_security_enabled", true)
	setDefault(p, "qos_policy_id", nil)
	setDefault(p, "dns_name", "")
	setDefault(p, "dns_domain", "")
	setDefault(p, "dns_assignment", []interface{}{})
	setDefault(p, "propagate_uplink_status", nil)
	setDefault(p, "binding:vnic_type", "normal")
	setDefault(p, "binding:vif_type", "ovs")
	setDefault(p, "binding:host_id", "")
	setDefault(p, "binding:profile", map[string]interface{}{})
	// Lists must never be nil: the port module compares them element-wise.
	setDefault(p, "fixed_ips", []interface{}{})
	resolveFixedIPs(p)
	setDefault(p, "allowed_address_pairs", []interface{}{})
	setDefault(p, "extra_dhcp_opts", []interface{}{})
	setDefault(p, "security_groups", []interface{}{})
	setDefault(p, "tags", []interface{}{})
	// An SR-IOV port carries the PCI binding details the migration code reads.
	if vnic, ok := p["binding:vnic_type"]; ok && vnic == "direct" {
		setDefault(p, "binding:vif_details", map[string]interface{}{
			"pci_slot":         "0000:af:06.0",
			"physical_network": "physnet2",
		})
	}
	setDefault(p, "binding:vif_details", map[string]interface{}{})
	if projectID != "" {
		setDefault(p, "project_id", projectID)
		setDefault(p, "tenant_id", p["project_id"])
	}
}

// resolveFixedIPs completes each fixed_ips entry the way Neutron does: an
// entry that names only an address gets the subnet it falls in, and one that
// names only a subnet gets an address from it. Clients read subnet_id back
// from here, so leaving it out makes them fail with a KeyError.
// The caller must hold the state mutex.
func resolveFixedIPs(p map[string]interface{}) {
	raw, ok := p["fixed_ips"].([]interface{})
	if !ok || len(raw) == 0 {
		return
	}
	networkID, _ := p["network_id"].(string)
	for i, item := range raw {
		entry, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		subnetID, _ := entry["subnet_id"].(string)
		address, _ := entry["ip_address"].(string)
		if subnetID == "" {
			if sub := subnetForAddress(networkID, address); sub != nil {
				entry["subnet_id"] = sub["id"]
				subnetID, _ = sub["id"].(string)
			}
		}
		if address == "" && subnetID != "" {
			entry["ip_address"] = allocateSubnetIP(subnetID)
		}
		raw[i] = entry
	}
	p["fixed_ips"] = raw
}

// subnetForAddress picks the subnet on a network that an address belongs to,
// falling back to the network's first subnet when the address does not
// parse. The caller must hold the state mutex.
func subnetForAddress(networkID, address string) map[string]interface{} {
	var fallback map[string]interface{}
	for _, s := range subnets {
		if networkID != "" && s["network_id"] != networkID {
			continue
		}
		if fallback == nil {
			fallback = s
		}
		cidr, _ := s["cidr"].(string)
		if cidr != "" && address != "" && addressInCIDR(address, cidr) {
			return s
		}
	}
	return fallback
}

// addressInCIDR reports whether an address falls inside a CIDR block.
func addressInCIDR(address, cidr string) bool {
	addr, err := netip.ParseAddr(address)
	if err != nil {
		return false
	}
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return false
	}
	return prefix.Contains(addr)
}

// subnetIPSeq numbers the addresses handed out within a subnet.
var subnetIPSeq = map[string]int{}

// allocateSubnetIP returns the next free-looking address in a subnet.
// The caller must hold the state mutex.
func allocateSubnetIP(subnetID string) string {
	subnetIPSeq[subnetID]++
	offset := subnetIPSeq[subnetID] + 1
	for _, s := range subnets {
		if s["id"] != subnetID {
			continue
		}
		cidr, _ := s["cidr"].(string)
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			break
		}
		addr := prefix.Addr()
		for i := 0; i < offset; i++ {
			addr = addr.Next()
		}
		return addr.String()
	}
	return fmt.Sprintf("10.0.0.%d", offset)
}

// defaultGatewayIP returns the address Neutron picks as a subnet's gateway:
// the first usable address in the block.
func defaultGatewayIP(cidr string) interface{} {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return nil
	}
	return prefix.Masked().Addr().Next().String()
}

// defaultAllocationPools returns the single pool Neutron creates for a
// subnet: everything after the gateway up to the last usable address.
func defaultAllocationPools(cidr string) []interface{} {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return []interface{}{}
	}
	start := prefix.Masked().Addr().Next().Next()
	end := lastAddress(prefix)
	if prefix.Addr().Is4() {
		// Skip the broadcast address.
		end = previousAddress(end)
	}
	if !start.IsValid() || !end.IsValid() || end.Less(start) {
		return []interface{}{}
	}
	return []interface{}{map[string]interface{}{
		"start": start.String(), "end": end.String(),
	}}
}

// lastAddress returns the highest address in a prefix.
func lastAddress(prefix netip.Prefix) netip.Addr {
	addr := prefix.Masked().Addr()
	bytes := addr.AsSlice()
	bits := prefix.Bits()
	for i := range bytes {
		shift := i * 8
		if shift >= bits {
			bytes[i] = 0xff
			continue
		}
		if remaining := bits - shift; remaining < 8 {
			bytes[i] |= byte(0xff >> remaining)
		}
	}
	out, ok := netip.AddrFromSlice(bytes)
	if !ok {
		return netip.Addr{}
	}
	return out
}

// previousAddress returns the address one below addr.
func previousAddress(addr netip.Addr) netip.Addr {
	bytes := addr.AsSlice()
	for i := len(bytes) - 1; i >= 0; i-- {
		if bytes[i] > 0 {
			bytes[i]--
			break
		}
		bytes[i] = 0xff
	}
	out, ok := netip.AddrFromSlice(bytes)
	if !ok {
		return netip.Addr{}
	}
	return out
}

// filterByFixedIPs applies Neutron's fixed_ips port filter. Each value is a
// "key=value" pair over one of the fixed-IP attributes, and the parameter
// may repeat; a port matches when every pair matches one of its entries.
// Clients rely on this to find the single port holding a given address.
func filterByFixedIPs(list []map[string]interface{}, filters []string) []map[string]interface{} {
	if len(filters) == 0 {
		return list
	}
	out := []map[string]interface{}{}
	for _, port := range list {
		entries, _ := port["fixed_ips"].([]interface{})
		matchedAll := true
		for _, filter := range filters {
			key, want, found := strings.Cut(filter, "=")
			if !found {
				continue
			}
			if !anyFixedIPMatches(entries, key, want) {
				matchedAll = false
				break
			}
		}
		if matchedAll {
			out = append(out, port)
		}
	}
	return out
}

// anyFixedIPMatches reports whether one of a port's fixed-IP entries
// satisfies a single key=value filter.
func anyFixedIPMatches(entries []interface{}, key, want string) bool {
	for _, raw := range entries {
		entry, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		switch key {
		case "ip_address":
			if stringOf(entry["ip_address"]) == want {
				return true
			}
		case "ip_address_substr":
			if strings.Contains(stringOf(entry["ip_address"]), want) {
				return true
			}
		case "subnet_id":
			if stringOf(entry["subnet_id"]) == want {
				return true
			}
		default:
			if stringOf(entry[key]) == want {
				return true
			}
		}
	}
	return false
}

// portForwardings holds the forwarding rules of each floating IP, keyed by
// floating IP id.
var (
	portForwardings   = map[string][]map[string]interface{}{}
	portForwardingSeq = 0
)

// servePortForwardings implements /v2.0/floatingips/{id}/port_forwardings,
// Neutron's floating IP port forwarding extension.
// The caller must hold the state mutex.
func servePortForwardings(w http.ResponseWriter, r *http.Request, fipID string, p []string) {
	if len(p) == 0 {
		switch r.Method {
		case http.MethodGet:
			list := portForwardings[fipID]
			if list == nil {
				list = []map[string]interface{}{}
			}
			writeJSON(w, map[string]interface{}{
				"port_forwardings": ApplyLimit(FilterList(list, r.URL.Query()), r.URL.Query()),
			})
		case http.MethodPost:
			var req struct {
				PortForwarding map[string]interface{} `json:"port_forwarding"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				badRequest(w, Neutron, "Invalid request body: "+err.Error())
				return
			}
			pf := req.PortForwarding
			if pf == nil {
				badRequest(w, Neutron, "Expecting to find port_forwarding in request body.")
				return
			}
			portForwardingSeq++
			pf["id"] = fmt.Sprintf("pf-%d", portForwardingSeq)
			enrichPortForwarding(pf, fipID)
			portForwardings[fipID] = append(portForwardings[fipID], pf)
			writeJSONStatus(w, http.StatusCreated,
				map[string]interface{}{"port_forwarding": pf})
		default:
			methodNotAllowed(w, Neutron, r.Method)
		}
		return
	}

	pfID := p[0]
	for i, pf := range portForwardings[fipID] {
		if pf["id"] != pfID {
			continue
		}
		enrichPortForwarding(pf, fipID)
		switch r.Method {
		case http.MethodGet:
			writeJSON(w, map[string]interface{}{"port_forwarding": pf})
		case http.MethodPut:
			var req struct {
				PortForwarding map[string]interface{} `json:"port_forwarding"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				badRequest(w, Neutron, "Invalid request body: "+err.Error())
				return
			}
			for k, v := range req.PortForwarding {
				pf[k] = v
			}
			bumpRevision(pf)
			writeJSON(w, map[string]interface{}{"port_forwarding": pf})
		case http.MethodDelete:
			rules := portForwardings[fipID]
			portForwardings[fipID] = append(rules[:i], rules[i+1:]...)
			w.WriteHeader(http.StatusNoContent)
		default:
			methodNotAllowed(w, Neutron, r.Method)
		}
		return
	}
	notFound(w, Neutron, "Port forwarding "+pfID)
}

// enrichPortForwarding fills the fields Neutron returns for a forwarding
// rule. The internal address is taken from the target port when the client
// did not name one, as Neutron does.
// The caller must hold the state mutex.
func enrichPortForwarding(pf map[string]interface{}, fipID string) {
	setDefault(pf, "protocol", "tcp")
	setDefault(pf, "description", "")
	setDefault(pf, "internal_port_id", nil)
	setDefault(pf, "external_port", nil)
	setDefault(pf, "internal_port", nil)
	setDefault(pf, "internal_port_range", nil)
	setDefault(pf, "external_port_range", nil)
	setDefault(pf, "revision_number", 1)
	if addr, ok := pf["internal_ip_address"].(string); !ok || addr == "" {
		pf["internal_ip_address"] = internalAddressOfPort(stringOf(pf["internal_port_id"]))
	}
	for _, f := range floatingIPs {
		if f["id"] == fipID {
			pf["floating_ip_address"] = f["floating_ip_address"]
			break
		}
	}
}

// internalAddressOfPort returns a port's first fixed address, or nil.
// The caller must hold the state mutex.
func internalAddressOfPort(portID string) interface{} {
	for _, p := range ports {
		if p["id"] != portID {
			continue
		}
		entries, _ := p["fixed_ips"].([]interface{})
		for _, raw := range entries {
			if entry, ok := raw.(map[string]interface{}); ok {
				if addr, ok := entry["ip_address"].(string); ok && addr != "" {
					return addr
				}
			}
		}
	}
	return nil
}
