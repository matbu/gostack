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

// RegisterNeutronHandlers registers Neutron API handlers on mux.
func RegisterNeutronHandlers(mux *http.ServeMux) {
	// GET and POST /v2.0/networks
	mux.HandleFunc("/v2.0/networks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		mu.Lock()
		defer mu.Unlock()
		if r.Method == http.MethodGet {
			tokenProject := ProjectIDFromToken(r)
			projectFilter := r.URL.Query().Get("project_id")
			nameFilter := r.URL.Query().Get("name")
			statusFilter := r.URL.Query().Get("status")

			filtered := []map[string]interface{}{}
			for _, n := range networks {
				enrichNetwork(n, tokenProject)
				// Project filtering (multi-tenant requirement)
				if projectFilter != "" {
					if n["project_id"] == projectFilter {
						// Apply name/status filters
						if nameFilter != "" {
							if netName, ok := n["name"].(string); !ok || netName != nameFilter {
								continue
							}
						}
						if statusFilter != "" {
							if netStatus, ok := n["status"].(string); !ok || netStatus != statusFilter {
								continue
							}
						}
						filtered = append(filtered, n)
					}
					continue
				}
				if n["project_id"] == tokenProject {
					// Filter by name if provided
					if nameFilter != "" {
						if netName, ok := n["name"].(string); !ok || netName != nameFilter {
							continue
						}
					}
					// Filter by status if provided
					if statusFilter != "" {
						if netStatus, ok := n["status"].(string); !ok || netStatus != statusFilter {
							continue
						}
					}
					filtered = append(filtered, n)
					continue
				}
				// Check shared networks with name/status filters
				if isShared, ok := n["shared"].(bool); ok && isShared {
					if nameFilter != "" {
						if netName, ok := n["name"].(string); !ok || netName != nameFilter {
							continue
						}
					}
					if statusFilter != "" {
						if netStatus, ok := n["status"].(string); !ok || netStatus != statusFilter {
							continue
						}
					}
					filtered = append(filtered, n)
				}
			}

			err := json.NewEncoder(w).Encode(map[string]interface{}{"networks": filtered})
			if err != nil {
				log.Printf("Error encoding JSON response: %v", err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
			return
		}
		if r.Method == http.MethodPost {
			var req struct {
				Network map[string]interface{} `json:"network"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			network := req.Network
			network["id"] = fmt.Sprintf("net-%d", len(networks)+1)
			enrichNetwork(network, ProjectIDFromToken(r))
			networks = append(networks, network)

			w.WriteHeader(http.StatusCreated)
			err := json.NewEncoder(w).Encode(map[string]interface{}{
				"network": network,
			})
			if err != nil {
				log.Printf("Error encoding JSON response: %v", err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
			return
		}

		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	})

	// GET/PUT/DELETE /v2.0/networks/{id} (+ /tags sub-resource)
	mux.HandleFunc("/v2.0/networks/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		parts := Parts(r.URL.Path)
		id := parts[2]
		mu.Lock()
		defer mu.Unlock()
		projectID := ProjectIDFromToken(r)

		for i, n := range networks {
			if n["id"] == id {
				enrichNetwork(n, projectID)
				if handleTags(w, r, parts, n) {
					return
				}
				if n["project_id"] != projectID {
					if shared, ok := n["shared"].(bool); !ok || !shared {
						http.NotFound(w, r)
						return
					}
				}
				switch r.Method {
				case http.MethodDelete:
					networks = append(networks[:i], networks[i+1:]...)
					w.WriteHeader(http.StatusNoContent)
					return
				case http.MethodPut:
					var req struct {
						Network map[string]interface{} `json:"network"`
					}
					if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
						http.Error(w, err.Error(), http.StatusBadRequest)
						return
					}
					for k, v := range req.Network {
						n[k] = v
					}
					if rev, ok := n["revision_number"].(int); ok {
						n["revision_number"] = rev + 1
					}
					networks[i] = n
					if err := json.NewEncoder(w).Encode(map[string]interface{}{"network": n}); err != nil {
						log.Printf("Error encoding JSON response: %v", err)
					}
					return
				default:
					if err := json.NewEncoder(w).Encode(map[string]interface{}{"network": n}); err != nil {
						log.Printf("Error encoding JSON response: %v", err)
						http.Error(w, "Internal Server Error", http.StatusInternalServerError)
					}
					return
				}
			}
		}

		http.NotFound(w, r)
	})

	// GET and POST /v2.0/subnets
	mux.HandleFunc("/v2.0/subnets", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		mu.Lock()
		defer mu.Unlock()

		// GET /v2.0/subnets
		if r.Method == http.MethodGet {
			projectFilter := r.URL.Query().Get("project_id")
			if projectFilter == "" {
				projectFilter = ProjectIDFromToken(r)
			}
			err := json.NewEncoder(w).Encode(map[string]interface{}{
				"subnets": func() []map[string]interface{} {
					filtered := []map[string]interface{}{}
					for _, s := range subnets {
						if projectFilter != "" && s["project_id"] != projectFilter {
							continue
						}
						filtered = append(filtered, s)
					}
					return filtered
				}(),
			})
			if err != nil {
				log.Printf("Error encoding JSON response: %v", err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
			return
		}

		// POST /v2.0/subnets
		if r.Method == http.MethodPost {
			var req struct {
				Subnet map[string]interface{} `json:"subnet"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			subnet := req.Subnet

			// ID
			if _, ok := subnet["id"]; !ok {
				subnet["id"] = fmt.Sprintf("subnet-%d", len(subnets)+1)
			}

			// Status (Neutron returns ACTIVE on create)
			subnet["status"] = "ACTIVE"

			// Defaults expected by Neutron / CLI
			if _, ok := subnet["ip_version"]; !ok {
				subnet["ip_version"] = 4
			}
			if _, ok := subnet["enable_dhcp"]; !ok {
				subnet["enable_dhcp"] = true
			}
			if _, ok := subnet["dns_publish_fixed_ip"]; !ok {
				subnet["dns_publish_fixed_ip"] = false
			}

			// Arrays MUST exist (never nil)
			if _, ok := subnet["allocation_pools"]; !ok {
				subnet["allocation_pools"] = []map[string]interface{}{}
			}
			if _, ok := subnet["dns_nameservers"]; !ok {
				subnet["dns_nameservers"] = []string{}
			}
			if _, ok := subnet["host_routes"]; !ok {
				subnet["host_routes"] = []map[string]interface{}{}
			}
			if _, ok := subnet["service_types"]; !ok {
				subnet["service_types"] = []string{}
			}
			if _, ok := subnet["tags"]; !ok {
				subnet["tags"] = []string{}
			}

			// Nullable fields Neutron always returns
			if _, ok := subnet["ipv6_address_mode"]; !ok {
				subnet["ipv6_address_mode"] = nil
			}
			if _, ok := subnet["ipv6_ra_mode"]; !ok {
				subnet["ipv6_ra_mode"] = nil
			}
			if _, ok := subnet["segment_id"]; !ok {
				subnet["segment_id"] = nil
			}
			if _, ok := subnet["subnetpool_id"]; !ok {
				subnet["subnetpool_id"] = nil
			}

			// Metadata
			if _, ok := subnet["revision_number"]; !ok {
				subnet["revision_number"] = 1
			}
			if _, ok := subnet["description"]; !ok {
				subnet["description"] = ""
			}

			// Timestamps (CLI expects strings, not time.Time)
			now := time.Now().UTC().Format(time.RFC3339)
			if _, ok := subnet["created_at"]; !ok {
				subnet["created_at"] = now
			}
			if _, ok := subnet["updated_at"]; !ok {
				subnet["updated_at"] = now
			}

			// router:external default (extension)
			if _, ok := subnet["router:external"]; !ok {
				subnet["router:external"] = false
			}

			// Project ID (required for module to fetch project info)
			if _, ok := subnet["project_id"]; !ok {
				subnet["project_id"] = ProjectIDFromToken(r)
			}

			subnets = append(subnets, subnet)

			w.WriteHeader(http.StatusCreated)
			err := json.NewEncoder(w).Encode(map[string]interface{}{
				"subnet": subnet,
			})
			if err != nil {
				log.Printf("Error encoding JSON response: %v", err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
			return
		}

		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	})

	// GET /v2.0/subnets/{id}
	mux.HandleFunc("/v2.0/subnets/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		parts := Parts(r.URL.Path)
		if len(parts) < 3 || parts[2] == "" {
			http.NotFound(w, r)
			return
		}
		id := parts[2]
		mu.Lock()
		defer mu.Unlock()
		projectID := ProjectIDFromToken(r)

		for i, s := range subnets {
			if s["id"] == id {
				if s["project_id"] != projectID {
					http.NotFound(w, r)
					return
				}
				if handleTags(w, r, parts, s) {
					return
				}
				switch r.Method {
				case http.MethodDelete:
					subnets = append(subnets[:i], subnets[i+1:]...)
					w.WriteHeader(http.StatusNoContent)
					return
				case http.MethodPut:
					var req struct {
						Subnet map[string]interface{} `json:"subnet"`
					}
					if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
						http.Error(w, err.Error(), http.StatusBadRequest)
						return
					}
					for k, v := range req.Subnet {
						s[k] = v
					}
					subnets[i] = s
					writeJSON(w, map[string]interface{}{"subnet": s})
					return
				default:
					writeJSON(w, map[string]interface{}{"subnet": s})
					return
				}
			}
		}

		http.NotFound(w, r)
	})

	// GET and POST /v2.0/ports
	mux.HandleFunc("/v2.0/ports", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		mu.Lock()
		defer mu.Unlock()
		if r.Method == http.MethodGet {
			// Extract query parameters
			projectFilter := r.URL.Query().Get("project_id")
			if projectFilter == "" {
				projectFilter = ProjectIDFromToken(r)
			}
			deviceIDFilter := r.URL.Query().Get("device_id")
			networkIDFilter := r.URL.Query().Get("network_id")
			statusFilter := r.URL.Query().Get("status")

			filtered := []map[string]interface{}{}
			for _, p := range ports {
				// Project filtering (multi-tenant requirement)
				if projectFilter != "" && p["project_id"] != projectFilter {
					continue
				}

				// Filter by device_id if provided
				if deviceIDFilter != "" {
					if portDeviceID, ok := p["device_id"].(string); ok {
						if portDeviceID != deviceIDFilter {
							continue
						}
					} else if deviceIDFilter != "" {
						// device_id is nil but filter is set
						continue
					}
				}

				// Filter by network_id if provided
				if networkIDFilter != "" {
					if portNetID, ok := p["network_id"].(string); !ok || portNetID != networkIDFilter {
						continue
					}
				}

				// Filter by status if provided
				if statusFilter != "" {
					if portStatus, ok := p["status"].(string); !ok || portStatus != statusFilter {
						continue
					}
				}

				filtered = append(filtered, p)
			}

			err := json.NewEncoder(w).Encode(map[string]interface{}{"ports": filtered})
			if err != nil {
				log.Printf("Error encoding JSON response: %v", err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
			return
		}
		if r.Method == http.MethodPost {
			var req struct {
				Port map[string]interface{} `json:"port"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			port := req.Port
			port["id"] = fmt.Sprintf("port-%d", len(ports)+1)
			port["status"] = "ACTIVE"
			if _, ok := port["binding:vif_type"]; !ok {
				port["binding:vif_type"] = "hw_veb"
			}
			if _, ok := port["device_owner"]; !ok {
				port["device_owner"] = ""
			}
			if _, ok := port["project_id"]; !ok {
				port["project_id"] = ProjectIDFromToken(r)
			}

			if vnic, ok := port["binding:vnic_type"]; ok && vnic == "direct" {
				port["binding:vif_details"] = map[string]interface{}{
					"pci_slot":         "0000:af:06.0",
					"physical_network": "physnet2",
				}
			}
			ports = append(ports, port)

			w.WriteHeader(http.StatusCreated)
			err := json.NewEncoder(w).Encode(map[string]interface{}{
				"port": port,
			})
			if err != nil {
				log.Printf("Error encoding JSON response: %v", err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
			return
		}

		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	})

	// GET /v2.0/ports/{id}
	mux.HandleFunc("/v2.0/ports/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		id := r.URL.Path[len("/v2.0/ports/"):]
		mu.Lock()
		defer mu.Unlock()
		projectID := ProjectIDFromToken(r)

		for i, p := range ports {
			if p["id"] == id {
				if p["project_id"] != projectID {
					http.NotFound(w, r)
					return
				}
				switch r.Method {
				case http.MethodDelete:
					ports = append(ports[:i], ports[i+1:]...)
					w.WriteHeader(http.StatusNoContent)
					return
				case http.MethodPut:
					var req struct {
						Port map[string]interface{} `json:"port"`
					}
					if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
						http.Error(w, err.Error(), http.StatusBadRequest)
						return
					}
					for k, v := range req.Port {
						p[k] = v
					}
					ports[i] = p
					writeJSON(w, map[string]interface{}{"port": p})
					return
				default:
					writeJSON(w, map[string]interface{}{"port": p})
					return
				}
			}
		}

		http.NotFound(w, r)
	})

	// GET /v2.0/floatingips
	mux.HandleFunc("/v2.0/floatingips", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			err := json.NewEncoder(w).Encode(map[string]interface{}{
				"floatingips": []interface{}{},
			})
			if err != nil {
				log.Printf("Error encoding JSON response: %v", err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
			return
		}
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	})

	registerNeutronRouters(mux)
	registerNeutronSecurityGroups(mux)
}

// setDefault sets m[key]=val only if key is absent.
func setDefault(m map[string]interface{}, key string, val interface{}) {
	if _, ok := m[key]; !ok {
		m[key] = val
	}
}

// enrichNetwork fills a network object with the full set of fields that
// openstacksdk's Network resource expects, so export/serialization never sees
// a missing (nil) list/attribute. Idempotent: only fills absent keys.
func enrichNetwork(n map[string]interface{}, projectID string) {
	now := time.Now().UTC().Format(time.RFC3339)
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
