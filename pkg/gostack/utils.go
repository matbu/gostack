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
	"crypto/rand"
	"fmt"
	"net/http"
	"strings"
)

// RandomID generates a UUID v4-ish formatted ID with the given prefix.
func RandomID(prefix string) string {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	return fmt.Sprintf(
		"%s-%x-%x-%x-%x-%x",
		prefix,
		b[0:4],
		b[4:6],
		b[6:8],
		b[8:10],
		b[10:16],
	)
}

// BuildAddresses builds the addresses map Nova returns for a server. Nova
// keys it by network *name*, not id, and lists each floating IP alongside
// the fixed address on the same network — clients (including the inventory
// plugin) pick ansible_host out of these entries.
//
// The caller must hold the state mutex.
func BuildAddresses(serverNets []map[string]string) map[string][]map[string]interface{} {
	addresses := map[string][]map[string]interface{}{}
	for i, net := range serverNets {
		netRef := net["uuid"]
		if netRef == "" {
			netRef = net["net-id"]
		}
		portID := net["port"]
		if portID == "" {
			portID = net["port_id"]
		}

		// A port pins both the network and the address; otherwise fall back
		// to the referenced network and a generated address.
		var port map[string]interface{}
		if portID != "" {
			for _, candidate := range ports {
				if candidate["id"] == portID {
					port = candidate
					if netRef == "" {
						netRef, _ = candidate["network_id"].(string)
					}
					break
				}
			}
		}

		netName := networkNameFor(netRef)
		entries := []map[string]interface{}{}
		mac := "fa:16:3e:00:00:01"
		if port != nil {
			if m, ok := port["mac_address"].(string); ok && m != "" {
				mac = m
			}
		}

		for _, addr := range fixedAddressesOf(port, net, i) {
			entries = append(entries, map[string]interface{}{
				"addr":                    addr,
				"version":                 4,
				"OS-EXT-IPS:type":         "fixed",
				"OS-EXT-IPS-MAC:mac_addr": mac,
			})
		}
		if portID != "" {
			for _, f := range floatingIPs {
				if f["port_id"] != portID {
					continue
				}
				entries = append(entries, map[string]interface{}{
					"addr":                    f["floating_ip_address"],
					"version":                 4,
					"OS-EXT-IPS:type":         "floating",
					"OS-EXT-IPS-MAC:mac_addr": mac,
				})
			}
		}
		addresses[netName] = append(addresses[netName], entries...)
	}
	return addresses
}

// fixedAddressesOf returns the fixed addresses to report for one attachment.
// The caller must hold the state mutex.
func fixedAddressesOf(port map[string]interface{}, net map[string]string, index int) []string {
	if port != nil {
		if raw, ok := port["fixed_ips"].([]interface{}); ok && len(raw) > 0 {
			out := []string{}
			for _, item := range raw {
				entry, ok := item.(map[string]interface{})
				if !ok {
					continue
				}
				if addr, ok := entry["ip_address"].(string); ok && addr != "" {
					out = append(out, addr)
				}
			}
			if len(out) > 0 {
				return out
			}
		}
	}
	if addr := net["fixed_ip"]; addr != "" {
		return []string{addr}
	}
	return []string{fmt.Sprintf("192.168.0.%d", 10+index)}
}

// networkNameFor resolves a network id to its name, which is how Nova keys
// the addresses map. The caller must hold the state mutex.
func networkNameFor(networkID string) string {
	if networkID == "" {
		return "private"
	}
	for _, n := range networks {
		if n["id"] == networkID {
			if name, ok := n["name"].(string); ok && name != "" {
				return name
			}
		}
		if n["name"] == networkID {
			return networkID
		}
	}
	return networkID
}

// Parts splits a path into path segments.
func Parts(p string) []string {
	return strings.Split(strings.Trim(p, "/"), "/")
}

// ProjectIDFromToken extracts project ID from request headers or token.
func ProjectIDFromToken(r *http.Request) string {
	token := r.Header.Get("X-Auth-Token")
	if token == "" {
		return "demo"
	}
	tokenMu.RLock()
	defer tokenMu.RUnlock()
	if projectID, ok := tokenProjects[token]; ok {
		return projectID
	}
	if strings.HasPrefix(token, "fake-token-") {
		proj := strings.TrimPrefix(token, "fake-token-")
		if p, ok := projects[proj]; ok {
			return p.ID
		}
		for _, p := range projects {
			if p.Name == proj {
				return p.ID
			}
		}
	}
	if projID := r.Header.Get("X-Project-Id"); projID != "" {
		if p, ok := projects[projID]; ok {
			return p.ID
		}
	}
	if projID := r.Header.Get("X-Auth-Project-Id"); projID != "" {
		if p, ok := projects[projID]; ok {
			return p.ID
		}
	}
	if projName := r.Header.Get("X-Project-Name"); projName != "" {
		for _, p := range projects {
			if p.Name == projName {
				return p.ID
			}
		}
	}
	if projName := r.Header.Get("X-Auth-Project-Name"); projName != "" {
		for _, p := range projects {
			if p.Name == projName {
				return p.ID
			}
		}
	}
	return "demo"
}
