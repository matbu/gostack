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
	"regexp"
	"strings"
	"time"
)

// enrichKeypair fills a keypair with the fields Nova returns, so export can
// serialize it. When no public_key is supplied (Nova would generate one), a
// deterministic fake key pair is produced. Idempotent.
func enrichKeypair(kp map[string]interface{}, projectID string) {
	name, _ := kp["name"].(string)
	if _, ok := kp["public_key"]; !ok || kp["public_key"] == "" {
		kp["public_key"] = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDfake" + name + " gostack@fake"
		kp["private_key"] = "-----BEGIN RSA PRIVATE KEY-----\nFAKE\n-----END RSA PRIVATE KEY-----\n"
	}
	setDefault(kp, "fingerprint", "fa:ke:fi:ng:er:pr:in:t0")
	setDefault(kp, "type", "ssh")
	setDefault(kp, "created_at", time.Now().UTC().Format(time.RFC3339))
	setDefault(kp, "deleted", false)
	setDefault(kp, "user_id", "demo-user")
	if projectID != "" {
		setDefault(kp, "project_id", projectID)
	}
}

// enrichFlavor fills a flavor with Nova's standard fields. Idempotent.
func enrichFlavor(f map[string]interface{}) {
	if _, ok := f["id"]; !ok || f["id"] == "" || f["id"] == nil {
		flavorSeq++
		f["id"] = fmt.Sprintf("flavor-%d", flavorSeq)
	}
	setDefault(f, "swap", "")
	setDefault(f, "rxtx_factor", 1.0)
	setDefault(f, "OS-FLV-EXT-DATA:ephemeral", 0)
	setDefault(f, "OS-FLV-DISABLED:disabled", false)
	setDefault(f, "os-flavor-access:is_public", true)
	setDefault(f, "disk", 0)
	setDefault(f, "ram", 0)
	setDefault(f, "vcpus", 1)
}

// RegisterNovaHandlers registers Nova (compute) API handlers on mux.
func RegisterNovaHandlers(mux *http.ServeMux) {
	mux.HandleFunc("/v2.1", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(map[string]interface{}{
			"version": map[string]interface{}{
				"id":          "v2.1",
				"status":      "CURRENT",
				"min_version": "2.1",
				"version":     "2.90",
				"updated":     "2023-01-01T00:00:00Z",
				"links": []map[string]string{
					{
						"rel":  "self",
						"href": baseURL + "/v2.1/",
					},
				},
			},
		})
		if err != nil {
			log.Printf("Error encoding JSON response: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
	})

	mux.HandleFunc("/v2.1/flavors/detail", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(map[string]interface{}{
			"flavors": flavors,
		})
		if err != nil {
			log.Printf("Error encoding JSON response: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
	})

	mux.HandleFunc("/v2.1/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.String())
		p := Parts(r.URL.Path)
		// Project-scoped compute root: GET /v2.1/{project} — novaclient does
		// endpoint version discovery here before any API call.
		if len(p) == 2 {
			w.Header().Set("Content-Type", "application/json")
			writeJSON(w, map[string]interface{}{
				"version": map[string]interface{}{
					"id": "v2.1", "status": "CURRENT", "min_version": "2.1",
					"version": "2.90", "updated": "2023-01-01T00:00:00Z",
					"links": []map[string]string{
						{"rel": "self", "href": baseURL + "/v2.1/"},
					},
				},
			})
			return
		}
		if len(p) < 3 {
			http.NotFound(w, r)
			return
		}
		switch p[2] {

		case "flavors":
			if len(p) == 3 {
				if r.Method == http.MethodGet {
					nameFilter := r.URL.Query().Get("name")
					mu.Lock()
					list := []interface{}{}
					for _, f := range flavors {
						if nameFilter != "" && f["name"] != nameFilter {
							continue
						}
						list = append(list, f)
					}
					mu.Unlock()
					w.Header().Set("Content-Type", "application/json")
					err := json.NewEncoder(w).Encode(map[string]interface{}{"flavors": list})
					if err != nil {
						log.Printf("Error encoding JSON response: %v", err)
						http.Error(w, "Internal Server Error", http.StatusInternalServerError)
					}
					return
				}
				if r.Method == http.MethodPost {
					var req struct {
						Flavor map[string]interface{} `json:"flavor"`
					}
					if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
						http.Error(w, "invalid JSON body", http.StatusBadRequest)
						return
					}
					f := req.Flavor
					enrichFlavor(f)
					mu.Lock()
					flavors = append(flavors, f)
					mu.Unlock()
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					writeJSON(w, map[string]interface{}{"flavor": f})
					return
				}
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
				return
			}
			if len(p) == 4 && p[3] == "detail" {
				list := []interface{}{}
				for _, f := range flavors {
					list = append(list, f)
				}
				w.Header().Set("Content-Type", "application/json")
				err := json.NewEncoder(w).Encode(map[string]interface{}{"flavors": list})
				if err != nil {
					log.Printf("Error encoding JSON response: %v", err)
					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				}
				return
			}
			if len(p) == 4 {
				flavorID := p[3]
				mu.Lock()
				defer mu.Unlock()
				for i, f := range flavors {
					if f["id"] == flavorID {
						w.Header().Set("Content-Type", "application/json")
						switch r.Method {
						case http.MethodDelete:
							flavors = append(flavors[:i], flavors[i+1:]...)
							delete(flavorExtraSpecs, flavorID)
							w.WriteHeader(http.StatusAccepted)
						default:
							writeJSON(w, map[string]interface{}{"flavor": f})
						}
						return
					}
				}
				http.NotFound(w, r)
				return
			}
			// Individual extra spec: /flavors/{id}/os-extra_specs/{key}
			if len(p) == 6 && p[4] == "os-extra_specs" {
				flavorID := p[3]
				key := p[5]
				mu.Lock()
				defer mu.Unlock()
				if _, ok := flavorExtraSpecs[flavorID]; !ok {
					flavorExtraSpecs[flavorID] = map[string]string{}
				}
				w.Header().Set("Content-Type", "application/json")
				switch r.Method {
				case http.MethodGet:
					val, ok := flavorExtraSpecs[flavorID][key]
					if !ok {
						http.NotFound(w, r)
						return
					}
					writeJSON(w, map[string]string{key: val})
				case http.MethodPut:
					var body map[string]string
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
						http.Error(w, "invalid JSON body", http.StatusBadRequest)
						return
					}
					for k, v := range body {
						flavorExtraSpecs[flavorID][k] = v
					}
					writeJSON(w, map[string]string{key: flavorExtraSpecs[flavorID][key]})
				case http.MethodDelete:
					delete(flavorExtraSpecs[flavorID], key)
					w.WriteHeader(http.StatusOK)
				default:
					http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
				}
				return
			}
			if len(p) == 5 && p[4] == "os-extra_specs" {
				flavorID := p[3]
				if _, ok := flavorExtraSpecs[flavorID]; !ok {
					flavorExtraSpecs[flavorID] = map[string]string{}
				}
				switch r.Method {
				case http.MethodGet:
					w.Header().Set("Content-Type", "application/json")
					err := json.NewEncoder(w).Encode(map[string]interface{}{
						"extra_specs": flavorExtraSpecs[flavorID],
					})
					if err != nil {
						log.Printf("Error encoding JSON response: %v", err)
						http.Error(w, "Internal Server Error", http.StatusInternalServerError)
					}
					return
				case http.MethodPost:
					var body struct {
						ExtraSpecs map[string]string `json:"extra_specs"`
					}
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
						http.Error(w, "invalid JSON body", http.StatusBadRequest)
						return
					}
					for k, v := range body.ExtraSpecs {
						flavorExtraSpecs[flavorID][k] = v
					}
					w.Header().Set("Content-Type", "application/json")
					err := json.NewEncoder(w).Encode(map[string]interface{}{
						"extra_specs": flavorExtraSpecs[flavorID],
					})
					if err != nil {
						log.Printf("Error encoding JSON response: %v", err)
						http.Error(w, "Internal Server Error", http.StatusInternalServerError)
					}
					return
				}
			}

		case "servers":
			// os-interface
			if len(p) >= 5 && p[4] == "os-interface" {
				srvID := p[3]
				mu.Lock()
				_, ok := servers[srvID]
				mu.Unlock()
				if !ok {
					http.NotFound(w, r)
					return
				}
				switch r.Method {
				case http.MethodPost:
					var req struct {
						InterfaceAttachment struct {
							PortID string `json:"port_id"`
						} `json:"interfaceAttachment"`
					}
					if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
						http.Error(w, "invalid JSON body", http.StatusBadRequest)
						return
					}
					if req.InterfaceAttachment.PortID == "" {
						http.Error(w, "missing port_id", http.StatusBadRequest)
						return
					}
					mu.Lock()
					for _, port := range ports {
						if port["id"] == req.InterfaceAttachment.PortID {
							port["device_id"] = srvID
							port["device_owner"] = "compute:nova"
							port["status"] = "ACTIVE"
							if _, ok := port["admin_state_up"]; !ok {
								port["admin_state_up"] = true
							}
							mu.Unlock()
							resp := map[string]interface{}{
								"interfaceAttachment": map[string]interface{}{
									"port_id":   req.InterfaceAttachment.PortID,
									"server_id": srvID,
								},
							}
							w.Header().Set("Content-Type", "application/json")
							w.WriteHeader(http.StatusOK)
							err := json.NewEncoder(w).Encode(resp)
							if err != nil {
								log.Printf("Error encoding JSON response: %v", err)
								http.Error(w, "Internal Server Error", http.StatusInternalServerError)
							}
							return
						}
					}
					mu.Unlock()
					http.NotFound(w, r)
					return
				case http.MethodDelete:
					if len(p) < 6 {
						http.Error(w, "missing port id", http.StatusBadRequest)
						return
					}
					portID := p[5]
					mu.Lock()
					for _, port := range ports {
						if port["id"] == portID {
							port["device_id"] = nil
							port["device_owner"] = nil
							port["status"] = "DOWN"
							mu.Unlock()
							w.WriteHeader(http.StatusNoContent)
							return
						}
					}
					mu.Unlock()
					http.NotFound(w, r)
					return
				}
			}

			// DELETE os-volume_attachments/{attachment-id}
			if r.Method == http.MethodDelete && len(p) >= 6 && p[4] == "os-volume_attachments" {
				attachmentID := p[5]
				srvID := p[3]
				volumeID := strings.TrimPrefix(attachmentID, "attach-")
				if volumeID == attachmentID {
					http.NotFound(w, r)
					return
				}
				mu.Lock()
				defer mu.Unlock()
				vol, ok := volumes[volumeID]
				if !ok {
					http.NotFound(w, r)
					return
				}
				newAttachments := []map[string]interface{}{}
				found := false
				for _, attachment := range vol.Attachments {
					if attachment["server_id"] == srvID {
						found = true
						log.Printf("Detaching volume %s from server %s", volumeID, srvID)
						continue
					}
					newAttachments = append(newAttachments, attachment)
				}
				if !found {
					http.NotFound(w, r)
					return
				}
				vol.Attachments = newAttachments
				if len(vol.Attachments) == 0 {
					vol.Status = "available"
					log.Printf("Volume %s set to available (no attachments)", volumeID)
				}
				w.WriteHeader(http.StatusNoContent)
				return
			}

			// POST/GET os-volume_attachments
			if strings.HasSuffix(r.URL.Path, "/os-volume_attachments") {
				srvID := p[len(p)-2]
				if r.Method == http.MethodPost {
					var req struct {
						VolumeAttachment struct {
							VolumeID string `json:"volumeId"`
						} `json:"volumeAttachment"`
					}
					if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
						http.Error(w, "invalid JSON body", http.StatusBadRequest)
						return
					}
					mu.Lock()
					_, serverExists := servers[srvID]
					mu.Unlock()
					if !serverExists {
						http.Error(w, "Server not found", http.StatusNotFound)
						return
					}
					mu.Lock()
					v, volumeExists := volumes[req.VolumeAttachment.VolumeID]
					mu.Unlock()
					if !volumeExists {
						http.Error(w, "Volume not found", http.StatusNotFound)
						return
					}
					if v.Status != "available" {
						http.Error(w, fmt.Sprintf("Volume must be available (current: %s)", v.Status), http.StatusBadRequest)
						return
					}
					for _, attachment := range v.Attachments {
						if attachment["server_id"] == srvID {
							http.Error(w, "Volume already attached to this server", http.StatusConflict)
							return
						}
					}
					mu.Lock()
					v.Status = "in-use"
					v.Attachments = append(v.Attachments, map[string]interface{}{
						"server_id": srvID,
						"device":    "/dev/vdb",
					})
					mu.Unlock()
					resp := map[string]interface{}{
						"volumeAttachment": map[string]interface{}{
							"id":       "attach-" + req.VolumeAttachment.VolumeID,
							"volumeId": req.VolumeAttachment.VolumeID,
							"serverId": srvID,
							"device":   "/dev/vdb",
						},
					}
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					err := json.NewEncoder(w).Encode(resp)
					if err != nil {
						log.Printf("Error encoding JSON response: %v", err)
						http.Error(w, "Internal Server Error", http.StatusInternalServerError)
					}
					return
				}
				if r.Method == http.MethodGet {
					list := []interface{}{}
					for _, v := range volumes {
						for _, a := range v.Attachments {
							if a["server_id"] == srvID {
								list = append(list, map[string]interface{}{
									"id":       "attach-" + v.ID,
									"volumeId": v.ID,
									"serverId": srvID,
									"device":   a["device"],
								})
							}
						}
					}
					w.Header().Set("Content-Type", "application/json")
					err := json.NewEncoder(w).Encode(map[string]interface{}{
						"volumeAttachments": list,
					})
					if err != nil {
						log.Printf("Error encoding JSON response: %v", err)
						http.Error(w, "Internal Server Error", http.StatusInternalServerError)
					}
					return
				}
			}

			// GET servers detail
			if strings.HasSuffix(r.URL.Path, "/detail") {
				projectFilter := ProjectIDFromToken(r)
				if projectFilter == "" {
					projectFilter = p[1]
				}
				nameFilter := r.URL.Query().Get("name")
				var nameRe *regexp.Regexp
				if nameFilter != "" {
					var err error
					nameRe, err = regexp.Compile(nameFilter)
					if err != nil {
						http.Error(w, "invalid name regex", http.StatusBadRequest)
						return
					}
				}
				list := []interface{}{}
				mu.Lock()
				for _, s := range servers {
					if projectFilter != "" && s.Project != projectFilter {
						continue
					}
					if nameRe != nil && !nameRe.MatchString(s.Name) {
						continue
					}
					list = append(list, map[string]interface{}{
						"id":               s.ID,
						"name":             s.Name,
						"status":           s.Status,
						"flavor":           s.Flavor,
						"image":            s.Image,
						"addresses":        BuildAddresses(s.Networks),
						"project_id":       s.Project,
						"security_groups":  []interface{}{},
						"metadata":         map[string]string{},
						"key_name":         nil,
						"accessIPv4":       s.AccessIPv4,
					})
				}
				mu.Unlock()
				w.Header().Set("Content-Type", "application/json")
				err := json.NewEncoder(w).Encode(map[string]interface{}{"servers": list})
				if err != nil {
					log.Printf("Error encoding JSON response: %v", err)
					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				}
				return
			}

			// GET server by ID
			if len(p) == 4 && r.Method == http.MethodGet {
				srvID := p[3]
				projectFilter := ProjectIDFromToken(r)
				if projectFilter == "" {
					projectFilter = p[1]
				}
				nameFilter := r.URL.Query().Get("name")
				var nameRe *regexp.Regexp
				if nameFilter != "" {
					var err error
					nameRe, err = regexp.Compile(nameFilter)
					if err != nil {
						http.Error(w, "invalid name regex", http.StatusBadRequest)
						return
					}
				}
				mu.Lock()
				s, ok := servers[srvID]
				mu.Unlock()
				if !ok {
					http.NotFound(w, r)
					return
				}
				if projectFilter != "" && s.Project != projectFilter {
					http.NotFound(w, r)
					return
				}
				if nameRe != nil && !nameRe.MatchString(s.Name) {
					http.NotFound(w, r)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				err := json.NewEncoder(w).Encode(map[string]interface{}{
					"server": map[string]interface{}{
						"id":               s.ID,
						"name":             s.Name,
						"status":           s.Status,
						"flavor":           s.Flavor,
						"image":            s.Image,
						"addresses":        BuildAddresses(s.Networks),
						"project_id":       s.Project,
						"security_groups":  []interface{}{},
						"metadata":         map[string]string{},
						"key_name":         nil,
						"accessIPv4":       s.AccessIPv4,
					},
				})
				if err != nil {
					log.Printf("Error encoding JSON response: %v", err)
					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				}
				return
			}

			// DELETE server
			if len(p) == 4 && r.Method == http.MethodDelete {
				srvID := p[3]
				mu.Lock()
				defer mu.Unlock()
				_, ok := servers[srvID]
				if !ok {
					http.NotFound(w, r)
					return
				}
				log.Printf("Deleting server %s", srvID)
				for volID, vol := range volumes {
					newAttachments := []map[string]interface{}{}
					detachedAny := false
					for _, attachment := range vol.Attachments {
						if attachment["server_id"] == srvID {
							detachedAny = true
							log.Printf("Auto-detaching volume %s from server %s", volID, srvID)
							continue
						}
						newAttachments = append(newAttachments, attachment)
					}
					if detachedAny {
						vol.Attachments = newAttachments
						if len(vol.Attachments) == 0 {
							vol.Status = "available"
							log.Printf("Volume %s set to available (server deleted)", volID)
						}
					}
				}
				for _, port := range ports {
					if port["device_id"] == srvID {
						log.Printf("Auto-detaching port %s from server %s", port["id"], srvID)
						port["device_id"] = nil
						port["device_owner"] = nil
						port["status"] = "DOWN"
					}
				}
				delete(servers, srvID)
				log.Printf("Server %s deleted", srvID)
				w.WriteHeader(http.StatusNoContent)
				return
			}

			// GET servers list
			if len(p) == 3 && r.Method == http.MethodGet {
				projectFilter := ProjectIDFromToken(r)
				if projectFilter == "" {
					projectFilter = p[1]
				}
				nameFilter := r.URL.Query().Get("name")
				statusFilter := r.URL.Query().Get("status")
				mu.Lock()
				list := []interface{}{}
				for _, s := range servers {
					if projectFilter != "" && s.Project != projectFilter {
						continue
					}
					if nameFilter != "" && s.Name != nameFilter {
						continue
					}
					if statusFilter != "" && s.Status != statusFilter {
						continue
					}
					list = append(list, map[string]interface{}{
						"id":               s.ID,
						"name":             s.Name,
						"status":           s.Status,
						"flavor":           s.Flavor,
						"image":            s.Image,
						"addresses":        BuildAddresses(s.Networks),
						"project_id":       s.Project,
						"security_groups":  []interface{}{},
						"metadata":         map[string]string{},
						"key_name":         nil,
						"accessIPv4":       s.AccessIPv4,
					})
				}
				mu.Unlock()
				w.Header().Set("Content-Type", "application/json")
				err := json.NewEncoder(w).Encode(map[string]interface{}{"servers": list})
				if err != nil {
					log.Printf("Error encoding JSON response: %v", err)
					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				}
				return
			}

			// POST create server
			if r.Method == http.MethodPost {
				var req struct {
					Server struct {
						Name       string              `json:"name"`
						Flavor     string              `json:"flavor"`
						FlavorRef  string              `json:"flavorRef"`
						Image      string              `json:"image"`
						ImageRef   string              `json:"imageRef"`
						Networks   []map[string]string `json:"networks"`
						AccessIPv4 string              `json:"accessIPv4"`
					} `json:"server"`
				}
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					http.Error(w, "invalid JSON body", http.StatusBadRequest)
					return
				}
				flavorParam := req.Server.Flavor
				if flavorParam == "" {
					flavorParam = req.Server.FlavorRef
				}
				imageParam := req.Server.Image
				if imageParam == "" {
					imageParam = req.Server.ImageRef
				}
				flavorRef := flavorParam
				if flavorRef != "" {
					for _, f := range flavors {
						if fID, ok := f["id"].(string); ok && fID == flavorRef {
							break
						}
						if fName, ok := f["name"].(string); ok && fName == flavorRef {
							if fID, ok := f["id"].(string); ok {
								flavorRef = fID
							}
							break
						}
					}
				}
				imageRef := imageParam
				if imageRef != "" {
					projectID := ProjectIDFromToken(r)
					var matchedImage map[string]interface{}
					for _, img := range images {
						if imgID, ok := img["id"].(string); ok && imgID == imageRef {
							matchedImage = img
							break
						}
					}
					if matchedImage == nil {
						for _, img := range images {
							if imgName, ok := img["name"].(string); ok && imgName == imageRef {
								owner, _ := img["owner"].(string)
								visibility, _ := img["visibility"].(string)
								if owner == projectID || visibility == "public" {
									if matchedImage == nil || owner == projectID {
										matchedImage = img
									}
								}
							}
						}
					}
					if matchedImage != nil {
						if imgID, ok := matchedImage["id"].(string); ok {
							imageRef = imgID
						}
					}
				}
				id := fmt.Sprintf("%d", serverID)
				serverID++
				projectID := ProjectIDFromToken(r)
				if projectID == "" {
					projectID = p[1]
				}
				s := &Server{
					ID:         id,
					Name:       req.Server.Name,
					Status:     "BUILD",
					Flavor:     map[string]string{"id": flavorRef},
					Image:      map[string]string{"id": imageRef},
					Networks:   req.Server.Networks,
					Project:    projectID,
					AccessIPv4: req.Server.AccessIPv4,
				}
				mu.Lock()
				servers[id] = s
				mu.Unlock()
				go func(srvID string) {
					time.Sleep(5 * time.Second)
					mu.Lock()
					defer mu.Unlock()
					if srv, ok := servers[srvID]; ok {
						srv.Status = "ACTIVE"
						log.Printf("Server %s transitioned to ACTIVE", srvID)
					}
				}(id)
				mu.Lock()
				for _, net := range req.Server.Networks {
					portID := ""
					if v, ok := net["port"]; ok {
						portID = v
					} else if v, ok := net["port_id"]; ok {
						portID = v
					}
					if portID == "" {
						continue
					}
					for _, port := range ports {
						if port["id"] == portID {
							port["device_id"] = id
							port["device_owner"] = "compute:nova"
							port["status"] = "ACTIVE"
							if _, ok := port["admin_state_up"]; !ok {
								port["admin_state_up"] = true
							}
						}
					}
				}
				mu.Unlock()
				w.WriteHeader(http.StatusAccepted)
				err := json.NewEncoder(w).Encode(map[string]interface{}{"server": s})
				if err != nil {
					log.Printf("Error encoding JSON response: %v", err)
					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				}
				return
			}

		case "images":
			if strings.HasSuffix(r.URL.Path, "/detail") {
				projectID := ProjectIDFromToken(r)
				list := []interface{}{}
				for _, img := range images {
					visibility, _ := img["visibility"].(string)
					owner, _ := img["owner"].(string)
					if visibility == "public" || owner == projectID {
						list = append(list, img)
					}
				}
				w.Header().Set("Content-Type", "application/json")
				err := json.NewEncoder(w).Encode(map[string]interface{}{"images": list})
				if err != nil {
					log.Printf("Error encoding JSON response: %v", err)
					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				}
				return
			}
			projectID := ProjectIDFromToken(r)
			list := []interface{}{}
			for _, img := range images {
				visibility, _ := img["visibility"].(string)
				owner, _ := img["owner"].(string)
				if visibility != "public" && owner != projectID {
					continue
				}
				list = append(list, map[string]interface{}{
					"id":   img["id"],
					"name": img["name"],
				})
			}
			w.Header().Set("Content-Type", "application/json")
			err := json.NewEncoder(w).Encode(map[string]interface{}{"images": list})
			if err != nil {
				log.Printf("Error encoding JSON response: %v", err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
			return

		case "os-keypairs":
			w.Header().Set("Content-Type", "application/json")
			mu.Lock()
			defer mu.Unlock()

			// /v2.1/{proj}/os-keypairs/{name}
			if len(p) >= 4 {
				name := p[3]
				for i, kp := range keypairs {
					if kp["name"] == name {
						switch r.Method {
						case http.MethodGet:
							writeJSON(w, map[string]interface{}{"keypair": kp})
						case http.MethodDelete:
							keypairs = append(keypairs[:i], keypairs[i+1:]...)
							w.WriteHeader(http.StatusAccepted)
						default:
							http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
						}
						return
					}
				}
				http.NotFound(w, r)
				return
			}

			if r.Method == http.MethodGet {
				list := []interface{}{}
				for _, kp := range keypairs {
					list = append(list, map[string]interface{}{"keypair": kp})
				}
				writeJSON(w, map[string]interface{}{"keypairs": list})
				return
			}
			if r.Method == http.MethodPost {
				var req struct {
					Keypair map[string]interface{} `json:"keypair"`
				}
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					http.Error(w, "invalid JSON body", http.StatusBadRequest)
					return
				}
				kp := req.Keypair
				enrichKeypair(kp, ProjectIDFromToken(r))
				keypairs = append(keypairs, kp)
				w.WriteHeader(http.StatusCreated)
				writeJSON(w, map[string]interface{}{"keypair": kp})
				return
			}
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		http.NotFound(w, r)
	})

	mux.HandleFunc("/v2.1/flavors/", func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/os-extra_specs") {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(map[string]interface{}{
			"extra_specs": map[string]string{},
		})
		if err != nil {
			log.Printf("Error encoding JSON response: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
	})
}
