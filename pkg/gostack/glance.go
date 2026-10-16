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
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

// imageData holds uploaded image blobs keyed by image id.
var imageData = map[string][]byte{}

// RegisterGlanceHandlers registers Glance (image) API handlers on mux.
func RegisterGlanceHandlers(mux *http.ServeMux) {
	mux.HandleFunc("/v2/images", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			projectID := ProjectIDFromToken(r)
			nameFilter := r.URL.Query().Get("name")
			ownerFilter := r.URL.Query().Get("owner")
			projectImages := []map[string]interface{}{}
			publicImages := []map[string]interface{}{}
			mu.Lock()
			for _, img := range images {
				visibility, _ := img["visibility"].(string)
				owner, _ := img["owner"].(string)
				if nameFilter != "" {
					if n, ok := img["name"].(string); !ok || n != nameFilter {
						continue
					}
				}
				if ownerFilter != "" && owner != ownerFilter {
					continue
				}
				if owner == projectID {
					projectImages = append(projectImages, img)
				} else if visibility == "public" {
					publicImages = append(publicImages, img)
				}
			}
			mu.Unlock()
			visible := []map[string]interface{}{}
			seenNames := make(map[string]bool)
			for _, img := range projectImages {
				name, _ := img["name"].(string)
				seenNames[name] = true
				visible = append(visible, img)
			}
			for _, img := range publicImages {
				name, _ := img["name"].(string)
				if !seenNames[name] {
					visible = append(visible, img)
				}
			}
			err := json.NewEncoder(w).Encode(map[string]interface{}{"images": visible})
			if err != nil {
				log.Printf("Error encoding JSON response: %v", err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
			return
		}

		if r.Method == http.MethodPost {
			var img map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&img); err != nil {
				http.Error(w, "invalid JSON body", http.StatusBadRequest)
				return
			}
			img["id"] = fmt.Sprintf("img-%d", len(images)+1)
			if _, ok := img["owner"]; !ok {
				img["owner"] = ProjectIDFromToken(r)
			}
			if _, ok := img["visibility"]; !ok {
				img["visibility"] = "private"
			}
			now := time.Now().UTC().Format(time.RFC3339)
			setDefault(img, "status", "queued")
			setDefault(img, "created_at", now)
			setDefault(img, "updated_at", now)
			setDefault(img, "protected", false)
			setDefault(img, "min_disk", 0)
			setDefault(img, "min_ram", 0)
			setDefault(img, "size", nil)
			setDefault(img, "checksum", nil)
			setDefault(img, "virtual_size", nil)
			setDefault(img, "tags", []interface{}{})
			setDefault(img, "file", "/v2/images/"+img["id"].(string)+"/file")
			mu.Lock()
			images = append(images, img)
			mu.Unlock()
			w.WriteHeader(http.StatusCreated)
			err := json.NewEncoder(w).Encode(img)
			if err != nil {
				log.Printf("Error encoding JSON response: %v", err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
			return
		}

		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	})

	mux.HandleFunc("/v2/images/", func(w http.ResponseWriter, r *http.Request) {
		parts := Parts(r.URL.Path) // ["v2","images","{id}", maybe "file"]
		if len(parts) < 3 {
			http.NotFound(w, r)
			return
		}
		id := parts[2]
		projectID := ProjectIDFromToken(r)

		mu.Lock()
		defer mu.Unlock()
		idx := -1
		for i, img := range images {
			if imgID, ok := img["id"].(string); ok && imgID == id {
				idx = i
				break
			}
		}
		if idx == -1 {
			http.NotFound(w, r)
			return
		}
		img := images[idx]

		// /v2/images/{id}/file : binary upload / download.
		if len(parts) == 4 && parts[3] == "file" {
			switch r.Method {
			case http.MethodPut:
				data, _ := io.ReadAll(r.Body)
				imageData[id] = data
				img["size"] = len(data)
				img["checksum"] = fmt.Sprintf("%x", md5.Sum(data))
				img["status"] = "active"
				w.WriteHeader(http.StatusNoContent)
			case http.MethodGet:
				w.Header().Set("Content-Type", "application/octet-stream")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(imageData[id])
			default:
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			}
			return
		}

		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			visibility, _ := img["visibility"].(string)
			owner, _ := img["owner"].(string)
			if visibility == "public" || owner == projectID {
				writeJSON(w, img)
				return
			}
			http.NotFound(w, r)
		case http.MethodPatch:
			// application/openstack-images-v2.1-json-patch : array of ops.
			var ops []map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&ops); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			for _, op := range ops {
				path, _ := op["path"].(string)
				key := strings.TrimPrefix(path, "/")
				switch op["op"] {
				case "add", "replace":
					img[key] = op["value"]
				case "remove":
					delete(img, key)
				}
			}
			images[idx] = img
			writeJSON(w, img)
		case http.MethodDelete:
			delete(imageData, id)
			images = append(images[:idx], images[idx+1:]...)
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})
}
