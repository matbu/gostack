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
	"net/http"
	"strings"
)

// imageData holds uploaded image blobs keyed by image id.
var imageData = map[string][]byte{}

// RegisterGlanceHandlers registers Glance (image) API handlers on mux.
func RegisterGlanceHandlers(mux *http.ServeMux) {
	mux.HandleFunc("/v2/images", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			projectID := ProjectIDFromToken(r)
			projectImages := []map[string]interface{}{}
			publicImages := []map[string]interface{}{}
			otherImages := []map[string]interface{}{}
			mu.Lock()
			for _, img := range images {
				enrichImage(img, projectID)
				visibility, _ := img["visibility"].(string)
				owner, _ := img["owner"].(string)
				switch {
				case owner == projectID:
					projectImages = append(projectImages, img)
				case visibility == "public" || visibility == "community":
					publicImages = append(publicImages, img)
				case adminScope:
					// With admin scope another project's private images
					// are visible too, as they are to an admin.
					otherImages = append(otherImages, img)
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
			// A public image is hidden by one of the project's own with the
			// same name, which is what a name lookup should resolve to.
			for _, img := range publicImages {
				name, _ := img["name"].(string)
				if !seenNames[name] {
					seenNames[name] = true
					visible = append(visible, img)
				}
			}
			visible = append(visible, otherImages...)
			q := r.URL.Query()
			visible = ApplyLimit(FilterList(visible, q), q)
			// Glance's list envelope carries the schema and paging links.
			writeJSON(w, map[string]interface{}{
				"images": visible,
				"schema": "/v2/schemas/images",
				"first":  "/v2/images",
			})
			return
		}

		if r.Method == http.MethodPost {
			var img map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&img); err != nil {
				badRequest(w, Glance, "Invalid request body: "+err.Error())
				return
			}
			img["id"] = RandomID("img")
			mu.Lock()
			enrichImage(img, ProjectIDFromToken(r))
			images = append(images, img)
			mu.Unlock()
			w.Header().Set("Location", baseURL+"/v2/images/"+stringOf(img["id"]))
			writeJSONStatus(w, http.StatusCreated, img)
			return
		}

		methodNotAllowed(w, Glance, r.Method)
	})

	mux.HandleFunc("/v2/images/", func(w http.ResponseWriter, r *http.Request) {
		parts := Parts(r.URL.Path) // ["v2","images","{id}", maybe "file"]
		if len(parts) < 3 || parts[2] == "" {
			notFound(w, Glance, "Image")
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
			notFound(w, Glance, "Image "+id)
			return
		}
		img := images[idx]

		// /v2/images/{id}/import : the interoperable image import, which
		// fetches the data itself instead of taking an upload.
		if len(parts) == 4 && parts[3] == "import" {
			if r.Method != http.MethodPost {
				methodNotAllowed(w, Glance, r.Method)
				return
			}
			var req struct {
				Method struct {
					Name string `json:"name"`
					URI  string `json:"uri"`
				} `json:"method"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				badRequest(w, Glance, "Invalid request body: "+err.Error())
				return
			}
			img["status"] = "active"
			img["updated_at"] = nowRFC3339()
			// The service fetched the data itself, so the image now has a
			// size and checksum even though nothing was uploaded here.
			if img["size"] == nil || img["size"] == 0 {
				img["size"] = 13287936
			}
			if img["checksum"] == nil {
				img["checksum"] = "443b7623e27ecf03dc9e01ee93f67afe"
			}
			images[idx] = img
			w.WriteHeader(http.StatusAccepted)
			return
		}

		// /v2/images/{id}/actions/{action} : deactivate and reactivate.
		if len(parts) == 5 && parts[3] == "actions" {
			if r.Method != http.MethodPost {
				methodNotAllowed(w, Glance, r.Method)
				return
			}
			switch parts[4] {
			case "deactivate":
				img["status"] = "deactivated"
			case "reactivate":
				img["status"] = "active"
			default:
				notFound(w, Glance, "Action "+parts[4])
				return
			}
			img["updated_at"] = nowRFC3339()
			images[idx] = img
			w.WriteHeader(http.StatusNoContent)
			return
		}

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
				methodNotAllowed(w, Glance, r.Method)
			}
			return
		}

		enrichImage(img, projectID)
		switch r.Method {
		case http.MethodGet:
			// With admin scope any image is readable, whoever owns it.
			visibility, _ := img["visibility"].(string)
			owner, _ := img["owner"].(string)
			if adminScope || visibility == "public" ||
				visibility == "community" || owner == projectID {
				writeJSON(w, img)
				return
			}
			notFound(w, Glance, "Image "+id)
		case http.MethodPatch:
			// application/openstack-images-v2.1-json-patch : array of ops.
			var ops []map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&ops); err != nil {
				badRequest(w, Glance, "Invalid request body: "+err.Error())
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
			methodNotAllowed(w, Glance, r.Method)
		}
	})

	registerGlanceSchemas(mux)
}

// enrichImage fills the field set Glance returns for an image, so the image
// module sees every attribute it compares. Idempotent.
func enrichImage(img map[string]interface{}, projectID string) {
	now := nowRFC3339()
	id := stringOf(img["id"])
	setDefault(img, "name", nil)
	setDefault(img, "owner", projectID)
	setDefault(img, "visibility", "private")
	setDefault(img, "status", "queued")
	setDefault(img, "created_at", now)
	setDefault(img, "updated_at", now)
	setDefault(img, "protected", false)
	setDefault(img, "os_hidden", false)
	setDefault(img, "min_disk", 0)
	setDefault(img, "min_ram", 0)
	setDefault(img, "size", nil)
	setDefault(img, "checksum", nil)
	setDefault(img, "os_hash_algo", nil)
	setDefault(img, "os_hash_value", nil)
	setDefault(img, "virtual_size", nil)
	setDefault(img, "disk_format", nil)
	setDefault(img, "container_format", nil)
	setDefault(img, "tags", []interface{}{})
	setDefault(img, "members", []interface{}{})
	setDefault(img, "file", "/v2/images/"+id+"/file")
	setDefault(img, "schema", "/v2/schemas/image")
	setDefault(img, "self", "/v2/images/"+id)
}

// imageSchema is the property schema Glance publishes for an image. Clients
// read it to learn which attributes are writable.
func imageSchema() map[string]interface{} {
	prop := func(t, desc string) map[string]interface{} {
		return map[string]interface{}{"type": t, "description": desc}
	}
	return map[string]interface{}{
		"name":                 "image",
		"additionalProperties": map[string]interface{}{"type": "string"},
		"properties": map[string]interface{}{
			"id":               prop("string", "An identifier for the image"),
			"name":             prop("string", "Descriptive name for the image"),
			"status":           prop("string", "Status of the image"),
			"visibility":       prop("string", "Scope of image accessibility"),
			"protected":        prop("boolean", "If true, image will not be deletable"),
			"os_hidden":        prop("boolean", "If true, image will not appear in default listing"),
			"checksum":         prop("string", "md5 hash of image contents"),
			"owner":            prop("string", "Owner of the image"),
			"size":             prop("integer", "Size of image file in bytes"),
			"virtual_size":     prop("integer", "Virtual size of image in bytes"),
			"container_format": prop("string", "Format of the container"),
			"disk_format":      prop("string", "Format of the disk"),
			"created_at":       prop("string", "Date and time of image registration"),
			"updated_at":       prop("string", "Date and time of the last image modification"),
			"tags":             map[string]interface{}{"type": "array", "description": "List of strings related to the image"},
			"min_ram":          prop("integer", "Amount of ram (in MB) required to boot image"),
			"min_disk":         prop("integer", "Amount of disk space (in GB) required to boot image"),
			"self":             prop("string", "An image self link"),
			"file":             prop("string", "An image file url"),
			"schema":           prop("string", "An image schema url"),
		},
	}
}

// registerGlanceSchemas serves the schema documents clients fetch before
// they build an image request.
func registerGlanceSchemas(mux *http.ServeMux) {
	mux.HandleFunc("/v2/schemas/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			methodNotAllowed(w, Glance, r.Method)
			return
		}
		switch segmentAt(r, 2) {
		case "image":
			writeJSON(w, imageSchema())
		case "images":
			writeJSON(w, map[string]interface{}{
				"name":  "images",
				"links": []map[string]string{{"rel": "first", "href": "/v2/images"}},
				"properties": map[string]interface{}{
					"images": map[string]interface{}{
						"type":  "array",
						"items": imageSchema(),
					},
					"schema": map[string]interface{}{"type": "string"},
					"first":  map[string]interface{}{"type": "string"},
					"next":   map[string]interface{}{"type": "string"},
				},
			})
		case "member":
			writeJSON(w, map[string]interface{}{
				"name": "member",
				"properties": map[string]interface{}{
					"image_id":   map[string]interface{}{"type": "string"},
					"member_id":  map[string]interface{}{"type": "string"},
					"status":     map[string]interface{}{"type": "string"},
					"created_at": map[string]interface{}{"type": "string"},
					"updated_at": map[string]interface{}{"type": "string"},
					"schema":     map[string]interface{}{"type": "string"},
				},
			})
		case "members":
			writeJSON(w, map[string]interface{}{
				"name": "members",
				"properties": map[string]interface{}{
					"members": map[string]interface{}{"type": "array"},
					"schema":  map[string]interface{}{"type": "string"},
				},
			})
		default:
			notFound(w, Glance, "Schema")
		}
	})
}
