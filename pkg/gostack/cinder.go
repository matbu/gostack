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
	"strings"
	"time"
)

// cinderPrefix is the path the catalog advertises for block storage. Cinder
// used to share /v3 with Keystone here, which meant every Keystone resource
// gostack had not registered fell through to the volume handler. Giving the
// service its own prefix keeps the two namespaces apart, the way separate
// endpoints do in a real deployment.
const cinderPrefix = "/volume/v3/"

// cinderResources are the collection names Cinder owns under
// /{version}/{project}/. Used to tell a legacy /v3/... volume request apart
// from a Keystone one.
var cinderResources = map[string]bool{
	"volumes":            true,
	"types":              true,
	"snapshots":          true,
	"backups":            true,
	"attachments":        true,
	"os-quota-sets":      true,
	"os-services":        true,
	"limits":             true,
	"os-volume-transfer": true,
	"qos-specs":          true,
	"group_types":        true,
	"groups":             true,
	"manageable_volumes": true,
}

// RegisterCinderHandlers registers Cinder (volume) API handlers on mux.
func RegisterCinderHandlers(mux *http.ServeMux) {
	// The service's own namespace, which the catalog points at.
	mux.HandleFunc(cinderPrefix, func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.String())
		// Parts: ["volume","v3",{project},...] -> drop the two prefix segments.
		serveCinder(w, r, Parts(r.URL.Path)[2:])
	})

	// Legacy namespace, shared with Keystone. Only paths that name a Cinder
	// collection are volume requests; anything else is a Keystone resource
	// gostack does not implement and must 404 as one.
	mux.HandleFunc("/v3/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.String())
		p := Parts(r.URL.Path) // ["v3",{project},{resource},...]
		if len(p) >= 3 && cinderResources[p[2]] {
			serveCinder(w, r, p[1:])
			return
		}
		notFound(w, Keystone, "The resource")
	})
}

// serveCinder dispatches a block-storage request. p is the path split from
// the project segment onwards: p[0] is the project id, p[1] the collection.
func serveCinder(w http.ResponseWriter, r *http.Request, p []string) {
	if len(p) < 2 {
		// GET /{prefix}/{project} — version discovery.
		writeJSON(w, map[string]interface{}{
			"version": map[string]interface{}{
				"id": "v3.0", "status": "CURRENT",
				"min_version": "3.0", "version": maxVolumeMicroversion,
				"updated": "2023-01-01T00:00:00Z",
				"links": []map[string]string{
					{"rel": "self", "href": baseURL + cinderPrefix},
				},
			},
		})
		return
	}
	projectID := ProjectIDFromToken(r)
	rest := p[2:]

	switch p[1] {
	case "volumes":
		serveVolumes(w, r, rest, projectID)
	case "types":
		serveVolumeTypes(w, r, rest)
	case "snapshots":
		serveSnapshots(w, r, rest, projectID)
	case "backups":
		serveBackups(w, r, rest, projectID)
	case "os-quota-sets":
		serveQuotaSet(w, r, rest, cinderQuotas, cinderQuotaDefaults, Cinder)
	case "os-services":
		serveVolumeServices(w, r)
	case "limits":
		serveVolumeLimits(w, r)
	default:
		notFound(w, Cinder, "Resource "+p[1])
	}
}

/* ============================
   Volumes
============================ */

// serveVolumes handles /volumes, /volumes/detail, /volumes/{id} and the
// action, metadata and image-metadata sub-resources.
func serveVolumes(w http.ResponseWriter, r *http.Request, p []string, projectID string) {
	// /volumes and /volumes/detail
	if len(p) == 0 || (len(p) == 1 && p[0] == "detail") {
		detail := len(p) == 1
		switch r.Method {
		case http.MethodGet:
			mu.Lock()
			list := AsList(volumes, func(v *Volume) map[string]interface{} { return v.toMap() })
			mu.Unlock()
			list = FilterList(list, r.URL.Query(), "metadata")
			list = filterByMetadataQuery(list, r)
			list = ApplyLimit(list, r.URL.Query())
			if !detail && strictResponses {
				list = briefVolumes(list)
			}
			writeJSON(w, map[string]interface{}{"volumes": list})
		case http.MethodPost:
			createVolume(w, r, projectID)
		default:
			methodNotAllowed(w, Cinder, r.Method)
		}
		return
	}

	volID := p[0]
	mu.Lock()
	vol, ok := volumes[volID]
	mu.Unlock()
	if !ok {
		notFound(w, Cinder, "Volume "+volID)
		return
	}

	// /volumes/{id}/action
	if len(p) == 2 && p[1] == "action" {
		volumeAction(w, r, vol)
		return
	}
	// /volumes/{id}/metadata
	if len(p) >= 2 && p[1] == "metadata" {
		volumeMetadata(w, r, vol, p[2:])
		return
	}

	switch r.Method {
	case http.MethodGet:
		mu.Lock()
		body := vol.toMap()
		mu.Unlock()
		writeJSON(w, map[string]interface{}{"volume": body})
	case http.MethodPut:
		var req struct {
			Volume map[string]interface{} `json:"volume"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			badRequest(w, Cinder, "Invalid request body: "+err.Error())
			return
		}
		mu.Lock()
		if v, ok := req.Volume["name"].(string); ok {
			vol.Name = v
		}
		if v, ok := req.Volume["description"].(string); ok {
			vol.Description = v
		}
		if v, ok := req.Volume["metadata"].(map[string]interface{}); ok {
			vol.Metadata = toStringMap(v)
		}
		vol.UpdatedAt = nowRFC3339()
		body := vol.toMap()
		mu.Unlock()
		writeJSON(w, map[string]interface{}{"volume": body})
	case http.MethodDelete:
		mu.Lock()
		attached := len(vol.Attachments) > 0
		status := vol.Status
		mu.Unlock()
		if attached {
			badRequest(w, Cinder, "Volume "+volID+" is still attached, detach volume first.")
			return
		}
		if status != "available" && status != "error" {
			badRequest(w, Cinder,
				"Invalid volume: Volume status must be available or error, but current status is: "+status)
			return
		}
		mu.Lock()
		delete(volumes, volID)
		mu.Unlock()
		log.Printf("Deleted volume %s", volID)
		w.WriteHeader(deleteStatus())
	default:
		methodNotAllowed(w, Cinder, r.Method)
	}
}

// createVolume handles POST /volumes.
func createVolume(w http.ResponseWriter, r *http.Request, projectID string) {
	var req struct {
		Volume struct {
			Name        string            `json:"name"`
			Size        int               `json:"size"`
			Metadata    map[string]string `json:"metadata"`
			Description string            `json:"description"`
			VolumeType  string            `json:"volume_type"`
			AvailZone   string            `json:"availability_zone"`
			SnapshotID  string            `json:"snapshot_id"`
			SourceVolID string            `json:"source_volid"`
			ImageRef    string            `json:"imageRef"`
			Multiattach bool              `json:"multiattach"`
		} `json:"volume"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		badRequest(w, Cinder, "Invalid request body: "+err.Error())
		return
	}

	mu.Lock()
	id := fmt.Sprintf("%d", volumeID)
	volumeID++
	now := nowRFC3339()

	size := req.Volume.Size
	// Cloning a volume or restoring a snapshot inherits the source size.
	if src, ok := volumes[req.Volume.SourceVolID]; ok && size == 0 {
		size = src.Size
	}
	if snap, ok := snapshots[req.Volume.SnapshotID]; ok && size == 0 {
		size = snap.Size
	}

	v := &Volume{
		ID: id, Name: req.Volume.Name, Size: size, Status: "creating",
		Attachments: []map[string]interface{}{}, Metadata: req.Volume.Metadata,
		Description: req.Volume.Description, VolumeType: req.Volume.VolumeType,
		AvailZone: req.Volume.AvailZone, SnapshotID: req.Volume.SnapshotID,
		SourceVolID: req.Volume.SourceVolID, ImageID: req.Volume.ImageRef,
		Multiattach: req.Volume.Multiattach, ProjectID: projectID,
		CreatedAt: now, UpdatedAt: now,
	}
	if v.Metadata == nil {
		v.Metadata = map[string]string{}
	}
	// A volume built from an image is bootable and carries the image's
	// metadata, which is what the volume_image_metadata module reads.
	if req.Volume.ImageRef != "" {
		v.Bootable = true
		v.ImageMeta = imageMetadataFor(req.Volume.ImageRef)
	}
	if src, ok := volumes[req.Volume.SourceVolID]; ok {
		v.Bootable = src.Bootable
		v.ImageMeta = src.ImageMeta
	}
	volumes[id] = v
	body := v.toMap()
	mu.Unlock()

	go func(volID string) {
		time.Sleep(volumeBuildDelay)
		mu.Lock()
		defer mu.Unlock()
		if vol, ok := volumes[volID]; ok {
			vol.Status = "available"
			log.Printf("Volume %s transitioned to available", volID)
		}
	}(id)

	writeJSONStatus(w, http.StatusAccepted, map[string]interface{}{"volume": body})
}

// volumeAction handles POST /volumes/{id}/action.
func volumeAction(w http.ResponseWriter, r *http.Request, vol *Volume) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, Cinder, r.Method)
		return
	}
	var body map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		badRequest(w, Cinder, "Invalid request body: "+err.Error())
		return
	}
	mu.Lock()
	defer mu.Unlock()
	if vol.Metadata == nil {
		vol.Metadata = map[string]string{}
	}

	for action, raw := range body {
		args, _ := raw.(map[string]interface{})
		switch action {
		case "os-set_bootable":
			if b, ok := args["bootable"]; ok {
				vol.Bootable = truthy(b)
				// Kept in metadata too: os-migrate reads it from there.
				vol.Metadata["bootable"] = fmt.Sprintf("%t", vol.Bootable)
			}
			w.WriteHeader(http.StatusOK)
			return
		case "os-set_image_metadata":
			if meta, ok := args["metadata"].(map[string]interface{}); ok {
				if vol.ImageMeta == nil {
					vol.ImageMeta = map[string]string{}
				}
				for k, v := range toStringMap(meta) {
					vol.ImageMeta[k] = v
					vol.Metadata[k] = v
				}
			}
			w.WriteHeader(http.StatusOK)
			return
		case "os-unset_image_metadata":
			if key, ok := args["key"].(string); ok {
				delete(vol.ImageMeta, key)
				delete(vol.Metadata, key)
			}
			w.WriteHeader(http.StatusOK)
			return
		case "os-show_image_metadata":
			meta := vol.ImageMeta
			if meta == nil {
				meta = map[string]string{}
			}
			writeJSON(w, map[string]interface{}{"metadata": meta})
			return
		case "os-extend":
			if size, ok := args["new_size"]; ok {
				if n, ok := normalizeScalar(size); ok {
					vol.Size = atoiSafe(n)
				}
			}
			w.WriteHeader(http.StatusAccepted)
			return
		case "os-retype":
			if vt, ok := args["new_type"].(string); ok {
				vol.VolumeType = vt
			}
			w.WriteHeader(http.StatusAccepted)
			return
		case "os-reset_status":
			if s, ok := args["status"].(string); ok {
				vol.Status = s
			}
			w.WriteHeader(http.StatusAccepted)
			return
		case "revert":
			w.WriteHeader(http.StatusAccepted)
			return
		}
	}
	badRequest(w, Cinder, "Unsupported volume action")
}

// volumeMetadata handles the /volumes/{id}/metadata sub-resource.
func volumeMetadata(w http.ResponseWriter, r *http.Request, vol *Volume, p []string) {
	mu.Lock()
	defer mu.Unlock()
	if vol.Metadata == nil {
		vol.Metadata = map[string]string{}
	}

	// /metadata/{key}
	if len(p) == 1 {
		key := p[0]
		switch r.Method {
		case http.MethodGet:
			val, ok := vol.Metadata[key]
			if !ok {
				notFound(w, Cinder, "Metadata item "+key)
				return
			}
			writeJSON(w, map[string]interface{}{"meta": map[string]string{key: val}})
		case http.MethodPut:
			var req struct {
				Meta map[string]string `json:"meta"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				badRequest(w, Cinder, "Invalid request body: "+err.Error())
				return
			}
			for k, v := range req.Meta {
				vol.Metadata[k] = v
			}
			writeJSON(w, map[string]interface{}{"meta": req.Meta})
		case http.MethodDelete:
			delete(vol.Metadata, key)
			w.WriteHeader(http.StatusOK)
		default:
			methodNotAllowed(w, Cinder, r.Method)
		}
		return
	}

	switch r.Method {
	case http.MethodGet:
		writeJSON(w, map[string]interface{}{"metadata": vol.Metadata})
	case http.MethodPost, http.MethodPut:
		var req struct {
			Metadata map[string]string `json:"metadata"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			badRequest(w, Cinder, "Invalid request body: "+err.Error())
			return
		}
		if r.Method == http.MethodPut {
			vol.Metadata = map[string]string{}
		}
		for k, v := range req.Metadata {
			vol.Metadata[k] = v
		}
		writeJSON(w, map[string]interface{}{"metadata": vol.Metadata})
	default:
		methodNotAllowed(w, Cinder, r.Method)
	}
}

/* ============================
   Volume types
============================ */

// serveVolumeTypes handles /types, /types/{id} and the access sub-resources.
func serveVolumeTypes(w http.ResponseWriter, r *http.Request, p []string) {
	if len(p) == 0 {
		switch r.Method {
		case http.MethodGet:
			mu.Lock()
			list := AsList(volumeTypes, func(t *VolumeType) map[string]interface{} { return t.toMap() })
			mu.Unlock()
			writeJSON(w, map[string]interface{}{
				"volume_types": FilterList(list, r.URL.Query(), "extra_specs"),
			})
		case http.MethodPost:
			var req struct {
				VolumeType struct {
					Name        string            `json:"name"`
					Description string            `json:"description"`
					IsPublic    *bool             `json:"os-volume-type-access:is_public"`
					Public      *bool             `json:"is_public"`
					ExtraSpecs  map[string]string `json:"extra_specs"`
				} `json:"volume_type"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				badRequest(w, Cinder, "Invalid request body: "+err.Error())
				return
			}
			if req.VolumeType.Name == "" {
				badRequest(w, Cinder, "Volume type name can not be empty.")
				return
			}
			isPublic := true
			if req.VolumeType.IsPublic != nil {
				isPublic = *req.VolumeType.IsPublic
			} else if req.VolumeType.Public != nil {
				isPublic = *req.VolumeType.Public
			}
			t := &VolumeType{
				ID: RandomID("voltype"), Name: req.VolumeType.Name,
				Description: req.VolumeType.Description, IsPublic: isPublic,
				ExtraSpecs: req.VolumeType.ExtraSpecs,
			}
			if t.ExtraSpecs == nil {
				t.ExtraSpecs = map[string]string{}
			}
			mu.Lock()
			volumeTypes[t.ID] = t
			body := t.toMap()
			mu.Unlock()
			writeJSONStatus(w, http.StatusOK, map[string]interface{}{"volume_type": body})
		default:
			methodNotAllowed(w, Cinder, r.Method)
		}
		return
	}

	typeID := p[0]
	mu.Lock()
	t, ok := volumeTypes[typeID]
	mu.Unlock()
	if !ok {
		notFound(w, Cinder, "Volume type "+typeID)
		return
	}

	// /types/{id}/extra_specs
	if len(p) >= 2 && p[1] == "extra_specs" {
		volumeTypeExtraSpecs(w, r, t, p[2:])
		return
	}
	// /types/{id}/os-volume-type-access and the action endpoint
	if len(p) == 2 && p[1] == "os-volume-type-access" {
		mu.Lock()
		list := []map[string]interface{}{}
		for _, proj := range volumeTypeAccess[typeID] {
			list = append(list, map[string]interface{}{
				"volume_type_id": typeID, "project_id": proj,
			})
		}
		mu.Unlock()
		writeJSON(w, map[string]interface{}{"volume_type_access": list})
		return
	}
	if len(p) == 2 && p[1] == "action" {
		volumeTypeAccessAction(w, r, typeID)
		return
	}
	// /types/{id}/encryption[/{key}]
	if len(p) >= 2 && p[1] == "encryption" {
		volumeTypeEncryption(w, r, typeID, p[2:])
		return
	}

	switch r.Method {
	case http.MethodGet:
		mu.Lock()
		body := t.toMap()
		mu.Unlock()
		writeJSON(w, map[string]interface{}{"volume_type": body})
	case http.MethodPut:
		var req struct {
			VolumeType struct {
				Name        *string `json:"name"`
				Description *string `json:"description"`
				IsPublic    *bool   `json:"is_public"`
			} `json:"volume_type"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			badRequest(w, Cinder, "Invalid request body: "+err.Error())
			return
		}
		mu.Lock()
		if req.VolumeType.Name != nil {
			t.Name = *req.VolumeType.Name
		}
		if req.VolumeType.Description != nil {
			t.Description = *req.VolumeType.Description
		}
		if req.VolumeType.IsPublic != nil {
			t.IsPublic = *req.VolumeType.IsPublic
		}
		body := t.toMap()
		mu.Unlock()
		writeJSON(w, map[string]interface{}{"volume_type": body})
	case http.MethodDelete:
		mu.Lock()
		delete(volumeTypes, typeID)
		delete(volumeTypeAccess, typeID)
		delete(volumeTypeEncryptions, typeID)
		mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
	default:
		methodNotAllowed(w, Cinder, r.Method)
	}
}

// volumeTypeExtraSpecs handles /types/{id}/extra_specs[/{key}].
func volumeTypeExtraSpecs(w http.ResponseWriter, r *http.Request, t *VolumeType, p []string) {
	mu.Lock()
	defer mu.Unlock()
	if t.ExtraSpecs == nil {
		t.ExtraSpecs = map[string]string{}
	}
	if len(p) == 1 {
		key := p[0]
		switch r.Method {
		case http.MethodGet:
			val, ok := t.ExtraSpecs[key]
			if !ok {
				notFound(w, Cinder, "Extra spec "+key)
				return
			}
			writeJSON(w, map[string]string{key: val})
		case http.MethodPut:
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				badRequest(w, Cinder, "Invalid request body: "+err.Error())
				return
			}
			for k, v := range body {
				t.ExtraSpecs[k] = v
			}
			writeJSON(w, body)
		case http.MethodDelete:
			delete(t.ExtraSpecs, key)
			w.WriteHeader(http.StatusAccepted)
		default:
			methodNotAllowed(w, Cinder, r.Method)
		}
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, map[string]interface{}{"extra_specs": t.ExtraSpecs})
	case http.MethodPost:
		var req struct {
			ExtraSpecs map[string]string `json:"extra_specs"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			badRequest(w, Cinder, "Invalid request body: "+err.Error())
			return
		}
		for k, v := range req.ExtraSpecs {
			t.ExtraSpecs[k] = v
		}
		writeJSON(w, map[string]interface{}{"extra_specs": t.ExtraSpecs})
	default:
		methodNotAllowed(w, Cinder, r.Method)
	}
}

// volumeTypeAccessAction handles the add/remove access actions on a type.
func volumeTypeAccessAction(w http.ResponseWriter, r *http.Request, typeID string) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, Cinder, r.Method)
		return
	}
	var body map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		badRequest(w, Cinder, "Invalid request body: "+err.Error())
		return
	}
	mu.Lock()
	defer mu.Unlock()
	if args, ok := body["addProjectAccess"].(map[string]interface{}); ok {
		proj, _ := args["project"].(string)
		for _, existing := range volumeTypeAccess[typeID] {
			if existing == proj {
				w.WriteHeader(http.StatusAccepted)
				return
			}
		}
		volumeTypeAccess[typeID] = append(volumeTypeAccess[typeID], proj)
		w.WriteHeader(http.StatusAccepted)
		return
	}
	if args, ok := body["removeProjectAccess"].(map[string]interface{}); ok {
		proj, _ := args["project"].(string)
		out := []string{}
		for _, existing := range volumeTypeAccess[typeID] {
			if existing != proj {
				out = append(out, existing)
			}
		}
		volumeTypeAccess[typeID] = out
		w.WriteHeader(http.StatusAccepted)
		return
	}
	badRequest(w, Cinder, "Unsupported volume type action")
}

/* ============================
   Snapshots and backups
============================ */

// serveSnapshots handles /snapshots, /snapshots/detail and /snapshots/{id}.
func serveSnapshots(w http.ResponseWriter, r *http.Request, p []string, projectID string) {
	if len(p) == 0 || (len(p) == 1 && p[0] == "detail") {
		switch r.Method {
		case http.MethodGet:
			mu.Lock()
			list := AsList(snapshots, func(s *Snapshot) map[string]interface{} { return s.toMap() })
			mu.Unlock()
			writeJSON(w, map[string]interface{}{
				"snapshots": ApplyLimit(FilterList(list, r.URL.Query()), r.URL.Query()),
			})
		case http.MethodPost:
			var req struct {
				Snapshot struct {
					Name        string            `json:"name"`
					VolumeID    string            `json:"volume_id"`
					Description string            `json:"description"`
					Force       bool              `json:"force"`
					Metadata    map[string]string `json:"metadata"`
				} `json:"snapshot"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				badRequest(w, Cinder, "Invalid request body: "+err.Error())
				return
			}
			mu.Lock()
			vol, ok := volumes[req.Snapshot.VolumeID]
			if !ok {
				mu.Unlock()
				notFound(w, Cinder, "Volume "+req.Snapshot.VolumeID)
				return
			}
			if len(vol.Attachments) > 0 && !req.Snapshot.Force {
				mu.Unlock()
				badRequest(w, Cinder,
					"Invalid volume: Volume is attached; use force to snapshot it.")
				return
			}
			snapshotSeq++
			id := fmt.Sprintf("snap-%d", snapshotSeq)
			s := &Snapshot{
				ID: id, Name: req.Snapshot.Name, VolumeID: req.Snapshot.VolumeID,
				Status: "creating", Size: vol.Size, Description: req.Snapshot.Description,
				Metadata: req.Snapshot.Metadata, ProjectID: projectID,
				CreatedAt: nowRFC3339(),
			}
			snapshots[id] = s
			body := s.toMap()
			mu.Unlock()
			go settleSnapshot(id)
			writeJSONStatus(w, http.StatusAccepted, map[string]interface{}{"snapshot": body})
		default:
			methodNotAllowed(w, Cinder, r.Method)
		}
		return
	}

	snapID := p[0]
	mu.Lock()
	s, ok := snapshots[snapID]
	mu.Unlock()
	if !ok {
		notFound(w, Cinder, "Snapshot "+snapID)
		return
	}
	switch r.Method {
	case http.MethodGet:
		mu.Lock()
		body := s.toMap()
		mu.Unlock()
		writeJSON(w, map[string]interface{}{"snapshot": body})
	case http.MethodPut:
		var req struct {
			Snapshot struct {
				Name        *string `json:"name"`
				Description *string `json:"description"`
			} `json:"snapshot"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			badRequest(w, Cinder, "Invalid request body: "+err.Error())
			return
		}
		mu.Lock()
		if req.Snapshot.Name != nil {
			s.Name = *req.Snapshot.Name
		}
		if req.Snapshot.Description != nil {
			s.Description = *req.Snapshot.Description
		}
		body := s.toMap()
		mu.Unlock()
		writeJSON(w, map[string]interface{}{"snapshot": body})
	case http.MethodDelete:
		mu.Lock()
		delete(snapshots, snapID)
		mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
	default:
		methodNotAllowed(w, Cinder, r.Method)
	}
}

// settleSnapshot moves a snapshot to available after the build delay.
func settleSnapshot(id string) {
	time.Sleep(volumeBuildDelay)
	mu.Lock()
	defer mu.Unlock()
	if s, ok := snapshots[id]; ok {
		s.Status = "available"
	}
}

// serveBackups handles /backups, /backups/detail and /backups/{id}.
func serveBackups(w http.ResponseWriter, r *http.Request, p []string, projectID string) {
	if len(p) == 0 || (len(p) == 1 && p[0] == "detail") {
		switch r.Method {
		case http.MethodGet:
			mu.Lock()
			list := AsList(backups, func(b *Backup) map[string]interface{} { return b.toMap() })
			mu.Unlock()
			writeJSON(w, map[string]interface{}{
				"backups": ApplyLimit(FilterList(list, r.URL.Query()), r.URL.Query()),
			})
		case http.MethodPost:
			var req struct {
				Backup struct {
					Name        string `json:"name"`
					VolumeID    string `json:"volume_id"`
					SnapshotID  string `json:"snapshot_id"`
					Description string `json:"description"`
					Force       bool   `json:"force"`
					Incremental bool   `json:"incremental"`
				} `json:"backup"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				badRequest(w, Cinder, "Invalid request body: "+err.Error())
				return
			}
			mu.Lock()
			vol, ok := volumes[req.Backup.VolumeID]
			if !ok {
				mu.Unlock()
				notFound(w, Cinder, "Volume "+req.Backup.VolumeID)
				return
			}
			backupSeq++
			id := fmt.Sprintf("backup-%d", backupSeq)
			b := &Backup{
				ID: id, Name: req.Backup.Name, VolumeID: req.Backup.VolumeID,
				SnapshotID: req.Backup.SnapshotID, Status: "creating", Size: vol.Size,
				Description: req.Backup.Description, Force: req.Backup.Force,
				IsIncremental: req.Backup.Incremental, ProjectID: projectID,
				CreatedAt: nowRFC3339(),
			}
			backups[id] = b
			body := b.toMap()
			mu.Unlock()
			go settleBackup(id)
			writeJSONStatus(w, http.StatusAccepted, map[string]interface{}{"backup": body})
		default:
			methodNotAllowed(w, Cinder, r.Method)
		}
		return
	}

	backupID := p[0]
	mu.Lock()
	b, ok := backups[backupID]
	mu.Unlock()
	if !ok {
		notFound(w, Cinder, "Backup "+backupID)
		return
	}
	switch r.Method {
	case http.MethodGet:
		mu.Lock()
		body := b.toMap()
		mu.Unlock()
		writeJSON(w, map[string]interface{}{"backup": body})
	case http.MethodDelete:
		mu.Lock()
		delete(backups, backupID)
		mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
	default:
		methodNotAllowed(w, Cinder, r.Method)
	}
}

// settleBackup moves a backup to available after the build delay.
func settleBackup(id string) {
	time.Sleep(volumeBuildDelay)
	mu.Lock()
	defer mu.Unlock()
	if b, ok := backups[id]; ok {
		b.Status = "available"
	}
}

/* ============================
   Services, limits, quotas
============================ */

// serveVolumeServices answers GET /os-services.
func serveVolumeServices(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, Cinder, r.Method)
		return
	}
	list := []map[string]interface{}{
		{"binary": "cinder-scheduler", "host": "fakehost", "zone": "nova",
			"status": "enabled", "state": "up", "disabled_reason": nil,
			"updated_at": nowRFC3339()},
		{"binary": "cinder-volume", "host": "fakehost@lvmdriver-1", "zone": "nova",
			"status": "enabled", "state": "up", "disabled_reason": nil,
			"updated_at": nowRFC3339()},
	}
	writeJSON(w, map[string]interface{}{
		"services": FilterList(list, r.URL.Query()),
	})
}

// serveVolumeLimits answers GET /limits.
func serveVolumeLimits(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, Cinder, r.Method)
		return
	}
	mu.Lock()
	usedVolumes := len(volumes)
	usedSnapshots := len(snapshots)
	usedGigabytes := 0
	for _, v := range volumes {
		usedGigabytes += v.Size
	}
	mu.Unlock()
	writeJSON(w, map[string]interface{}{
		"limits": map[string]interface{}{
			"rate": []interface{}{},
			"absolute": map[string]interface{}{
				"totalSnapshotsUsed":       usedSnapshots,
				"maxTotalBackups":          10,
				"maxTotalVolumeGigabytes":  1000,
				"maxTotalSnapshots":        10,
				"maxTotalBackupGigabytes":  1000,
				"totalBackupGigabytesUsed": 0,
				"maxTotalVolumes":          10,
				"totalVolumesUsed":         usedVolumes,
				"totalBackupsUsed":         len(backups),
				"totalGigabytesUsed":       usedGigabytes,
			},
		},
	})
}

// cinderQuotaDefaults are the per-project block storage quotas devstack ships.
var cinderQuotaDefaults = map[string]int{
	"volumes": 10, "snapshots": 10, "gigabytes": 1000, "backups": 10,
	"backup_gigabytes": 1000, "per_volume_gigabytes": -1, "groups": 10,
}

/* ============================
   Helpers
============================ */

// volumeBuildDelay is how long a volume stays in "creating" before it becomes
// available, so clients exercise their wait-for-status paths.
var volumeBuildDelay = 2 * time.Second

// nowRFC3339 renders the current time the way the OpenStack APIs do.
func nowRFC3339() string {
	return time.Now().UTC().Format("2006-01-02T15:04:05.000000")
}

// toStringMap flattens a decoded JSON object into string values.
func toStringMap(in map[string]interface{}) map[string]string {
	out := map[string]string{}
	for k, v := range in {
		out[k] = stringOf(v)
	}
	return out
}

// truthy interprets a JSON value as a boolean, accepting "true"/"True".
func truthy(v interface{}) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return strings.EqualFold(t, "true")
	default:
		return false
	}
}

// imageMetadataFor renders the volume_image_metadata Cinder copies onto a
// volume created from an image. The caller must hold the state mutex.
func imageMetadataFor(imageRef string) map[string]string {
	for _, img := range images {
		if img["id"] == imageRef || img["name"] == imageRef {
			meta := map[string]string{}
			for _, k := range []string{"image_id", "image_name", "disk_format",
				"container_format", "min_disk", "min_ram", "size", "checksum"} {
				switch k {
				case "image_id":
					meta[k] = stringOf(img["id"])
				case "image_name":
					meta[k] = stringOf(img["name"])
				default:
					if v, ok := img[k]; ok && v != nil {
						meta[k] = stringOf(v)
					}
				}
			}
			return meta
		}
	}
	return map[string]string{"image_id": imageRef}
}

// filterByMetadataQuery applies Cinder's metadata[key]=value filters.
func filterByMetadataQuery(list []map[string]interface{}, r *http.Request) []map[string]interface{} {
	filters := map[string]string{}
	for key, values := range r.URL.Query() {
		if strings.HasPrefix(key, "metadata[") && strings.HasSuffix(key, "]") && len(values) > 0 {
			filters[key[len("metadata["):len(key)-1]] = values[0]
		}
	}
	if len(filters) == 0 {
		return list
	}
	out := []map[string]interface{}{}
	for _, item := range list {
		meta, _ := item["metadata"].(map[string]string)
		ok := true
		for k, want := range filters {
			if meta[k] != want {
				ok = false
				break
			}
		}
		if ok {
			out = append(out, item)
		}
	}
	return out
}

// volumeTypeEncryptions holds the encryption settings of a volume type,
// keyed by type id. A type with no entry is unencrypted, which Cinder
// reports as an empty document rather than a 404.
var volumeTypeEncryptions = map[string]map[string]interface{}{}

// volumeTypeEncryption handles /types/{id}/encryption[/{key}].
func volumeTypeEncryption(w http.ResponseWriter, r *http.Request, typeID string, p []string) {
	mu.Lock()
	defer mu.Unlock()

	// /encryption/{specs_id or key}: Cinder answers a single attribute.
	if len(p) == 1 && r.Method == http.MethodGet {
		spec, ok := volumeTypeEncryptions[typeID]
		if !ok {
			writeJSON(w, map[string]interface{}{})
			return
		}
		if v, ok := spec[p[0]]; ok {
			writeJSON(w, map[string]interface{}{p[0]: v})
			return
		}
		writeJSON(w, spec)
		return
	}

	switch r.Method {
	case http.MethodGet:
		spec, ok := volumeTypeEncryptions[typeID]
		if !ok {
			// An unencrypted type has an empty encryption document.
			writeJSON(w, map[string]interface{}{})
			return
		}
		writeJSON(w, spec)
	case http.MethodPost:
		var req struct {
			Encryption map[string]interface{} `json:"encryption"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			badRequest(w, Cinder, "Invalid request body: "+err.Error())
			return
		}
		spec := req.Encryption
		if spec == nil {
			spec = map[string]interface{}{}
		}
		spec["volume_type_id"] = typeID
		setDefault(spec, "encryption_id", RandomID("encryption"))
		setDefault(spec, "control_location", "front-end")
		setDefault(spec, "provider", "luks")
		setDefault(spec, "cipher", nil)
		setDefault(spec, "key_size", nil)
		volumeTypeEncryptions[typeID] = spec
		writeJSON(w, map[string]interface{}{"encryption": spec})
	case http.MethodPut:
		var req struct {
			Encryption map[string]interface{} `json:"encryption"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			badRequest(w, Cinder, "Invalid request body: "+err.Error())
			return
		}
		spec, ok := volumeTypeEncryptions[typeID]
		if !ok {
			notFound(w, Cinder, "Volume type encryption for "+typeID)
			return
		}
		for k, v := range req.Encryption {
			spec[k] = v
		}
		writeJSON(w, map[string]interface{}{"encryption": spec})
	case http.MethodDelete:
		delete(volumeTypeEncryptions, typeID)
		w.WriteHeader(http.StatusAccepted)
	default:
		methodNotAllowed(w, Cinder, r.Method)
	}
}

// briefVolumes reduces a volume listing to the summary form Cinder returns
// from /volumes, as opposed to /volumes/detail. Only used under strict
// responses: clients built against gostack read a volume's status straight
// out of the plain listing.
func briefVolumes(list []map[string]interface{}) []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(list))
	for _, v := range list {
		out = append(out, map[string]interface{}{
			"id": v["id"], "name": v["name"], "links": v["links"],
		})
	}
	return out
}
