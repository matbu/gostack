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

// serverBuildDelay is how long a server stays in BUILD before going ACTIVE,
// so clients exercise their wait-for-status paths.
var serverBuildDelay = 5 * time.Second

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
	setDefault(kp, "created_at", nowRFC3339())
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
	setDefault(f, "ephemeral", f["OS-FLV-EXT-DATA:ephemeral"])
	setDefault(f, "is_public", f["os-flavor-access:is_public"])
	setDefault(f, "description", nil)
	id, _ := f["id"].(string)
	setDefault(f, "links", []map[string]string{
		{"rel": "self", "href": baseURL + "/v2.1/flavors/" + id},
	})
	if specs, ok := flavorExtraSpecs[id]; ok {
		f["extra_specs"] = specs
	} else {
		setDefault(f, "extra_specs", map[string]string{})
	}
}

// RegisterNovaHandlers registers Nova (compute) API handlers on mux.
func RegisterNovaHandlers(mux *http.ServeMux) {
	mux.HandleFunc("/v2.1", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, computeVersionDocument())
	})

	mux.HandleFunc("/v2.1/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.String())
		p := Parts(r.URL.Path)
		// Project-scoped compute root: GET /v2.1/{project} — clients do
		// endpoint version discovery here before any API call.
		if len(p) == 2 {
			writeJSON(w, computeVersionDocument())
			return
		}
		if len(p) < 3 {
			notFound(w, Nova, "The resource")
			return
		}
		projectID := ProjectIDFromToken(r)
		rest := p[3:]

		switch p[2] {
		case "flavors":
			serveFlavors(w, r, rest)
		case "servers":
			serveServers(w, r, rest, projectID, p[1])
		case "images":
			serveNovaImages(w, r, rest, projectID)
		case "os-keypairs":
			serveKeypairs(w, r, rest, projectID)
		case "os-server-groups":
			serveServerGroups(w, r, rest, projectID)
		case "os-aggregates":
			serveAggregates(w, r, rest)
		case "os-services":
			serveComputeServices(w, r, rest)
		case "os-availability-zone":
			serveAvailabilityZones(w, r, rest)
		case "os-quota-sets":
			serveQuotaSet(w, r, rest, novaQuotas, novaQuotaDefaults, Nova)
		case "os-hypervisors":
			serveHypervisors(w, r, rest)
		case "limits":
			serveComputeLimits(w, r)
		default:
			notFound(w, Nova, "Resource "+p[2])
		}
	})
}

// computeVersionDocument is the version document Nova serves at its root.
func computeVersionDocument() map[string]interface{} {
	return map[string]interface{}{
		"version": map[string]interface{}{
			"id": "v2.1", "status": "CURRENT",
			"min_version": minComputeMicroversion,
			"version":     maxComputeMicroversion,
			"updated":     "2023-01-01T00:00:00Z",
			"links": []map[string]string{
				{"rel": "self", "href": baseURL + "/v2.1/"},
			},
		},
	}
}

/* ============================
   Flavors
============================ */

// serveFlavors handles /flavors, /flavors/detail, /flavors/{id} and the
// extra-specs and access sub-resources.
func serveFlavors(w http.ResponseWriter, r *http.Request, p []string) {
	// /flavors and /flavors/detail
	if len(p) == 0 || (len(p) == 1 && p[0] == "detail") {
		switch r.Method {
		case http.MethodGet:
			mu.Lock()
			list := []map[string]interface{}{}
			for _, f := range flavors {
				enrichFlavor(f)
				list = append(list, f)
			}
			mu.Unlock()
			writeJSON(w, map[string]interface{}{
				"flavors": ApplyLimit(FilterList(list, r.URL.Query(), "extra_specs", "min_disk", "min_ram"), r.URL.Query()),
			})
		case http.MethodPost:
			var req struct {
				Flavor map[string]interface{} `json:"flavor"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				badRequest(w, Nova, "Invalid request body: "+err.Error())
				return
			}
			f := req.Flavor
			if f == nil {
				badRequest(w, Nova, "Expecting to find flavor in request body.")
				return
			}
			mu.Lock()
			enrichFlavor(f)
			flavors = append(flavors, f)
			mu.Unlock()
			writeJSONStatus(w, http.StatusOK, map[string]interface{}{"flavor": f})
		default:
			methodNotAllowed(w, Nova, r.Method)
		}
		return
	}

	flavorID := p[0]
	mu.Lock()
	idx := -1
	for i, f := range flavors {
		if f["id"] == flavorID {
			idx = i
			break
		}
	}
	mu.Unlock()
	if idx == -1 {
		notFound(w, Nova, "Flavor "+flavorID)
		return
	}

	// /flavors/{id}/os-extra_specs[/{key}]
	if len(p) >= 2 && p[1] == "os-extra_specs" {
		flavorExtraSpecsHandler(w, r, flavorID, p[2:])
		return
	}
	// /flavors/{id}/os-flavor-access
	if len(p) == 2 && p[1] == "os-flavor-access" {
		mu.Lock()
		list := []map[string]interface{}{}
		for _, proj := range flavorAccess[flavorID] {
			list = append(list, map[string]interface{}{
				"flavor_id": flavorID, "tenant_id": proj,
			})
		}
		mu.Unlock()
		writeJSON(w, map[string]interface{}{"flavor_access": list})
		return
	}
	// /flavors/{id}/action — tenant access grants
	if len(p) == 2 && p[1] == "action" {
		flavorAccessAction(w, r, flavorID)
		return
	}

	mu.Lock()
	defer mu.Unlock()
	f := flavors[idx]
	enrichFlavor(f)
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, map[string]interface{}{"flavor": f})
	case http.MethodPut:
		var req struct {
			Flavor map[string]interface{} `json:"flavor"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			badRequest(w, Nova, "Invalid request body: "+err.Error())
			return
		}
		for k, v := range req.Flavor {
			f[k] = v
		}
		writeJSON(w, map[string]interface{}{"flavor": f})
	case http.MethodDelete:
		flavors = append(flavors[:idx], flavors[idx+1:]...)
		delete(flavorExtraSpecs, flavorID)
		delete(flavorAccess, flavorID)
		w.WriteHeader(http.StatusAccepted)
	default:
		methodNotAllowed(w, Nova, r.Method)
	}
}

// flavorExtraSpecsHandler handles /flavors/{id}/os-extra_specs[/{key}].
func flavorExtraSpecsHandler(w http.ResponseWriter, r *http.Request, flavorID string, p []string) {
	mu.Lock()
	defer mu.Unlock()
	if _, ok := flavorExtraSpecs[flavorID]; !ok {
		flavorExtraSpecs[flavorID] = map[string]string{}
	}

	if len(p) == 1 {
		key := p[0]
		switch r.Method {
		case http.MethodGet:
			val, ok := flavorExtraSpecs[flavorID][key]
			if !ok {
				notFound(w, Nova, "Extra spec "+key)
				return
			}
			writeJSON(w, map[string]string{key: val})
		case http.MethodPut:
			// Nova accepts any scalar here and stores it as a string.
			var body map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				badRequest(w, Nova, "Invalid request body: "+err.Error())
				return
			}
			for k, v := range toStringMap(body) {
				flavorExtraSpecs[flavorID][k] = v
			}
			writeJSON(w, map[string]string{key: flavorExtraSpecs[flavorID][key]})
		case http.MethodDelete:
			delete(flavorExtraSpecs[flavorID], key)
			w.WriteHeader(http.StatusOK)
		default:
			methodNotAllowed(w, Nova, r.Method)
		}
		return
	}

	switch r.Method {
	case http.MethodGet:
		writeJSON(w, map[string]interface{}{"extra_specs": flavorExtraSpecs[flavorID]})
	case http.MethodPost, http.MethodPut:
		var body struct {
			ExtraSpecs map[string]interface{} `json:"extra_specs"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			badRequest(w, Nova, "Invalid request body: "+err.Error())
			return
		}
		if r.Method == http.MethodPut {
			flavorExtraSpecs[flavorID] = map[string]string{}
		}
		for k, v := range toStringMap(body.ExtraSpecs) {
			flavorExtraSpecs[flavorID][k] = v
		}
		writeJSON(w, map[string]interface{}{"extra_specs": flavorExtraSpecs[flavorID]})
	default:
		methodNotAllowed(w, Nova, r.Method)
	}
}

// flavorAccessAction handles addTenantAccess / removeTenantAccess.
func flavorAccessAction(w http.ResponseWriter, r *http.Request, flavorID string) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, Nova, r.Method)
		return
	}
	var body map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		badRequest(w, Nova, "Invalid request body: "+err.Error())
		return
	}
	mu.Lock()
	defer mu.Unlock()
	render := func() {
		list := []map[string]interface{}{}
		for _, proj := range flavorAccess[flavorID] {
			list = append(list, map[string]interface{}{
				"flavor_id": flavorID, "tenant_id": proj,
			})
		}
		writeJSON(w, map[string]interface{}{"flavor_access": list})
	}
	if args, ok := body["addTenantAccess"].(map[string]interface{}); ok {
		tenant, _ := args["tenant"].(string)
		for _, existing := range flavorAccess[flavorID] {
			if existing == tenant {
				apiError(w, Nova, http.StatusConflict,
					"Flavor access already exists for flavor "+flavorID+" and tenant "+tenant+".")
				return
			}
		}
		flavorAccess[flavorID] = append(flavorAccess[flavorID], tenant)
		render()
		return
	}
	if args, ok := body["removeTenantAccess"].(map[string]interface{}); ok {
		tenant, _ := args["tenant"].(string)
		out := []string{}
		found := false
		for _, existing := range flavorAccess[flavorID] {
			if existing == tenant {
				found = true
				continue
			}
			out = append(out, existing)
		}
		if !found {
			notFound(w, Nova, "Flavor access for tenant "+tenant)
			return
		}
		flavorAccess[flavorID] = out
		render()
		return
	}
	badRequest(w, Nova, "Unsupported flavor action")
}

/* ============================
   Servers
============================ */

// serveServers handles /servers and everything beneath it.
func serveServers(w http.ResponseWriter, r *http.Request, p []string, projectID, pathProject string) {
	if projectID == "" {
		projectID = pathProject
	}

	// /servers and /servers/detail
	if len(p) == 0 || (len(p) == 1 && p[0] == "detail") {
		switch r.Method {
		case http.MethodGet:
			listServers(w, r, projectID)
		case http.MethodPost:
			createServer(w, r, projectID)
		default:
			methodNotAllowed(w, Nova, r.Method)
		}
		return
	}

	srvID := p[0]
	mu.Lock()
	s, ok := servers[srvID]
	mu.Unlock()
	if !ok {
		notFound(w, Nova, "Instance "+srvID)
		return
	}

	switch {
	case len(p) >= 2 && p[1] == "tags":
		serverTags(w, r, s, p[2:])
		return
	case len(p) >= 2 && p[1] == "os-interface":
		serverInterface(w, r, srvID, p[2:])
		return
	case len(p) >= 2 && p[1] == "os-volume_attachments":
		serverVolumeAttachments(w, r, srvID, p[2:])
		return
	case len(p) >= 2 && p[1] == "metadata":
		serverMetadata(w, r, s, p[2:])
		return
	case len(p) == 2 && p[1] == "action":
		serverAction(w, r, s)
		return
	case len(p) == 2 && p[1] == "os-security-groups":
		mu.Lock()
		body := serverSecurityGroups(s)
		mu.Unlock()
		writeJSON(w, map[string]interface{}{"security_groups": body})
		return
	}

	switch r.Method {
	case http.MethodGet:
		// With admin scope, reading a server by id is not project-scoped:
		// clients fetch servers found through an all-projects listing by
		// id alone.
		mu.Lock()
		if !adminScope && s.Project != "" && projectID != "" && s.Project != projectID {
			mu.Unlock()
			notFound(w, Nova, "Instance "+srvID)
			return
		}
		body := s.toMap()
		mu.Unlock()
		writeJSON(w, map[string]interface{}{"server": body})
	case http.MethodPut:
		var req struct {
			Server struct {
				Name        *string `json:"name"`
				Description *string `json:"description"`
				AccessIPv4  *string `json:"accessIPv4"`
			} `json:"server"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			badRequest(w, Nova, "Invalid request body: "+err.Error())
			return
		}
		mu.Lock()
		if req.Server.Name != nil {
			s.Name = *req.Server.Name
		}
		if req.Server.Description != nil {
			s.Description = *req.Server.Description
		}
		if req.Server.AccessIPv4 != nil {
			s.AccessIPv4 = *req.Server.AccessIPv4
		}
		s.Updated = nowRFC3339()
		body := s.toMap()
		mu.Unlock()
		writeJSON(w, map[string]interface{}{"server": body})
	case http.MethodDelete:
		deleteServer(w, srvID)
	default:
		methodNotAllowed(w, Nova, r.Method)
	}
}

// listServers answers GET /servers and GET /servers/detail. Nova matches the
// name filter as a regular expression.
func listServers(w http.ResponseWriter, r *http.Request, projectID string) {
	q := r.URL.Query()
	var nameRe *regexp.Regexp
	if nameFilter := q.Get("name"); nameFilter != "" {
		re, err := regexp.Compile(nameFilter)
		if err != nil {
			badRequest(w, Nova, "Invalid name filter: not a valid regular expression.")
			return
		}
		nameRe = re
	}
	allTenants, _ := QueryBool(q, "all_tenants")

	mu.Lock()
	list := []map[string]interface{}{}
	for _, s := range servers {
		if !allTenants && projectID != "" && s.Project != projectID {
			continue
		}
		if nameRe != nil && !nameRe.MatchString(s.Name) {
			continue
		}
		list = append(list, s.toMap())
	}
	mu.Unlock()
	list = FilterList(list, q, "name", "all_tenants", "flavor", "image", "status")
	// Status is compared case-insensitively by Nova.
	if status := q.Get("status"); status != "" {
		kept := []map[string]interface{}{}
		for _, item := range list {
			if strings.EqualFold(stringOf(item["status"]), status) {
				kept = append(kept, item)
			}
		}
		list = kept
	}
	writeJSON(w, map[string]interface{}{"servers": ApplyLimit(list, q)})
}

// createServer handles POST /servers.
func createServer(w http.ResponseWriter, r *http.Request, projectID string) {
	var req struct {
		Server struct {
			Name           string              `json:"name"`
			Flavor         string              `json:"flavor"`
			FlavorRef      string              `json:"flavorRef"`
			Image          string              `json:"image"`
			ImageRef       string              `json:"imageRef"`
			Networks       []map[string]string `json:"networks"`
			AccessIPv4     string              `json:"accessIPv4"`
			KeyName        string              `json:"key_name"`
			Metadata       map[string]string   `json:"metadata"`
			AvailZone      string              `json:"availability_zone"`
			Description    string              `json:"description"`
			UserData       string              `json:"user_data"`
			ConfigDrive    bool                `json:"config_drive"`
			Tags           []string            `json:"tags"`
			SecurityGroups []struct {
				Name string `json:"name"`
			} `json:"security_groups"`
		} `json:"server"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		badRequest(w, Nova, "Invalid request body: "+err.Error())
		return
	}

	flavorRef := req.Server.Flavor
	if flavorRef == "" {
		flavorRef = req.Server.FlavorRef
	}
	imageRef := req.Server.Image
	if imageRef == "" {
		imageRef = req.Server.ImageRef
	}

	mu.Lock()
	flavorRef = resolveFlavorRef(flavorRef)
	imageRef = resolveImageRef(imageRef, projectID)

	id := fmt.Sprintf("%d", serverID)
	serverID++
	now := nowRFC3339()
	sgs := []string{}
	for _, sg := range req.Server.SecurityGroups {
		sgs = append(sgs, sg.Name)
	}
	s := &Server{
		ID: id, Name: req.Server.Name, Status: "BUILD",
		Flavor:         map[string]string{"id": flavorRef},
		Image:          map[string]string{"id": imageRef},
		Networks:       req.Server.Networks,
		Project:        projectID,
		AccessIPv4:     req.Server.AccessIPv4,
		KeyName:        req.Server.KeyName,
		Metadata:       req.Server.Metadata,
		AvailZone:      req.Server.AvailZone,
		Description:    req.Server.Description,
		UserData:       req.Server.UserData,
		ConfigDrive:    req.Server.ConfigDrive,
		SecurityGroups: sgs,
		Tags:           req.Server.Tags,
		Created:        now,
		Updated:        now,
		TaskState:      "spawning",
		PowerState:     0,
	}
	servers[id] = s

	// Bind the ports the request named, and create one for each network
	// given without a port — Nova allocates a port per network at boot, and
	// clients look the server's addresses up through them.
	for i, net := range req.Server.Networks {
		portID := net["port"]
		if portID == "" {
			portID = net["port_id"]
		}
		if portID == "" {
			portID = attachServerPort(id, net, projectID)
			if portID == "" {
				continue
			}
			req.Server.Networks[i]["port"] = portID
		}
		for _, port := range ports {
			if port["id"] == portID {
				port["device_id"] = id
				port["device_owner"] = "compute:nova"
				port["status"] = "ACTIVE"
				setDefault(port, "admin_state_up", true)
			}
		}
	}
	body := s.toMap()
	mu.Unlock()

	go func(srvID string) {
		time.Sleep(serverBuildDelay)
		mu.Lock()
		defer mu.Unlock()
		if srv, ok := servers[srvID]; ok {
			srv.Status = "ACTIVE"
			srv.TaskState = ""
			srv.PowerState = 1
			srv.Updated = nowRFC3339()
			log.Printf("Server %s transitioned to ACTIVE", srvID)
		}
	}(id)

	// Nova's create response is a short form: id, links and security
	// groups. Clients built against gostack read the whole server out of
	// it, so the full object is returned unless responses are strict.
	if strictResponses {
		writeJSONStatus(w, http.StatusAccepted, map[string]interface{}{
			"server": map[string]interface{}{
				"id":                id,
				"links":             body["links"],
				"security_groups":   body["security_groups"],
				"adminPass":         "fakeAdminPass",
				"OS-DCF:diskConfig": "MANUAL",
			},
		})
		return
	}
	body["adminPass"] = "fakeAdminPass"
	writeJSONStatus(w, http.StatusAccepted, map[string]interface{}{"server": body})
}

// resolveFlavorRef turns a flavor name into its id, leaving ids untouched.
// The caller must hold the state mutex.
func resolveFlavorRef(ref string) string {
	if ref == "" {
		return ref
	}
	for _, f := range flavors {
		if f["id"] == ref {
			return ref
		}
	}
	for _, f := range flavors {
		if f["name"] == ref {
			if id, ok := f["id"].(string); ok {
				return id
			}
		}
	}
	return ref
}

// resolveImageRef turns an image name into its id, preferring an image the
// project owns. The caller must hold the state mutex.
func resolveImageRef(ref, projectID string) string {
	if ref == "" {
		return ref
	}
	for _, img := range images {
		if img["id"] == ref {
			return ref
		}
	}
	var matched map[string]interface{}
	for _, img := range images {
		if img["name"] != ref {
			continue
		}
		owner, _ := img["owner"].(string)
		visibility, _ := img["visibility"].(string)
		if owner != projectID && visibility != "public" {
			continue
		}
		if matched == nil || owner == projectID {
			matched = img
		}
	}
	if matched != nil {
		if id, ok := matched["id"].(string); ok {
			return id
		}
	}
	return ref
}

// deleteServer removes a server and releases its volumes and ports.
func deleteServer(w http.ResponseWriter, srvID string) {
	mu.Lock()
	defer mu.Unlock()
	if _, ok := servers[srvID]; !ok {
		notFound(w, Nova, "Instance "+srvID)
		return
	}
	log.Printf("Deleting server %s", srvID)
	for volID, vol := range volumes {
		remaining := []map[string]interface{}{}
		detached := false
		for _, attachment := range vol.Attachments {
			if attachment["server_id"] == srvID {
				detached = true
				log.Printf("Auto-detaching volume %s from server %s", volID, srvID)
				continue
			}
			remaining = append(remaining, attachment)
		}
		if detached {
			vol.Attachments = remaining
			if len(vol.Attachments) == 0 {
				vol.Status = "available"
			}
		}
	}
	for _, port := range ports {
		if port["device_id"] == srvID {
			port["device_id"] = nil
			port["device_owner"] = nil
			port["status"] = "DOWN"
		}
	}
	delete(servers, srvID)
	w.WriteHeader(http.StatusNoContent)
}

// serverAction handles POST /servers/{id}/action.
func serverAction(w http.ResponseWriter, r *http.Request, s *Server) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, Nova, r.Method)
		return
	}
	var body map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		badRequest(w, Nova, "Invalid request body: "+err.Error())
		return
	}
	mu.Lock()
	defer mu.Unlock()

	for action, raw := range body {
		args, _ := raw.(map[string]interface{})
		switch action {
		case "os-start":
			if s.Status == "ACTIVE" {
				apiError(w, Nova, http.StatusConflict,
					"Cannot 'os-start' instance "+s.ID+" while it is in vm_state active")
				return
			}
			s.Status, s.PowerState = "ACTIVE", 1
		case "os-stop":
			if s.Status == "SHUTOFF" {
				apiError(w, Nova, http.StatusConflict,
					"Cannot 'os-stop' instance "+s.ID+" while it is in vm_state stopped")
				return
			}
			s.Status, s.PowerState = "SHUTOFF", 4
		case "pause":
			s.Status, s.PowerState = "PAUSED", 3
		case "unpause", "resume":
			s.Status, s.PowerState = "ACTIVE", 1
		case "suspend":
			s.Status, s.PowerState = "SUSPENDED", 7
		case "lock":
			s.Locked = true
		case "unlock":
			s.Locked = false
		case "reboot":
			s.Status, s.PowerState = "ACTIVE", 1
		case "rebuild":
			if args != nil {
				if ref, ok := args["imageRef"].(string); ok {
					s.Image = map[string]string{"id": resolveImageRef(ref, s.Project)}
				}
			}
			s.Status = "ACTIVE"
		case "resize":
			if args != nil {
				if ref, ok := args["flavorRef"].(string); ok {
					s.Flavor = map[string]string{"id": resolveFlavorRef(ref)}
				}
			}
			s.Status = "VERIFY_RESIZE"
		case "confirmResize", "revertResize":
			s.Status = "ACTIVE"
		case "shelve":
			s.Status = "SHELVED_OFFLOADED"
		case "unshelve":
			s.Status = "ACTIVE"
		case "addSecurityGroup":
			if args != nil {
				if name, ok := args["name"].(string); ok {
					s.SecurityGroups = append(s.SecurityGroups, name)
				}
			}
		case "removeSecurityGroup":
			if args != nil {
				if name, ok := args["name"].(string); ok {
					out := []string{}
					for _, existing := range s.SecurityGroups {
						if existing != name {
							out = append(out, existing)
						}
					}
					s.SecurityGroups = out
				}
			}
		case "os-getConsoleOutput":
			writeJSON(w, map[string]interface{}{"output": "gostack fake console output\n"})
			return
		case "createImage":
			name := "snapshot"
			if args != nil {
				if n, ok := args["name"].(string); ok {
					name = n
				}
			}
			img := map[string]interface{}{
				"id": RandomID("img"), "name": name, "status": "active",
				"owner": s.Project, "visibility": "private",
				"disk_format": "qcow2", "container_format": "bare",
				"min_disk": 0, "min_ram": 0, "protected": false,
				"tags": []interface{}{}, "size": 0,
			}
			images = append(images, img)
			w.Header().Set("Location", baseURL+"/v2/images/"+stringOf(img["id"]))
			w.WriteHeader(http.StatusAccepted)
			return
		default:
			badRequest(w, Nova, "Unsupported server action: "+action)
			return
		}
		s.Updated = nowRFC3339()
		w.WriteHeader(http.StatusAccepted)
		return
	}
	badRequest(w, Nova, "Expecting an action in the request body.")
}

// serverMetadata handles /servers/{id}/metadata[/{key}].
func serverMetadata(w http.ResponseWriter, r *http.Request, s *Server, p []string) {
	mu.Lock()
	defer mu.Unlock()
	if s.Metadata == nil {
		s.Metadata = map[string]string{}
	}

	if len(p) == 1 {
		key := p[0]
		switch r.Method {
		case http.MethodGet:
			val, ok := s.Metadata[key]
			if !ok {
				notFound(w, Nova, "Metadata item "+key)
				return
			}
			writeJSON(w, map[string]interface{}{"meta": map[string]string{key: val}})
		case http.MethodPut:
			var req struct {
				Meta map[string]string `json:"meta"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				badRequest(w, Nova, "Invalid request body: "+err.Error())
				return
			}
			for k, v := range req.Meta {
				s.Metadata[k] = v
			}
			writeJSON(w, map[string]interface{}{"meta": req.Meta})
		case http.MethodDelete:
			delete(s.Metadata, key)
			w.WriteHeader(http.StatusNoContent)
		default:
			methodNotAllowed(w, Nova, r.Method)
		}
		return
	}

	switch r.Method {
	case http.MethodGet:
		writeJSON(w, map[string]interface{}{"metadata": s.Metadata})
	case http.MethodPost, http.MethodPut:
		var req struct {
			Metadata map[string]string `json:"metadata"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			badRequest(w, Nova, "Invalid request body: "+err.Error())
			return
		}
		// POST merges, PUT replaces.
		if r.Method == http.MethodPut {
			s.Metadata = map[string]string{}
		}
		for k, v := range req.Metadata {
			s.Metadata[k] = v
		}
		writeJSON(w, map[string]interface{}{"metadata": s.Metadata})
	default:
		methodNotAllowed(w, Nova, r.Method)
	}
}

// serverInterface handles /servers/{id}/os-interface[/{port}].
func serverInterface(w http.ResponseWriter, r *http.Request, srvID string, p []string) {
	switch r.Method {
	case http.MethodGet:
		mu.Lock()
		list := []map[string]interface{}{}
		for _, port := range ports {
			if port["device_id"] == srvID {
				list = append(list, map[string]interface{}{
					"port_id": port["id"], "net_id": port["network_id"],
					"mac_addr": "fa:16:3e:00:00:01", "port_state": port["status"],
					"fixed_ips": port["fixed_ips"],
				})
			}
		}
		mu.Unlock()
		writeJSON(w, map[string]interface{}{"interfaceAttachments": list})
	case http.MethodPost:
		var req struct {
			InterfaceAttachment struct {
				PortID string `json:"port_id"`
			} `json:"interfaceAttachment"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			badRequest(w, Nova, "Invalid request body: "+err.Error())
			return
		}
		if req.InterfaceAttachment.PortID == "" {
			badRequest(w, Nova, "Expecting to find port_id in interfaceAttachment.")
			return
		}
		mu.Lock()
		for _, port := range ports {
			if port["id"] == req.InterfaceAttachment.PortID {
				port["device_id"] = srvID
				port["device_owner"] = "compute:nova"
				port["status"] = "ACTIVE"
				setDefault(port, "admin_state_up", true)
				mu.Unlock()
				writeJSON(w, map[string]interface{}{
					"interfaceAttachment": map[string]interface{}{
						"port_id": req.InterfaceAttachment.PortID, "server_id": srvID,
					},
				})
				return
			}
		}
		mu.Unlock()
		notFound(w, Nova, "Port "+req.InterfaceAttachment.PortID)
	case http.MethodDelete:
		if len(p) == 0 {
			badRequest(w, Nova, "Expecting a port id in the request path.")
			return
		}
		portID := p[0]
		mu.Lock()
		for _, port := range ports {
			if port["id"] == portID {
				port["device_id"] = nil
				port["device_owner"] = nil
				port["status"] = "DOWN"
				mu.Unlock()
				w.WriteHeader(deleteStatus())
				return
			}
		}
		mu.Unlock()
		notFound(w, Nova, "Port "+portID)
	default:
		methodNotAllowed(w, Nova, r.Method)
	}
}

// serverVolumeAttachments handles /servers/{id}/os-volume_attachments.
func serverVolumeAttachments(w http.ResponseWriter, r *http.Request, srvID string, p []string) {
	switch r.Method {
	case http.MethodGet:
		mu.Lock()
		list := []map[string]interface{}{}
		for _, v := range volumes {
			for _, a := range v.Attachments {
				if a["server_id"] == srvID {
					list = append(list, map[string]interface{}{
						"id": "attach-" + v.ID, "volumeId": v.ID,
						"serverId": srvID, "device": a["device"],
					})
				}
			}
		}
		mu.Unlock()
		writeJSON(w, map[string]interface{}{"volumeAttachments": list})
	case http.MethodPost:
		var req struct {
			VolumeAttachment struct {
				VolumeID string `json:"volumeId"`
				Device   string `json:"device"`
			} `json:"volumeAttachment"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			badRequest(w, Nova, "Invalid request body: "+err.Error())
			return
		}
		mu.Lock()
		if _, ok := servers[srvID]; !ok {
			mu.Unlock()
			notFound(w, Nova, "Instance "+srvID)
			return
		}
		v, ok := volumes[req.VolumeAttachment.VolumeID]
		if !ok {
			mu.Unlock()
			notFound(w, Nova, "Volume "+req.VolumeAttachment.VolumeID)
			return
		}
		if v.Status != "available" && !v.Multiattach {
			mu.Unlock()
			badRequest(w, Nova, "Invalid volume: Volume "+v.ID+" status must be available, is "+v.Status)
			return
		}
		for _, attachment := range v.Attachments {
			if attachment["server_id"] == srvID {
				mu.Unlock()
				apiError(w, Nova, http.StatusConflict,
					"Volume "+v.ID+" is already attached to instance "+srvID+".")
				return
			}
		}
		device := req.VolumeAttachment.Device
		if device == "" {
			device = "/dev/vdb"
		}
		v.Status = "in-use"
		v.Attachments = append(v.Attachments, map[string]interface{}{
			"server_id": srvID, "device": device, "volume_id": v.ID,
			"id": "attach-" + v.ID, "attachment_id": "attach-" + v.ID,
		})
		mu.Unlock()
		writeJSON(w, map[string]interface{}{
			"volumeAttachment": map[string]interface{}{
				"id": "attach-" + v.ID, "volumeId": v.ID,
				"serverId": srvID, "device": device,
			},
		})
	case http.MethodDelete:
		if len(p) == 0 {
			badRequest(w, Nova, "Expecting an attachment id in the request path.")
			return
		}
		volumeID := strings.TrimPrefix(p[0], "attach-")
		mu.Lock()
		defer mu.Unlock()
		vol, ok := volumes[volumeID]
		if !ok {
			notFound(w, Nova, "Volume attachment "+p[0])
			return
		}
		remaining := []map[string]interface{}{}
		found := false
		for _, attachment := range vol.Attachments {
			if attachment["server_id"] == srvID {
				found = true
				continue
			}
			remaining = append(remaining, attachment)
		}
		if !found {
			notFound(w, Nova, "Volume attachment "+p[0])
			return
		}
		vol.Attachments = remaining
		if len(vol.Attachments) == 0 {
			vol.Status = "available"
		}
		w.WriteHeader(deleteStatus())
	default:
		methodNotAllowed(w, Nova, r.Method)
	}
}

/* ============================
   Images (proxied compute view)
============================ */

// serveNovaImages answers the deprecated compute image proxy.
func serveNovaImages(w http.ResponseWriter, r *http.Request, p []string, projectID string) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, Nova, r.Method)
		return
	}
	detail := len(p) == 1 && p[0] == "detail"
	mu.Lock()
	list := []map[string]interface{}{}
	for _, img := range images {
		visibility, _ := img["visibility"].(string)
		owner, _ := img["owner"].(string)
		if visibility != "public" && owner != projectID {
			continue
		}
		if detail {
			list = append(list, img)
			continue
		}
		list = append(list, map[string]interface{}{"id": img["id"], "name": img["name"]})
	}
	mu.Unlock()
	writeJSON(w, map[string]interface{}{"images": FilterList(list, r.URL.Query())})
}

/* ============================
   Keypairs
============================ */

// serveKeypairs handles /os-keypairs[/{name}].
func serveKeypairs(w http.ResponseWriter, r *http.Request, p []string, projectID string) {
	mu.Lock()
	defer mu.Unlock()

	if len(p) >= 1 {
		name := p[0]
		for i, kp := range keypairs {
			if kp["name"] == name {
				switch r.Method {
				case http.MethodGet:
					writeJSON(w, map[string]interface{}{"keypair": kp})
				case http.MethodDelete:
					keypairs = append(keypairs[:i], keypairs[i+1:]...)
					w.WriteHeader(http.StatusAccepted)
				default:
					methodNotAllowed(w, Nova, r.Method)
				}
				return
			}
		}
		notFound(w, Nova, "Keypair "+name)
		return
	}

	switch r.Method {
	case http.MethodGet:
		list := []interface{}{}
		for _, kp := range keypairs {
			list = append(list, map[string]interface{}{"keypair": kp})
		}
		writeJSON(w, map[string]interface{}{"keypairs": list})
	case http.MethodPost:
		var req struct {
			Keypair map[string]interface{} `json:"keypair"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			badRequest(w, Nova, "Invalid request body: "+err.Error())
			return
		}
		kp := req.Keypair
		if kp == nil {
			badRequest(w, Nova, "Expecting to find keypair in request body.")
			return
		}
		name, _ := kp["name"].(string)
		for _, existing := range keypairs {
			if existing["name"] == name {
				apiError(w, Nova, http.StatusConflict,
					"Key pair '"+name+"' already exists.")
				return
			}
		}
		enrichKeypair(kp, projectID)
		keypairs = append(keypairs, kp)
		writeJSONStatus(w, http.StatusCreated, map[string]interface{}{"keypair": kp})
	default:
		methodNotAllowed(w, Nova, r.Method)
	}
}

// attachServerPort creates the port Nova allocates when a server is booted
// on a network without one. It returns the new port id, or "" when the
// request did not name a usable network.
// The caller must hold the state mutex.
func attachServerPort(serverID string, net map[string]string, projectID string) string {
	networkID := net["uuid"]
	if networkID == "" {
		networkID = net["net-id"]
	}
	if networkID == "" {
		networkID = net["net_id"]
	}
	if networkID == "" {
		return ""
	}
	portID := fmt.Sprintf("port-%d", len(ports)+1)
	port := map[string]interface{}{
		"id":           portID,
		"network_id":   networkID,
		"device_id":    serverID,
		"device_owner": "compute:nova",
		"project_id":   projectID,
		"status":       "ACTIVE",
	}
	if addr := net["fixed_ip"]; addr != "" {
		port["fixed_ips"] = []interface{}{map[string]interface{}{"ip_address": addr}}
	} else if sub := firstSubnetOf(networkID); sub != "" {
		port["fixed_ips"] = []interface{}{map[string]interface{}{"subnet_id": sub}}
	}
	enrichPort(port, projectID)
	ports = append(ports, port)
	return portID
}

// serverTags handles /servers/{id}/tags[/{tag}], Nova's tag sub-resource.
func serverTags(w http.ResponseWriter, r *http.Request, s *Server, p []string) {
	mu.Lock()
	defer mu.Unlock()
	if s.Tags == nil {
		s.Tags = []string{}
	}

	if len(p) == 1 {
		tag := p[0]
		has := false
		for _, t := range s.Tags {
			if t == tag {
				has = true
			}
		}
		switch r.Method {
		case http.MethodGet:
			if has {
				w.WriteHeader(http.StatusNoContent)
			} else {
				notFound(w, Nova, "Tag "+tag)
			}
		case http.MethodPut:
			if !has {
				s.Tags = append(s.Tags, tag)
			}
			w.WriteHeader(http.StatusCreated)
		case http.MethodDelete:
			out := []string{}
			for _, t := range s.Tags {
				if t != tag {
					out = append(out, t)
				}
			}
			s.Tags = out
			w.WriteHeader(http.StatusNoContent)
		default:
			methodNotAllowed(w, Nova, r.Method)
		}
		return
	}

	switch r.Method {
	case http.MethodGet:
		writeJSON(w, map[string]interface{}{"tags": s.Tags})
	case http.MethodPut:
		var req struct {
			Tags []string `json:"tags"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			badRequest(w, Nova, "Invalid request body: "+err.Error())
			return
		}
		if req.Tags == nil {
			req.Tags = []string{}
		}
		s.Tags = req.Tags
		writeJSON(w, map[string]interface{}{"tags": s.Tags})
	case http.MethodDelete:
		s.Tags = []string{}
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w, Nova, r.Method)
	}
}

// serverSecurityGroups renders the groups attached to a server as the whole
// objects Nova returns from /servers/{id}/os-security-groups. Clients read
// the ids from here to work out which groups to add or remove.
// The caller must hold the state mutex.
func serverSecurityGroups(s *Server) []map[string]interface{} {
	wanted := s.SecurityGroups
	if len(wanted) == 0 {
		wanted = []string{"default"}
	}
	out := []map[string]interface{}{}
	for _, name := range wanted {
		found := false
		for _, sg := range neutronSecGroups {
			if sg["name"] == name || sg["id"] == name {
				enrichSecGroup(sg, s.Project)
				sg["security_group_rules"] = secGroupRulesFor(sg["id"])
				out = append(out, sg)
				found = true
				break
			}
		}
		if !found {
			out = append(out, map[string]interface{}{"name": name})
		}
	}
	return out
}
