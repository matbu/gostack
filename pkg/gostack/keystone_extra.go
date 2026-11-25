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
	"log"
	"net/http"
)

// catalogEntry builds one service catalog entry with a single public
// endpoint in RegionOne.
func catalogEntry(svcType, name, id, url string) map[string]interface{} {
	return map[string]interface{}{
		"type": svcType,
		"name": name,
		"endpoints": []map[string]interface{}{
			{
				"id": id, "interface": "public",
				"region": "RegionOne", "region_id": "RegionOne",
				"url": url,
			},
		},
	}
}

// catalogFor renders the service catalog for a project. Cinder is published
// under its own /volume prefix so it does not shadow the Keystone resources
// that also live under /v3.
func catalogFor(projectID string) []map[string]interface{} {
	return []map[string]interface{}{
		catalogEntry("identity", "keystone", "keystone-public", baseURL+"/v3/"),
		catalogEntry("compute", "nova", "nova-public", baseURL+"/v2.1/"+projectID),
		catalogEntry("network", "neutron", "neutron-public", baseURL+"/v2.0"),
		catalogEntry("image", "glance", "glance-public", baseURL+"/v2"),
		catalogEntry("volumev3", "cinder", "cinder-public", baseURL+cinderPrefix+projectID),
		catalogEntry("block-storage", "cinder", "cinder-public-bs", baseURL+cinderPrefix+projectID),
	}
}

// tokenDocument renders the token body Keystone returns from both token
// creation and token validation.
func tokenDocument(projectID, projectName string, catalog []map[string]interface{}) map[string]interface{} {
	doc := map[string]interface{}{
		"expires_at": "2099-01-01T00:00:00.000000Z",
		"issued_at":  "2026-01-01T00:00:00.000000Z",
		"methods":    []string{"password"},
		"audit_ids":  []string{"gostackauditid00000000"},
		"project": map[string]interface{}{
			"id": projectID, "name": projectName,
			"domain": map[string]string{"id": "default", "name": "Default"},
		},
		"user": map[string]interface{}{
			"id": "demo-user", "name": "demo",
			"domain":              map[string]string{"id": "default", "name": "Default"},
			"password_expires_at": nil,
		},
		"roles": []map[string]string{
			{"id": "member", "name": "member"},
			{"id": "admin", "name": "admin"},
		},
	}
	if catalog != nil {
		doc["catalog"] = catalog
	}
	return doc
}

// validateToken answers GET/HEAD /v3/auth/tokens, which checks the token in
// X-Subject-Token instead of issuing a new one.
func validateToken(w http.ResponseWriter, r *http.Request) {
	subject := r.Header.Get("X-Subject-Token")
	if subject == "" {
		badRequest(w, Keystone, "Expecting to find X-Subject-Token in request.")
		return
	}
	if !tokenKnown(subject) {
		apiError(w, Keystone, http.StatusNotFound, "Could not find token: "+subject+".")
		return
	}
	tokenMu.RLock()
	projectID, ok := tokenProjects[subject]
	tokenMu.RUnlock()
	if !ok {
		projectID = "demo"
	}
	projectName := projectID
	mu.Lock()
	if p, found := projects[projectID]; found {
		projectName = p.Name
	}
	mu.Unlock()

	w.Header().Set("X-Subject-Token", subject)
	if r.Method == http.MethodHead {
		// HEAD carries the status only, with no body.
		w.WriteHeader(http.StatusOK)
		return
	}
	// A validation response omits the catalog unless asked for it.
	writeJSON(w, map[string]interface{}{
		"token": tokenDocument(projectID, projectName, nil),
	})
}

// RegisterKeystoneExtraHandlers registers the identity resources beyond the
// core users/projects/roles set: the service catalog, regions, groups and the
// auth scope listings.
func RegisterKeystoneExtraHandlers(mux *http.ServeMux) {
	registerCatalogServices(mux)
	registerEndpoints(mux)
	registerRegions(mux)
	registerGroups(mux)
	registerAuthScopes(mux)
}

// registerCatalogServices implements /v3/services.
func registerCatalogServices(mux *http.ServeMux) {
	handle := func(w http.ResponseWriter, r *http.Request, id string) {
		mu.Lock()
		defer mu.Unlock()
		if id == "" {
			switch r.Method {
			case http.MethodGet:
				list := AsList(catalogServices, func(s *CatalogService) map[string]interface{} {
					return s.toMap()
				})
				writeJSON(w, map[string]interface{}{"services": FilterList(list, r.URL.Query())})
			case http.MethodPost:
				var req struct {
					Service struct {
						Name        string `json:"name"`
						Type        string `json:"type"`
						Description string `json:"description"`
						Enabled     *bool  `json:"enabled"`
					} `json:"service"`
				}
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					badRequest(w, Keystone, "Invalid request body.")
					return
				}
				if req.Service.Type == "" {
					badRequest(w, Keystone, "Expecting to find type in service.")
					return
				}
				enabled := true
				if req.Service.Enabled != nil {
					enabled = *req.Service.Enabled
				}
				s := &CatalogService{
					ID: RandomID("service"), Name: req.Service.Name,
					Type: req.Service.Type, Description: req.Service.Description,
					Enabled: enabled,
				}
				catalogServices[s.ID] = s
				writeJSONStatus(w, http.StatusCreated, map[string]interface{}{"service": s.toMap()})
			default:
				methodNotAllowed(w, Keystone, r.Method)
			}
			return
		}

		s, ok := catalogServices[id]
		if !ok {
			notFound(w, Keystone, "Could not find service: "+id+".")
			return
		}
		switch r.Method {
		case http.MethodGet:
			writeJSON(w, map[string]interface{}{"service": s.toMap()})
		case http.MethodPatch:
			var req struct {
				Service struct {
					Name        *string `json:"name"`
					Type        *string `json:"type"`
					Description *string `json:"description"`
					Enabled     *bool   `json:"enabled"`
				} `json:"service"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				badRequest(w, Keystone, "Invalid request body.")
				return
			}
			if req.Service.Name != nil {
				s.Name = *req.Service.Name
			}
			if req.Service.Type != nil {
				s.Type = *req.Service.Type
			}
			if req.Service.Description != nil {
				s.Description = *req.Service.Description
			}
			if req.Service.Enabled != nil {
				s.Enabled = *req.Service.Enabled
			}
			writeJSON(w, map[string]interface{}{"service": s.toMap()})
		case http.MethodDelete:
			delete(catalogServices, id)
			w.WriteHeader(http.StatusNoContent)
		default:
			methodNotAllowed(w, Keystone, r.Method)
		}
	}

	mux.HandleFunc("/v3/services", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.String())
		handle(w, r, "")
	})
	mux.HandleFunc("/v3/services/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.String())
		handle(w, r, segmentAt(r, 2))
	})
}

// registerEndpoints implements /v3/endpoints.
func registerEndpoints(mux *http.ServeMux) {
	handle := func(w http.ResponseWriter, r *http.Request, id string) {
		mu.Lock()
		defer mu.Unlock()
		if id == "" {
			switch r.Method {
			case http.MethodGet:
				list := AsList(catalogEndpoints, func(e *Endpoint) map[string]interface{} {
					return e.toMap()
				})
				writeJSON(w, map[string]interface{}{"endpoints": FilterList(list, r.URL.Query())})
			case http.MethodPost:
				var req struct {
					Endpoint struct {
						ServiceID string `json:"service_id"`
						Interface string `json:"interface"`
						URL       string `json:"url"`
						Region    string `json:"region"`
						RegionID  string `json:"region_id"`
						Enabled   *bool  `json:"enabled"`
					} `json:"endpoint"`
				}
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					badRequest(w, Keystone, "Invalid request body.")
					return
				}
				if req.Endpoint.ServiceID == "" || req.Endpoint.URL == "" {
					badRequest(w, Keystone, "Expecting to find service_id and url in endpoint.")
					return
				}
				if _, ok := catalogServices[req.Endpoint.ServiceID]; !ok {
					notFound(w, Keystone, "Could not find service: "+req.Endpoint.ServiceID+".")
					return
				}
				enabled := true
				if req.Endpoint.Enabled != nil {
					enabled = *req.Endpoint.Enabled
				}
				region := req.Endpoint.Region
				if region == "" {
					region = req.Endpoint.RegionID
				}
				e := &Endpoint{
					ID: RandomID("endpoint"), ServiceID: req.Endpoint.ServiceID,
					Interface: req.Endpoint.Interface, URL: req.Endpoint.URL,
					Region: region, Enabled: enabled,
				}
				catalogEndpoints[e.ID] = e
				writeJSONStatus(w, http.StatusCreated, map[string]interface{}{"endpoint": e.toMap()})
			default:
				methodNotAllowed(w, Keystone, r.Method)
			}
			return
		}

		e, ok := catalogEndpoints[id]
		if !ok {
			notFound(w, Keystone, "Could not find endpoint: "+id+".")
			return
		}
		switch r.Method {
		case http.MethodGet:
			writeJSON(w, map[string]interface{}{"endpoint": e.toMap()})
		case http.MethodPatch:
			var req struct {
				Endpoint struct {
					ServiceID *string `json:"service_id"`
					Interface *string `json:"interface"`
					URL       *string `json:"url"`
					Region    *string `json:"region"`
					Enabled   *bool   `json:"enabled"`
				} `json:"endpoint"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				badRequest(w, Keystone, "Invalid request body.")
				return
			}
			if req.Endpoint.ServiceID != nil {
				e.ServiceID = *req.Endpoint.ServiceID
			}
			if req.Endpoint.Interface != nil {
				e.Interface = *req.Endpoint.Interface
			}
			if req.Endpoint.URL != nil {
				e.URL = *req.Endpoint.URL
			}
			if req.Endpoint.Region != nil {
				e.Region = *req.Endpoint.Region
			}
			if req.Endpoint.Enabled != nil {
				e.Enabled = *req.Endpoint.Enabled
			}
			writeJSON(w, map[string]interface{}{"endpoint": e.toMap()})
		case http.MethodDelete:
			delete(catalogEndpoints, id)
			w.WriteHeader(http.StatusNoContent)
		default:
			methodNotAllowed(w, Keystone, r.Method)
		}
	}

	mux.HandleFunc("/v3/endpoints", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.String())
		handle(w, r, "")
	})
	mux.HandleFunc("/v3/endpoints/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.String())
		handle(w, r, segmentAt(r, 2))
	})
}

// registerRegions implements /v3/regions.
func registerRegions(mux *http.ServeMux) {
	handle := func(w http.ResponseWriter, r *http.Request, id string) {
		mu.Lock()
		defer mu.Unlock()
		if id == "" {
			switch r.Method {
			case http.MethodGet:
				list := AsList(regions, func(rg *Region) map[string]interface{} { return rg.toMap() })
				writeJSON(w, map[string]interface{}{"regions": FilterList(list, r.URL.Query())})
			case http.MethodPost:
				var req struct {
					Region struct {
						ID           string `json:"id"`
						Description  string `json:"description"`
						ParentRegion string `json:"parent_region_id"`
					} `json:"region"`
				}
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					badRequest(w, Keystone, "Invalid request body.")
					return
				}
				if req.Region.ID == "" {
					req.Region.ID = RandomID("region")
				}
				rg := &Region{ID: req.Region.ID, Description: req.Region.Description,
					ParentRegion: req.Region.ParentRegion}
				regions[rg.ID] = rg
				writeJSONStatus(w, http.StatusCreated, map[string]interface{}{"region": rg.toMap()})
			default:
				methodNotAllowed(w, Keystone, r.Method)
			}
			return
		}

		rg, ok := regions[id]
		if !ok {
			notFound(w, Keystone, "Could not find region: "+id+".")
			return
		}
		switch r.Method {
		case http.MethodGet:
			writeJSON(w, map[string]interface{}{"region": rg.toMap()})
		case http.MethodPatch:
			var req struct {
				Region struct {
					Description *string `json:"description"`
				} `json:"region"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				badRequest(w, Keystone, "Invalid request body.")
				return
			}
			if req.Region.Description != nil {
				rg.Description = *req.Region.Description
			}
			writeJSON(w, map[string]interface{}{"region": rg.toMap()})
		case http.MethodDelete:
			delete(regions, id)
			w.WriteHeader(http.StatusNoContent)
		default:
			methodNotAllowed(w, Keystone, r.Method)
		}
	}

	mux.HandleFunc("/v3/regions", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.String())
		handle(w, r, "")
	})
	mux.HandleFunc("/v3/regions/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.String())
		handle(w, r, segmentAt(r, 2))
	})
}

// groupMembers maps a group id to the ids of its member users.
var groupMembers = map[string][]string{}

// registerGroups implements /v3/groups and its users sub-resource.
func registerGroups(mux *http.ServeMux) {
	collection := func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.Method {
		case http.MethodGet:
			list := AsList(groups, func(g *Group) map[string]interface{} { return g.toMap() })
			writeJSON(w, map[string]interface{}{"groups": FilterList(list, r.URL.Query())})
		case http.MethodPost:
			var req struct {
				Group struct {
					Name        string `json:"name"`
					DomainID    string `json:"domain_id"`
					Description string `json:"description"`
				} `json:"group"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				badRequest(w, Keystone, "Invalid request body.")
				return
			}
			if req.Group.Name == "" {
				badRequest(w, Keystone, "Expecting to find name in group.")
				return
			}
			domainID := req.Group.DomainID
			if domainID == "" {
				domainID = "default"
			}
			g := &Group{ID: RandomID("group"), Name: req.Group.Name,
				DomainID: domainID, Description: req.Group.Description}
			groups[g.ID] = g
			writeJSONStatus(w, http.StatusCreated, map[string]interface{}{"group": g.toMap()})
		default:
			methodNotAllowed(w, Keystone, r.Method)
		}
	}

	mux.HandleFunc("/v3/groups", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.String())
		collection(w, r)
	})

	mux.HandleFunc("/v3/groups/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.String())
		parts := Parts(r.URL.Path) // ["v3","groups",{id},"users",{user}]
		if len(parts) < 3 || parts[2] == "" {
			collection(w, r)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		id := parts[2]
		g, ok := groups[id]
		if !ok {
			notFound(w, Keystone, "Could not find group: "+id+".")
			return
		}

		// /v3/groups/{id}/users[/{user_id}]
		if len(parts) >= 4 && parts[3] == "users" {
			if len(parts) == 4 {
				if r.Method != http.MethodGet {
					methodNotAllowed(w, Keystone, r.Method)
					return
				}
				list := []map[string]interface{}{}
				for _, uid := range groupMembers[id] {
					if u, ok := users[uid]; ok {
						list = append(list, u.toMap(baseURL))
					}
				}
				writeJSON(w, map[string]interface{}{"users": list})
				return
			}
			userID := parts[4]
			member := false
			for _, uid := range groupMembers[id] {
				if uid == userID {
					member = true
				}
			}
			switch r.Method {
			case http.MethodPut:
				if !member {
					groupMembers[id] = append(groupMembers[id], userID)
				}
				w.WriteHeader(http.StatusNoContent)
			case http.MethodHead, http.MethodGet:
				if member {
					w.WriteHeader(http.StatusNoContent)
				} else {
					notFound(w, Keystone, "Group membership")
				}
			case http.MethodDelete:
				out := []string{}
				for _, uid := range groupMembers[id] {
					if uid != userID {
						out = append(out, uid)
					}
				}
				groupMembers[id] = out
				w.WriteHeader(http.StatusNoContent)
			default:
				methodNotAllowed(w, Keystone, r.Method)
			}
			return
		}

		switch r.Method {
		case http.MethodGet:
			writeJSON(w, map[string]interface{}{"group": g.toMap()})
		case http.MethodPatch:
			var req struct {
				Group struct {
					Name        *string `json:"name"`
					Description *string `json:"description"`
				} `json:"group"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				badRequest(w, Keystone, "Invalid request body.")
				return
			}
			if req.Group.Name != nil {
				g.Name = *req.Group.Name
			}
			if req.Group.Description != nil {
				g.Description = *req.Group.Description
			}
			writeJSON(w, map[string]interface{}{"group": g.toMap()})
		case http.MethodDelete:
			delete(groups, id)
			delete(groupMembers, id)
			w.WriteHeader(http.StatusNoContent)
		default:
			methodNotAllowed(w, Keystone, r.Method)
		}
	})
}

// registerAuthScopes implements the /v3/auth/projects and /v3/auth/domains
// listings, which tell a client what its token may be rescoped to.
func registerAuthScopes(mux *http.ServeMux) {
	mux.HandleFunc("/v3/auth/projects", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.String())
		if r.Method != http.MethodGet {
			methodNotAllowed(w, Keystone, r.Method)
			return
		}
		mu.Lock()
		list := AsList(projects, func(p *Project) map[string]interface{} { return p.toMap() })
		mu.Unlock()
		writeJSON(w, map[string]interface{}{"projects": list})
	})

	mux.HandleFunc("/v3/auth/domains", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.String())
		if r.Method != http.MethodGet {
			methodNotAllowed(w, Keystone, r.Method)
			return
		}
		mu.Lock()
		list := AsList(domains, func(d *Domain) map[string]interface{} { return d.toMap(baseURL) })
		mu.Unlock()
		writeJSON(w, map[string]interface{}{"domains": list})
	})

	mux.HandleFunc("/v3/auth/catalog", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.String())
		if r.Method != http.MethodGet {
			methodNotAllowed(w, Keystone, r.Method)
			return
		}
		writeJSON(w, map[string]interface{}{"catalog": catalogFor(ProjectIDFromToken(r))})
	})
}

// segmentAt returns the nth path segment of the request, or "" when the path
// is shorter than that (a collection request with a trailing slash).
func segmentAt(r *http.Request, n int) string {
	parts := Parts(r.URL.Path)
	if len(parts) <= n {
		return ""
	}
	return parts[n]
}

// resolveScope turns the project a token request asked for into the id and
// name to scope the token to.
//
// What the request named decides which lookup applies: an id is matched by
// id, a name by name. Trying the id first regardless would let the default
// project swallow a request that named a different one by name.
func resolveScope(askedID, askedName string) (id, name string) {
	mu.Lock()
	defer mu.Unlock()

	if askedID != "" {
		if p, ok := projects[askedID]; ok {
			return p.ID, p.Name
		}
	}
	if askedName != "" {
		for _, p := range projects {
			if p.Name == askedName {
				return p.ID, p.Name
			}
		}
		// A project keyed by the requested name is still a match: gostack's
		// default seed keys some projects by a name rather than a uuid.
		if p, ok := projects[askedName]; ok {
			return p.ID, p.Name
		}
	}
	// Scoping to a project that does not exist would leave every later
	// request pointing at nothing; fall back to the seed's default.
	if p, ok := projects[defaultProjectID]; ok {
		return p.ID, p.Name
	}
	return defaultProjectID, defaultProjectName
}
