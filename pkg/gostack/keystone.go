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
	"path"
)

// RegisterKeystoneHandlers registers Keystone API handlers on mux.
func RegisterKeystoneHandlers(mux *http.ServeMux) {
	mux.HandleFunc("/v3", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.String())
		writeJSON(w, map[string]interface{}{
			"version": map[string]interface{}{
				"id":      "v3.14",
				"status":  "stable",
				"updated": "2023-01-01T00:00:00Z",
				"links": []map[string]string{
					{"rel": "self", "href": baseURL + "/v3/"},
				},
				"media-types": []map[string]string{
					{"base": "application/json", "type": "application/vnd.openstack.identity-v3+json"},
				},
			},
		})
	})

	mux.HandleFunc("/v3/auth/tokens", func(w http.ResponseWriter, r *http.Request) {
		// GET and HEAD validate the token in X-Subject-Token rather than
		// issuing a new one; DELETE revokes it.
		switch r.Method {
		case http.MethodGet, http.MethodHead:
			validateToken(w, r)
			return
		case http.MethodDelete:
			subject := r.Header.Get("X-Subject-Token")
			tokenMu.Lock()
			delete(tokenProjects, subject)
			tokenMu.Unlock()
			w.WriteHeader(http.StatusNoContent)
			return
		case http.MethodPost:
			// fall through to issue a token
		default:
			methodNotAllowed(w, Keystone, r.Method)
			return
		}

		var askedID, askedName string
		if r.Body != nil {
			var authReq struct {
				Auth struct {
					Scope struct {
						Project struct {
							ID   string `json:"id"`
							Name string `json:"name"`
						} `json:"project"`
					} `json:"scope"`
				} `json:"auth"`
			}
			if err := json.NewDecoder(r.Body).Decode(&authReq); err == nil {
				askedID = authReq.Auth.Scope.Project.ID
				askedName = authReq.Auth.Scope.Project.Name
			}
		}
		projectID, projectName := resolveScope(askedID, askedName)
		token := "fake-token-" + projectID
		w.Header().Set("X-Subject-Token", token)
		tokenMu.Lock()
		tokenProjects[token] = projectID
		tokenMu.Unlock()
		catalog := catalogFor(projectID)
		writeJSONStatus(w, http.StatusCreated,
			map[string]interface{}{"token": tokenDocument(projectID, projectName, catalog)})
	})

	mux.HandleFunc("/v3/domains", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		log.Printf("%s %s", r.Method, r.URL.String())
		if r.Method == http.MethodGet {
			list := AsList(domains, func(d *Domain) map[string]interface{} { return d.toMap(baseURL) })
			writeJSON(w, map[string]interface{}{"domains": FilterList(list, r.URL.Query())})
			return
		}
		if r.Method == http.MethodPost {
			var req struct {
				Domain struct {
					Name        string `json:"name"`
					Description string `json:"description"`
					Enabled     *bool  `json:"enabled"`
				} `json:"domain"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				badRequest(w, Keystone, "Invalid request body.")
				return
			}
			id := RandomID("domain")
			enabled := true
			if req.Domain.Enabled != nil {
				enabled = *req.Domain.Enabled
			}
			name := req.Domain.Name
			if name == "" {
				name = id
			}
			domains[id] = &Domain{ID: id, Name: name, Description: req.Domain.Description, Enabled: enabled}
			writeJSONStatus(w, http.StatusCreated,
				map[string]interface{}{"domain": domains[id].toMap(baseURL)})
			return
		}
		methodNotAllowed(w, Keystone, r.Method)
	})

	mux.HandleFunc("/v3/domains/", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		log.Printf("%s %s", r.Method, r.URL.String())
		pathParts := Parts(r.URL.Path)
		// Grants: /v3/domains/{dom}/{users|groups}/{id}/roles[/{role}]
		if serveRoleGrants(w, r, pathParts) {
			return
		}
		id := pathParts[2]
		d, ok := domains[id]
		if !ok {
			notFound(w, Keystone, "Could not find domain: "+id+".")
			return
		}
		switch r.Method {
		case http.MethodGet:
			writeJSON(w, map[string]interface{}{"domain": d.toMap(baseURL)})
		case http.MethodPatch:
			var req struct {
				Domain struct {
					Name        *string `json:"name"`
					Description *string `json:"description"`
					Enabled     *bool   `json:"enabled"`
				} `json:"domain"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				badRequest(w, Keystone, "Invalid request body.")
				return
			}
			if req.Domain.Name != nil {
				d.Name = *req.Domain.Name
			}
			if req.Domain.Description != nil {
				d.Description = *req.Domain.Description
			}
			if req.Domain.Enabled != nil {
				d.Enabled = *req.Domain.Enabled
			}
			writeJSON(w, map[string]interface{}{"domain": d.toMap(baseURL)})
		case http.MethodDelete:
			// Keystone refuses to delete a domain that is still enabled.
			if d.Enabled {
				apiError(w, Keystone, http.StatusForbidden,
					"Cannot delete a domain that is enabled, please disable it first.")
				return
			}
			delete(domains, id)
			w.WriteHeader(http.StatusNoContent)
		default:
			methodNotAllowed(w, Keystone, r.Method)
		}
	})

	mux.HandleFunc("/v3/projects", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		log.Printf("%s %s", r.Method, r.URL.String())
		if r.Method == http.MethodGet {
			list := AsList(projects, func(p *Project) map[string]interface{} { return p.toMap() })
			writeJSON(w, map[string]interface{}{"projects": FilterList(list, r.URL.Query())})
			return
		}
		if r.Method == http.MethodPost {
			var req struct {
				Project struct {
					Name        string `json:"name"`
					DomainID    string `json:"domain_id"`
					Description string `json:"description"`
					Enabled     *bool  `json:"enabled"`
				} `json:"project"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				badRequest(w, Keystone, "Invalid request body.")
				return
			}
			if req.Project.Name == "" {
				badRequest(w, Keystone, "Expecting to find name in project.")
				return
			}
			domainID := req.Project.DomainID
			if domainID == "" {
				domainID = "default"
			}
			enabled := true
			if req.Project.Enabled != nil {
				enabled = *req.Project.Enabled
			}
			id := RandomID("project")
			p := &Project{ID: id, Name: req.Project.Name, DomainID: domainID,
				Description: req.Project.Description, Enabled: enabled}
			projects[id] = p
			w.WriteHeader(http.StatusCreated)
			writeJSON(w, map[string]interface{}{"project": p.toMap()})
			return
		}
		methodNotAllowed(w, Keystone, r.Method)
	})

	mux.HandleFunc("/v3/projects/", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		log.Printf("%s %s", r.Method, r.URL.String())
		w.Header().Set("Content-Type", "application/json")
		// pathParts = [v3, projects, {proj}, users, {user}, roles, {role}]
		pathParts := Parts(r.URL.Path)

		// Collection with trailing slash: POST /v3/projects/ , GET /v3/projects/
		if len(pathParts) == 2 {
			if r.Method == http.MethodPost {
				var req struct {
					Project struct {
						Name        string `json:"name"`
						DomainID    string `json:"domain_id"`
						Description string `json:"description"`
						Enabled     *bool  `json:"enabled"`
					} `json:"project"`
				}
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					badRequest(w, Keystone, "Invalid request body.")
					return
				}
				id := RandomID("project")
				domainID := req.Project.DomainID
				if domainID == "" {
					domainID = "default"
				}
				enabled := true
				if req.Project.Enabled != nil {
					enabled = *req.Project.Enabled
				}
				p := &Project{ID: id, Name: req.Project.Name, DomainID: domainID,
					Description: req.Project.Description, Enabled: enabled}
				projects[id] = p
				w.WriteHeader(http.StatusCreated)
				writeJSON(w, map[string]interface{}{"project": p.toMap()})
				return
			}
			if r.Method == http.MethodGet {
				list := AsList(projects, func(p *Project) map[string]interface{} { return p.toMap() })
				writeJSON(w, map[string]interface{}{"projects": FilterList(list, r.URL.Query())})
				return
			}
			methodNotAllowed(w, Keystone, r.Method)
			return
		}

		// Grants: /v3/projects/{proj}/{users|groups}/{id}/roles[/{role}]
		if serveRoleGrants(w, r, pathParts) {
			return
		}
		// GET/PATCH/DELETE /v3/projects/{proj}
		if len(pathParts) == 3 {
			projectID := pathParts[2]
			p, ok := projects[projectID]
			if !ok {
				notFound(w, Keystone, "Could not find project: "+projectID+".")
				return
			}
			switch r.Method {
			case http.MethodGet:
				writeJSON(w, map[string]interface{}{"project": p.toMap()})
			case http.MethodPatch:
				var req struct {
					Project struct {
						Name        *string `json:"name"`
						Description *string `json:"description"`
						Enabled     *bool   `json:"enabled"`
					} `json:"project"`
				}
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					badRequest(w, Keystone, "Invalid request body.")
					return
				}
				if req.Project.Name != nil {
					p.Name = *req.Project.Name
				}
				if req.Project.Description != nil {
					p.Description = *req.Project.Description
				}
				if req.Project.Enabled != nil {
					p.Enabled = *req.Project.Enabled
				}
				writeJSON(w, map[string]interface{}{"project": p.toMap()})
			case http.MethodDelete:
				delete(projects, projectID)
				w.WriteHeader(http.StatusNoContent)
			default:
				methodNotAllowed(w, Keystone, r.Method)
			}
			return
		}
		methodNotAllowed(w, Keystone, r.Method)
	})

	mux.HandleFunc("/v3/roles", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.String())
		mu.Lock()
		defer mu.Unlock()
		switch r.Method {
		case http.MethodGet:
			list := AsList(roles, func(rl *Role) map[string]interface{} { return rl.toMap() })
			writeJSON(w, map[string]interface{}{"roles": FilterList(list, r.URL.Query())})
			return
		case http.MethodPost:
			var req struct {
				Role struct {
					ID          string `json:"id"`
					Name        string `json:"name"`
					DomainID    string `json:"domain_id"`
					Description string `json:"description"`
				} `json:"role"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				badRequest(w, Keystone, "Invalid request body.")
				return
			}
			if req.Role.Name == "" {
				badRequest(w, Keystone, "Expecting to find name in role.")
				return
			}
			if req.Role.ID == "" {
				req.Role.ID = RandomID("role")
			}
			rl := &Role{ID: req.Role.ID, Name: req.Role.Name,
				DomainID: req.Role.DomainID, Description: req.Role.Description}
			roles[req.Role.ID] = rl
			writeJSONStatus(w, http.StatusCreated, map[string]interface{}{"role": rl.toMap()})
			return
		default:
			methodNotAllowed(w, Keystone, r.Method)
		}
	})

	mux.HandleFunc("/v3/roles/", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		log.Printf("%s %s", r.Method, r.URL.String())
		id := path.Base(r.URL.Path)
		rl, ok := roles[id]
		if !ok {
			notFound(w, Keystone, "Could not find role: "+id+".")
			return
		}
		switch r.Method {
		case http.MethodGet:
			writeJSON(w, map[string]interface{}{"role": rl.toMap()})
			return
		case http.MethodPatch, http.MethodPut:
			var req map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				badRequest(w, Keystone, "Invalid request body.")
				return
			}
			if rReq, ok := req["role"].(map[string]interface{}); ok {
				if name, ok := rReq["name"].(string); ok {
					rl.Name = name
				}
				if desc, ok := rReq["description"].(string); ok {
					rl.Description = desc
				}
			}
			writeJSON(w, map[string]interface{}{"role": rl.toMap()})
			return
		case http.MethodDelete:
			delete(roles, id)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		methodNotAllowed(w, Keystone, r.Method)
	})

	mux.HandleFunc("/v3/users", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.String())
		mu.Lock()
		defer mu.Unlock()
		if r.Method == http.MethodDelete {
			part := Parts(r.URL.Path)
			userID := part[len(part)-1]
			delete(users, userID)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method == http.MethodGet {
			list := AsList(users, func(u *User) map[string]interface{} { return u.toMap(baseURL) })
			writeJSON(w, map[string]interface{}{"users": FilterList(list, r.URL.Query())})
			return
		}
		if r.Method == http.MethodPost {
			var req struct {
				User struct {
					Name             string `json:"name"`
					DomainID         string `json:"domain_id"`
					DefaultProjectID string `json:"default_project_id"`
					Email            string `json:"email"`
					Description      string `json:"description"`
					Enabled          *bool  `json:"enabled"`
				} `json:"user"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				badRequest(w, Keystone, "Invalid request body.")
				return
			}
			id := RandomID("user")
			enabled := true
			if req.User.Enabled != nil {
				enabled = *req.User.Enabled
			}
			u := &User{
				ID: id, Name: req.User.Name, DomainID: req.User.DomainID,
				DefaultProjectID: req.User.DefaultProjectID, Email: req.User.Email,
				Description: req.User.Description, Enabled: enabled,
			}
			users[id] = u
			w.WriteHeader(http.StatusCreated)
			writeJSON(w, map[string]interface{}{"user": u.toMap(baseURL)})
			return
		}
	})

	mux.HandleFunc("/v3/users/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.String())
		mu.Lock()
		defer mu.Unlock()
		id := path.Base(r.URL.Path)
		u, ok := users[id]
		if !ok {
			notFound(w, Keystone, "Could not find user: "+id+".")
			return
		}
		switch r.Method {
		case http.MethodGet:
			writeJSON(w, map[string]interface{}{"user": u.toMap(baseURL)})
			return
		case http.MethodPatch, http.MethodPut:
			var req map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				badRequest(w, Keystone, "Invalid request body.")
				return
			}
			if userReq, ok := req["user"].(map[string]interface{}); ok {
				if v, ok := userReq["name"].(string); ok {
					u.Name = v
				}
				if v, ok := userReq["email"].(string); ok {
					u.Email = v
				}
				if v, ok := userReq["description"].(string); ok {
					u.Description = v
				}
				if v, ok := userReq["default_project_id"].(string); ok {
					u.DefaultProjectID = v
				}
				if v, ok := userReq["enabled"].(bool); ok {
					u.Enabled = v
				}
			}
			writeJSON(w, map[string]interface{}{"user": u.toMap(baseURL)})
			return
		case http.MethodDelete:
			delete(users, id)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		methodNotAllowed(w, Keystone, r.Method)
	})

	registerRoleAssignments(mux)
}
