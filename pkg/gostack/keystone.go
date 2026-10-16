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
func RegisterKeystoneHandlers(mux *http.ServeMux, roleAssignments map[string]map[string][]string) {
	mux.HandleFunc("/v3", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.String())
		log.Printf("%s %s", r.URL.Path, r.URL.RawQuery)
		err := json.NewEncoder(w).Encode(map[string]interface{}{
			"version": map[string]interface{}{
				"id":     "v3.14",
				"status": "stable",
				"links": []map[string]string{
					{"rel": "self", "href": baseURL + "/v3/"},
				},
			},
		})
		if err != nil {
			log.Printf("Error encoding JSON response: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
	})

	mux.HandleFunc("/v3/auth/tokens", func(w http.ResponseWriter, r *http.Request) {
		projectID := "source"
		projectName := "source"
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
				if authReq.Auth.Scope.Project.ID != "" {
					projectID = authReq.Auth.Scope.Project.ID
				}
				if authReq.Auth.Scope.Project.Name != "" {
					projectName = authReq.Auth.Scope.Project.Name
				}
			}
		}
		if p, ok := projects[projectID]; ok {
			projectID = p.ID
			projectName = p.Name
		} else if p, ok := projects[projectName]; ok {
			projectID = p.ID
			projectName = p.Name
		} else {
			for _, p := range projects {
				if p.Name == projectName {
					projectID = p.ID
					projectName = p.Name
					break
				}
			}
		}
		token := "fake-token-" + projectID
		w.Header().Set("X-Subject-Token", token)
		tokenMu.Lock()
		tokenProjects[token] = projectID
		tokenMu.Unlock()
		w.WriteHeader(http.StatusCreated)
		catalog := []map[string]interface{}{
			{
				"type": "identity",
				"name": "keystone",
				"endpoints": []map[string]interface{}{
					{
						"id": "keystone-public", "interface": "public",
						"region": "RegionOne", "region_id": "RegionOne",
						"url": baseURL + "/v3/",
					},
				},
			},
			{
				"type": "compute",
				"name": "nova",
				"endpoints": []map[string]interface{}{
					{
						"id": "nova-public", "interface": "public",
						"region": "RegionOne", "region_id": "RegionOne",
						"url": baseURL + "/v2.1/" + projectID,
					},
				},
			},
			{
				"type": "network",
				"name": "neutron",
				"endpoints": []map[string]interface{}{
					{
						"id": "neutron-public", "interface": "public",
						"region": "RegionOne", "region_id": "RegionOne",
						"url": baseURL + "/v2.0",
					},
				},
			},
			{
				"type": "image",
				"name": "glance",
				"endpoints": []map[string]interface{}{
					{
						"id": "glance-public", "interface": "public",
						"region": "RegionOne", "region_id": "RegionOne",
						"url": baseURL + "/v2",
					},
				},
			},
			{
				"type": "volumev3",
				"name": "cinder",
				"endpoints": []map[string]interface{}{
					{
						"id": "cinder-public", "interface": "public",
						"region": "RegionOne", "region_id": "RegionOne",
						"url": baseURL + "/v3/" + projectID,
					},
				},
			},
		}
		err := json.NewEncoder(w).Encode(map[string]interface{}{
			"token": map[string]interface{}{
				"expires_at": "2099-01-01T00:00:00.000000Z",
				"issued_at":  "2026-01-01T00:00:00.000000Z",
				"project": map[string]string{"id": projectID, "name": projectName},
				"user": map[string]string{"id": "demo-user", "name": "demo"},
				"catalog": catalog,
			},
		})
		if err != nil {
			log.Printf("Error encoding JSON response: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
	})

	mux.HandleFunc("/v3/domains", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		log.Printf("%s %s", r.Method, r.URL.String())
		if r.Method == http.MethodGet {
			nameFilter := r.URL.Query().Get("name")
			list := []interface{}{}
			for _, d := range domains {
				if nameFilter != "" && d.Name != nameFilter {
					continue
				}
				list = append(list, d)
			}
			writeJSON(w, map[string]interface{}{"domains": list})
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
				http.Error(w, "invalid JSON body", http.StatusBadRequest)
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
			w.WriteHeader(http.StatusCreated)
			writeJSON(w, map[string]interface{}{"domain": domains[id]})
			return
		}
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	})

	mux.HandleFunc("/v3/domains/", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		log.Printf("%s %s", r.Method, r.URL.String())
		id := Parts(r.URL.Path)[2]
		d, ok := domains[id]
		if !ok {
			http.NotFound(w, r)
			return
		}
		switch r.Method {
		case http.MethodGet:
			writeJSON(w, map[string]interface{}{"domain": d})
		case http.MethodPatch:
			var req struct {
				Domain struct {
					Name        *string `json:"name"`
					Description *string `json:"description"`
					Enabled     *bool   `json:"enabled"`
				} `json:"domain"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "invalid JSON body", http.StatusBadRequest)
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
			writeJSON(w, map[string]interface{}{"domain": d})
		case http.MethodDelete:
			delete(domains, id)
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/v3/projects", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		log.Printf("%s %s", r.Method, r.URL.String())
		if r.Method == http.MethodGet {
			name := r.URL.Query().Get("name")
			list := []interface{}{}
			for _, p := range projects {
				if name != "" && p.Name != name {
					continue
				}
				list = append(list, p.toMap())
			}
			writeJSON(w, map[string]interface{}{"projects": list})
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
				http.Error(w, "invalid JSON body", http.StatusBadRequest)
				return
			}
			if req.Project.Name == "" {
				http.Error(w, "Missing project name", http.StatusBadRequest)
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
			writeJSON(w, map[string]interface{}{"project": p})
			return
		}
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
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
					http.Error(w, "invalid JSON body", http.StatusBadRequest)
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
				writeJSON(w, map[string]interface{}{"project": p})
				return
			}
			if r.Method == http.MethodGet {
				name := r.URL.Query().Get("name")
				list := []interface{}{}
				for _, p := range projects {
					if name != "" && p.Name != name {
						continue
					}
					list = append(list, p.toMap())
				}
				writeJSON(w, map[string]interface{}{"projects": list})
				return
			}
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// GET /v3/projects/{proj}/users/{user}/roles
		if len(pathParts) == 6 && pathParts[3] == "users" && pathParts[5] == "roles" && r.Method == http.MethodGet {
			projectID := pathParts[2]
			userID := pathParts[4]
			userRoles := []map[string]string{}
			if projMap, ok := roleAssignments[projectID]; ok {
				if roleIDs, ok := projMap[userID]; ok {
					for _, roleID := range roleIDs {
						if role, ok := roles[roleID]; ok {
							userRoles = append(userRoles, map[string]string{"id": role.ID, "name": role.Name})
						}
					}
				}
			}
			writeJSON(w, map[string]interface{}{"roles": userRoles})
			return
		}
		// PUT/HEAD/GET/DELETE /v3/projects/{proj}/users/{user}/roles/{role}
		if len(pathParts) == 7 && pathParts[3] == "users" && pathParts[5] == "roles" {
			projectID := pathParts[2]
			userID := pathParts[4]
			roleID := pathParts[6]
			assigned := false
			for _, rid := range roleAssignments[projectID][userID] {
				if rid == roleID {
					assigned = true
				}
			}
			switch r.Method {
			case http.MethodPut:
				if _, ok := roleAssignments[projectID]; !ok {
					roleAssignments[projectID] = map[string][]string{}
				}
				if !assigned {
					roleAssignments[projectID][userID] = append(roleAssignments[projectID][userID], roleID)
				}
				w.WriteHeader(http.StatusNoContent)
			case http.MethodHead, http.MethodGet:
				if assigned {
					w.WriteHeader(http.StatusNoContent)
				} else {
					http.NotFound(w, r)
				}
			case http.MethodDelete:
				out := []string{}
				for _, rid := range roleAssignments[projectID][userID] {
					if rid != roleID {
						out = append(out, rid)
					}
				}
				roleAssignments[projectID][userID] = out
				w.WriteHeader(http.StatusNoContent)
			default:
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			}
			return
		}
		// GET/PATCH/DELETE /v3/projects/{proj}
		if len(pathParts) == 3 {
			projectID := pathParts[2]
			p, ok := projects[projectID]
			if !ok {
				http.NotFound(w, r)
				return
			}
			switch r.Method {
			case http.MethodGet:
				writeJSON(w, map[string]interface{}{"project": p})
			case http.MethodPatch:
				var req struct {
					Project struct {
						Name        *string `json:"name"`
						Description *string `json:"description"`
						Enabled     *bool   `json:"enabled"`
					} `json:"project"`
				}
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					http.Error(w, "invalid JSON body", http.StatusBadRequest)
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
				writeJSON(w, map[string]interface{}{"project": p})
			case http.MethodDelete:
				delete(projects, projectID)
				w.WriteHeader(http.StatusNoContent)
			default:
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			}
			return
		}
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	})

	mux.HandleFunc("/v3/roles", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.String())
		switch r.Method {
		case http.MethodGet:
			name := r.URL.Query().Get("name")
			list := []interface{}{}
			for _, role := range roles {
				if name != "" && role.Name != name {
					continue
				}
				list = append(list, map[string]interface{}{"id": role.ID, "name": role.Name})
			}
			err := json.NewEncoder(w).Encode(map[string]interface{}{"roles": list})
			if err != nil {
				log.Printf("Error encoding JSON response: %v", err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
			return
		case http.MethodPost:
			var req struct {
				Role struct {
					ID   string `json:"id"`
					Name string `json:"name"`
				} `json:"role"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "Invalid JSON body", http.StatusBadRequest)
				return
			}
			if req.Role.Name == "" {
				http.Error(w, "Missing role id or name", http.StatusBadRequest)
				return
			}
			if req.Role.ID == "" {
				req.Role.ID = RandomID("role")
			}
			rl := &Role{ID: req.Role.ID, Name: req.Role.Name}
			roles[req.Role.ID] = rl
			w.WriteHeader(http.StatusCreated)
			err := json.NewEncoder(w).Encode(map[string]interface{}{"role": rl})
			if err != nil {
				log.Printf("Error encoding JSON response: %v", err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
			return
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/v3/roles/", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		log.Printf("%s %s", r.Method, r.URL.String())
		id := path.Base(r.URL.Path)
		rl, ok := roles[id]
		if !ok {
			http.NotFound(w, r)
			return
		}
		switch r.Method {
		case http.MethodGet:
			err := json.NewEncoder(w).Encode(map[string]interface{}{
				"role": map[string]interface{}{"id": rl.ID, "name": rl.Name},
			})
			if err != nil {
				log.Printf("Error encoding JSON response: %v", err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
			return
		case http.MethodPatch, http.MethodPut:
			var req map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "invalid JSON body", http.StatusBadRequest)
				return
			}
			if rReq, ok := req["role"].(map[string]interface{}); ok {
				if name, ok := rReq["name"].(string); ok {
					rl.Name = name
				}
			}
			err := json.NewEncoder(w).Encode(map[string]interface{}{
				"user": map[string]interface{}{"id": rl.ID, "name": rl.Name},
			})
			if err != nil {
				log.Printf("Error encoding JSON response: %v", err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
			return
		case http.MethodDelete:
			delete(roles, id)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
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
			name := r.URL.Query().Get("name")
			list := []interface{}{}
			for _, u := range users {
				if name != "" && u.Name != name && u.ID != name {
					continue
				}
				list = append(list, u.toMap(baseURL))
			}
			writeJSON(w, map[string]interface{}{"users": list})
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
				http.Error(w, "invalid JSON body", http.StatusBadRequest)
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
			http.NotFound(w, r)
			return
		}
		switch r.Method {
		case http.MethodGet:
			writeJSON(w, map[string]interface{}{"user": u.toMap(baseURL)})
			return
		case http.MethodPatch, http.MethodPut:
			var req map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "invalid JSON body", http.StatusBadRequest)
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
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	})

	mux.HandleFunc("/v3/role_assignments", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.String())
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		q := r.URL.Query()
		userFilter := q.Get("user.id")
		projectFilter := q.Get("scope.project.id")
		if projectFilter == "" {
			projectFilter = q.Get("project.id")
		}
		roleFilter := q.Get("role.id")

		mu.Lock()
		list := []interface{}{}
		for projID, userMap := range roleAssignments {
			if projectFilter != "" && projID != projectFilter {
				continue
			}
			for userID, roleIDs := range userMap {
				if userFilter != "" && userID != userFilter {
					continue
				}
				for _, roleID := range roleIDs {
					if roleFilter != "" && roleID != roleFilter {
						continue
					}
					// Populate names (keystone does this for ?include_names=True).
					userObj := map[string]string{"id": userID}
					if u, ok := users[userID]; ok {
						userObj["name"] = u.Name
						userObj["domain_id"] = u.DomainID
					}
					roleObj := map[string]string{"id": roleID}
					if rl, ok := roles[roleID]; ok {
						roleObj["name"] = rl.Name
					}
					projObj := map[string]interface{}{"id": projID}
					if pr, ok := projects[projID]; ok {
						projObj["name"] = pr.Name
						projObj["domain_id"] = pr.DomainID
					}
					list = append(list, map[string]interface{}{
						"role":  roleObj,
						"scope": map[string]interface{}{"project": projObj},
						"user":  userObj,
						"links": map[string]string{"assignment": baseURL + "/v3/role_assignments"},
					})
				}
			}
		}
		mu.Unlock()
		writeJSON(w, map[string]interface{}{"role_assignments": list})
	})
}
