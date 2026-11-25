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
	"log"
	"net/http"
)

// RoleAssignment is one grant of a role to an actor on a scope. Keystone
// allows the actor to be a user or a group, and the scope to be a project or
// a domain, so all four combinations have to be representable.
type RoleAssignment struct {
	// ActorType is "user" or "group".
	ActorType string
	ActorID   string
	// ScopeType is "project" or "domain".
	ScopeType string
	ScopeID   string
	RoleID    string
}

// roleAssignmentList holds every grant. A slice keeps all four
// actor/scope combinations in one place, which a nested map cannot.
var roleAssignmentList []RoleAssignment

// findAssignment returns the index of a matching grant, or -1.
// The caller must hold the state mutex.
func findAssignment(a RoleAssignment) int {
	for i, existing := range roleAssignmentList {
		if existing == a {
			return i
		}
	}
	return -1
}

// grantRole records a role assignment, ignoring a duplicate.
// The caller must hold the state mutex.
func grantRole(a RoleAssignment) {
	if findAssignment(a) == -1 {
		roleAssignmentList = append(roleAssignmentList, a)
	}
}

// revokeRole removes a role assignment if present, reporting whether it was.
// The caller must hold the state mutex.
func revokeRole(a RoleAssignment) bool {
	i := findAssignment(a)
	if i == -1 {
		return false
	}
	roleAssignmentList = append(roleAssignmentList[:i], roleAssignmentList[i+1:]...)
	return true
}

// assignmentDocument renders one grant the way GET /v3/role_assignments does.
// The caller must hold the state mutex.
func (a RoleAssignment) toMap() map[string]interface{} {
	role := map[string]interface{}{"id": a.RoleID}
	if rl, ok := roles[a.RoleID]; ok {
		role["name"] = rl.Name
	}

	actor := map[string]interface{}{"id": a.ActorID}
	switch a.ActorType {
	case "user":
		if u, ok := users[a.ActorID]; ok {
			actor["name"] = u.Name
			actor["domain_id"] = u.DomainID
		}
	case "group":
		if g, ok := groups[a.ActorID]; ok {
			actor["name"] = g.Name
			actor["domain_id"] = g.DomainID
		}
	}

	scopeTarget := map[string]interface{}{"id": a.ScopeID}
	switch a.ScopeType {
	case "project":
		if p, ok := projects[a.ScopeID]; ok {
			scopeTarget["name"] = p.Name
			scopeTarget["domain_id"] = p.DomainID
		}
	case "domain":
		if d, ok := domains[a.ScopeID]; ok {
			scopeTarget["name"] = d.Name
		}
	}

	return map[string]interface{}{
		"role":      role,
		a.ActorType: actor,
		"scope":     map[string]interface{}{a.ScopeType: scopeTarget},
		"links":     map[string]string{"assignment": baseURL + "/v3/role_assignments"},
	}
}

// serveRoleGrants handles the grant sub-resource under a project or domain:
//
//	GET    /v3/{projects|domains}/{id}/{users|groups}/{id}/roles
//	PUT    /v3/{projects|domains}/{id}/{users|groups}/{id}/roles/{role}
//	HEAD   ... same
//	DELETE ... same
//
// parts is the full split path. It reports whether it handled the request.
func serveRoleGrants(w http.ResponseWriter, r *http.Request, parts []string) bool {
	// Canonical layout:
	// [v3, {scope}s, {scope_id}, {actor}s, {actor_id}, roles, {role_id}?]
	if len(parts) < 6 || parts[5] != "roles" {
		return false
	}
	a := RoleAssignment{ScopeID: parts[2], ActorID: parts[4]}
	switch parts[1] {
	case "projects":
		a.ScopeType = "project"
	case "domains":
		a.ScopeType = "domain"
	default:
		return false
	}
	switch parts[3] {
	case "users":
		a.ActorType = "user"
	case "groups":
		a.ActorType = "group"
	default:
		return false
	}

	// Listing the roles an actor holds on a scope.
	if len(parts) == 6 {
		if r.Method != http.MethodGet {
			methodNotAllowed(w, Keystone, r.Method)
			return true
		}
		list := []map[string]interface{}{}
		for _, existing := range roleAssignmentList {
			if existing.ActorType != a.ActorType || existing.ActorID != a.ActorID ||
				existing.ScopeType != a.ScopeType || existing.ScopeID != a.ScopeID {
				continue
			}
			if rl, ok := roles[existing.RoleID]; ok {
				list = append(list, rl.toMap())
			}
		}
		writeJSON(w, map[string]interface{}{"roles": list})
		return true
	}

	a.RoleID = parts[6]
	switch r.Method {
	case http.MethodPut:
		grantRole(a)
		w.WriteHeader(http.StatusNoContent)
	case http.MethodHead, http.MethodGet:
		if findAssignment(a) != -1 {
			w.WriteHeader(http.StatusNoContent)
		} else {
			notFound(w, Keystone, "Role assignment")
		}
	case http.MethodDelete:
		if !revokeRole(a) {
			notFound(w, Keystone, "Role assignment")
			return true
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w, Keystone, r.Method)
	}
	return true
}

// registerRoleAssignments implements GET /v3/role_assignments.
func registerRoleAssignments(mux *http.ServeMux) {
	mux.HandleFunc("/v3/role_assignments", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.String())
		if r.Method != http.MethodGet {
			methodNotAllowed(w, Keystone, r.Method)
			return
		}
		q := r.URL.Query()
		userFilter := q.Get("user.id")
		groupFilter := q.Get("group.id")
		roleFilter := q.Get("role.id")
		projectFilter := q.Get("scope.project.id")
		if projectFilter == "" {
			projectFilter = q.Get("project.id")
		}
		domainFilter := q.Get("scope.domain.id")
		if domainFilter == "" {
			domainFilter = q.Get("domain.id")
		}

		mu.Lock()
		list := []map[string]interface{}{}
		for _, a := range roleAssignmentList {
			if roleFilter != "" && a.RoleID != roleFilter {
				continue
			}
			if userFilter != "" && (a.ActorType != "user" || a.ActorID != userFilter) {
				continue
			}
			if groupFilter != "" && (a.ActorType != "group" || a.ActorID != groupFilter) {
				continue
			}
			if projectFilter != "" && (a.ScopeType != "project" || a.ScopeID != projectFilter) {
				continue
			}
			if domainFilter != "" && (a.ScopeType != "domain" || a.ScopeID != domainFilter) {
				continue
			}
			list = append(list, a.toMap())
		}
		mu.Unlock()
		writeJSON(w, map[string]interface{}{"role_assignments": list})
	})
}
