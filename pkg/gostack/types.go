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

/* ============================
   Keystone
============================ */

// Domain represents a Keystone domain.
type Domain struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`
}

// User represents a Keystone user.
type User struct {
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	DomainID         string            `json:"domain_id"`
	DefaultProjectID string            `json:"default_project_id,omitempty"`
	Email            string            `json:"email,omitempty"`
	Description      string            `json:"description,omitempty"`
	Enabled          bool              `json:"enabled"`
	Federated        []interface{}     `json:"federated"`
	Links            map[string]string `json:"links"`
	PasswordExpires  *string           `json:"password_expires_at"`
}

// toMap renders a User as the map keystone returns (stable field set).
func (u *User) toMap(baseURL string) map[string]interface{} {
	return map[string]interface{}{
		"id": u.ID, "name": u.Name, "domain_id": u.DomainID,
		"default_project_id": u.DefaultProjectID, "enabled": u.Enabled,
		"email": u.Email, "description": u.Description,
		"federated":           []interface{}{},
		"links":               map[string]string{"self": baseURL + "/v3/users/" + u.ID},
		"password_expires_at": nil,
	}
}

// Project represents a Keystone project.
type Project struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	DomainID    string `json:"domain_id"`
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`
}

// toMap renders a Project as the map keystone returns.
func (p *Project) toMap() map[string]interface{} {
	return map[string]interface{}{
		"id": p.ID, "name": p.Name, "domain_id": p.DomainID,
		"description": p.Description, "enabled": p.Enabled,
	}
}

// Role represents a Keystone role.
type Role struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

/* ============================
   Nova
============================ */

// Server represents a Nova server.
type Server struct {
	ID         string              `json:"id"`
	Name       string              `json:"name"`
	Status     string              `json:"status"`
	Flavor     map[string]string   `json:"flavor"`
	Image      map[string]string   `json:"image"`
	Networks   []map[string]string `json:"addresses"`
	Project    string              `json:"project_id"`
	AccessIPv4 string              `json:"accessIPv4,omitempty"`
}

/* ============================
   Cinder
============================ */

// Volume represents a Cinder volume.
type Volume struct {
	ID          string                   `json:"id"`
	Name        string                   `json:"name"`
	Size        int                      `json:"size"`
	Status      string                   `json:"status"`
	Attachments []map[string]interface{} `json:"attachments"`
	Metadata    map[string]string        `json:"metadata"`
}
