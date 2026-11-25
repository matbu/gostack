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
	"strconv"
	"strings"
)

/* ============================
   Keystone
============================ */

// Domain represents a Keystone domain.
type Domain struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Enabled     bool     `json:"enabled"`
	Tags        []string `json:"tags"`
}

// toMap renders a Domain as the map keystone returns.
func (d *Domain) toMap(baseURL string) map[string]interface{} {
	tags := d.Tags
	if tags == nil {
		tags = []string{}
	}
	return map[string]interface{}{
		"id": d.ID, "name": d.Name, "description": d.Description,
		"enabled": d.Enabled, "tags": tags,
		"options": map[string]interface{}{},
		"links":   map[string]string{"self": baseURL + "/v3/domains/" + d.ID},
	}
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
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	DomainID    string   `json:"domain_id"`
	Description string   `json:"description"`
	Enabled     bool     `json:"enabled"`
	IsDomain    bool     `json:"is_domain"`
	ParentID    string   `json:"parent_id"`
	Tags        []string `json:"tags"`
}

// toMap renders a Project as the map keystone returns.
func (p *Project) toMap() map[string]interface{} {
	tags := p.Tags
	if tags == nil {
		tags = []string{}
	}
	parent := p.ParentID
	if parent == "" {
		parent = p.DomainID
	}
	return map[string]interface{}{
		"id": p.ID, "name": p.Name, "domain_id": p.DomainID,
		"description": p.Description, "enabled": p.Enabled,
		"is_domain": p.IsDomain, "parent_id": parent, "tags": tags,
		"options": map[string]interface{}{},
		"links":   map[string]string{"self": baseURL + "/v3/projects/" + p.ID},
	}
}

// Role represents a Keystone role.
type Role struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	DomainID    string `json:"domain_id"`
	Description string `json:"description"`
}

// toMap renders a Role as the map keystone returns. domain_id is null for a
// global role, which is what the role modules compare against.
func (r *Role) toMap() map[string]interface{} {
	out := map[string]interface{}{
		"id": r.ID, "name": r.Name,
		"description": r.Description,
		"options":     map[string]interface{}{},
		"links":       map[string]string{"self": baseURL + "/v3/roles/" + r.ID},
	}
	if r.DomainID == "" {
		out["domain_id"] = nil
	} else {
		out["domain_id"] = r.DomainID
	}
	return out
}

// Group represents a Keystone group.
type Group struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	DomainID    string `json:"domain_id"`
	Description string `json:"description"`
}

// toMap renders a Group as the map keystone returns.
func (g *Group) toMap() map[string]interface{} {
	return map[string]interface{}{
		"id": g.ID, "name": g.Name, "domain_id": g.DomainID,
		"description": g.Description,
		"links":       map[string]string{"self": baseURL + "/v3/groups/" + g.ID},
	}
}

// CatalogService represents a Keystone service catalog entry.
type CatalogService struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Type        string `json:"type"`
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`
}

// toMap renders a CatalogService as the map keystone returns.
func (s *CatalogService) toMap() map[string]interface{} {
	return map[string]interface{}{
		"id": s.ID, "name": s.Name, "type": s.Type,
		"description": s.Description, "enabled": s.Enabled,
		"links": map[string]string{"self": baseURL + "/v3/services/" + s.ID},
	}
}

// Endpoint represents a Keystone endpoint.
type Endpoint struct {
	ID        string `json:"id"`
	ServiceID string `json:"service_id"`
	Interface string `json:"interface"`
	URL       string `json:"url"`
	Region    string `json:"region"`
	Enabled   bool   `json:"enabled"`
}

// toMap renders an Endpoint as the map keystone returns.
func (e *Endpoint) toMap() map[string]interface{} {
	return map[string]interface{}{
		"id": e.ID, "service_id": e.ServiceID, "interface": e.Interface,
		"url": e.URL, "region": e.Region, "region_id": e.Region,
		"enabled": e.Enabled,
		"links":   map[string]string{"self": baseURL + "/v3/endpoints/" + e.ID},
	}
}

// Region represents a Keystone region.
type Region struct {
	ID           string `json:"id"`
	Description  string `json:"description"`
	ParentRegion string `json:"parent_region_id"`
}

// toMap renders a Region as the map keystone returns.
func (rg *Region) toMap() map[string]interface{} {
	var parent interface{}
	if rg.ParentRegion != "" {
		parent = rg.ParentRegion
	}
	return map[string]interface{}{
		"id": rg.ID, "description": rg.Description, "parent_region_id": parent,
		"links": map[string]string{"self": baseURL + "/v3/regions/" + rg.ID},
	}
}

/* ============================
   Nova
============================ */

// Server represents a Nova server.
type Server struct {
	ID             string              `json:"id"`
	Name           string              `json:"name"`
	Status         string              `json:"status"`
	Flavor         map[string]string   `json:"flavor"`
	Image          map[string]string   `json:"image"`
	Networks       []map[string]string `json:"addresses"`
	Project        string              `json:"project_id"`
	AccessIPv4     string              `json:"accessIPv4,omitempty"`
	KeyName        string              `json:"key_name"`
	Metadata       map[string]string   `json:"metadata"`
	SecurityGroups []string            `json:"-"`
	AvailZone      string              `json:"-"`
	Description    string              `json:"-"`
	UserData       string              `json:"-"`
	ConfigDrive    bool                `json:"-"`
	Created        string              `json:"-"`
	Updated        string              `json:"-"`
	TaskState      string              `json:"-"`
	PowerState     int                 `json:"-"`
	Locked         bool                `json:"-"`
	Tags           []string            `json:"-"`
}

// toMap renders a Server with the field set Nova returns from a detail
// listing. openstacksdk compares many of these when deciding whether a
// server needs updating, so none of them may be absent.
func (s *Server) toMap() map[string]interface{} {
	sgs := []map[string]interface{}{}
	for _, name := range s.SecurityGroups {
		sgs = append(sgs, map[string]interface{}{"name": name})
	}
	if len(sgs) == 0 {
		sgs = append(sgs, map[string]interface{}{"name": "default"})
	}
	meta := s.Metadata
	if meta == nil {
		meta = map[string]string{}
	}
	var keyName interface{}
	if s.KeyName != "" {
		keyName = s.KeyName
	}
	vmState := "active"
	if s.Status != "ACTIVE" {
		vmState = strings.ToLower(s.Status)
	}
	var taskState interface{}
	if s.TaskState != "" {
		taskState = s.TaskState
	}
	az := s.AvailZone
	if az == "" {
		az = "nova"
	}
	return map[string]interface{}{
		"id":                                   s.ID,
		"name":                                 s.Name,
		"status":                               s.Status,
		"flavor":                               s.Flavor,
		"image":                                s.Image,
		"addresses":                            BuildAddresses(s.Networks),
		"project_id":                           s.Project,
		"tenant_id":                            s.Project,
		"user_id":                              "demo-user",
		"created":                              s.Created,
		"updated":                              s.Updated,
		"launched_at":                          s.Created,
		"terminated_at":                        nil,
		"accessIPv4":                           s.AccessIPv4,
		"accessIPv6":                           "",
		"hostId":                               "fakehost-" + s.ID,
		"key_name":                             keyName,
		"metadata":                             meta,
		"description":                          s.Description,
		"locked":                               s.Locked,
		"config_drive":                         boolToNovaString(s.ConfigDrive),
		"security_groups":                      sgs,
		"tags":                                 serverTagList(s.Tags),
		"volumes_attached":                     attachedVolumesFor(s.ID),
		"os-extended-volumes:volumes_attached": attachedVolumesFor(s.ID),
		"OS-EXT-AZ:availability_zone":          az,
		"OS-EXT-STS:task_state":                taskState,
		"OS-EXT-STS:vm_state":                  vmState,
		"OS-EXT-STS:power_state":               s.PowerState,
		"OS-SRV-USG:launched_at":               s.Created,
		"OS-SRV-USG:terminated_at":             nil,
		"OS-DCF:diskConfig":                    "MANUAL",
		"progress":                             100,
		"links": []map[string]string{
			{"rel": "self", "href": baseURL + "/v2.1/servers/" + s.ID},
		},
	}
}

// boolToNovaString renders config_drive the way Nova does: "True" or "".
func boolToNovaString(b bool) string {
	if b {
		return "True"
	}
	return ""
}

// attachedVolumesFor lists the volume ids currently attached to a server.
// The caller must hold the state mutex.
func attachedVolumesFor(serverID string) []map[string]interface{} {
	out := []map[string]interface{}{}
	for _, v := range volumes {
		for _, a := range v.Attachments {
			if a["server_id"] == serverID {
				out = append(out, map[string]interface{}{"id": v.ID})
			}
		}
	}
	return out
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
	Description string                   `json:"description"`
	VolumeType  string                   `json:"volume_type"`
	Bootable    bool                     `json:"-"`
	Multiattach bool                     `json:"multiattach"`
	Encrypted   bool                     `json:"encrypted"`
	AvailZone   string                   `json:"availability_zone"`
	SnapshotID  string                   `json:"-"`
	SourceVolID string                   `json:"-"`
	ImageID     string                   `json:"-"`
	ProjectID   string                   `json:"-"`
	CreatedAt   string                   `json:"-"`
	UpdatedAt   string                   `json:"-"`
	ImageMeta   map[string]string        `json:"-"`
}

// toMap renders a Volume with the field set Cinder returns. "bootable" is a
// string in the Cinder API, not a boolean, and several of these fields are
// what openstacksdk compares when deciding whether a volume changed.
func (v *Volume) toMap() map[string]interface{} {
	meta := v.Metadata
	if meta == nil {
		meta = map[string]string{}
	}
	attachments := v.Attachments
	if attachments == nil {
		attachments = []map[string]interface{}{}
	}
	az := v.AvailZone
	if az == "" {
		az = "nova"
	}
	vt := v.VolumeType
	if vt == "" {
		vt = "__DEFAULT__"
	}
	out := map[string]interface{}{
		"id":                             v.ID,
		"name":                           v.Name,
		"size":                           v.Size,
		"status":                         v.Status,
		"attachments":                    attachments,
		"metadata":                       meta,
		"description":                    v.Description,
		"volume_type":                    vt,
		"bootable":                       strconv.FormatBool(v.Bootable),
		"multiattach":                    v.Multiattach,
		"encrypted":                      v.Encrypted,
		"availability_zone":              az,
		"created_at":                     v.CreatedAt,
		"updated_at":                     v.UpdatedAt,
		"replication_status":             nil,
		"consistencygroup_id":            nil,
		"group_id":                       nil,
		"user_id":                        "demo-user",
		"shareable":                      v.Multiattach,
		"os-vol-tenant-attr:tenant_id":   v.ProjectID,
		"os-vol-host-attr:host":          "fakehost@lvmdriver-1#lvmdriver-1",
		"os-vol-mig-status-attr:migstat": nil,
		"os-vol-mig-status-attr:name_id": nil,
		"migration_status":               nil,
		"links": []map[string]string{
			{"rel": "self", "href": baseURL + "/volume/v3/volumes/" + v.ID},
		},
	}
	if v.SnapshotID != "" {
		out["snapshot_id"] = v.SnapshotID
	} else {
		out["snapshot_id"] = nil
	}
	if v.SourceVolID != "" {
		out["source_volid"] = v.SourceVolID
	} else {
		out["source_volid"] = nil
	}
	if len(v.ImageMeta) > 0 {
		out["volume_image_metadata"] = v.ImageMeta
	}
	return out
}

// Snapshot represents a Cinder volume snapshot.
type Snapshot struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	VolumeID    string            `json:"volume_id"`
	Status      string            `json:"status"`
	Size        int               `json:"size"`
	Description string            `json:"description"`
	Metadata    map[string]string `json:"metadata"`
	ProjectID   string            `json:"-"`
	CreatedAt   string            `json:"-"`
	Force       bool              `json:"-"`
}

// toMap renders a Snapshot as Cinder returns it.
func (s *Snapshot) toMap() map[string]interface{} {
	meta := s.Metadata
	if meta == nil {
		meta = map[string]string{}
	}
	return map[string]interface{}{
		"id": s.ID, "name": s.Name, "volume_id": s.VolumeID,
		"status": s.Status, "size": s.Size, "description": s.Description,
		"metadata": meta, "created_at": s.CreatedAt, "updated_at": s.CreatedAt,
		"os-extended-snapshot-attributes:project_id": s.ProjectID,
		"os-extended-snapshot-attributes:progress":   "100%",
	}
}

// Backup represents a Cinder volume backup.
type Backup struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	VolumeID      string `json:"volume_id"`
	SnapshotID    string `json:"snapshot_id"`
	Status        string `json:"status"`
	Size          int    `json:"size"`
	Description   string `json:"description"`
	Force         bool   `json:"force"`
	IsIncremental bool   `json:"is_incremental"`
	ProjectID     string `json:"-"`
	CreatedAt     string `json:"-"`
	AvailZone     string `json:"-"`
}

// toMap renders a Backup as Cinder returns it.
func (b *Backup) toMap() map[string]interface{} {
	var snap interface{}
	if b.SnapshotID != "" {
		snap = b.SnapshotID
	}
	az := b.AvailZone
	if az == "" {
		az = "nova"
	}
	return map[string]interface{}{
		"id": b.ID, "name": b.Name, "volume_id": b.VolumeID,
		"snapshot_id": snap, "status": b.Status, "size": b.Size,
		"description": b.Description, "is_incremental": b.IsIncremental,
		"has_dependent_backups": false, "availability_zone": az,
		"container": "volumebackups", "fail_reason": nil,
		"created_at": b.CreatedAt, "updated_at": b.CreatedAt,
		"data_timestamp": b.CreatedAt, "object_count": 0,
		"os-backup-project-attr:project_id": b.ProjectID,
	}
}

// VolumeType represents a Cinder volume type.
type VolumeType struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	IsPublic    bool              `json:"is_public"`
	ExtraSpecs  map[string]string `json:"extra_specs"`
}

// toMap renders a VolumeType as Cinder returns it.
func (t *VolumeType) toMap() map[string]interface{} {
	specs := t.ExtraSpecs
	if specs == nil {
		specs = map[string]string{}
	}
	var desc interface{}
	if t.Description != "" {
		desc = t.Description
	}
	return map[string]interface{}{
		"id": t.ID, "name": t.Name, "description": desc,
		"is_public": t.IsPublic, "os-volume-type-access:is_public": t.IsPublic,
		"extra_specs": specs, "qos_specs_id": nil,
	}
}

// serverTagList renders a server's tags, never as null.
func serverTagList(tags []string) []string {
	if tags == nil {
		return []string{}
	}
	return tags
}
