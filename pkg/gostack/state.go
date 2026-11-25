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

import "sync"

// Package-level state for the fake OpenStack API (shared across handlers).
var (
	mu      sync.Mutex
	tokenMu sync.RWMutex
	domains = map[string]*Domain{
		"default": {ID: "default", Name: "Default", Enabled: true,
			Description: "The default domain"},
	}
	users = map[string]*User{
		"demo-user":  {ID: "demo-user", Name: "demo", DomainID: "default", Enabled: true},
		"admin-user": {ID: "admin-user", Name: "admin", DomainID: "default", Enabled: true},
	}
	projects = map[string]*Project{
		"demo":        {ID: "demo", Name: "source", DomainID: "default", Enabled: true},
		"destination": {ID: "destination", Name: "destination", DomainID: "default", Enabled: true},
		"admin":       {ID: "admin", Name: "admin", DomainID: "default", Enabled: true},
	}
	roles = map[string]*Role{
		"member": {ID: "member", Name: "member"},
		"admin":  {ID: "admin", Name: "admin"},
		"reader": {ID: "reader", Name: "reader"},
		// devstack creates a spare role for assignment tests.
		"anotherrole": {ID: "anotherrole", Name: "anotherrole"},
	}
	groups = map[string]*Group{
		// devstack creates a spare group for assignment tests.
		"nonadmins": {ID: "nonadmins", Name: "nonadmins", DomainID: "default"},
	}
	// The catalog is also exposed as editable Keystone resources, seeded to
	// match the endpoints the token catalog advertises.
	catalogServices = map[string]*CatalogService{
		"keystone": {ID: "keystone", Name: "keystone", Type: "identity", Enabled: true},
		"nova":     {ID: "nova", Name: "nova", Type: "compute", Enabled: true},
		"neutron":  {ID: "neutron", Name: "neutron", Type: "network", Enabled: true},
		"glance":   {ID: "glance", Name: "glance", Type: "image", Enabled: true},
		"cinder":   {ID: "cinder", Name: "cinder", Type: "volumev3", Enabled: true},
	}
	catalogEndpoints = map[string]*Endpoint{}
	regions          = map[string]*Region{
		"RegionOne": {ID: "RegionOne", Description: ""},
	}
	tokenProjects = map[string]string{}

	// defaultProjectID and defaultProjectName scope a token whose request
	// named no project, and are reset by the seed profile.
	defaultProjectID   = "demo"
	defaultProjectName = "source"
)

/* ============================
   Nova
============================ */

var (
	servers  = map[string]*Server{}
	serverID = 1
	// The original flavors keep ids 1-3: os-migrate and the VMware
	// migration kit assert on them by id, so these must not be renumbered.
	// devstack's m1.* names are appended for suites that assume them.
	flavors = []map[string]interface{}{
		{"id": "1", "name": "small", "ram": 2048, "vcpus": 1, "disk": 20},
		{"id": "2", "name": "medium", "ram": 4096, "vcpus": 2, "disk": 40},
		{"id": "3", "name": "large", "ram": 8192, "vcpus": 4, "disk": 80},
		{"id": "4", "name": "m1.tiny", "ram": 512, "vcpus": 1, "disk": 1},
		{"id": "5", "name": "m1.small", "ram": 2048, "vcpus": 1, "disk": 20},
		{"id": "6", "name": "m1.medium", "ram": 4096, "vcpus": 2, "disk": 40},
		{"id": "7", "name": "m1.large", "ram": 8192, "vcpus": 4, "disk": 80},
		{"id": "8", "name": "m1.xlarge", "ram": 16384, "vcpus": 8, "disk": 160},
	}
	flavorExtraSpecs = map[string]map[string]string{
		"osm_flavor": {},
	}
	// flavorAccess maps a private flavor id to the projects granted access.
	flavorAccess = map[string][]string{}
	flavorSeq    = 8
	keypairs     = []map[string]interface{}{}
	serverGroups = map[string]map[string]interface{}{}
	aggregates   = map[string]map[string]interface{}{}
	aggregateSeq = 0
)

/* ============================
   Cinder
============================ */

var (
	volumes = map[string]*Volume{
		"vol-1": {ID: "vol-1", Name: "volume-1", Size: 10, Status: "available",
			Attachments: []map[string]interface{}{}, Metadata: map[string]string{},
			ProjectID: "demo"},
	}
	volumeID    = 1
	snapshots   = map[string]*Snapshot{}
	snapshotSeq = 0
	backups     = map[string]*Backup{}
	backupSeq   = 0
	volumeTypes = map[string]*VolumeType{
		"__DEFAULT__": {ID: "__DEFAULT__", Name: "__DEFAULT__", IsPublic: true,
			Description: "Default Volume Type", ExtraSpecs: map[string]string{}},
	}
	// volumeTypeAccess maps a private volume type id to the projects granted
	// access to it.
	volumeTypeAccess = map[string][]string{}
)

/* ============================
   Glance
============================ */

var images = []map[string]interface{}{
	{"id": "img-1", "name": "cirros", "status": "active", "owner": "demo",
		"visibility": "public", "disk_format": "qcow2", "container_format": "bare",
		"min_disk": 0, "min_ram": 0, "protected": false, "tags": []interface{}{},
		"size": 13287936, "virtual_size": nil, "checksum": "443b7623e27ecf03dc9e01ee93f67afe"},
}

/* ============================
   Neutron
============================ */

var (
	networks = []map[string]interface{}{
		{"id": "net-1", "name": "private", "project_id": "demo"},
		// External provider network used as the router gateway in func tests.
		{"id": "public", "name": "public", "project_id": "demo",
			"router:external": true, "shared": true, "status": "ACTIVE"},
	}
	subnets = []map[string]interface{}{}
	ports   = []map[string]interface{}{
		{
			"id":                "port-sriov",
			"network_id":        "net-1",
			"binding:vnic_type": "direct",
			"project_id":        "demo",
			"device_owner":      "",
			"device_id":         nil,
			"status":            "DOWN",
		},
	}
	neutronSecGroups = []map[string]interface{}{
		{"id": "nsg-1", "name": "default", "project_id": "demo",
			"description": "Default security group"},
	}
	floatingIPs   = []map[string]interface{}{}
	floatingIPSeq = 0
	addressScopes = []map[string]interface{}{}
	subnetPools   = []map[string]interface{}{}
	netSegments   = []map[string]interface{}{}
	rbacPolicies  = []map[string]interface{}{}
	trunks        = []map[string]interface{}{}
	neutronSeq    = 0

	// baseURL is set by NewFakeServer for catalog/links (e.g. "http://127.0.0.1:5000").
	baseURL = "http://127.0.0.1:5000"
)

// quotaStore holds per-project quota overrides, keyed by project then by
// quota name. Absent entries fall back to the service defaults.
var (
	novaQuotas    = map[string]map[string]int{}
	cinderQuotas  = map[string]map[string]int{}
	neutronQuotas = map[string]map[string]int{}
)

// SetBaseURL sets the base URL for catalog and link responses.
func SetBaseURL(url string) {
	baseURL = url
}

// Seed profiles select which sample resources the cloud starts with.
const (
	// SeedOSMigrate is gostack's historical seed: a volume, an SR-IOV
	// port and the networks os-migrate's own export tests read.
	SeedOSMigrate = "osmigrate"
	// SeedDevstack starts with what a freshly stacked devstack has — a
	// cirros image, the private and public networks, and a default
	// security group — and nothing else. Conformance suites written
	// against a real cloud assume this baseline and index into listings,
	// so a stray pre-seeded volume or port makes them fail.
	SeedDevstack = "devstack"
)

// ApplySeedProfile resets the tenant collections to the chosen profile.
// An unknown name leaves the default seed in place.
func ApplySeedProfile(profile string) {
	if profile != SeedDevstack {
		return
	}
	// A suite written against a real cloud authenticates as admin, lists
	// resources across projects, and expects responses to carry exactly
	// what the real services send.
	SetAdminScope(true)
	SetStrictResponses(true)
	mu.Lock()
	defer mu.Unlock()

	// Collections a fresh devstack has nothing in.
	volumes = map[string]*Volume{}
	snapshots = map[string]*Snapshot{}
	backups = map[string]*Backup{}
	servers = map[string]*Server{}
	serverGroups = map[string]map[string]interface{}{}
	aggregates = map[string]map[string]interface{}{}
	keypairs = []map[string]interface{}{}
	ports = []map[string]interface{}{}
	routers = []map[string]interface{}{}
	floatingIPs = []map[string]interface{}{}
	addressScopes = []map[string]interface{}{}
	subnetPools = []map[string]interface{}{}
	netSegments = []map[string]interface{}{}
	rbacPolicies = []map[string]interface{}{}
	trunks = []map[string]interface{}{}
	neutronSecGroupRules = []map[string]interface{}{}

	// devstack's projects, replacing gostack's own. They have to replace
	// rather than extend them: the default seed has a project whose *id*
	// is "demo" but whose name is "source", and a client looking up "demo"
	// would match both it and a project actually named demo.
	projects = map[string]*Project{
		"demo":               {ID: "demo", Name: "demo", DomainID: "default", Enabled: true},
		"admin":              {ID: "admin", Name: "admin", DomainID: "default", Enabled: true},
		"alt_demo":           {ID: "alt_demo", Name: "alt_demo", DomainID: "default", Enabled: true},
		"service":            {ID: "service", Name: "service", DomainID: "default", Enabled: true},
		"invisible_to_admin": {ID: "invisible_to_admin", Name: "invisible_to_admin", DomainID: "default", Enabled: true},
	}
	defaultProjectID, defaultProjectName = "demo", "demo"

	// What devstack does leave behind.
	images = []map[string]interface{}{
		{"id": "img-1", "name": "cirros-0.6.2-x86_64-disk", "status": "active",
			"owner": "demo", "visibility": "public", "disk_format": "qcow2",
			"container_format": "bare", "min_disk": 0, "min_ram": 0,
			"protected": false, "tags": []interface{}{}, "size": 21430272,
			"virtual_size": nil, "checksum": "443b7623e27ecf03dc9e01ee93f67afe"},
	}
	networks = []map[string]interface{}{
		{"id": "net-1", "name": "private", "project_id": "demo"},
		{"id": "public", "name": "public", "project_id": "demo",
			"router:external": true, "shared": true, "status": "ACTIVE"},
		{"id": "shared", "name": "shared", "project_id": "demo", "shared": true},
	}
	subnets = []map[string]interface{}{
		{"id": "subnet-private", "name": "private-subnet", "network_id": "net-1",
			"project_id": "demo", "cidr": "10.0.0.0/26", "ip_version": 4},
		{"id": "subnet-public", "name": "public-subnet", "network_id": "public",
			"project_id": "demo", "cidr": "172.24.4.0/24", "ip_version": 4},
	}
	neutronSecGroups = []map[string]interface{}{
		{"id": "nsg-1", "name": "default", "project_id": "demo",
			"description": "Default security group"},
	}
}
