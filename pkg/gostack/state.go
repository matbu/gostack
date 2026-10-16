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
	mu       sync.Mutex
	tokenMu  sync.RWMutex
	domains  = map[string]*Domain{
		"default": {ID: "default", Name: "default", Enabled: true},
	}
	users    = map[string]*User{}
	projects = map[string]*Project{
		"demo":        {ID: "demo", Name: "source", DomainID: "default", Enabled: true},
		"destination": {ID: "destination", Name: "destination", DomainID: "default", Enabled: true},
	}
	roles         = map[string]*Role{
		"member": {ID: "member", Name: "member"},
		"admin":  {ID: "admin", Name: "admin"},
	}
	tokenProjects = map[string]string{}
)

/* ============================
   Nova
============================ */

var (
	servers         = map[string]*Server{}
	serverID        = 1
	flavors         = []map[string]interface{}{
		{"id": "1", "name": "small", "ram": 2048, "vcpus": 1, "disk": 20},
		{"id": "2", "name": "medium", "ram": 4096, "vcpus": 2, "disk": 40},
		{"id": "3", "name": "large", "ram": 8192, "vcpus": 4, "disk": 80},
	}
	flavorExtraSpecs = map[string]map[string]string{
		"osm_flavor": {},
	}
	flavorSeq = 3
	keypairs  = []map[string]interface{}{}
)

/* ============================
   Cinder
============================ */

var (
	volumes  = map[string]*Volume{
		"vol-1": {ID: "vol-1", Name: "volume-1", Size: 10, Status: "available", Attachments: []map[string]interface{}{}, Metadata: map[string]string{}},
	}
	volumeID = 1
)

/* ============================
   Glance
============================ */

var images = []map[string]interface{}{
	{"id": "img-1", "name": "cirros", "status": "active", "owner": "demo", "visibility": "public"},
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
		{"id": "nsg-1", "name": "default"},
	}

	// baseURL is set by NewFakeServer for catalog/links (e.g. "http://127.0.0.1:5000").
	baseURL = "http://127.0.0.1:5000"
)

// SetBaseURL sets the base URL for catalog and link responses.
func SetBaseURL(url string) {
	baseURL = url
}
