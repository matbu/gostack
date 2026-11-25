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
	"testing"

	"github.com/stretchr/testify/assert"
)

// withProjects swaps the project store for the duration of a test.
func withProjects(t *testing.T, replacement map[string]*Project, defaultID, defaultName string) {
	t.Helper()
	mu.Lock()
	savedProjects := projects
	savedID, savedName := defaultProjectID, defaultProjectName
	projects = replacement
	defaultProjectID, defaultProjectName = defaultID, defaultName
	mu.Unlock()

	t.Cleanup(func() {
		mu.Lock()
		projects = savedProjects
		defaultProjectID, defaultProjectName = savedID, savedName
		mu.Unlock()
	})
}

func TestResolveScope(t *testing.T) {
	// A store shaped like the default seed, where one project's *id* is
	// "demo" but its name is something else. Resolving a request by id
	// first would let this project answer a request that named another
	// one by name, and every later call would hit the wrong project.
	withProjects(t, map[string]*Project{
		"demo":        {ID: "demo", Name: "source"},
		"destination": {ID: "destination", Name: "destination"},
		"other":       {ID: "other-id", Name: "other"},
	}, "demo", "source")

	tests := []struct {
		name      string
		askedID   string
		askedName string
		wantID    string
		wantName  string
	}{
		{"by id", "destination", "", "destination", "destination"},
		{"by name", "", "destination", "destination", "destination"},
		{"name wins over the default id", "", "other", "other-id", "other"},
		{"name matching a key", "", "source", "demo", "source"},
		{"nothing asked falls back to the default", "", "", "demo", "source"},
		{"unknown name falls back to the default", "", "nope", "demo", "source"},
		{"unknown id falls back to the default", "nope", "", "demo", "source"},
		{"id is preferred when both are given", "destination", "other", "destination", "destination"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, name := resolveScope(tt.askedID, tt.askedName)
			assert.Equal(t, tt.wantID, id)
			assert.Equal(t, tt.wantName, name)
		})
	}
}

func TestResolveScopeWithDevstackProjects(t *testing.T) {
	// The devstack profile names its projects after their ids, so a client
	// scoping to alt_demo must land there rather than on demo.
	withProjects(t, map[string]*Project{
		"demo":     {ID: "demo", Name: "demo"},
		"alt_demo": {ID: "alt_demo", Name: "alt_demo"},
	}, "demo", "demo")

	id, name := resolveScope("", "alt_demo")
	assert.Equal(t, "alt_demo", id)
	assert.Equal(t, "alt_demo", name)
}

func TestRoleGrantsAcrossActorsAndScopes(t *testing.T) {
	// Keystone grants a role to a user or a group, on a project or a
	// domain; all four combinations have to be distinguishable.
	mu.Lock()
	saved := roleAssignmentList
	roleAssignmentList = nil
	mu.Unlock()
	t.Cleanup(func() {
		mu.Lock()
		roleAssignmentList = saved
		mu.Unlock()
	})

	userOnProject := RoleAssignment{
		ActorType: "user", ActorID: "u1",
		ScopeType: "project", ScopeID: "p1", RoleID: "admin",
	}
	groupOnDomain := RoleAssignment{
		ActorType: "group", ActorID: "g1",
		ScopeType: "domain", ScopeID: "default", RoleID: "member",
	}

	mu.Lock()
	defer mu.Unlock()

	grantRole(userOnProject)
	grantRole(groupOnDomain)
	assert.Len(t, roleAssignmentList, 2)

	// Granting the same thing twice is not an error and adds nothing.
	grantRole(userOnProject)
	assert.Len(t, roleAssignmentList, 2)

	// The same role, actor and scope id under a different actor or scope
	// type is a different assignment.
	assert.Equal(t, -1, findAssignment(RoleAssignment{
		ActorType: "group", ActorID: "u1",
		ScopeType: "project", ScopeID: "p1", RoleID: "admin",
	}))

	assert.True(t, revokeRole(userOnProject))
	assert.False(t, revokeRole(userOnProject), "revoking twice reports nothing to do")
	assert.Len(t, roleAssignmentList, 1)
}
