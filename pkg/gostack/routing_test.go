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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newAPITestServer starts every service on one mux, as the real server does,
// so routing between them can be exercised.
func newAPITestServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		notFound(w, serviceForPath(r.URL.Path), "The resource")
	})
	RegisterKeystoneHandlers(mux)
	RegisterKeystoneExtraHandlers(mux)
	RegisterNovaHandlers(mux)
	RegisterNeutronHandlers(mux)
	RegisterCinderHandlers(mux)
	RegisterGlanceHandlers(mux)

	srv := httptest.NewServer(NormalizeV2Path(mux))
	t.Cleanup(srv.Close)
	return srv
}

// getPath performs a GET and returns the status and decoded body.
func getPath(t *testing.T, srv *httptest.Server, path string) (int, map[string]interface{}) {
	t.Helper()
	resp, err := http.Get(srv.URL + path)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	out := map[string]interface{}{}
	// A 204 has no body to decode.
	if resp.StatusCode != http.StatusNoContent {
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&out),
			"response to %s is not JSON", path)
	}
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"),
		"every response is JSON, including errors")
	return resp.StatusCode, out
}

func TestCinderDoesNotShadowKeystone(t *testing.T) {
	srv := newAPITestServer(t)

	// Cinder used to be registered on the bare /v3/ prefix, so every
	// Keystone resource without its own handler fell through to the volume
	// code and answered as if it were one.
	t.Run("unimplemented keystone path 404s as keystone", func(t *testing.T) {
		for _, path := range []string{"/v3/credentials", "/v3/OS-FEDERATION/identity_providers"} {
			code, body := getPath(t, srv, path)
			assert.Equal(t, http.StatusNotFound, code, "path %s", path)
			assert.Contains(t, body, "error", "path %s should answer as keystone", path)
		}
	})

	t.Run("keystone collections still resolve", func(t *testing.T) {
		for _, path := range []string{"/v3/projects", "/v3/services", "/v3/endpoints", "/v3/regions"} {
			code, _ := getPath(t, srv, path)
			assert.Equal(t, http.StatusOK, code, "path %s", path)
		}
	})

	t.Run("volumes are served under their own prefix", func(t *testing.T) {
		code, body := getPath(t, srv, "/volume/v3/demo/volumes")
		assert.Equal(t, http.StatusOK, code)
		assert.Contains(t, body, "volumes")
	})

	t.Run("the legacy volume path still works", func(t *testing.T) {
		code, body := getPath(t, srv, "/v3/demo/volumes")
		assert.Equal(t, http.StatusOK, code)
		assert.Contains(t, body, "volumes")
	})
}

func TestCinderDetailRoutesByCollection(t *testing.T) {
	srv := newAPITestServer(t)

	// Any path ending in /detail used to return the volume list, so asking
	// for snapshots or backups silently got volumes back.
	code, body := getPath(t, srv, "/volume/v3/demo/snapshots/detail")
	require.Equal(t, http.StatusOK, code)
	assert.Contains(t, body, "snapshots")
	assert.NotContains(t, body, "volumes")

	code, body = getPath(t, srv, "/volume/v3/demo/backups/detail")
	require.Equal(t, http.StatusOK, code)
	assert.Contains(t, body, "backups")
	assert.NotContains(t, body, "volumes")
}

func TestCollectionsAnswerAsTheirOwnService(t *testing.T) {
	srv := newAPITestServer(t)

	tests := []struct {
		path    string
		wantKey string
	}{
		{"/v2.0/networks/does-not-exist", "NeutronError"},
		{"/v2.1/demo/servers/does-not-exist", "itemNotFound"},
		{"/volume/v3/demo/volumes/does-not-exist", "itemNotFound"},
		{"/v2/images/does-not-exist", "message"},
		{"/v3/projects/does-not-exist", "error"},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			code, body := getPath(t, srv, tt.path)
			assert.Equal(t, http.StatusNotFound, code)
			assert.Contains(t, body, tt.wantKey)
		})
	}
}

func TestNeutronExtensionDiscovery(t *testing.T) {
	srv := newAPITestServer(t)

	// openstacksdk consults the extension list before using an optional
	// feature, so an empty one makes it skip capabilities that do work.
	code, body := getPath(t, srv, "/v2.0/extensions")
	require.Equal(t, http.StatusOK, code)
	extensions, ok := body["extensions"].([]interface{})
	require.True(t, ok)
	assert.NotEmpty(t, extensions)

	aliases := map[string]bool{}
	for _, raw := range extensions {
		ext := raw.(map[string]interface{})
		aliases[ext["alias"].(string)] = true
	}
	for _, want := range []string{"router", "security-group", "quotas", "trunk", "rbac-policies"} {
		assert.True(t, aliases[want], "extension %q should be advertised", want)
	}
}
