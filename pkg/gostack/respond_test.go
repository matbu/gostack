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

// decodeBody reads a recorded response as a JSON object.
func decodeBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	out := map[string]interface{}{}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out),
		"response body is not JSON: %s", rec.Body.String())
	return out
}

func TestAPIErrorEnvelopes(t *testing.T) {
	// Each project renders errors in its own shape; a client that reads the
	// message out of the wrong envelope sees nothing.
	tests := []struct {
		name    string
		svc     Service
		code    int
		wantKey string
	}{
		{"keystone", Keystone, http.StatusNotFound, "error"},
		{"nova not found", Nova, http.StatusNotFound, "itemNotFound"},
		{"nova bad request", Nova, http.StatusBadRequest, "badRequest"},
		{"nova conflict", Nova, http.StatusConflict, "conflictingRequest"},
		{"cinder", Cinder, http.StatusNotFound, "itemNotFound"},
		{"neutron", Neutron, http.StatusNotFound, "NeutronError"},
		{"glance", Glance, http.StatusNotFound, "message"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			apiError(rec, tt.svc, tt.code, "it went wrong")

			assert.Equal(t, tt.code, rec.Code)
			assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
			body := decodeBody(t, rec)
			require.Contains(t, body, tt.wantKey)

			if tt.svc == Glance {
				assert.Equal(t, "it went wrong", body["message"])
				return
			}
			inner, ok := body[tt.wantKey].(map[string]interface{})
			require.True(t, ok, "envelope %q should hold an object", tt.wantKey)
			assert.Equal(t, "it went wrong", inner["message"])
		})
	}
}

func TestNeutronErrorCarriesType(t *testing.T) {
	rec := httptest.NewRecorder()
	apiError(rec, Neutron, http.StatusNotFound, "Network x could not be found.")
	inner := decodeBody(t, rec)["NeutronError"].(map[string]interface{})
	assert.Equal(t, "NotFound", inner["type"])
	assert.Equal(t, "", inner["detail"])
}

func TestWriteJSONSetsContentType(t *testing.T) {
	rec := httptest.NewRecorder()
	// A handler may have declared another type earlier; a JSON body wins.
	rec.Header().Set("Content-Type", "text/plain; charset=utf-8")
	writeJSON(rec, map[string]string{"hello": "world"})

	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	assert.Equal(t, "world", decodeBody(t, rec)["hello"])
}

func TestRequireToken(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]string{"ok": "yes"})
	})
	handler := RequireToken(next)

	t.Run("no token is rejected", func(t *testing.T) {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v2.0/networks", nil))
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.NotEmpty(t, rec.Header().Get("WWW-Authenticate"))
		assert.Contains(t, decodeBody(t, rec), "NeutronError")
	})

	t.Run("unknown token is rejected", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v2.0/networks", nil)
		req.Header.Set("X-Auth-Token", "not-one-of-ours")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("issued token is accepted", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v2.0/networks", nil)
		req.Header.Set("X-Auth-Token", "fake-token-demo")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("version discovery stays open", func(t *testing.T) {
		for _, path := range []string{"/v3", "/v2.0", "/v2.1", "/v3/auth/tokens"} {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
			assert.Equal(t, http.StatusOK, rec.Code, "path %s should not need a token", path)
		}
	})
}

func TestMicroversionHeaders(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]string{"ok": "yes"})
	})
	handler := Microversion(next)

	t.Run("compute echoes the requested version", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v2.1/demo/servers", nil)
		req.Header.Set("OpenStack-API-Version", "compute 2.79")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equal(t, "compute 2.79", rec.Header().Get("OpenStack-API-Version"))
		assert.Equal(t, "2.79", rec.Header().Get("X-OpenStack-Nova-API-Version"))
		assert.Equal(t, "OpenStack-API-Version", rec.Header().Get("Vary"))
	})

	t.Run("a version above ours is capped", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v2.1/demo/servers", nil)
		req.Header.Set("OpenStack-API-Version", "compute 2.99")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equal(t, "compute "+maxComputeMicroversion, rec.Header().Get("OpenStack-API-Version"))
	})

	t.Run("latest resolves to our maximum", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v2.1/demo/servers", nil)
		req.Header.Set("OpenStack-API-Version", "compute latest")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equal(t, "compute "+maxComputeMicroversion, rec.Header().Get("OpenStack-API-Version"))
	})

	t.Run("block storage is reported too", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/volume/v3/demo/volumes", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equal(t, "volume "+maxVolumeMicroversion, rec.Header().Get("OpenStack-API-Version"))
	})

	t.Run("other services get no microversion", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v2.0/networks", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Empty(t, rec.Header().Get("OpenStack-API-Version"))
	})
}

func TestServiceForPath(t *testing.T) {
	// An error raised outside a handler still has to pick the right
	// envelope, which it does from the path.
	assert.Equal(t, Neutron, serviceForPath("/v2.0/networks"))
	assert.Equal(t, Nova, serviceForPath("/v2.1/demo/servers"))
	assert.Equal(t, Cinder, serviceForPath("/volume/v3/demo/volumes"))
	assert.Equal(t, Glance, serviceForPath("/v2/images"))
	assert.Equal(t, Keystone, serviceForPath("/v3/projects"))
}

func TestDeleteStatusFollowsProfile(t *testing.T) {
	t.Cleanup(func() { SetStrictResponses(false) })

	// Clients built against gostack assert on 204, so the default keeps
	// sending it; the real services answer an asynchronous delete with
	// 202, which strict responses restore.
	SetStrictResponses(false)
	assert.Equal(t, http.StatusNoContent, deleteStatus())

	SetStrictResponses(true)
	assert.Equal(t, http.StatusAccepted, deleteStatus())
}
