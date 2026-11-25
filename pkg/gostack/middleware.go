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
	"strings"
)

// maxComputeMicroversion is the highest compute microversion gostack claims.
const maxComputeMicroversion = "2.90"

// minComputeMicroversion is the lowest compute microversion gostack accepts.
const minComputeMicroversion = "2.1"

// maxVolumeMicroversion is the highest block-storage microversion gostack claims.
const maxVolumeMicroversion = "3.70"

// Recover wraps a handler so a panic in request handling returns 500 instead of
// killing the connection (which clients see as a reset / RemoteDisconnected).
func Recover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("panic serving %s %s: %v", r.Method, r.URL.Path, rec)
				apiError(w, serviceForPath(r.URL.Path), http.StatusInternalServerError,
					"The server has either erred or is incapable of performing the requested operation.")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// NormalizeV2Path fixes double /v2.0/v2.0/ in paths.
func NormalizeV2Path(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for strings.HasPrefix(r.URL.Path, "/v2.0/v2.0/") {
			r.URL.Path = strings.Replace(r.URL.Path, "/v2.0/v2.0/", "/v2.0/", 1)
		}
		next.ServeHTTP(w, r)
	})
}

// serviceForPath guesses which service owns a path, so errors raised outside a
// handler still use the right envelope.
func serviceForPath(path string) Service {
	switch {
	case strings.HasPrefix(path, "/v2.0"):
		return Neutron
	case strings.HasPrefix(path, "/v2.1"):
		return Nova
	case strings.HasPrefix(path, "/volume/"):
		return Cinder
	case strings.HasPrefix(path, "/v2"):
		return Glance
	default:
		return Keystone
	}
}

// unauthenticatedPaths are reachable without a token: version discovery and
// the token endpoint itself.
func unauthenticatedPath(path string) bool {
	switch path {
	case "/", "/v3", "/v3/", "/v2.0", "/v2.0/", "/v2.1", "/v2.1/", "/v2", "/v2/":
		return true
	case "/v3/auth/tokens":
		return true
	}
	return false
}

// RequireToken rejects unauthenticated requests the way the real services do,
// so tests can cover the 401 path. Version documents and token creation stay
// open.
func RequireToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if unauthenticatedPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		token := r.Header.Get("X-Auth-Token")
		if token == "" {
			w.Header().Set("WWW-Authenticate", `Keystone uri="`+baseURL+`/v3"`)
			apiError(w, serviceForPath(r.URL.Path), http.StatusUnauthorized,
				"The request you have made requires authentication.")
			return
		}
		if !tokenKnown(token) {
			w.Header().Set("WWW-Authenticate", `Keystone uri="`+baseURL+`/v3"`)
			apiError(w, serviceForPath(r.URL.Path), http.StatusUnauthorized,
				"The request you have made requires authentication.")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// tokenKnown reports whether a token was issued by this server.
func tokenKnown(token string) bool {
	tokenMu.RLock()
	_, ok := tokenProjects[token]
	tokenMu.RUnlock()
	if ok {
		return true
	}
	// Tokens are deterministic ("fake-token-<project>"), so one minted by an
	// earlier run of the server is still recognisable after a restart.
	return strings.HasPrefix(token, "fake-token-")
}

// Microversion echoes the negotiated microversion on compute and block-storage
// responses, as Nova and Cinder do. Clients use the response header to confirm
// which version they actually got.
func Microversion(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var service, version string
		switch {
		case strings.HasPrefix(r.URL.Path, "/v2.1"):
			service, version = "compute", negotiate(r, "compute", maxComputeMicroversion)
		case strings.HasPrefix(r.URL.Path, "/volume/v3"):
			service, version = "volume", negotiate(r, "volume", maxVolumeMicroversion)
		default:
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("OpenStack-API-Version", service+" "+version)
		w.Header().Set("Vary", "OpenStack-API-Version")
		if service == "compute" {
			w.Header().Set("X-OpenStack-Nova-API-Version", version)
		}
		next.ServeHTTP(w, r)
	})
}

// negotiate resolves the microversion to report for a request, honouring
// "latest" and capping an explicit request at what gostack supports.
func negotiate(r *http.Request, service, max string) string {
	requested := r.Header.Get("OpenStack-API-Version")
	if fields := strings.Fields(requested); len(fields) == 2 {
		// "compute 2.79" — a version for another service tells us nothing.
		if !strings.EqualFold(fields[0], service) {
			return max
		}
		requested = fields[1]
	} else if requested == "" && service == "compute" {
		requested = r.Header.Get("X-OpenStack-Nova-API-Version")
	}
	requested = strings.TrimSpace(requested)
	if requested == "" || strings.EqualFold(requested, "latest") {
		return max
	}
	if compareMicroversion(requested, max) > 0 {
		return max
	}
	if service == "compute" && compareMicroversion(requested, minComputeMicroversion) < 0 {
		return minComputeMicroversion
	}
	return requested
}

// compareMicroversion orders two "major.minor" microversion strings.
func compareMicroversion(a, b string) int {
	amaj, amin := splitMicroversion(a)
	bmaj, bmin := splitMicroversion(b)
	switch {
	case amaj != bmaj:
		if amaj < bmaj {
			return -1
		}
		return 1
	case amin != bmin:
		if amin < bmin {
			return -1
		}
		return 1
	}
	return 0
}

// splitMicroversion parses "major.minor"; unparseable parts count as zero.
func splitMicroversion(v string) (int, int) {
	parts := strings.SplitN(v, ".", 2)
	major := atoiSafe(parts[0])
	minor := 0
	if len(parts) == 2 {
		minor = atoiSafe(parts[1])
	}
	return major, minor
}

// atoiSafe parses a non-negative integer, returning 0 on failure.
func atoiSafe(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n
}
