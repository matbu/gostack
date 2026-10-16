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

// Recover wraps a handler so a panic in request handling returns 500 instead of
// killing the connection (which clients see as a reset / RemoteDisconnected).
func Recover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("panic serving %s %s: %v", r.Method, r.URL.Path, rec)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
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
