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
	"log"
	"net/http"
)

// Service identifies which OpenStack service a handler belongs to. Each
// project renders API errors in its own envelope, so error helpers need to
// know who is answering.
type Service int

// Services whose error envelopes gostack reproduces.
const (
	Keystone Service = iota
	Nova
	Neutron
	Glance
	Cinder
)

// errorTitle maps an HTTP status to the title/key OpenStack services use.
func errorTitle(code int) string {
	switch code {
	case http.StatusBadRequest:
		return "Bad Request"
	case http.StatusUnauthorized:
		return "Unauthorized"
	case http.StatusForbidden:
		return "Forbidden"
	case http.StatusNotFound:
		return "Not Found"
	case http.StatusMethodNotAllowed:
		return "Method Not Allowed"
	case http.StatusConflict:
		return "Conflict"
	case http.StatusNotImplemented:
		return "Not Implemented"
	default:
		return http.StatusText(code)
	}
}

// novaErrorKey maps an HTTP status to the Nova/Cinder fault key. Both projects
// use the same "compute fault" envelope: a single key naming the fault.
func novaErrorKey(code int) string {
	switch code {
	case http.StatusBadRequest:
		return "badRequest"
	case http.StatusUnauthorized:
		return "unauthorized"
	case http.StatusForbidden:
		return "forbidden"
	case http.StatusNotFound:
		return "itemNotFound"
	case http.StatusMethodNotAllowed:
		return "methodNotAllowed"
	case http.StatusConflict:
		return "conflictingRequest"
	case http.StatusNotImplemented:
		return "notImplemented"
	default:
		return "computeFault"
	}
}

// neutronErrorType maps an HTTP status to a Neutron exception class name.
func neutronErrorType(code int) string {
	switch code {
	case http.StatusBadRequest:
		return "BadRequest"
	case http.StatusUnauthorized:
		return "Unauthorized"
	case http.StatusForbidden:
		return "PolicyNotAuthorized"
	case http.StatusNotFound:
		return "NotFound"
	case http.StatusConflict:
		return "Conflict"
	default:
		return "NeutronError"
	}
}

// writeJSON encodes v as a JSON response, declaring the content type.
func writeJSON(w http.ResponseWriter, v interface{}) {
	setJSONContentType(w)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("Error encoding JSON response: %v", err)
	}
}

// writeJSONStatus writes v as JSON with an explicit status code.
func writeJSONStatus(w http.ResponseWriter, status int, v interface{}) {
	setJSONContentType(w)
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("Error encoding JSON response: %v", err)
	}
}

// setJSONContentType declares the body as JSON. Handlers sometimes set a
// content type of their own earlier; for a JSON body application/json wins.
func setJSONContentType(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
}

// apiError writes an error response in the envelope used by the given service.
// Detail may be empty; it maps to Neutron's "detail" field and is appended to
// the message elsewhere.
func apiError(w http.ResponseWriter, svc Service, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	var body interface{}
	switch svc {
	case Keystone:
		body = map[string]interface{}{
			"error": map[string]interface{}{
				"code":    code,
				"title":   errorTitle(code),
				"message": message,
			},
		}
	case Neutron:
		body = map[string]interface{}{
			"NeutronError": map[string]interface{}{
				"type":    neutronErrorType(code),
				"message": message,
				"detail":  "",
			},
		}
	case Glance:
		// Glance answers with a bare message document.
		body = map[string]interface{}{
			"message": message,
		}
	default: // Nova and Cinder share the compute fault envelope.
		body = map[string]interface{}{
			novaErrorKey(code): map[string]interface{}{
				"code":    code,
				"message": message,
			},
		}
	}
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		log.Printf("Error encoding error response: %v", err)
	}
}

// notFound writes a 404 in the service's envelope.
func notFound(w http.ResponseWriter, svc Service, what string) {
	apiError(w, svc, http.StatusNotFound, what+" could not be found.")
}

// methodNotAllowed writes a 405 in the service's envelope.
func methodNotAllowed(w http.ResponseWriter, svc Service, method string) {
	apiError(w, svc, http.StatusMethodNotAllowed,
		"Method "+method+" is not allowed for this resource.")
}

// badRequest writes a 400 in the service's envelope.
func badRequest(w http.ResponseWriter, svc Service, message string) {
	apiError(w, svc, http.StatusBadRequest, message)
}

// deleteStatus is the status an asynchronous delete answers with: the 202
// Nova and Cinder really send under strict responses, or the 204 gostack
// has always sent otherwise. Clients built against gostack assert on 204.
func deleteStatus() int {
	if strictResponses {
		return http.StatusAccepted
	}
	return http.StatusNoContent
}
