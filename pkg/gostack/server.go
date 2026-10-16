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
	"fmt"
	"log"
	"net/http"
	"os"
)

// Options configures the fake OpenStack server.
type Options struct {
	// BindAddr is the address to listen on (e.g. "127.0.0.1" or "" for all).
	BindAddr string
	// Port is the port to listen on (default 5000).
	Port int
	// PIDFile is the path to write the process ID (default /tmp/fake_os_server.pid).
	PIDFile string
	// BaseURL is the base URL for catalog/links (e.g. "http://127.0.0.1:5000").
	BaseURL string
}

// DefaultOptions returns default server options.
func DefaultOptions() Options {
	return Options{
		BindAddr: "127.0.0.1",
		Port:     5000,
		PIDFile:  "/tmp/fake_os_server.pid",
		BaseURL:  "http://127.0.0.1:5000",
	}
}

// FakeServer is a fake OpenStack API server for integration tests.
type FakeServer struct {
	URL     string
	PIDFile string
}

// Close stops the server and removes the PID file.
func (f *FakeServer) Close() {
	if f.PIDFile != "" {
		if err := os.Remove(f.PIDFile); err != nil {
			log.Printf("Failed to remove PID file: %v", err)
		}
	}
}

// NewFakeServer creates and starts a fake OpenStack API server.
// It starts the server in a goroutine and returns immediately.
// The server runs until the process exits.
func NewFakeServer(opts Options) *FakeServer {
	if opts.Port == 0 {
		opts.Port = 5000
	}
	if opts.PIDFile == "" {
		opts.PIDFile = "/tmp/fake_os_server.pid"
	}
	if opts.BaseURL == "" {
		opts.BaseURL = fmt.Sprintf("http://127.0.0.1:%d", opts.Port)
	}

	SetBaseURL(opts.BaseURL)

	pid := os.Getpid()
	if err := os.WriteFile(opts.PIDFile, []byte(fmt.Sprintf("%d", pid)), 0644); err != nil {
		log.Fatalf("Failed to write PID file: %v", err)
	}

	roleAssignments := map[string]map[string][]string{}
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.Path)
		http.NotFound(w, r)
	})

	RegisterKeystoneHandlers(mux, roleAssignments)
	RegisterNovaHandlers(mux)
	RegisterNeutronHandlers(mux)
	RegisterCinderHandlers(mux)
	RegisterGlanceHandlers(mux)

	addr := fmt.Sprintf("%s:%d", opts.BindAddr, opts.Port)
	fs := &FakeServer{URL: "http://" + addr, PIDFile: opts.PIDFile}

	go func() {
		log.Printf("Fake OpenStack API listening on %s", addr)
		err := http.ListenAndServe(addr, Recover(NormalizeV2Path(mux)))
		if err != nil {
			log.Fatalf("Server failed: %v", err)
		}
	}()

	return fs
}
