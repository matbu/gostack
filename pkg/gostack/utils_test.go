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
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParts(t *testing.T) {
	tests := []struct {
		input    string
		expected []string
	}{
		{"", []string{""}},
		{"/", []string{""}},
		{"/v2.1/demo/servers", []string{"v2.1", "demo", "servers"}},
		{"/v3/auth/tokens", []string{"v3", "auth", "tokens"}},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := Parts(tt.input)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestRandomID(t *testing.T) {
	id1 := RandomID("test")
	id2 := RandomID("test")
	require.NotEmpty(t, id1)
	require.NotEmpty(t, id2)
	require.NotEqual(t, id1, id2)
	require.Contains(t, id1, "test-")
}

func TestBuildAddresses(t *testing.T) {
	// Nova keys the addresses map by network name, so a known network id
	// resolves to its name ("net-1" is the seeded "private" network) and an
	// unknown one is passed through as-is.
	serverNets := []map[string]string{
		{"uuid": "net-1"},
		{"uuid": "net-2"},
	}
	addr := BuildAddresses(serverNets)
	require.Len(t, addr, 2)
	require.Contains(t, addr, "private")
	require.Contains(t, addr, "net-2")
	require.Len(t, addr["private"], 1)
	require.Equal(t, "192.168.0.10", addr["private"][0]["addr"])
	require.Equal(t, "fixed", addr["private"][0]["OS-EXT-IPS:type"])
}

func TestProjectIDFromToken_EmptyToken(t *testing.T) {
	req, _ := http.NewRequest("GET", "/", nil)
	got := ProjectIDFromToken(req)
	assert.Equal(t, "demo", got)
}
