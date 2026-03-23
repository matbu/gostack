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
package main

import (
	"fmt"

	"github.com/os-migrate/gostack/pkg/gostack"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "fake-openstack",
		Short: "Fake OpenStack API server for integration tests",
		Long: `Starts a mock OpenStack API (Keystone, Nova, Neutron, Cinder, Glance) for OS-to-OS and VMware-to-OS migration integration tests.

Use from CI or Ansible playbooks with: go run github.com/os-migrate/gostack/cmd/fake-openstack@latest --port 5000 --pid-file /tmp/fake_os_server.pid

Runs from any directory; no chdir required.`,
		Run: runServe,
	}

	rootCmd.PersistentFlags().IntP("port", "p", 5000, "Port to listen on")
	rootCmd.PersistentFlags().StringP("bind", "b", "127.0.0.1", "Address to bind to")
	rootCmd.PersistentFlags().String("pid-file", "/tmp/fake_os_server.pid", "Path to PID file")
	rootCmd.PersistentFlags().String("log-level", "info", "Log level (debug, info, warn, error)")
	rootCmd.PersistentFlags().String("base-url", "", "Base URL for catalog (default: http://bind:port)")

	_ = viper.BindPFlag("port", rootCmd.PersistentFlags().Lookup("port"))
	_ = viper.BindPFlag("base_url", rootCmd.PersistentFlags().Lookup("base-url"))
	_ = viper.BindPFlag("bind", rootCmd.PersistentFlags().Lookup("bind"))
	_ = viper.BindPFlag("pid_file", rootCmd.PersistentFlags().Lookup("pid-file"))
	_ = viper.BindPFlag("log_level", rootCmd.PersistentFlags().Lookup("log-level"))

	viper.SetEnvPrefix("GOSTACK")
	viper.AutomaticEnv()

	if err := rootCmd.Execute(); err != nil {
		logrus.Fatal(err)
	}
}

func runServe(cmd *cobra.Command, _ []string) {
	level, err := logrus.ParseLevel(viper.GetString("log_level"))
	if err != nil {
		level = logrus.InfoLevel
	}
	logrus.SetLevel(level)

	port := viper.GetInt("port")
	bind := viper.GetString("bind")
	pidFile := viper.GetString("pid_file")
	baseURL := viper.GetString("base_url")
	if baseURL == "" {
		baseURL = fmt.Sprintf("http://%s:%d", bind, port)
	}

	opts := gostack.Options{
		BindAddr: bind,
		Port:     port,
		PIDFile:  pidFile,
		BaseURL:  baseURL,
	}

	fs := gostack.NewFakeServer(opts)
	defer fs.Close()

	logrus.Infof("Fake OpenStack server running at %s", fs.URL)
	select {} // Block forever
}
