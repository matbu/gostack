# gostack

Integration test framework for OpenStack-to-OpenStack and VMware-to-OpenStack migration. Provides a fake OpenStack API server (Keystone, Nova, Neutron, Cinder, Glance) for Ansible-based integration tests.

## Usage

### Run the fake server

```bash
go run ./cmd/fake-openstack
# or
make build && ./bin/fake-openstack
```

### Configuration (viper + cobra)

- `--port`, `-p` (default: 5000)
- `--bind`, `-b` (default: 127.0.0.1)
- `--pid-file` (default: /tmp/fake_os_server.pid)
- `--log-level` (debug, info, warn, error)
- `--base-url` (default: http://bind:port)
- `--seed` (default: osmigrate) — which sample resources to start with
- `--require-auth` — answer requests without a valid token with 401
  (default: only under `--seed devstack`)

Environment: `GOSTACK_PORT`, `GOSTACK_BIND`, etc.

### Seed profiles

The profile selects the sample resources *and* the behaviours that go with
them, so existing callers are unaffected by the default:

- `osmigrate` (default): the fixtures os-migrate's export tests read — a
  volume, an SR-IOV port, the `private`/`public` networks, the
  `source`/`destination` projects. Listings and reads are scoped to the
  token's project, and requests without a token are served.
- `devstack`: what a freshly stacked devstack has — a cirros image, the
  `private`/`public`/`shared` networks with subnets, a default security
  group, devstack's projects, and nothing else. Listings span all projects
  (matching the admin role the token carries), a token is required, and
  responses carry exactly what the real services send — including the few
  places where that is *less* than gostack has historically returned. Use
  this for clients written against a real cloud.

The fixes that can only help a client — error envelopes, JSON content
types, query filters, stable ordering, fuller resource field sets, the
Cinder/Keystone namespace split — apply under both profiles.

## API conformance

[`docs/api-conformance.md`](docs/api-conformance.md) records how closely
gostack follows the real APIs, which services it covers, and what is
missing.

It is measured by running the upstream `ansible-collections-openstack`
functional test roles against a build:

```bash
make conformance-test
```

That needs `ansible-core`, `openstacksdk` and `python-openstackclient` on
`PATH`. The same run happens in CI on every pull request, and weekly
against the collection's master branch.

### As a Go package

```go
import "github.com/os-migrate/gostack/pkg/gostack"

opts := gostack.DefaultOptions()
opts.Port = 5000
fs := gostack.NewFakeServer(opts)
defer fs.Close()
// Server runs at fs.URL
select {} // or run your tests
```

## Dependencies

- [cobra](https://github.com/spf13/cobra) - CLI
- [viper](https://github.com/spf13/viper) - Config
- [logrus](https://github.com/sirupsen/logrus) - Logging
- [testify](https://github.com/stretchr/testify) - Testing

## License

Apache-2.0
