#!/usr/bin/env bash
#
# Run the upstream openstack.cloud functional test roles against gostack.
#
# The roles live in the ansible-collections-openstack repository under
# ci/roles (not tests/, which holds unit and sanity checks only), one role
# per module, and are driven by ci/run-collection.yml. They go through
# openstacksdk, so passing them means a real OpenStack client works against
# gostack.
#
# Required:
#   GOSTACK_BIN      Path to a built gostack `fake-openstack` binary.
#
# Optional:
#   OSA_SRC          Checkout of ansible-collections-openstack.
#                    Cloned into the workdir when unset.
#   OSA_REF          Branch to clone when OSA_SRC is unset (default master).
#   CONFORMANCE_ROLES    Space-separated roles to run (default: see below).
#   CONFORMANCE_PORT     Port for the fake cloud (default 5000).
#   CONFORMANCE_WORKDIR  Scratch dir (default: mktemp).
#
# Each role runs against a freshly restarted server: they assume a clean
# cloud, and several assert on the first element of a listing.
set -uo pipefail

: "${GOSTACK_BIN:?Set GOSTACK_BIN to a built gostack fake-openstack binary}"
PORT="${CONFORMANCE_PORT:-5000}"
WORKDIR="${CONFORMANCE_WORKDIR:-$(mktemp -d)}"
OSA_REF="${OSA_REF:-master}"
URL="http://127.0.0.1:${PORT}"
mkdir -p "$WORKDIR"

# Roles gostack is expected to pass. Two upstream roles are left out
# because they do not test anything gostack implements:
#
#   quota                  also reads load-balancer quotas, and gostack has
#                          no Octavia; its network, compute and volume
#                          sections pass.
#   volume_image_metadata  asserts that setting disk_format/container_format
#                          on a volume built from an image is a change, but
#                          Cinder copies both off the image at creation, so
#                          there is nothing to change. The assertion depends
#                          on the test image's format, not on the API.
#
# Roles for services gostack does not implement at all (dns_zone, stack,
# loadbalancer, object*, coe_cluster*, baremetal_*, share_type, trait,
# federation/application credentials, volume_manage, volume_retype,
# logging) are out of scope.
DEFAULT_ROLES="
auth config
identity_domain identity_user identity_role identity_group
project role_assignment group_assignment
catalog_service endpoint
network subnet port security_group security_group_rule
router floating_ip port_forwarding trunk
address_scope subnet_pool network_segment neutron_rbac_policy
image keypair
compute_flavor compute_flavor_access compute_service host_aggregate
server server_action server_group server_metadata server_volume
volume volume_type volume_type_access volume_snapshot volume_backup
volume_service
resource resources inventory
"
ROLES="${CONFORMANCE_ROLES:-$DEFAULT_ROLES}"

# ---------------------------------------------------------------- sources

if [ -z "${OSA_SRC:-}" ]; then
  OSA_SRC="$WORKDIR/ansible-collections-openstack"
  if [ ! -d "$OSA_SRC" ]; then
    echo "Cloning ansible-collections-openstack ($OSA_REF)..."
    git clone --depth 1 --branch "$OSA_REF" \
      https://opendev.org/openstack/ansible-collections-openstack.git \
      "$OSA_SRC" || exit 1
  fi
fi
OSA_SRC="$(cd "$OSA_SRC" && pwd)"

# Ansible imports the collection from a path shaped like
# <collections_path>/ansible_collections/<namespace>/<name>.
COLLECTIONS="$WORKDIR/collections"
mkdir -p "$COLLECTIONS/ansible_collections/openstack"
ln -sfn "$OSA_SRC" "$COLLECTIONS/ansible_collections/openstack/cloud"

# The image role uses community.general.filesize; ansible.posix comes along
# as a common dependency.
if [ ! -d "$COLLECTIONS/ansible_collections/community/general" ]; then
  echo "Installing collection dependencies..."
  ANSIBLE_COLLECTIONS_PATH="$COLLECTIONS" \
    ansible-galaxy collection install community.general ansible.posix \
      -p "$COLLECTIONS" >/dev/null || exit 1
fi

# ----------------------------------------------------------------- config

# Three cloud names are needed: the roles take `cloud` and `cloud_alt` as
# variables, and compute_flavor_access and volume_type_access hardcode
# "devstack-admin".
cat >"$WORKDIR/clouds.yaml" <<EOF
clouds:
  devstack:
    auth: &auth
      auth_url: ${URL}/v3
      username: demo
      password: secret
      project_name: demo
      project_domain_id: default
      user_domain_id: default
    region_name: RegionOne
    interface: public
    identity_api_version: 3
  devstack-admin:
    auth: *auth
    region_name: RegionOne
    interface: public
    identity_api_version: 3
  devstack-alt:
    auth:
      auth_url: ${URL}/v3
      username: demo
      password: secret
      project_name: alt_demo
      project_domain_id: default
      user_domain_id: default
    region_name: RegionOne
    interface: public
    identity_api_version: 3
EOF

cat >"$WORKDIR/ansible.cfg" <<EOF
[defaults]
collections_path = ${COLLECTIONS}
host_key_checking = False
retry_files_enabled = False
EOF

export ANSIBLE_CONFIG="$WORKDIR/ansible.cfg"
export ANSIBLE_COLLECTIONS_PATH="$COLLECTIONS"
export OS_CLIENT_CONFIG_FILE="$WORKDIR/clouds.yaml"
export ANSIBLE_DEPRECATION_WARNINGS=False
export ANSIBLE_LOCALHOST_WARNING=False

# ------------------------------------------------------------------ server

server_pid=""

stop_server() {
  if [ -n "$server_pid" ] && kill -0 "$server_pid" 2>/dev/null; then
    kill "$server_pid" 2>/dev/null
    wait "$server_pid" 2>/dev/null
  fi
  server_pid=""
}

# shellcheck disable=SC2317,SC2329  # invoked via trap
cleanup() { stop_server; }
trap cleanup EXIT

start_server() {
  local role="$1"
  # The devstack seed profile is what a suite written against a real cloud
  # expects: devstack's own resources, listings across projects, and a
  # required auth token.
  "$GOSTACK_BIN" --port "$PORT" --bind 127.0.0.1 --seed devstack \
    --pid-file "$WORKDIR/gostack.pid" \
    >"$WORKDIR/${role}.server.log" 2>&1 &
  server_pid=$!
  for _ in $(seq 1 50); do
    if curl -sf -o /dev/null "$URL/v3"; then
      return 0
    fi
    if ! kill -0 "$server_pid" 2>/dev/null; then
      break
    fi
    sleep 0.2
  done
  echo "ERROR: gostack did not become ready on $URL" >&2
  cat "$WORKDIR/${role}.server.log" >&2
  return 1
}

# ------------------------------------------------------------------- run

echo "Running openstack.cloud roles against $URL"
echo "  collection: $OSA_SRC ($(cd "$OSA_SRC" && git rev-parse --short HEAD 2>/dev/null || echo unknown))"
echo "  logs:       $WORKDIR"
echo

printf '%-26s %6s %8s %8s  %s\n' ROLE OK CHANGED FAILED RESULT
failures=""

for role in $ROLES; do
  stop_server
  if ! start_server "$role"; then
    failures="$failures $role"
    printf '%-26s %6s %8s %8s  %s\n' "$role" - - - "SERVER-FAILED"
    continue
  fi

  log="$WORKDIR/${role}.log"
  (
    cd "$OSA_SRC" &&
      ansible-playbook ci/run-collection.yml --tags "$role" \
        -e cloud=devstack -e cloud_alt=devstack-alt
  ) >"$log" 2>&1
  rc=$?

  recap="$(grep -m1 -E '^localhost +: ok=' "$log")"
  get() { echo "$recap" | grep -oE "$1=[0-9]+" | cut -d= -f2; }
  ok="$(get ok)"; changed="$(get changed)"; failed="$(get failed)"

  if [ "$rc" -eq 0 ]; then
    printf '%-26s %6s %8s %8s  %s\n' "$role" "${ok:-0}" "${changed:-0}" "${failed:-0}" PASS
  else
    printf '%-26s %6s %8s %8s  %s\n' "$role" "${ok:-0}" "${changed:-0}" "${failed:-0}" FAIL
    failures="$failures $role"
  fi
done

stop_server
echo

if [ -n "$failures" ]; then
  echo "FAILED roles:$failures"
  echo
  for role in $failures; do
    echo "=============================================================="
    echo "First failure in $role"
    echo "=============================================================="
    # The task name is the last TASK banner before the first failure.
    grep -B400 -m1 -E '^(fatal|failed):' "$WORKDIR/${role}.log" 2>/dev/null |
      grep -E '^TASK \[' | tail -1
    grep -m1 -A20 -E '^(fatal|failed):' "$WORKDIR/${role}.log" 2>/dev/null
    echo
  done
  exit 1
fi

echo "All roles passed."
