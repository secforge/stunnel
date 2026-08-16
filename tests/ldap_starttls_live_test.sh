#!/bin/bash
# Live integration test: LDAP StartTLS through stunnel server-side proxy.
#
# Topology:
#   ldapsearch (STARTTLS) -> stunnel server (protocol=ldap) -> slapd (plain LDAP)
#
# Also tests the full proxy chain:
#   ldapsearch (plain) -> stunnel client (protocol=ldap) -> stunnel server (protocol=ldap) -> slapd

set -e
set -u
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
STUNNEL="$REPO_ROOT/src/stunnel"
CERTDIR="$SCRIPT_DIR/certs"
TMPDIR_BASE="$(mktemp -d /tmp/stunnel_ldap_live_XXXXXX)"
CONTAINER_NAME="stunnel-ldap-test-$$"

LDAP_CONTAINER_PORT=10389   # slapd plain LDAP mapped to this host port
STUNNEL_SERVER_PORT=10636   # stunnel accepts STARTTLS here (server-side test)
STUNNEL_CLIENT_PORT=10388   # stunnel client accepts plain here (proxy chain test)
STUNNEL_PROXY_SERVER_PORT=10637  # stunnel server for the proxy chain test

LDAP_BASE="dc=example,dc=org"
LDAP_ADMIN_DN="cn=admin,dc=example,dc=org"
LDAP_ADMIN_PASS="adminpassword"

PASS=0
FAIL=0

# Colour helpers
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

ok()   { echo -e "${GREEN}PASS${NC}: $*"; PASS=$((PASS+1)); }
fail() { echo -e "${RED}FAIL${NC}: $*"; FAIL=$((FAIL+1)); }
info() { echo "INFO: $*"; }

cleanup() {
    info "Cleaning up..."
    # Kill stunnel instances
    for pidfile in "$TMPDIR_BASE"/*.pid; do
        [ -f "$pidfile" ] && kill "$(cat "$pidfile")" 2>/dev/null || true
    done
    # Remove container
    docker rm -f "$CONTAINER_NAME" 2>/dev/null || true
    rm -rf "$TMPDIR_BASE"
}
trap cleanup EXIT

# ── 1. Start slapd in Docker ──────────────────────────────────────────────────
info "Starting slapd container (plain LDAP on port $LDAP_CONTAINER_PORT)..."
docker run -d \
    --name "$CONTAINER_NAME" \
    -p "127.0.0.1:${LDAP_CONTAINER_PORT}:389" \
    -e LDAP_ORGANISATION="Example Org" \
    -e LDAP_DOMAIN="example.org" \
    -e LDAP_ADMIN_PASSWORD="$LDAP_ADMIN_PASS" \
    -e LDAP_TLS=false \
    osixia/openldap:1.5.0 \
    >/dev/null

# Wait for slapd to be ready (typically ~8s)
info "Waiting for slapd to become ready..."
sleep 5
for i in $(seq 1 30); do
    if ldapsearch -x -H "ldap://127.0.0.1:${LDAP_CONTAINER_PORT}" \
            -b "$LDAP_BASE" -D "$LDAP_ADMIN_DN" -w "$LDAP_ADMIN_PASS" \
            "(objectClass=*)" dn >/dev/null 2>&1; then
        info "slapd is ready (${i}s)"
        break
    fi
    sleep 1
done

# Verify slapd is actually answering
if ! ldapsearch -x -H "ldap://127.0.0.1:${LDAP_CONTAINER_PORT}" \
        -b "$LDAP_BASE" -D "$LDAP_ADMIN_DN" -w "$LDAP_ADMIN_PASS" \
        "(objectClass=*)" dn >/dev/null 2>&1; then
    echo "ERROR: slapd did not start in time" >&2
    exit 1
fi

# ── 2. Generate a self-signed cert trusted by ldapsearch ─────────────────────
info "Generating a CA + server cert for stunnel..."
CAKEY="$TMPDIR_BASE/ca.key"
CACERT="$TMPDIR_BASE/ca.crt"
SRVKEY="$TMPDIR_BASE/server.key"
SRVCSR="$TMPDIR_BASE/server.csr"
SRVCERT="$TMPDIR_BASE/server.crt"
SRVPEM="$TMPDIR_BASE/server.pem"

openssl genrsa -out "$CAKEY" 2048 2>/dev/null
openssl req -new -x509 -days 3650 -key "$CAKEY" -out "$CACERT" \
    -subj "/CN=StunnelTestCA" 2>/dev/null
openssl genrsa -out "$SRVKEY" 2048 2>/dev/null
openssl req -new -key "$SRVKEY" -out "$SRVCSR" \
    -subj "/CN=127.0.0.1" 2>/dev/null
openssl x509 -req -days 3650 -in "$SRVCSR" -CA "$CACERT" -CAkey "$CAKEY" \
    -CAcreateserial -out "$SRVCERT" \
    -extfile <(printf "subjectAltName=IP:127.0.0.1") 2>/dev/null
cat "$SRVCERT" "$SRVKEY" > "$SRVPEM"

# ── 3. Test A: server-side STARTTLS ──────────────────────────────────────────
#   ldapsearch (STARTTLS) -> stunnel server (protocol=ldap) -> slapd (plain)
info ""
info "=== Test A: stunnel server-side LDAP STARTTLS ==="

STUNNEL_A_CONF="$TMPDIR_BASE/stunnel_server.conf"
STUNNEL_A_PID="$TMPDIR_BASE/stunnel_server.pid"
STUNNEL_A_LOG="$TMPDIR_BASE/stunnel_server.log"

cat > "$STUNNEL_A_CONF" <<EOF
foreground = no
debug = info
syslog = no
output = $STUNNEL_A_LOG
pid = $STUNNEL_A_PID

[ldap-server]
accept  = 127.0.0.1:${STUNNEL_SERVER_PORT}
connect = 127.0.0.1:${LDAP_CONTAINER_PORT}
protocol = ldap
cert    = $SRVPEM
EOF

"$STUNNEL" "$STUNNEL_A_CONF"
sleep 1

# Verify stunnel is listening
if ! ss -tlnp 2>/dev/null | grep -q ":${STUNNEL_SERVER_PORT}"; then
    fail "Test A: stunnel server not listening on port $STUNNEL_SERVER_PORT"
    cat "$STUNNEL_A_LOG" >&2
else
    info "stunnel server-side STARTTLS proxy is up on port $STUNNEL_SERVER_PORT"

    # Test A.1: anonymous bind (read rootDSE) with STARTTLS
    info "A.1 Anonymous STARTTLS bind / rootDSE search..."
    if LDAPTLS_REQCERT=never ldapsearch -x \
            -H "ldap://127.0.0.1:${STUNNEL_SERVER_PORT}" \
            -Z \
            -b "" \
            -s base \
            "(objectClass=*)" \
            namingContexts \
            2>/dev/null | grep -q "namingContexts"; then
        ok "Test A.1: anonymous STARTTLS rootDSE query succeeded"
    else
        fail "Test A.1: anonymous STARTTLS rootDSE query failed"
        cat "$STUNNEL_A_LOG" >&2
    fi

    # Test A.2: authenticated search with STARTTLS (-Z forces STARTTLS, -ZZ requires it)
    info "A.2 Authenticated STARTTLS bind / base search..."
    if LDAPTLS_CACERT="$CACERT" ldapsearch -x \
            -H "ldap://127.0.0.1:${STUNNEL_SERVER_PORT}" \
            -ZZ \
            -b "$LDAP_BASE" \
            -D "$LDAP_ADMIN_DN" \
            -w "$LDAP_ADMIN_PASS" \
            "(objectClass=*)" dn \
            2>/dev/null | grep -q "dn:"; then
        ok "Test A.2: authenticated STARTTLS search succeeded"
    else
        fail "Test A.2: authenticated STARTTLS search failed"
        cat "$STUNNEL_A_LOG" >&2
    fi

    # Test A.3: plain (non-STARTTLS) connection must still work (stunnel speaks plain to client until STARTTLS)
    info "A.3 Verify plain LDAP to stunnel port fails (STARTTLS is required by protocol)..."
    # A plain LDAP bind to the stunnel port will fail because stunnel waits for
    # the LDAP StartTLS ExtendedRequest before the TLS handshake.
    if ldapsearch -x \
            -H "ldap://127.0.0.1:${STUNNEL_SERVER_PORT}" \
            -b "" \
            -s base \
            "(objectClass=*)" \
            namingContexts \
            >/dev/null 2>&1; then
        fail "Test A.3: plain LDAP to stunnel server-side port unexpectedly succeeded"
    else
        ok "Test A.3: plain LDAP (no STARTTLS) to stunnel server-side port correctly rejected"
    fi
fi

# ── 4. Test B: full proxy chain (client+server stunnel, protocol=ldap) ───────
#   ldapsearch (plain) -> stunnel client (protocol=ldap) -> stunnel server (protocol=ldap) -> slapd
info ""
info "=== Test B: stunnel client+server LDAP STARTTLS proxy chain ==="

STUNNEL_B_SRV_CONF="$TMPDIR_BASE/stunnel_proxy_server.conf"
STUNNEL_B_SRV_PID="$TMPDIR_BASE/stunnel_proxy_server.pid"
STUNNEL_B_SRV_LOG="$TMPDIR_BASE/stunnel_proxy_server.log"
STUNNEL_B_CLI_CONF="$TMPDIR_BASE/stunnel_proxy_client.conf"
STUNNEL_B_CLI_PID="$TMPDIR_BASE/stunnel_proxy_client.pid"
STUNNEL_B_CLI_LOG="$TMPDIR_BASE/stunnel_proxy_client.log"

cat > "$STUNNEL_B_SRV_CONF" <<EOF
foreground = no
debug = info
syslog = no
output = $STUNNEL_B_SRV_LOG
pid = $STUNNEL_B_SRV_PID

[ldap-proxy-server]
accept  = 127.0.0.1:${STUNNEL_PROXY_SERVER_PORT}
connect = 127.0.0.1:${LDAP_CONTAINER_PORT}
protocol = ldap
cert    = $SRVPEM
EOF

cat > "$STUNNEL_B_CLI_CONF" <<EOF
foreground = no
debug = info
syslog = no
output = $STUNNEL_B_CLI_LOG
pid = $STUNNEL_B_CLI_PID

[ldap-proxy-client]
client  = yes
accept  = 127.0.0.1:${STUNNEL_CLIENT_PORT}
connect = 127.0.0.1:${STUNNEL_PROXY_SERVER_PORT}
protocol = ldap
EOF

"$STUNNEL" "$STUNNEL_B_SRV_CONF"
sleep 0.5
"$STUNNEL" "$STUNNEL_B_CLI_CONF"
sleep 1

if ! ss -tlnp 2>/dev/null | grep -q ":${STUNNEL_CLIENT_PORT}"; then
    fail "Test B: stunnel client proxy not listening on port $STUNNEL_CLIENT_PORT"
    cat "$STUNNEL_B_CLI_LOG" >&2
    cat "$STUNNEL_B_SRV_LOG" >&2
else
    info "stunnel client proxy is up on port $STUNNEL_CLIENT_PORT"

    # Test B.1: plain ldapsearch through the proxy chain (STARTTLS is transparent)
    info "B.1 Plain ldapsearch through client->server proxy chain..."
    if ldapsearch -x \
            -H "ldap://127.0.0.1:${STUNNEL_CLIENT_PORT}" \
            -b "$LDAP_BASE" \
            -D "$LDAP_ADMIN_DN" \
            -w "$LDAP_ADMIN_PASS" \
            "(objectClass=*)" dn \
            2>/dev/null | grep -q "dn:"; then
        ok "Test B.1: plain LDAP through client→server proxy chain succeeded"
    else
        fail "Test B.1: plain LDAP through client→server proxy chain failed"
        info "--- client log ---"
        cat "$STUNNEL_B_CLI_LOG" >&2
        info "--- server log ---"
        cat "$STUNNEL_B_SRV_LOG" >&2
    fi

    # Test B.2: add an entry and search for it through the proxy
    info "B.2 ldapadd + ldapsearch through proxy chain..."
    LDIF="$TMPDIR_BASE/test.ldif"
    cat > "$LDIF" <<LDIF
dn: ou=people,dc=example,dc=org
objectClass: organizationalUnit
ou: people

dn: uid=testuser,ou=people,dc=example,dc=org
objectClass: inetOrgPerson
uid: testuser
cn: Test User
sn: User
mail: testuser@example.org
userPassword: secret
LDIF

    ldapadd -x \
        -H "ldap://127.0.0.1:${STUNNEL_CLIENT_PORT}" \
        -D "$LDAP_ADMIN_DN" \
        -w "$LDAP_ADMIN_PASS" \
        -f "$LDIF" >/dev/null 2>&1 || true  # may already exist

    if ldapsearch -x \
            -H "ldap://127.0.0.1:${STUNNEL_CLIENT_PORT}" \
            -b "ou=people,dc=example,dc=org" \
            -D "$LDAP_ADMIN_DN" \
            -w "$LDAP_ADMIN_PASS" \
            "(uid=testuser)" cn mail \
            2>/dev/null | grep -q "cn: Test User"; then
        ok "Test B.2: ldapadd + ldapsearch through proxy chain succeeded"
    else
        fail "Test B.2: ldapadd + ldapsearch through proxy chain failed"
        cat "$STUNNEL_B_CLI_LOG" >&2
        cat "$STUNNEL_B_SRV_LOG" >&2
    fi
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "────────────────────────────────────────"
echo "Results: ${PASS} passed, ${FAIL} failed"
echo "────────────────────────────────────────"
[ "$FAIL" -eq 0 ] || exit 1
