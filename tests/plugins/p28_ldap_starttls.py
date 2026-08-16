"""stunnel LDAP STARTTLS protocol tests"""

import asyncio
import logging
import os
import pathlib
import ssl
from plugin_collection import Plugin, ERR_CONN_RESET
from maketest import (
    Config,
    StunnelAcceptConnect,
    OutputError,
    UnexpectedWarning,
    LogEvent,
    ConnectionDoneEvent,
    TestConnection,
)

# RFC 2830 LDAP StartTLS ExtendedRequest, messageID=1
LDAP_STARTTLS_REQUEST = bytes([
    0x30, 0x1d,              # UNIVERSAL SEQUENCE, len=29
    0x02, 0x01, 0x01,        # INTEGER messageID=1
    0x77, 0x18,              # APPLICATION 23 (ExtendedRequest), len=24
    0x80, 0x16,              # CONTEXT [0] requestName, len=22
    0x31, 0x2e, 0x33, 0x2e, 0x36, 0x2e, 0x31, 0x2e,
    0x34, 0x2e, 0x31, 0x2e, 0x31, 0x34, 0x36, 0x36,
    0x2e, 0x32, 0x30, 0x30, 0x33, 0x37,  # "1.3.6.1.4.1.1466.20037"
])

LDAP_UNIVERSAL_SEQUENCE = 0x30
LDAP_RESULT_SUCCESS = 0x00
# Offset of resultCode value in the ExtendedResponse body
# 0x30 len 0x02 0x01 msgid 0x78 len 0x0a 0x01 <result>
LDAP_RESPONSE_RESULT_OFFSET = 9


def validate_ldap_starttls_response(data: bytes) -> None:
    """Raise UnexpectedWarning if the LDAP StartTLS response is not a success."""
    if len(data) < LDAP_RESPONSE_RESULT_OFFSET + 1:
        raise UnexpectedWarning(
            f"LDAP StartTLS response too short ({len(data)} bytes)"
        )
    if data[0] != LDAP_UNIVERSAL_SEQUENCE:
        raise UnexpectedWarning(
            f"LDAP response is not UNIVERSAL SEQUENCE (got 0x{data[0]:02x})"
        )
    if data[LDAP_RESPONSE_RESULT_OFFSET] != LDAP_RESULT_SUCCESS:
        raise UnexpectedWarning(
            f"LDAP StartTLS response returned error code "
            f"0x{data[LDAP_RESPONSE_RESULT_OFFSET]:02x}"
        )


class LdapStartTlsServer(StunnelAcceptConnect):
    """Test stunnel server-side LDAP STARTTLS (ldap_server_middle).

    The Python test client performs the LDAP StartTLS exchange (sends the
    ExtendedRequest, validates the ExtendedResponse), then upgrades the
    connection to TLS before sending data.

    Topology:
        Python test client (plain→LDAP STARTTLS→TLS)
            → stunnel server (protocol=ldap, cert)
                → plain TCP test listener
    """

    def __init__(self, cfg: Config, logger: logging.Logger):
        super().__init__(cfg, logger)
        self.params.description = '281. LDAP server-side STARTTLS'
        self.params.ssl_client = False   # we handle the upgrade ourselves
        self.params.ssl_server = False   # backend listener is plain TCP
        self.params.services = ['server']
        self.events.failure = [
            "peer did not return a certificate",
            "bad certificate",
            "certificate verify failed",
            "unsupported protocol",
            "TLS accepted: previous session reused",
            "Redirecting connection",
            ERR_CONN_RESET,
            "Connection lost",
            "Client received unexpected message",
            "Server received unexpected message",
            "Something went wrong",
            "INTERNAL ERROR",
        ]


    async def prepare_server_cfgfile(
        self, cfg: Config, port: int, service: str
    ) -> pathlib.Path:
        """Create a configuration file for a stunnel LDAP server."""
        contents = f"""
    foreground = yes
    debug = debug
    syslog = no

    [{service}]
    accept = 127.0.0.1:0
    connect = 127.0.0.1:{port}
    protocol = ldap
    cert = {cfg.certdir}/server_cert.pem
    """
        cfgfile = cfg.tempd / "stunnel_server.conf"
        cfgfile.write_text(contents, encoding="UTF-8")
        return cfgfile


    async def get_io_stream(
        self, conn: TestConnection
    ) -> tuple:
        """Connect plain, do LDAP StartTLS exchange, then upgrade to TLS."""
        tag = f"get_io_stream [127.0.0.1]:{conn.port} #{conn.idx}"

        # 1. Plain asyncio connection.
        reader, writer = await asyncio.open_connection('127.0.0.1', conn.port)

        # 2. Send LDAP StartTLS ExtendedRequest over the plain stream.
        await self.cfg.mainq.put(LogEvent(
            etype="log", level=20,
            log=f"[{tag}] Sending LDAP StartTLS request"
        ))
        writer.write(LDAP_STARTTLS_REQUEST)
        await writer.drain()

        # 3. Receive LDAP StartTLS ExtendedResponse.
        response = await reader.read(128)
        await self.cfg.mainq.put(LogEvent(
            etype="log", level=20,
            log=f"[{tag}] Received LDAP StartTLS response ({len(response)} bytes)"
        ))
        validate_ldap_starttls_response(response)

        # 4. Upgrade to TLS using loop.start_tls().
        # This creates a proper _SSLProtocol transport that drives the TLS
        # state machine through the event loop, handling SSLWantReadError /
        # SSLWantWriteError correctly — including TLS 1.3 post-handshake
        # messages (session tickets, client Finished).  Using wrap_socket()
        # on a non-blocking socket and handing it to a plain asyncio transport
        # instead would break on those SSL-layer want conditions.
        await self.cfg.mainq.put(LogEvent(
            etype="log", level=20,
            log=f"[{tag}] Upgrading connection to TLS"
        ))
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
        loop = asyncio.get_event_loop()
        new_transport = await loop.start_tls(
            writer.transport,
            writer.transport.get_protocol(),
            ssl_ctx,
        )
        # start_tls() updates the protocol's transport (so reader sees the
        # new SSL transport via connection_made), but StreamWriter caches
        # _transport independently and must be patched manually.
        writer._transport = new_transport
        return reader, writer


class LdapStartTlsProxy(StunnelAcceptConnect):
    """Test LDAP STARTTLS through a full stunnel client→server proxy chain.

    The test client connects plain TCP to the stunnel client.  The stunnel
    client performs the LDAP StartTLS exchange with the stunnel server and
    both sides upgrade to TLS.  The test client and the backend listener
    both speak plain TCP; only the stunnel-to-stunnel leg uses LDAP+TLS.

    Topology:
        Python test client (plain TCP)
            → stunnel client (protocol=ldap)
                → stunnel server (protocol=ldap, cert)
                    → plain TCP test listener
    """

    def __init__(self, cfg: Config, logger: logging.Logger):
        super().__init__(cfg, logger)
        self.params.description = '282. LDAP STARTTLS client→server proxy'
        self.params.ssl_client = False
        self.params.ssl_server = False
        self.params.services = ['server', 'client']
        self.events.failure = [
            "peer did not return a certificate",
            "bad certificate",
            "certificate verify failed",
            "unsupported protocol",
            "TLS accepted: previous session reused",
            "Redirecting connection",
            ERR_CONN_RESET,
            "Connection lost",
            "Client received unexpected message",
            "Server received unexpected message",
            "Something went wrong",
            "INTERNAL ERROR",
        ]


    async def prepare_server_cfgfile(
        self, cfg: Config, port: int, service: str
    ) -> pathlib.Path:
        """Create a configuration file for the stunnel LDAP server."""
        contents = f"""
    foreground = yes
    debug = debug
    syslog = no

    [{service}]
    accept = 127.0.0.1:0
    connect = 127.0.0.1:{port}
    protocol = ldap
    cert = {cfg.certdir}/server_cert.pem
    """
        cfgfile = cfg.tempd / "stunnel_server.conf"
        cfgfile.write_text(contents, encoding="UTF-8")
        return cfgfile


    async def prepare_client_cfgfile(
        self, cfg: Config, ports: list, service: str
    ) -> tuple:
        """Create a configuration file for the stunnel LDAP client."""
        contents = f"""
    foreground = yes
    debug = debug
    syslog = no

    [{service}]
    client = yes
    accept = 127.0.0.1:0
    connect = 127.0.0.1:{ports[1]}
    protocol = ldap
    """
        cfgfile = cfg.tempd / "stunnel_client.conf"
        cfgfile.write_text(contents, encoding="UTF-8")
        return cfgfile, os.devnull


class StunnelClientTest(Plugin):
    """LDAP STARTTLS protocol tests

    Test 281: Python client ↔ stunnel server (server-side STARTTLS only)
    Test 282: stunnel client ↔ stunnel server (full proxy, both sides)
    """
    # pylint: disable=too-few-public-methods

    def __init__(self):
        super().__init__()
        self.description = 'LDAP STARTTLS'


    async def perform_operation(self, cfg: Config, logger: logging.Logger) -> None:
        """Run LDAP STARTTLS tests"""
        stunnel = LdapStartTlsServer(cfg, logger)
        await stunnel.test_stunnel(cfg)

        stunnel = LdapStartTlsProxy(cfg, logger)
        await stunnel.test_stunnel(cfg)
