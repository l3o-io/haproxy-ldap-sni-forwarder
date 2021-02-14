# haproxy-ldap-sni-forwarder

haproxy-ldap-sni-forwarder is tcp reverse proxy server for ldap connections
supporting Server Name Indication (SNI) for TLS based connections.

Existing solutions with TCP TLS SNI support do not work for ldap servers
because prior to the TLS handshake a ldap extended request
``LDAP_START_TLS_OID`` must send.

This server intercepts the ldap extended requests for ``LDAP_START_TLS_OID``
pretending the server supports TLS and detects the SNI server name from the
client hello message. Based on SNI, traffic will be forwarded to backends
configured in ``conf.yaml`` either directly (1) or through haproxy (2) using
the ``/etc/haproxy/tcp2be.map`` map (file) dynamically configured using
haproxy's control socket.

For production deployments preferably use method (2) because haproxy does
a great job in proxying including health checks.

## Requirements

* haproxy with ``concat`` converter support (1.9+), when using haproxy


## License

haproxy-ldap-sni-forwarder is open source software released under the
**AGPL-3.0-or-later license** (http://www.gnu.org/licenses/agpl-3.0.html)
