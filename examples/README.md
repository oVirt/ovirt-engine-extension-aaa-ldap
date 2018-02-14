Advanced Active Directory Configurations
========================================

This directory contains examples of advanced configurations that cannot be
created automatically with the `ovirt-engine-extension-aaa-ldap-setup` tool.
These manual configurations enable you to use some of the advanced Active
Directory (AD) features.

Single AD server using StartTLS
-----------------------------------------------------------
[This example](./ad-singleserver-starttls) describes how to configure a single
AD server using StartTLS. The server is specified in the `aaa-ldap`
configuration file, not in the DNS SRV records.

The connection between `aaa-ldap` and the AD server is secured with StartTLS.
The StartTLS connection requires you to import either the CA certificate that
signed the AD server certificate, or the AD server certificate itself, into
the Java keystore. The path to the Java keystore is specified
in the configuration file.

Multiple AD servers using StartTLS
--------------------------------------------------------------
[This example](./ad-failover-starttls) describes how to configure multiple AD
servers using StartTLS. There are two different mechanisms for selecting
the actual AD server that fulfills the request:

 - __failover__: If the first server fails, the request is passed on to
   the second server. If the second server fails, the request is passed to
   the third, and so on.

 - __round-robin__: The actual server is selected using a round-robin
   algorithm.

This example uses the configuration for `failover`. If `round-robin` is
required, replace all occurrences of `failover` with `round-robin`.

The AD servers are specified in the `aaa-ldap` configuration file, not in
the DNS SRV records.

The connection between `aaa-ldap` and the AD servers is secured with StartTLS.
The StartTLS connection requires you to import the CA certificate that signed
all the AD server certificates into the Java keystore. The path to the Java
keystore is specified in the configuration.

Multiple AD servers using LDAPS
-----------------------------------------------------------
[This example](./ad-failover-ldaps) describes how to configure multiple AD
servers using LDAPS. There are two different mechanisms for selecting
the actual AD server that fulfills the request:

 - __failover__: If the first server fails, the request is passed on to
   the second server. If the second server fails, the request is passed to
   the third, and so on.

 - __round-robin__: The actual server is selected using a round-robin
   algorithm.

This example uses the configuration for `failover`. If `round-robin` is
required, replace all occurrences of `failover` with `round-robin`.

The AD servers are specified in the aaa-ldap configuration file, not in
the DNS SRV records.

The connection between `aaa-ldap` and AD servers is secured using LDAPS, which
requires specific ports (636 for LDAP, 3269 for Global Catalog) that are
different from those used by plaintext or StartTLS connections.

The LDAPS connection requires you to import the CA certificate that signed all
the AD server certificates into the Java keystore. The path to the Java
keystore is specified in the configuration.

AD servers defined in DNS SRV records using LDAPS
-------------------------------------------------------------------
[This example](./ad-srvrecord-ldaps) shows how to use AD servers defined in
DNS SRV records.

The connection between `aaa-ldap` and the AD servers is secured using LDAPS,
which requires specific ports (636 for LDAP, 3269 for Global Catalog) that are
different from those used by plaintext or StartTLS connections.

The default port, defined in the '_ldap._tcp' SRV record, is port 389. To use
port 636, you must do one of the following:

 - The preferred method is to create a new _ldaps._tcp SRV record containing
   port 636 and then change the SRV record's service name (example below)
 - Alternatively, you can change the port to 636 in the _ldap._tcp SRV record.

See the AD documentation for information on how to configure DNS SRV records.

Single sign-on with AD
------------------------------------
[This example](./ad-sso) shows how to use AD with Kerberos for single sign-on.

Single sign-on requires some changes to the Apache configuration because
Apache performs the authentication and specifies the service principal in HTTP
headers to `aaa-ldap`. Here is an [example](./ad-sso/aaa/ovirt-sso.conf) of
the Apache configuration.

First, configure the mapping of the Kerberos realm to the aaa-ldap principal,
if necessary. Then configure `ovirt-engine-extension-aaa-misc`, in order
to pass the principal from the HTTP header to `aaa-ldap`.

In the Apache configuration, set the X-Remote-User header. This header is read
and the user is set as the principal in the AuthN configuration.

Using GSSAPI to authenticate against IPA
----------------------------------------
[This example](./ipa-gssapi) shows how to use GSSAPI instead of a standard
password to authenticate users against an IPA server.

Kerberos must be configured for GSSAPI. The default Kerberos configuration
file is `/etc/krb5.conf`, like this [example](./ipa-gssapi/aaa/krb5.conf).

Using GSSAPI with ticket cache to authenticate against IPA
----------------------------------------------------------
[This example](./ipa-ticketcache-gssapi) shows how to use GSSAPI with a ticket
cache to authenticate a search user against the IPA, so that the search user's
password does not need to be provided in the `aaa-ldap` configuration.

1. Create an `/etc/krb5.conf` file, like this
   [example](./ipa-ticketcache-gssapi/aaa/krb5.conf), with the appropriate
   Kerberos configuration.

2. Run `kinit` with your search user to create a ticket cache and verify that
   the ticket cache is readable by the ovirt user:

```
  $ klist
  $ ls -l /tmp/krb5cc_{userUID}
  $ chown ovirt /tmp/krb5cc_{userUID}
```

3. Create a configuration file, like this
   [example](./ipa-ticketcache-gssapi/aaa/99-jaas.conf), with the appropriate
   `{userUID}`, and save it in the `/etc/ovirt-engine/engine.conf.d/`
   directory.

```
/etc/ovirt-engine/engine.conf.d/99-jaas.conf
AAA_JAAS_USE_TICKET_CACHE=true
AAA_JAAS_TICKET_CACHE_FILE=/tmp/krb5cc_{userUID}
```

4. Configure Kerberos for GSSAPI, like this
   [`/etc/krb5.conf` example](./ipa-gssapi/aaa/krb5.conf).

5. Restart the engine:

```
systemctl restart ovirt-engine
```
