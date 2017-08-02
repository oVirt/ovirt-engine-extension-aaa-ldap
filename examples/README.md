Advanced Active Directory configurations
========================================

This directory includes advanced configurations, which can't be created
using `ovirt-engine-extension-aaa-ldap-setup` tool, so users need to
tweak the configuration manually in order to leverage some advanced
behaviour of their AD server(s).

Active Directory with selected single server using StartTLS
-----------------------------------------------------------
[This](./ad-singleserver-starttls) example describes how to use single AD server,
which is specified in aaa-ldap configuration file, so DNS SRV records are not used.

Connection between aaa-ldap and AD server is secured using StartTLS mechanism.
To use StartTLS connection it's required to include CA certificate, which
signed AD server certificate or the AD server certificate itself, into
Java KeyStore file and then specify a path to this file in configuration.

Active Directory with selected multiple servers using StartTLS
--------------------------------------------------------------
[This](./ad-failover-starttls) example describes how to configure multiple AD
servers. There are available 2 different mechanisms to select concrete AD
server to fulfil the request:

 - __failover__: if 1st server fails, then request will be sent to 2nd,
                 if 2nd fails, then 3rd and so on

 - __round-robin__: concrete server is selected using round-robin algorithm

The example below shows configuration for `failover` mechanism,
if `round-robin` should be the used, then it's needed just to
replace all occurences of `failover` string with `round-robin`.

AD servers are specified in aaa-ldap configuration file,
so DNS SRV records are not used.

Connection between aaa-ldap and AD servers is secured using StartTLS mechanism.
To use StartTLS connection it's required to include CA certificate, which signed
all AD servers certificates, into Java KeyStore file and then specify a path to
this file in configuration.

Active Directory with selected multiple servers using LDAPS
-----------------------------------------------------------
[This](./ad-failover-ldaps) example describes how to configure multiple AD
servers. There are available 2 different mechanisms to select concrete AD
server to fulfil the request:

 - __failover__: if 1st server fails, then request will be sent to 2nd,
                 if 2nd fails, then 3rd and so on

 - __round-robin__: concrete server is selected using round-robin algorithm

The example below shows configuration for `failover` mechanism,
if `round-robin` should be the used, then it's needed just to
replace all occurences of `failover` string with `round-robin`.

AD servers are specified in aaa-ldap configuration file,
so DNS SRV records are not used.

Connection between aaa-ldap and AD servers is secured using LDAPS mechanism,
which requires to use different ports (636 for LDAP and 3269 for Global
Catalog communication) than Plain or StartTLS mechanism.

Also to use LDAPS connection it's required to include CA certificate, which
signed all AD servers certificates, into Java KeyStore file and then specify
a path to this file in configuration.

Active Directory with server defined in DNS SRV records using LDAPS
-------------------------------------------------------------------
[This](./ad-srvrecord-ldaps) example shows how to use AD servers defined in
DNS SRV records. Connection between aaa-ldap and AD servers is secured using
LDAPS mechanism, which requires to use different ports (636 for LDAP and
3269 for Global Catalog communication) than Plain or StartTLS mechanism.
Port in DNS SRV record is defined in '_ldap._tcp' SRV record and by default
it defines port 389. So in order to use port 636, it's required to either:

 - create new _ldaps._tcp SRV record (preferred) containing port 636 and afterwards
   change SRV record service name (example below) or
 - change the port to 636 in _ldap._tcp SRV record

Please consult Active Directory documentation how to configure those DNS SRV records.

Single sign-on with Active Directory
------------------------------------
[This](./ad-sso) example shows how to use Active Directory with kerberos for single
sign-on.

In order the configure single sign-on user need to modify also Apache configuration.
The Apache performs the authentication and delegate the principal name via HTTP headers
to aaa-ldap. The example apache configuration is [here](./ad-sso/aaa/ovirt-sso.conf).

In order to pass the principal from HTTP header to aaa-ldap we need to setup also
aaa-misc extension. First we need to configure mapping, if needed which maps the
kerberos realm to aaa-ldap principal.

As acpache configuration set X-Remote-User header, we need read this header and set
it as the principal in the authn configuration.
