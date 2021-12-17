# oVirt Engine Extension AAA LDAP

[![Copr build status](https://copr.fedorainfracloud.org/coprs/ovirt/ovirt-master-snapshot/package/ovirt-engine-extension-aaa-ldap/status_image/last_build.png)](https://copr.fedorainfracloud.org/coprs/ovirt/ovirt-master-snapshot/package/ovirt-engine-extension-aaa-ldap/)

Welcome to the oVirt Engine AAA LDAP Extension source repository.
This repository is hosted on [GitHub:ovirt-engine-extension-aaa-ldap](https://github.com/oVirt/ovirt-engine-extension-aaa-ldap)

This repository contains extension to use LDAP servers to authenticate users to oVirt Engine.

##QUICK START

USING INSTALLER

Install ovirt-engine-extension-aaa-ldap-setup and execute:

```
 # ovirt-engine-extension-aaa-ldap-setup
```

The setup will guide you throughout the process of most common use cases.

USING CONFIGURATION FILES

Examples are available at the following directory:

  `/usr/share/ovirt-engine-extension-aaa-ldap*/examples`

Content is relative to /etc/ovirt-engine directory.

1. Per your setup, copy recursive examples/ad/. (Active Directory) or
   examples/simple/. to /etc/ovirt-engine, optionally modify the profile1
   within the file names and profile1 within the content to a value
   that suites your environment.

2. Customize the vars.* variables within files to meet your setup.

3. Test drive your configuration

   oVirt 3.6/4.x
   -------------

   Test drive can be done as standalone process.

   a. Test login:

   Execute:

   ```
   # ovirt-engine-extensions-tool aaa login-user \
        --profile=@PROFILE@ --user-name=@USER@
   ```

   Replace:
    - @PROFILE@ with authn ovirt.engine.aaa.authn.profile.name.
    - @USER@ with user you want to test.

   Inspect output for initialization errors.

   Inspect PrincipalRecord and GroupRecord within the output and verify it
   matches expectations.

   b. Test search:

   Search by executing:
   ```
   # ovirt-engine-extensions-tool aaa search --extension-name=@AUTHZ@ \
        --entity=@ENTITY@ --entity-name=@NAME@
   ```
   Optionally add the following to enable group resolution:
       --authz-flag=resolve-groups --authz-flag=resolve-groups-recursive

   Replace:
    - @AUTHZ@ with authz extension name.
    - @ENTITY@ with either 'principal' or 'group'.
    - @NAME@ with requested name to search.

   Inspect output for initialization errors.

   Inspect PrincipalRecord and GroupRecord within the output and verify it
   matches expectations.

   c. Restart ovirt-engine, verify no startup errors.

   oVirt 3.5
   ---------

   a. Restart ovirt-engine, verify no startup errors.

   b. Within ovirt-engine try to search for users, add a user and assign
      SuperUser system roles.

   c. Try to login using the newly added user.

4. Complete customization of profile, such as enabling startTLS.

## IMPLEMENTATION NOTES

Implementation uses UnboundID LDAP SDK for Java. Many of the terms and
configuration options derived from the SDK terms. More information can
be found at UnboundID site[1].

Refer to README.unboundid-ldapsdk for known issues and limitations.

[1] https://www.ldap.com/unboundid-ldap-sdk-for-java

## EXTENSION CONFIGURATION

AUTHZ

Configure authorization extension.

`/etc/ovirt-engine/extensions.d/@AUTHZ_NAME@.properties`

```
ovirt.engine.extension.name = @AUTHZ_NAME@
ovirt.engine.extension.bindings.method = jbossmodule
ovirt.engine.extension.binding.jbossmodule.module = org.ovirt.engine.extension.aaa.ldap
ovirt.engine.extension.binding.jbossmodule.class = org.ovirt.engine.extension.aaa.ldap.AuthzExtension
ovirt.engine.extension.provides = org.ovirt.engine.api.extensions.aaa.Authz
config.profile.file.1 = @PROFILE_CONFIGURATION@

@AUTHZ_NAME@
    Extension instance name.
@PROFILE@
    Profile name, visible to user.
@PROFILE_CONFIGURATION@
    Profile configuration file, may be relative to extension configuration.
```

AUTHN

Configure authentication extension.

`/etc/ovirt-engine/extensions.d/@AUTHN_NAME@.properties`

```
ovirt.engine.extension.name = @AUTHN_NAME@
ovirt.engine.extension.bindings.method = jbossmodule
ovirt.engine.extension.binding.jbossmodule.module = org.ovirt.engine.extension.aaa.ldap
ovirt.engine.extension.binding.jbossmodule.class = org.ovirt.engine.extension.aaa.ldap.AuthnExtension
ovirt.engine.extension.provides = org.ovirt.engine.api.extensions.aaa.Authn
ovirt.engine.aaa.authn.profile.name = @PROFILE@
ovirt.engine.aaa.authn.authz.plugin = @AUTHZ_NAME@
config.profile.file.1 = @PROFILE_CONFIGURATION@

@AUTHN_NAME@
    Extension instance name.
@AUTHZ_NAME@
    Authz extension instance name.
@PROFILE@
    Profile name, visible to user.
@PROFILE_CONFIGURATION@
    Profile configuration file, may be relative to extension configuration.
```

## REMOVING CONFIGURED PROFILE

Following steps describe how to remove a configured LDAP profile (profile name
'profile1' is assumed in commands, please adapt to profile name that should be
removed):

  1. Remove profile configuration files
      ```
      rm /etc/ovirt-engine/extensions.d/profile1-authn.properties
      rm /etc/ovirt-engine/extensions.d/profile1-authz.properties
      rm /etc/ovirt-engine/aaa/profile1.properties
      ```

  2. Restart ovirt-engine
      ```
      systemctl restart ovirt-engine
      ```


Note:
  The above steps will remove profile configuration, so users from this
  profile will no longer be able to login into engine. But those users still
  have permissions defined in engine, so if you want to remove those
  permissions you need to do following:

    1. Login into webadmin and switch to Users tab
    2. Remove all users from the provider you have removed above (they should
       have their Authorization provider set to 'profile1-authz'

## PROFILE CONFIGURATION EXAMPLES

OPENLDAP/389DS/IPA/...

Using simple bind transport using startTLS:

```
    # select one
    include = <openldap.properties>
    #include = <389ds.properties>
    #include = <rhds.properties>
    #include = <ipa.properties>
    #include = <iplanet.properties>
    #include = <rfc2307-generic.properties>
    #include = <rfc2307-389ds.properties>
    #include = <rfc2307-rhds.properties>
    #include = <rfc2307-openldap.properties>
    #include = <rfc2307-edir.properties>

    vars.server = ldap1.company.com
    vars.user = uid=search,cn=users,cn=accounts,dc=company,dc=com
    vars.password = 123456

    pool.default.serverset.single.server = ${global:vars.server}
    pool.default.auth.simple.bindDN = ${global:vars.user}
    pool.default.auth.simple.password = ${global:vars.password}
    pool.default.ssl.startTLS = true
    pool.default.ssl.truststore.file = ${local:_basedir}/${global:vars.server}.jks
    pool.default.ssl.truststore.password = changeit
```

Round robin configuration:

```
    pool.default.serverset.type = round-robin
    pool.default.serverset.round-robin.1.server = ${global:vars.server1}
    pool.default.serverset.round-robin.2.server = ${global:vars.server2}
```

In case sasl mechanism is used, such as gssapi, set the following within
extension configuration:

```
   # Except of active directory
   config.globals.bindFormat.simple_bindFormat = realm
```

More supported configuration at README.profile.

ACTIVE DIRECTORY

Active Directory 2003 R2 and above is supported.

Using simple bind transport using startTLS. Unfortunately, SASL does not
provide bind failure reasons.

User name is the `userPrincipalName` field of the user, the suffix is usually the
domain name.

Connect to Domain Controller DNS Server directly, use SRV record to
resolve hosts.

```
    include = <ad.properties>

    vars.forest = company.com
    vars.user = search@${global:vars.forest}
    vars.password = 123456
    vars.dns = dns://dc1.${global:vars.forest} dns://dc2.${global:vars.forest}

    pool.default.serverset.type = srvrecord
    pool.default.serverset.srvrecord.domain = ${global:vars.forest}
    pool.default.auth.simple.bindDN = ${global:vars.user}
    pool.default.auth.simple.password = ${global:vars.password}
    pool.default.serverset.srvrecord.jndi-properties.java.naming.provider.url = ${global:vars.dns}
    pool.default.socketfactory.resolver.uRL = ${global:vars.dns}
    pool.default.ssl.startTLS = true
    pool.default.ssl.truststore.file = ${local:_basedir}/${global:vars.forest}.jks
    pool.default.ssl.truststore.password = changeit
```

More supported configuration at `README.profile`.


## Single Sign-On for Virtual Machines

If you are going to use Single Sign-On for Virtual Machines, your authz name
has to match your real domain name.

If you are going to use ovirt-engine-extension-aaa-ldap-setup, you will be
asked to support Single Sign-On for Virtual Machines or not. So generated
configuration files will be created upon answer to that question.

If you are going to create your configuration files manually, please beware
that by default authz name is specified with '-authz' suffix in all examples,
so please make sure to correct it in your final configuration file.

Once rhbz#1133137 is resolved, this behaviour would not be longer needed.


## X.509 CERTIFICATE TRUST STORE

When using TLS/SSL to communicate with LDAP server an X.509 certificate
trust store should be provided if the certificate of the LDAP server is
not signed by well known certification authority.

The trust store can be anything Java supports, by default it is
JKS (Java Key Store) format.

Use the following command to create a JKS `myrootca.jks` trust store using
password '`changeit`' and import the certificate `myrootca.pem` into
alias `myrootca`:

```bash
 $ keytool -importcert -noprompt -trustcacerts -alias myrootca \
       -file myrootca.pem -keystore myrootca.jks -storepass changeit
```

The root certificate should be obtained from the LDAP server, exact
method is vendor specific.

OpenLDAP

- Open `/etc/openldap/slapd.conf`
- Seek `TLSCACertificateFile` or `TLSCACertificatePath`.
- Locate certificate file.

FreeIPA

- `/etc/ipa/ca.crt`

Active Directory

- Windows: `> certutil -ca.cert myrootca.der`
- Linux:   `$ openssl -in myrootca.der -inform DER -out myrootca.pem`

Most LDAP servers will provide root certificate within TLS/SSL negotiation.
- Use the following sequence to extract:
    ```bash
    $ openssl s_client -connect @HOST@:636 -showcerts < /dev/null
    ```

    Copy/paste the last certificate into myrootca.pem
    Copy/paste the first certificate into end.pem

Check if it is a root certificate:

```bash
$ openssl verify -CAfile myrootca.pem end.pem
```

## APACHE SSO CONFIGURATION

Authorization extension can be used in an environment in which apache
preforms the authentication, common example is kerberos. Use the
ovirt-engine-extension-aaa-misc and configure the http authentication
extension to acquire principal name out of the request.

APACHE CONFIGURATION

The following example enforces kerberos authentication, and delegate
principal name via HTTP headers. The actual kerberos configuration is
out of scope for this document.

   oVirt 3.x
   ---------
   ```xml
   # mod_auth_kerb module has to be enabled and loaded
   <LocationMatch ^(/ovirt-engine/(webadmin|userportal|api)|/api)>
       RewriteEngine on
       RewriteCond %{LA-U:REMOTE_USER} ^(.*)$
       RewriteRule ^(.*)$ - [L,NS,P,E=REMOTE_USER:%1]
       RequestHeader set X-Remote-User %{REMOTE_USER}s

       AuthType Kerberos
       AuthName "Kerberos Login"

       # Modify to match installation
       Krb5Keytab /etc/krb5.keytab

       # Modify to match installation
       KrbAuthRealms REALM.COM

       KrbMethodK5Password off
       Require valid-user
   </LocationMatch>
   ```

   oVirt 4.x
   ---------

   ```xml
   # mod_auth_gssapi and mod_session modules have to be enabled and loaded
   <LocationMatch ^/ovirt-engine/sso/(interactive-login-negotiate|oauth/token-http-auth)|^/ovirt-engine/api>
     <If "req('Authorization') !~ /^(Bearer|Basic)/i">
       RewriteEngine on
       RewriteCond %{LA-U:REMOTE_USER} ^(.*)$
       RewriteRule ^(.*)$ - [L,NS,P,E=REMOTE_USER:%1]
       RequestHeader set X-Remote-User %{REMOTE_USER}s

       AuthType GSSAPI
       AuthName "Kerberos Login"

       GssapiCredStore keytab:/etc/httpd/http.keytab
       GssapiUseSessions On
       Session On
       SessionCookieName ovirt_gssapi_session path=/private;httponly;secure;

       Require valid-user
       ErrorDocument 401 "<html><meta http-equiv=\"refresh\" content=\"0; url=/ovirt-engine/sso/login-unauthorized\"/><body><a href=\"/ovirt-engine/sso/login-unauthorized\">Here</a></body></html>"
     </If>
   </LocationMatch>
   ```

WARNING!!!

In case SSO is enforced on partial URI list (example only api), The
X-Remote-User must be reseted for the remaining URIs, to avoid security
bypass.

AUTHN EXTENSION

The following configuration read the X-Remote-User header and sets it as
principal name.

`/etc/ovirt-engine/extensions.d/http-authn.properties`

```
ovirt.engine.extension.name = http-authn
ovirt.engine.extension.bindings.method = jbossmodule
ovirt.engine.extension.binding.jbossmodule.module = org.ovirt.engine.extension.aaa.misc
ovirt.engine.extension.binding.jbossmodule.class = org.ovirt.engine.extension.aaa.misc.http.AuthnExtension
ovirt.engine.extension.provides = org.ovirt.engine.api.extensions.aaa.Authn
ovirt.engine.aaa.authn.profile.name = http
ovirt.engine.aaa.authn.authz.plugin = ldap-authz
ovirt.engine.aaa.authn.mapping.plugin = http-mapping
config.artifact.name = HEADER
config.artifact.arg = X-Remote-User
```

MAPPING

`/etc/ovirt-engine/extensions.d/http-mapping.properties`

```
ovirt.engine.extension.enabled = true
ovirt.engine.extension.name = http-mapping
ovirt.engine.extension.bindings.method = jbossmodule
ovirt.engine.extension.binding.jbossmodule.module = org.ovirt.engine.extension.aaa.misc
ovirt.engine.extension.binding.jbossmodule.class = org.ovirt.engine.extension.aaa.misc.mapping.MappingExtension
ovirt.engine.extension.provides = org.ovirt.engine.api.extensions.aaa.Mapping
config.mapAuthRecord.type = regex
config.mapAuthRecord.regex.mustMatch = true
config.mapAuthRecord.regex.pattern = ^(?<user>.*?)((\\\\(?<at>@)(?<suffix>.*?)@.*)|(?<realm>@.*))$

# START-PLATFORM-DEPENDED
# Active directory:
config.mapAuthRecord.regex.replacement = ${user}${at}${suffix}${realm}
# Other
config.mapAuthRecord.regex.replacement = ${user}${at}${suffix}
# END-PLATFORM-DEPENDED
```

## PROBLEM DETERMINATION

USEFUL LDAP COMMANDS

Notations:
 * @HOST@ - LDAP HOST
 * @USERDN@ - Bind user DN, empty for anonymous.
 * @USERPW@ - Bind user password.
 * @BASEDN@ - Base DN

Find base DN

```
$ ldapsearch -H ldap://@HOST@ -x -D '@USERDN@' -w '@USERPW@' -b '' -s BASE defaultNamingContext namingContexts
```

Fetch entire rootDSE

```
$ ldapsearch -H ldap://@HOST@ -x -D '@USERDN@' -w '@USERPW@' -b '' -s BASE '*' +
```

Dump entire directory

```
$ ldapsearch -E pr=1024/noprompt -o ldif-wrap=no -H ldap://@HOST@ -x -D '@USERDN@' -w '@USERPW@' -b '@BASEDN@' '*' +
```

Test startTLS (preferred)

```
$ LDAPTLS_REQCERT=never ldapsearch -ZZ -H ldap://@HOST@ -x -D '@USERDN@' -w '@USERPW@' -b '@BASEDN@'
```

Test LDAP over SSL/TLS

```
LDAPTLS_REQCERT=never ldapsearch -H ldaps://@HOST@ -x -D '@USERDN@' -w '@USERPW@' -b '@BASEDN@'
```

Test LDAP over SSL/TLS using GSSAPI

```
$ LDAPTLS_REQCERT=never ldapsearch -H ldaps://@HOST@ -Y GSSAPI -b '@BASEDN@'
```

To test using a specific CA certificate, replace `LDAPTLS_REQCERT=never`
with `LDAPTLS_CACERT=ca.cer`.

USEFUL DNS COMMANDS

Resolve forest LDAP SRV record

```
$ dig _ldap._tcp.@FOREST@ SRV
```

Resolve global catalog SRV record from specific dns server

```
$ dig @dc1.@FOREST@ _ldap._tcp.gc._msdcs.@FOREST@ SRV
```

ENGINE LOG

A logger by the name of org.ovirt.engine.extension.aaa.ldap can be set to
INFO, DEBUG, FINE, FINER or ALL to receive verbose output.

To modify logger level to ALL while ovirt-engine is running use the following
command, replace admin@internal with any user with SuperUser role:

```
    $ "${JBOSS_HOME}/bin/jboss-cli.sh" \
        --connect \
        --timeout=30000 \
        --controller=localhost:8706 \
        --user=admin@internal \
        --commands="
            if (outcome != success) of /subsystem=logging/logger=org.ovirt.engine.extension.aaa.ldap:read-attribute(name=level),
              /subsystem=logging/logger=org.ovirt.engine.extension.aaa.ldap:add,
            end-if,
            /subsystem=logging/logger=org.ovirt.engine.extension.aaa.ldap:write-attribute(name=level,value=ALL)
        "
```

## ADVANCED EXTENSION CONFIGURATION

`config.profile.searchdir.@SORT@ = DIRECTORY`

Additional profile configuration search directories.
xxx is alphabetic sorted.

`config.profile.file.@SORT@ = FILE`

Profile configurations to read.
xxx is alphabetic sorted.

`config.globals.@SORT@.@VAR@ = VALUE`

Sequence variables to set before initialization.

`config.authn.credentials-change.message = TEXT`

A message to display if password is expired.

`config.authn.credentials-change.url = URL`

A URL to display if password is expired.

`attrmap.map-principal-record.name = ID [map-principal-record]`

Attribute map to map between principal record and native attributes.

`attrmap.map-group-record.name = ID [map-group-record]`

Attribute map to map between group record and native attributes.

`config.authz.query.max_filter_size = INT [50]`

A default maximum filter size in elements. Usually, should be set by
configuration.

`config.authz.sequence.namespace.attribute.namespace = ID [namespace]`

Attribute name of namespace within the namespace query.

```
config.authn.sequence.authn.name = ID [authn]
config.authz.sequence.credentials-change.name = ID [credentials-change]
config.authz.sequence.namespace.name = ID [namespace]
config.authz.sequence.query-groups.name = ID [query-groups]
config.authz.sequence.query-principals.name = ID [query-principals]
config.authz.sequence.resolve-groups.name = ID [resolve-groups]
config.authz.sequence.resolve-principal.name = ID [resolve-principal]
```

## How to contribute

All contributions are welcome - patches, bug reports, and documentation issues.

### Submitting patches

Please submit patches to [GitHub:ovirt-engine-extension-aaa-ldap](https://github.com/oVirt/ovirt-engine-extension-aaa-ldap)
 If you are not familiar with the process, you can read about [collaborating with pull requests](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/proposing-changes-to-your-work-with-pull-requests) on the GitHub website.

### Found a bug or documentation issue?
To submit a bug or suggest an enhancement for oVirt Engine Extension AAA LDAP please use
[oVirt Bugzilla for ovirt-engine-extension-aaa-ldap product](https://bugzilla.redhat.com/enter_bug.cgi?product=ovirt-engine-extension-aaa-ldap).

If you don't have a Bugzilla account, you can still report [issues](https://github.com/oVirt/ovirt-engine-extension-aaa-ldap/issues).

## Still need help?

If you have any other questions or suggestions, you can join and contact us on the [oVirt Users forum / mailing list](https://lists.ovirt.org/admin/lists/users.ovirt.org/).

