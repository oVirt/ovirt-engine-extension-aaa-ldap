oVirt LDAP authentication and authorization extension - PROFILE CONFIGURATION
=============================================================================

OUTLINE
-------

FORMAT

The format of profile is properties file. Every rule[1] of Java property file
applies.

[1] http://docs.oracle.com/javase/7/docs/api/java/util/Properties.html#load%28java.io.Reader%29

SORTING

Sort hint is marked as @SORT@, it is alphabetic sort not number sort. Content
is not important.

INCLUDES

Property file can include other property files. In order to include more than
one file use include.@SORT@ directive. Files are relative to them-selves, unless
specified within <> brackets, these are read from search directories.

Examples:

    include.1 = <file1>
    include.2 = file2

VARIABLES

Recursive value substitution is available, format is ${namespace:name}, where
namespace is:

 - local
    processed during read, variables:
        _basedir - directory where property file resides.
 - global
    processed after all files are processed, can reference to any
    property.
 - sys
    Reference to system property.
 - seq
    Sequence context, (key, value) pair, where value usually string. These are
    marked as @VAR@ across this document.

SEQ VARIABLES

authn_enable
    set if authn is initialized.

authz_enable
    set if authz is initialized.

capability_recursiveGroupResolution
    true if directory resolves groups recursively.

capability_credentialsChange
    true if directory supports password modify extended request (RFC-3062).

dn
    dn of input/output object.

filter
    requested filter.

maxFilterSize
    maximum filter size, set by profile.

namespace
    namespace of input/output.

namespaces
    a list of namespaces to use.

namespaceDefault
    a default namespace to use if cannot be found within available
    namespaces.

password
    password to use.

passwordNew
    used for credentials change.

query
    query instance output.

sensitiveKeys
    holds a comma separated list of variables that
    are not to be dumped.

user
    user of input/output.

ATTRIBUTES

Attribute with suffix of .@ATTRIBUTE@ can contain attributes of referenced Java
object. Only setXXXX() setters are supported, first letter of setter is
lower case. Lists are also supported using comma separated strings. Enum
should use their native names. In order to call setter multiple time, the notation
of .@ATTRIBUTE@.@SORT@ is supported.

Examples:

    The following will call LDAPConnectionPool.setMaxWaitTimeMillis(1000):

    pool.default.connection-pool.maxWaitTimeMillis = 1000

    The following will call DIGESTMD5BindRequestProperties.setAllowedQoP(AUTH, AUTH_CONF, AUTH_INT):

    pool.default.auth.digest-md5.allowedQoP = AUTH, AUTH_CONF, AUTH_INT

SEQUENCES
---------

NOTE: Sequence names can be altered by extension configuration.

namespace
    Sequence name of namespace query.
    Used during initialization to determine namespaces.

    Output:
        query
        namespaces (list)
        namespaceDefault

authn
    Sequence name of authentication.

    Input:
        user
        password

    Output:
        authTranslatedMessage
        PrincipalRecord_PRINCIPAL
        message

credentials-change
    Sequence name of credentials change.

    Input:
        user
        password
        passwordNew

resolve-principal
    Sequence name of resolve principal.
    Used during user login to fetch properties of principal name.

    Input:
        PrincipalRecord_PRINCIPAL

    Output:
        query*

resolve-groups
    Sequence name of resolve groups out of DN.
    Used during user login to fetch groups recursively.
    Used during directory sync.

    Input:
        dn
        dnType - principal|group

    Output:
        query*

query-principals
    Sequence name of query principal.
    Used during administrative tasks.

    Input:
        namespace
        filter

    Output:
        query

query-groups
    Sequence name of query groups.
    Used during administrative tasks.

    Input:
        namespace
        filter

    Output:
        query

MODEL
-----

POOL

Pool of LDAP connections, based on specific policy.

    # Default settings
    pool.default.*

    # Specific settings
    pool.@ID@.*

    # CONNECTION OPTIONS
    # Class: LDAPConnectionOptions.
    # Documentation and options at:
    # https://docs.ldap.com/ldap-sdk/docs/javadoc/com/unboundid/ldap/sdk/LDAPConnectionOptions.html
    pool.default.connection-options.@ATTRIBUTE@ = value

    # POOL OPTIONS
    pool.default.connection-pool.initialConnections = 4
    pool.default.connection-pool.maxConnections = 20
    pool.default.connection-pool.initialConnectThreads = 1
    # Class: LDAPConnectionPool.
    # Documentation and options at:
    # https://docs.ldap.com/ldap-sdk/docs/javadoc/com/unboundid/ldap/sdk/LDAPConnectionPool.html
    pool.default.connection-pool.@ATTRIBUTE@ = value

    # SOCKET FACTORY
    pool.default.socketfactory.type = resolver
    # standard java
    pool.default.socketfactory.java
    # jndi resolver hack
    # Support IPv6
    pool.default.socketfactory.resolver.supportIPv6 = false
    # Cache lifetime of resolved addresses
    pool.default.socketfactory.resolver.cacheTTL = 10000
    # jndi URL to use
    pool.default.socketfactory.resolver.uRL = dns://
    # jndi properties to use, prefix is truncated.
    pool.default.socketfactory.resolver.jndi-properties.@PROPERTY@ = @STRING@
    # permit plain address usage
    pool.default.socketfactory.resolver.enableAddressOnly = false

    # SSL
    pool.default.ssl.enable = false
    pool.default.ssl.startTLS = false
    pool.default.ssl.host-name-verify.enable = true
    pool.default.ssl.host-name-verify.wildcards = true
    pool.default.ssl.insecure = false
    pool.default.ssl.protocol = TLSv1
    pool.default.ssl.startTLSProtocol = TLSv1
    pool.default.ssl.truststore.provider = (JRE default)
    pool.default.ssl.truststore.type = (JRE default)
    pool.default.ssl.truststore.file = (JRE default)
    pool.default.ssl.truststore.password = (JRE default)|changeit
    pool.default.ssl.keystore.provider = (JRE default)
    pool.default.ssl.keystore.type = (JRE default)
    pool.default.ssl.keystore.file = @FILE@
    pool.default.ssl.keystore.password = changeit
    pool.default.ssl.trustmanager.algorithm = (JRE default)
    pool.default.ssl.keymanager.algorithm = (JRE default)

    # SERVERSET
    # Documentation at:
    # https://docs.ldap.com/ldap-sdk/docs/javadoc/com/unboundid/ldap/sdk/SingleServerSet.html
    # https://docs.ldap.com/ldap-sdk/docs/javadoc/com/unboundid/ldap/sdk/RoundRobinServerSet.html
    # https://docs.ldap.com/ldap-sdk/docs/javadoc/com/unboundid/ldap/sdk/FailoverServerSet.html
    # https://docs.ldap.com/ldap-sdk/docs/javadoc/com/unboundid/ldap/sdk/FastestConnectServerSet.html
    # https://docs.ldap.com/ldap-sdk/docs/javadoc/com/unboundid/ldap/sdk/FewestConnectionsServerSet.html
    # https://docs.ldap.com/ldap-sdk/docs/javadoc/com/unboundid/ldap/sdk/RoundRobinDNSServerSet.html
    # https://docs.ldap.com/ldap-sdk/docs/javadoc/com/unboundid/ldap/sdk/DNSSRVRecordServerSet.html
    pool.default.serverset.type = single
    pool.default.serverset.single.server = @STRING@
    pool.default.serverset.single.port = 389
    pool.default.serverset.{round-robin|failover|fastest-connect|fewest-connections}.@SORT@.server = @STRING@
    pool.default.serverset.{round-robin|failover|fastest-connect|fewest-connections}.@SORT@.port = 389
    pool.default.serverset.dns-round-robin.server = @STRING@
    pool.default.serverset.dns-round-robin.port = 389
    pool.default.serverset.dns-round-robin.selectionMode = RANDOM
    pool.default.serverset.dns-round-robin.dnsRecordTypes = A
    pool.default.serverset.dns-round-robin.cacheTimeoutMillis = @INT@
    # jndi properties to use, prefix is truncated.
    pool.default.serverset.dns-round-robin.jndi-properties.@PROPERTY@ = @STRING@
    pool.default.serverset.srvrecord.service = ldap
    pool.default.serverset.srvrecord.protocol = tcp
    pool.default.serverset.srvrecord.domain = @STRING@
    pool.default.serverset.srvrecord.ttlMillis = @INT@
    # jndi properties to use, prefix is truncated.
    pool.default.serverset.srvrecord.jndi-properties.@PROPERTY@ = @STRING@

    # AUTHENTICATION
    pool.default.auth.type = none
    pool.default.auth.none
    pool.default.auth.simple.bindDN = @STRING@
    pool.default.auth.simple.password = @STRING@
    pool.default.auth.external
    pool.default.auth.sasl-anonymous
    pool.default.auth.sasl-plain.authenticationID = @STRING@
    pool.default.auth.sasl-plain.password = @STRING@
    pool.default.auth.cram-md5.authenticationID = @STRING@
    pool.default.auth.cram-md5.password = @STRING@
    # Class: DIGESTMD5BindRequestProperties
    # Documentation and options at:
    # https://docs.ldap.com/ldap-sdk/docs/javadoc/com/unboundid/ldap/sdk/DIGESTMD5BindRequest.html
    pool.default.auth.digest-md5.@ATTRIBUTE@ = value
        authenticationID = @STRING@
        password = @STRING@
    # Class: GSSAPIBindRequestProperties
    # Documentation and options at:
    # https://docs.ldap.com/ldap-sdk/docs/javadoc/com/unboundid/ldap/sdk/GSSAPIBindRequestProperties.html
    pool.default.auth.gssapi.@ATTRIBUTE@ = value
        authenticationID = @STRING@
        password = @STRING@

STATS

    # statistics interval in milliseconds
    stats.interval = 60000

AUTH CHECK

    # Default settings
    auth-check.default.*

    # Specific settings
    auth-check.@ID@.*

    # Pool to use
    auth-check.default.pool = @ID@
    # User, most probably sequence variable.
    auth-check.default.user = @STRING@
    # Password, most probably sequence variable.
    auth-check.default.password = @STRING@
    # Authentication method, same as pool.auth.
    auth-check.default.auth.*
    auth-check.default.auth.type = simple
    # Enable who am I if available (RFC-4532).
    auth-check.default.whoami.enable = true
    # Reuse connection after authentication attempt
    auth-check.default.reuse-connections = false

ATTRIBUTE MAP

    # NOTE: _dn is always alias for object dn.

    # Default settings
    attrmap.default.*

    # Specific settings
    attrmap.@POOLID@.*

    # Conversion to use: STRING, BASE64, DATE
    attrmap.default.attr.@ALIAS@.conversion = STRING
    # Map attribute.
    attrmap.default.attr.@ALIAS@.map = @ATTRIBUTE@
    # String.format
    attrmap.default.attr.@ALIAS@.format = %s

SEARCH

    # Default settings
    search.default.*

    # Specific settings
    search.@ID@.*

    # Pool id.
    search.default.pool = @ID@
    # Use paging.
    search.default.paging = true
    # Default page size.
    search.default.pageSize = 100
    # Limit.
    search.default.limit = (Max Integer)
    # SEARCH OPTIONS
    # Class: SearchRequest.
    # Documentation and options at:
    # https://docs.ldap.com/ldap-sdk/docs/javadoc/com/unboundid/ldap/sdk/SearchRequest.html
    #
    # NOTE:
    # all variables are also available as @NAME@_encoded to be safely put within
    # filter statement. DO NOT put raw variables.
    #
    search.default.search-request.@ATTRIBUTE@ = value
        filter = @FILTER@
        attributes = attr1, attr, ...

INITIALIZATION SEQUENCE

    # Run sequence during initialization
    # must not fail
    sequence-init.init.@SORT@ = @ID@
    # Run sequence during open, happens post
    # initialization
    sequence-init.open.@SORT@ = @ID@

SEQUENCE

    # sequence description
    sequence.@ID@.@SORT@.description = @STRING@

    # CONDITION
    # Condition type.
    sequence.@ID@.@SORT@.condition.type = true
    # true condition.
    sequence.@ID@.@SORT@.condition.true
    # var-set
    # Check if variable is set.
    sequence.@ID@.@SORT@.condition.var-set.variable = @VAR@
    # compare
    # Compare left and right.
    # default string conversion and equals
    sequence.@ID@.@SORT@.condition.compare.conversion = string|numeric
    sequence.@ID@.@SORT@.condition.compare.left = @STRING@
    sequence.@ID@.@SORT@.condition.compare.right = @STRING@
    sequence.@ID@.@SORT@.condition.compare.result = -1|0|1
    # invert result.
    sequence.@ID@.@SORT@.condition.not = false
    
    # OPCODES
    # Opcode type
    sequence.@ID@.@SORT@.type = noop
    # Noop
    sequence.@ID@.@SORT@.noop
    # Stop sequence
    sequence.@ID@.@SORT@.stop
    # Call other sequence 
    sequence.@ID@.@SORT@.call.name = @ID@
    # Iterate collection by calling sequence
    sequence.@ID@.@SORT@.for-each.sequence = @ID@
    sequence.@ID@.@SORT@.for-each.variable = @VAR@
    sequence.@ID@.@SORT@.for-each.var-index = @VAR@  # will hold index default: forEachIndex
    sequence.@ID@.@SORT@.for-each.var-value = @VAR@  # will hold value default: forEachValue
    # Log
    # Log message at level (trace, debug, info, warn, error, fatal)
    sequence.@ID@.@SORT@.log.level = info
    sequence.@ID@.@SORT@.log.message = @STRING@
    # Execute auth-check
    sequence.@ID@.@SORT@.auth-check.name = @ID@
    # Execute LDAP search
    # Map attributes to variables.
    # Select index of attribute, -1 stores entire list.
    sequence.@ID@.@SORT@.fetch-record.search = @ID@
    sequence.@ID@.@SORT@.fetch-record.map.@ATTR@.name = @VAR@
    sequence.@ID@.@SORT@.fetch-record.map.@ATTR@.select = 0
    # Set variable.
    sequence.@ID@.@SORT@.var-set.variable = @VAR@
    sequence.@ID@.@SORT@.var-set.value = @STRING@
    # Get entry from list.
    sequence.@ID@.@SORT@.var-list-get.variable = @VAR@
    sequence.@ID@.@SORT@.var-list-get.var-list = @VAR@  # list content
    sequence.@ID@.@SORT@.var-list-get.index = @VAR@
    # Set list.
    sequence.@ID@.@SORT@.var-list-set.variable = @VAR@
    sequence.@ID@.@SORT@.var-list-set.values.@SEQ@.value = @STRING@
    sequence.@ID@.@SORT@.var-list-set.values.@SEQ@.var = @VAR@
    sequence.@ID@.@SORT@.var-list-set.values.@SEQ@.var-list = @VAR@  # append list content
    # Set system property.
    sequence.@ID@.@SORT@.sysprop-set.name = @STRING@
    sequence.@ID@.@SORT@.sysprop-set.value = @STRING@
    # Execute regular expression.
    # Apply pattern on value and execute replacements.
    # At replacements ${xxx} can be used to replace group names.
    sequence.@ID@.@SORT@.regex.pattern = @PATTERN@
    sequence.@ID@.@SORT@.regex.value = @STRING@
    sequence.@ID@.@SORT@.regex.replacement.@VAR@ = @REPLACEMENT@
    # Execute credentials modify.
    sequence.@ID@.@SORT@.credentials-modify.pool = @ID@
    sequence.@ID@.@SORT@.credentials-modify.user = @STRING@
    sequence.@ID@.@SORT@.credentials-modify.password.current = @STRING@
    sequence.@ID@.@SORT@.credentials-modify.password.new = @STRING@
    # Register attribute map.
    sequence.@ID@.@SORT@.register-attrmap.name = @ID@
    # Create pool.
    sequence.@ID@.@SORT@.pool-create.name = @ID@
    # Open a search.
    # Please instance into variable.
    sequence.@ID@.@SORT@.search-open.name = @ID@
    sequence.@ID@.@SORT@.search-open.variable = @VAR@
    # Get current time
    sequence.@ID@.@SORT@.time-get.variable = @ID@

SENSITIVE KEYS

    # sensitive components within property name.
    sensitive-keys.@SORT@ = password
