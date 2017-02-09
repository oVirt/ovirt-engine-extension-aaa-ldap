#
# Copyright (C) 2012-2015 Red Hat, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#


import gettext
import ldap
import re
import socket
import ssl
import sys
import tempfile

from otopi import constants as otopicons
from otopi import plugin, util

from ovirt_engine_extension_aaa_ldap_setup import constants


def _(m):
    return gettext.dgettext(
        message=m,
        domain='ovirt-engine-extension-aaa-ldap-setup',
    )


@util.export
class Plugin(plugin.PluginBase):

    class SoftRuntimeError(RuntimeError):
        pass

    # _ldap._tcp.redhat.com.  600     IN      SRV     5 0 389 \
    # ldap01.intranet.prod.int.rdu2.redhat.com.
    _DOMAIN_RE = re.compile(
        flags=re.VERBOSE,
        pattern=r"""
            ^
            [\w._-]+
            \s+
            \d+
            \s+
            IN
            \s+
            SRV
            \s+
            (?P<priority>\d+)
            \s+
            \d+
            \s+
            (?P<port>\d+)
            \s+
            (?P<host>[\w._-]+)
            \s*
            $
        """
    )

    _SERVERSETS = (
        {
            'serverset': 'single',
            'display': _('Single server'),
            'prompt': _('host address'),
            'validate': lambda self, arg: self._resolveHost(arg),
            'key': constants.LDAPEnv.HOSTS,
        },
        {
            'serverset': 'srvrecord',
            'display': _('DNS domain LDAP SRV record'),
            'prompt': _('DNS domain'),
            'validate': lambda self, arg: self._resolveDomain(arg),
            'key': constants.LDAPEnv.DOMAIN,
        },
        {
            'serverset': 'round-robin',
            'display': _('Round-robin between multiple hosts'),
            'prompt': _('space separated list of hosts'),
            'validate': lambda self, arg: self._resolveHost(arg),
            'key': constants.LDAPEnv.HOSTS,
        },
        {
            'serverset': 'failover',
            'display': _('Failover between multiple hosts'),
            'prompt': _('space separated list of hosts'),
            'validate': lambda self, arg: self._resolveHost(arg),
            'key': constants.LDAPEnv.HOSTS,
        },
    )

    @staticmethod
    def _isAddress(candidate):
        ret = False

        if not ret:
            try:
                socket.inet_pton(socket.AF_INET, candidate)
                ret = True
            except AttributeError:
                try:
                    socket.inet_aton(candidate)
                    ret = candidate.count('.') == 3
                except socket.error:
                    pass
            except socket.error:
                pass

        if not ret:
            try:
                socket.inet_pton(socket.AF_INET6, candidate)
                ret = True
            except AttributeError:
                pass
            except socket.error:
                pass

        return ret

    @staticmethod
    def _fetchURL(url):
        if sys.version_info[0] < 3:
            import urllib
            return urllib.urlopen(url).read().splitlines()
        else:
            import urllib.request
            with urllib.request.urlopen(
                url
            ) as f:
                return f.read().decode('utf-8').splitlines()

    @staticmethod
    def _resolver(plugin, record, what):
        rc, stdout, stderr = plugin.execute(
            args=(
                (
                    plugin.command.get('dig'),
                    '+noall',
                    '+answer',
                    what,
                    record
                )
            ),
        )
        return stdout

    def _resolveHost(self, arg):
        ret = True

        for h in arg.split():
            h = h.strip()

            if self._isAddress(h):
                if self.environment[constants.LDAPEnv.USE_DNS]:
                    self.logger.warning(
                        _(
                            "Detected plain IP address '{address}', "
                            "disabling DNS."
                        ).format(
                            address=h,
                        )
                    )
                    self.environment[constants.LDAPEnv.USE_DNS] = False
            else:
                self.logger.info(
                    _("Trying to resolve host '{host}'").format(
                        host=h,
                    )
                )
                if not (
                    self.environment[constants.LDAPEnv.RESOLVER](
                        plugin=self,
                        record='A',
                        what=h,
                    ) or
                    self.environment[constants.LDAPEnv.RESOLVER](
                        plugin=self,
                        record='AAAA',
                        what=h,
                    )
                ):
                    self.logger.error(
                        _("Cannot resolve host '{host}'").format(
                            host=h
                        )
                    )
                    ret = False

        return ret

    def _resolveDomain(self, arg):
        self.logger.info(
            _("Trying to resolve domain '{domain}'").format(
                domain=arg,
            )
        )
        if self.environment[constants.LDAPEnv.RESOLVER](
            plugin=self,
            record='SRV',
            what='_ldap._tcp.%s' % arg,
        ):
            return True
        else:
            self.logger.error(
                _("Cannot resolve LDAP service in domain '{domain}'").format(
                    domain=arg
                )
            )
            return False

    def _getURLs(self):

        def _buildURL(host, port):
            return '%s://%s:%s' % (
                (
                    'ldaps' if self.environment[
                        constants.LDAPEnv.PROTOCOL
                    ] == 'ldaps' else 'ldap'
                ),
                host,
                (
                    636 if self.environment[
                        constants.LDAPEnv.PROTOCOL
                    ] == 'ldaps'
                    else (389 if port is None else port)
                ),
            )

        ret = []
        if self.environment[constants.LDAPEnv.SERVERSET] == 'srvrecord':
            self.logger.info(
                _("Resolving SRV record '{record}'").format(
                    record=self.environment[
                        constants.LDAPEnv.DOMAIN
                    ],
                )
            )
            stdout = self.environment[constants.LDAPEnv.RESOLVER](
                self,
                'SRV',
                '_ldap._tcp.%s' % self.environment[
                    constants.LDAPEnv.DOMAIN
                ]
            )
            ret.extend(
                [
                    _buildURL(
                        m.group('host').rstrip('.'),
                        m.group('port'),
                    )
                    for m in sorted(
                        [
                            m for m in [
                                self._DOMAIN_RE.match(l) for l in stdout
                            ] if m
                        ],
                        key=lambda e: int(e.group('priority')),
                        reverse=True,
                    )
                ]
            )
        else:
            ret.extend([
                _buildURL(host.strip(), None)
                for host in self.environment[
                    constants.LDAPEnv.HOSTS
                ].split()
            ])

        self.logger.debug('URLs: %s', ret)
        return ret

    def _getCACert(self):
        insecure = False
        cacertfile = None
        cacert = None

        method = self.dialog.queryString(
            name='OVAAALDAP_LDAP_CACERT_METHOD',
            note=_(
                'Please select method to obtain PEM encoded CA certificate '
                '(@VALUES@): '
            ),
            prompt=True,
            caseSensitive=False,
            validValues=(
                _('File'),
                _('URL'),
                _('Inline'),
                _('System'),
                _('Insecure'),
            ),
        )
        if method == _('File').lower():
            filepath = self.dialog.queryString(
                name='OVAAALDAP_LDAP_CACERT_FILE',
                note=_(
                    'File path: '
                ),
                prompt=True,
            )
            try:
                with open(filepath) as f:
                    cacert = f.read().splitlines()
            except IOError as e:
                raise self.SoftRuntimeError(
                    _("Cannot open CA file '{filepath}': {error}").format(
                        filepath=filepath,
                        error=e,
                    ),
                )
        elif method == _('URL').lower():
            url = self.dialog.queryString(
                name='OVAAALDAP_LDAP_CACERT_URL',
                note=_(
                    'URL: '
                ),
                prompt=True,
            )
            try:
                cacert = self._fetchURL(url)
            except Exception as e:
                raise self.SoftRuntimeError(
                    _(
                        "Cannot fetch CA certificate from "
                        "'{url}': {error}"
                    ).format(
                        url=url,
                        error=e,
                    ),
                )
        elif method == _('Inline').lower():
            cacert = self.dialog.queryMultiString(
                name='OVAAALDAP_LDAP_CACERT_INLINE',
                note=_('Please paste CA certificate'),
            )
        elif method == _('Insecure').lower():
            insecure = True

        if cacert is not None:
            _cacertfile = None
            try:
                _cacertfile = tempfile.NamedTemporaryFile()
                _cacertfile.write('\n'.join(cacert) + '\n')
                _cacertfile.flush()

                if getattr(ssl, 'create_default_context', None):
                    context = ssl.create_default_context()
                    parsed = None
                    try:
                        context.load_verify_locations(cafile=_cacertfile.name)
                        parsed = context.get_ca_certs()[0]
                    except Exception as e:
                        raise self.SoftRuntimeError(
                            _("Invalid CA certificate: {error}").format(
                                error=e,
                            ),
                        )

                    if parsed.get('subject') != parsed.get('issuer'):
                        raise self.SoftRuntimeError(
                            _("Not Root CA certificate.")
                        )

                cacertfile = _cacertfile
                _cacertfile = None
            finally:
                if _cacertfile is not None:
                    _cacertfile.close()

        return (cacert, cacertfile, insecure)

    def _connectLDAP(self, cafile=None, insecure=False):
        ret = None

        for url in self._getURLs():
            try:
                self.logger.info(
                    _("Connecting to LDAP using '{url}'").format(
                        url=url,
                    ),
                )
                c = ldap.initialize(url)

                if self.environment[constants.LDAPEnv.PROTOCOL] != 'plain':
                    if insecure:
                        c.set_option(
                            ldap.OPT_X_TLS_REQUIRE_CERT,
                            ldap.OPT_X_TLS_NEVER
                        )
                    else:
                        c.set_option(
                            ldap.OPT_X_TLS_REQUIRE_CERT,
                            ldap.OPT_X_TLS_DEMAND
                        )

                if cafile is None:
                    if self.environment[
                        constants.LDAPEnv.SYSTEM_CACERTS
                    ] is not None:
                        c.set_option(
                            ldap.OPT_X_TLS_CACERTFILE,
                            self.environment[
                                constants.LDAPEnv.SYSTEM_CACERTS
                            ],
                        )
                else:
                    c.set_option(
                        ldap.OPT_X_TLS_CACERTFILE,
                        cafile
                    )

                #
                # Force create a new ssl connection.
                # Must be last TLS option.
                #
                c.set_option(ldap.OPT_X_TLS_NEWCTX, 0)

                c.set_option(
                    ldap.OPT_REFERRALS,
                    0,
                )
                c.set_option(
                    ldap.OPT_PROTOCOL_VERSION,
                    ldap.VERSION3,
                )

                if self.environment[
                    constants.LDAPEnv.PROTOCOL
                ] == 'starttls':
                    self.logger.info(_("Executing startTLS"))
                    c.start_tls_s()

                self.logger.debug('Perform search')
                ret = c.search_st(
                    '',
                    ldap.SCOPE_BASE,
                    '(objectClass=*)',
                    ['supportedLDAPVersion'],
                    timeout=60,
                )
                self.logger.debug('Result: %s', ret)
                if ret:
                    self.logger.info(_("Connection succeeded"))
                    ret = c
                    break
            except Exception as e:
                self.logger.debug('Exception', exc_info=True)
                self.logger.warning(
                    _("Cannot connect using '{url}': {error}").format(
                        url=url,
                        error=e,
                    )
                )
        else:
            raise self.SoftRuntimeError(
                _('Cannot connect using any of available options')
            )

        return ret

    def _bindLDAP(self, connection, user, password):
        self.logger.info(
            _("Attempting to bind using '{user}'").format(
                user=user if user else '[Anonymous]',
            )
        )
        connection.simple_bind_s(
            user,
            password
        )

    def __init__(self, context):
        super(Plugin, self).__init__(context=context)

    @plugin.event(
        stage=plugin.Stages.STAGE_BOOT,
    )
    def _boot(self):
        self.environment[
            otopicons.CoreEnv.LOG_FILTER_KEYS
        ].append(
            constants.LDAPEnv.PASSWORD
        )

    @plugin.event(
        stage=plugin.Stages.STAGE_INIT,
        name=constants.Stages.LDAP_COMMON_INIT,
    )
    def _init(self):
        self.environment.setdefault(
            constants.LDAPEnv.PROFILE,
            None
        )
        self.environment.setdefault(
            constants.LDAPEnv.AAA_PROFILE_NAME,
            None
        )
        self.environment.setdefault(
            constants.LDAPEnv.AAA_USE_VM_SSO,
            None
        )
        self.environment.setdefault(
            constants.LDAPEnv.SOCKET_FACTORY,
            None
        )
        self.environment.setdefault(
            constants.LDAPEnv.USER,
            None
        )
        self.environment.setdefault(
            constants.LDAPEnv.PASSWORD,
            None
        )
        self.environment.setdefault(
            constants.LDAPEnv.USE_DNS,
            None
        )
        self.environment.setdefault(
            constants.LDAPEnv.SERVERSET,
            None
        )
        self.environment.setdefault(
            constants.LDAPEnv.DOMAIN,
            None
        )
        self.environment.setdefault(
            constants.LDAPEnv.HOSTS,
            None
        )
        self.environment.setdefault(
            constants.LDAPEnv.PROTOCOL,
            None
        )
        self.environment.setdefault(
            constants.LDAPEnv.CACERT,
            None
        )
        self.environment.setdefault(
            constants.LDAPEnv.SYSTEM_CACERTS,
            None
        )
        self.environment.setdefault(
            constants.LDAPEnv.INSECURE,
            False
        )
        self.environment.setdefault(
            constants.LDAPEnv.BASE_DN,
            None
        )
        self.environment[
            constants.LDAPEnv.RESOLVER
        ] = self._resolver
        self.environment[
            constants.LDAPEnv.AVAILABLE_PROFILES
        ] = []

    @plugin.event(
        stage=plugin.Stages.STAGE_SETUP,
    )
    def _setup(self):
        self.command.detect('dig')

    @plugin.event(
        stage=plugin.Stages.STAGE_CUSTOMIZATION,
        name=constants.Stages.LDAP_COMMON_CUSTOMIZATION_EARLY,
    )
    def _customization_early(self):

        self.dialog.note(
            text=_(
                'Welcome to LDAP extension configuration program'
            ),
        )

        if self.environment[constants.LDAPEnv.PROFILE] is not None:
            if self.environment[constants.LDAPEnv.PROFILE] not in [
                e['profile'] for e in self.environment[
                    constants.LDAPEnv.AVAILABLE_PROFILES
                ]
            ]:
                raise self.SoftRuntimeError(
                    _("Profile {profile} was not found.").format(
                        profile=self.environment[constants.LDAPEnv.PROFILE],
                    )
                )
        else:
            profiles = []
            values = {}
            for i, p in enumerate(
                sorted(
                    self.environment[
                        constants.LDAPEnv.AVAILABLE_PROFILES
                    ],
                    key=lambda e: e['display'],
                ),
                start=1,
            ):
                profiles.append(
                    '%2s - %s' % (
                        i,
                        p['display']
                    )
                )
                values[i] = p['profile']

            self.dialog.note(
                (_('Available LDAP implementations:'),) +
                tuple(profiles)
            )

            self.environment[
                constants.LDAPEnv.PROFILE
            ] = values[
                int(
                    self.dialog.queryString(
                        name='OVAAALDAP_LDAP_PROFILES',
                        note=_('Please select: '),
                        prompt=True,
                        validValues=values.keys(),
                    )
                )
            ]

    @plugin.event(
        stage=plugin.Stages.STAGE_CUSTOMIZATION,
        name=constants.Stages.LDAP_COMMON_CUSTOMIZATION_LATE,
    )
    def _customization_late(self):
        if self.environment[constants.LDAPEnv.USE_DNS] is None:
            self.dialog.note(
                (
                    _('NOTE:'),
                    _(
                        'It is highly recommended to use DNS resolution for '
                        'LDAP server.'
                    ),
                    _(
                        'If for some reason you intend to use hosts or plain '
                        'address disable DNS usage.'
                    ),
                )
            )
            self.environment[
                constants.LDAPEnv.USE_DNS
            ] = self.dialog.queryString(
                name='OVAAALDAP_LDAP_USE_DNS',
                note=_(
                    'Use DNS (@VALUES@) [@DEFAULT@]: '
                ),
                prompt=True,
                caseSensitive=False,
                validValues=(_('Yes'), _('No')),
                default=_('Yes'),
            ) != _('No').lower()

        if self.environment[constants.LDAPEnv.SERVERSET] is None:
            serversets = []
            values = {}
            for i, s in enumerate(self._SERVERSETS, start=1):
                serversets.append(
                    '%2s - %s' % (
                        i,
                        s['display']
                    )
                )
                values[i] = s

            self.dialog.note(
                (_('Available policy method:'),) +
                tuple(serversets)
            )

            s = values[
                int(
                    self.dialog.queryString(
                        name='OVAAALDAP_LDAP_SERVERSET',
                        note=_('Please select: '),
                        prompt=True,
                        validValues=values.keys(),
                    )
                )
            ]

            self.environment[constants.LDAPEnv.SERVERSET] = s['serverset']

            while self.environment[s['key']] is None:
                arg = self.dialog.queryString(
                    name='OVAAALDAP_LDAP_SERVERSET',
                    note=_('Please enter {what}: ').format(
                        what=s['prompt'],
                    ),
                    prompt=True,
                )

                if s['validate'](self, arg):
                    self.environment[s['key']] = arg

        if self.environment[constants.LDAPEnv.PROTOCOL] is None:
            self.dialog.note(
                (
                    _('NOTE:'),
                    _(
                        'It is highly recommended to use secure protocol to '
                        'access the LDAP server.'
                    ),
                    _(
                        'Protocol startTLS is the standard recommended '
                        'method to do so.'
                    ),
                    _(
                        'Only in cases in which the startTLS is not '
                        'supported, fallback to non standard ldaps protocol.'
                    ),
                    (
                        'Use plain for test environments only.'
                    ),
                )
            )
            self.environment[
                constants.LDAPEnv.PROTOCOL
            ] = self.dialog.queryString(
                name='OVAAALDAP_LDAP_PROTOCOL',
                note=_(
                    'Please select protocol to use (@VALUES@) [@DEFAULT@]: '
                ),
                prompt=True,
                caseSensitive=False,
                validValues=('startTLS', 'ldaps', 'plain'),
                default='startTLS',
            )

        connection = None

        if self.environment[constants.LDAPEnv.PROTOCOL] == 'plain':
            connection = self._connectLDAP()
        else:
            if self.environment[constants.LDAPEnv.CACERT] is not None:
                cacertfile = None
                try:
                    cacert, cacertfile, insecure = self._getCACert()
                    connection = self._connectLDAP(
                        cafile=cacertfile.name if cacert else None,
                        insecure=insecure,
                    )
                finally:
                    if cacertfile is not None:
                        cacertfile.close()
            else:
                while connection is None:
                    cacertfile = None
                    try:
                        cacert, cacertfile, insecure = self._getCACert()
                        connection = self._connectLDAP(
                            cafile=cacertfile.name if cacert else None,
                            insecure=insecure,
                        )
                        self.environment[constants.LDAPEnv.INSECURE] = insecure
                        self.environment[constants.LDAPEnv.CACERT] = cacert
                    except self.SoftRuntimeError as e:
                        self.logger.error('%s', e)
                        self.logger.debug('Exception', exc_info=True)
                    finally:
                        if cacertfile is not None:
                            cacertfile.close()

        if self.environment[constants.LDAPEnv.USER] is not None:
            self._bindLDAP(
                connection,
                self.environment[constants.LDAPEnv.USER],
                self.environment[constants.LDAPEnv.PASSWORD],
            )
        else:
            while self.environment[
                constants.LDAPEnv.USER
            ] is None:
                user = self.dialog.queryString(
                    name='OVAAALDAP_LDAP_USER',
                    note=_(
                        'Enter search user DN (for example uid=username,'
                        'dc=example,dc=com or leave empty for anonymous): '
                    ),
                    prompt=True,
                    default='',
                )
                if not user:
                    password = ''
                else:
                    password = self.dialog.queryString(
                        name='OVAAALDAP_LDAP_PASSWORD',
                        note=_(
                            'Enter search user password: '
                        ),
                        prompt=True,
                        hidden=True
                    )
                try:
                    self._bindLDAP(connection, user, password)
                    self.environment[constants.LDAPEnv.USER] = user
                    self.environment[constants.LDAPEnv.PASSWORD] = password
                except Exception as e:
                    self.logger.error(
                        _(
                            "Cannot authenticate using '{user}': {error}"
                        ).format(
                            user=user,
                            error=e,
                        )
                    )

            self.environment[
                otopicons.CoreEnv.LOG_FILTER
            ].append(self.environment[constants.LDAPEnv.PASSWORD])

        if (
            self.environment[
                constants.LDAPEnv.BASE_DN
            ] is None and
            self.environment[
                constants.LDAPEnv.PROFILE
            ] != constants.PROFILES.AD
        ):
            basedn = [
                v['basedn'] for v in self.environment[
                    constants.LDAPEnv.AVAILABLE_PROFILES
                ] if v['profile'] == self.environment[
                    constants.LDAPEnv.PROFILE
                ]
            ]
            self.logger.debug('Perform search for base DN: %s', basedn)
            result = connection.search_st(
                '',
                ldap.SCOPE_BASE,
                '(objectClass=*)',
                basedn,
                timeout=60,
            )[0][1]
            self.logger.debug('Result: %s', result)
            if result:
                values = result.values()[0]
                default = values[0]
                self.environment[
                    constants.LDAPEnv.BASE_DN
                ] = self.dialog.queryString(
                    name='OVAAALDAP_LDAP_BASE_DN',
                    note=_(
                        'Please enter base DN (%s) [@DEFAULT@]: ' % (
                            ','.join(values)
                        )
                    ),
                    default=default,
                    prompt=True,
                )

        if self.environment[constants.LDAPEnv.AAA_USE_VM_SSO] is None:
            self.environment[
                constants.LDAPEnv.AAA_USE_VM_SSO
            ] = self.dialog.queryString(
                name='OVAAALDAP_LDAP_AAA_USE_VM_SSO',
                note=_(
                    'Are you going to use Single Sign-On for Virtual Machines'
                    ' (@VALUES@) [@DEFAULT@]: '
                ),
                prompt=True,
                caseSensitive=False,
                validValues=(_('Yes'), _('No')),
                default=_('No'),
            ) != _('No').lower()

        if self.environment[constants.LDAPEnv.AAA_USE_VM_SSO]:
            self.dialog.note(
                (
                    _('NOTE:'),
                    _(
                        'Profile name has to match domain name, otherwise '
                        'Single Sign-On for Virtual Machines will not work.'
                    ),
                )
            )

        # Default profile name:
        default = ''
        if self.environment[constants.LDAPEnv.SERVERSET] == 'single':
            default = self.environment[constants.LDAPEnv.HOSTS]
        elif self.environment[constants.LDAPEnv.SERVERSET] == 'srvrecord':
            default = self.environment[constants.LDAPEnv.DOMAIN]

        if self.environment[constants.LDAPEnv.AAA_PROFILE_NAME] is None:
            self.environment[
                constants.LDAPEnv.AAA_PROFILE_NAME
            ] = self.dialog.queryString(
                name='OVAAALDAP_LDAP_AAA_PROFILE',
                note=_(
                    'Please specify profile name that will be visible to '
                    'users %s: ' % ('[%s]' % default if default else '')
                ),
                default=default if default else None,
                prompt=True,
            )


# vim: expandtab tabstop=4 shiftwidth=4
