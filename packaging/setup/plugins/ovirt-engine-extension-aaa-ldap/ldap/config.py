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
import os
import re
import tempfile

from otopi import constants as otopicons
from otopi import filetransaction, plugin, util

from ovirt_engine_extension_aaa_ldap_setup import constants


def _(m):
    return gettext.dgettext(
        message=m,
        domain='ovirt-engine-extension-aaa-ldap-setup',
    )


@util.export
class Plugin(plugin.PluginBase):

    def __init__(self, context):
        super(Plugin, self).__init__(context=context)
        self._files = []

    @plugin.event(
        stage=plugin.Stages.STAGE_INIT,
    )
    def _init(self):
        self.environment.setdefault(
            constants.LDAPEnv.CONFIG_OVERWRITE,
            False
        )

    @plugin.event(
        stage=plugin.Stages.STAGE_CUSTOMIZATION,
        priority=plugin.Stages.PRIORITY_LOW,
    )
    def _customization(self):
        mydict = {}
        for e in (
            (constants.LDAPEnv.AAA_PROFILE_NAME, 'aaaprofile'),
            (constants.LDAPEnv.PROFILE, 'profile'),
            (constants.LDAPEnv.SERVERSET, 'serverset'),
            (constants.LDAPEnv.USER, 'user'),
            (constants.LDAPEnv.PASSWORD, 'password'),
            (constants.LDAPEnv.DOMAIN, 'domain'),
        ):
            mydict[e[1]] = self.environment[e[0]]

        # Escape backslash characters in the password
        mydict['password'] = mydict['password'].replace('\\', '\\\\')

        # Escape whitespace character at the beginning of the password to
        # be able to store the password properly in Java properties file
        m = re.search('^(\s)+(\S)+.*', mydict['password'])
        if m:
            mydict['password'] = (
                '\\' + mydict['password']
            )

        if self.environment[constants.LDAPEnv.HOSTS]:
            mydict['hosts'] = [
                h.strip() for h in self.environment[
                    constants.LDAPEnv.HOSTS
                ].split()
            ]
        mydict['authnName'] = '%s-%s' % (
            mydict['aaaprofile'],
            'authn',
        )
        mydict['authzName'] = '%s%s' % (
            mydict['aaaprofile'],
            '' if self.environment[
                constants.LDAPEnv.AAA_USE_VM_SSO
            ] else '-authz',
        )

        for e in (
            (
                constants.LDAPEnv.CONFIG_AUTHN_FILE_NAME,
                'extensions.d/{authnName}.properties',
            ),
            (
                constants.LDAPEnv.CONFIG_AUTHZ_FILE_NAME,
                'extensions.d/{authzName}.properties',
            ),
            (
                constants.LDAPEnv.CONFIG_PROFILE_FILE_NAME,
                'aaa/{aaaprofile}.properties',
            ),
            (
                constants.LDAPEnv.CONFIG_JKS_FILE_NAME,
                'aaa/{aaaprofile}.jks',
            ),
        ):
            self.environment[e[0]] = e[1].format(**mydict)

        self.environment[
            constants.LDAPEnv.CONFIG_AUTHN
        ] = (
            'ovirt.engine.extension.name = {authnName}\n'
            'ovirt.engine.extension.bindings.method = jbossmodule\n'
            'ovirt.engine.extension.binding.jbossmodule.module = org.ovirt.'
            'engine.extension.aaa.ldap\n'
            'ovirt.engine.extension.binding.jbossmodule.class = org.ovirt.'
            'engine.extension.aaa.ldap.AuthnExtension\n'
            'ovirt.engine.extension.provides = org.ovirt.engine.api.'
            'extensions.aaa.Authn\n'
            'ovirt.engine.aaa.authn.profile.name = {aaaprofile}\n'
            'ovirt.engine.aaa.authn.authz.plugin = {authzName}\n'
            'config.profile.file.1 = ../aaa/{aaaprofile}.properties\n'
        ).format(**mydict).splitlines()

        self.environment[
            constants.LDAPEnv.CONFIG_AUTHZ
        ] = (
            'ovirt.engine.extension.name = {authzName}\n'
            'ovirt.engine.extension.bindings.method = jbossmodule\n'
            'ovirt.engine.extension.binding.jbossmodule.module = org.ovirt.'
            'engine.extension.aaa.ldap\n'
            'ovirt.engine.extension.binding.jbossmodule.class = org.ovirt.'
            'engine.extension.aaa.ldap.AuthzExtension\n'
            'ovirt.engine.extension.provides = org.ovirt.engine.api.'
            'extensions.aaa.Authz\n'
            'config.profile.file.1 = ../aaa/{aaaprofile}.properties\n'
        ).format(**mydict).splitlines()

        if self.environment[constants.LDAPEnv.BASE_DN] is not None:
            base_dn = 'config.globals.baseDN.simple_baseDN = %s' % (
                self.environment[constants.LDAPEnv.BASE_DN]
            )
            self.environment[constants.LDAPEnv.CONFIG_AUTHZ].append(base_dn)
            self.environment[constants.LDAPEnv.CONFIG_AUTHN].append(base_dn)

        #
        # This is ugly, however, we want human readable output.
        #
        content = (
            'include = <{profile}.properties>\n'
            '\n'
        )
        if self.environment[constants.LDAPEnv.SERVERSET] == 'srvrecord':
            content += (
                'vars.domain = {domain}\n'
            )
        elif self.environment[constants.LDAPEnv.SERVERSET] == 'single':
            content += (
                'vars.server = {hosts[0]}\n'
            )
        if self.environment[constants.LDAPEnv.USER]:
            content += (
                'vars.user = {user}\n'
                'vars.password = {password}\n'
            )

        content += '\n'

        if self.environment[constants.LDAPEnv.USER]:
            content += (
                'pool.default.auth.simple.bindDN = ${{global:vars.user}}\n'
                'pool.default.auth.simple.password = '
                '${{global:vars.password}}\n'
            )
        else:
            content += (
                'pool.authz.auth.type = none\n'
            )

        content += (
            'pool.default.serverset.type = {serverset}\n'
        )
        if self.environment[constants.LDAPEnv.SERVERSET] == 'srvrecord':
            content += (
                'pool.default.serverset.srvrecord.domain = '
                '${{global:vars.domain}}\n'
            )
            if self.environment[constants.LDAPEnv.PROTOCOL] == 'ldaps':
                content += 'pool.default.serverset.srvrecord.service = ldaps\n'
        elif self.environment[constants.LDAPEnv.SERVERSET] == 'single':
            content += (
                'pool.default.serverset.single.server = '
                '${{global:vars.server}}\n'
            )
            if self.environment[constants.LDAPEnv.PROTOCOL] == 'ldaps':
                content += (
                    'pool.default.serverset.single.port = 636\n'
                )
        else:
            for i in range(
                len(self.environment[constants.LDAPEnv.HOSTS].split())
            ):
                l = (
                    'pool.default.serverset.{{serverset}}.{index:02d}.'
                    'server = {{hosts[{index}]}}\n'
                )
                if self.environment[constants.LDAPEnv.PROTOCOL] == 'ldaps':
                    l += (
                        'pool.default.serverset.{{serverset}}.{index:02d}.'
                        'port = 636\n'
                    )
                content += l.format(index=i)

        if not self.environment[constants.LDAPEnv.USE_DNS]:
            content += (
                'pool.default.socketfactory.type = java\n'
            )
        if self.environment[constants.LDAPEnv.PROTOCOL] == 'starttls':
            content += (
                'pool.default.ssl.startTLS = true\n'
            )
        if self.environment[constants.LDAPEnv.PROTOCOL] == 'ldaps':
            content += (
                'pool.default.ssl.enable = true\n'
            )
        if self.environment[constants.LDAPEnv.INSECURE]:
            content += (
                'pool.default.ssl.insecure = true\n'
            )
        if self.environment[constants.LDAPEnv.CACERT] is not None:
            content += (
                'pool.default.ssl.truststore.file = '
                '${{local:_basedir}}/{aaaprofile}.jks\n'
                'pool.default.ssl.truststore.password = changeit\n'
            )

        self.environment[
            constants.LDAPEnv.CONFIG_PROFILE
        ] = content.format(**mydict).splitlines()

        for k in (
            constants.LDAPEnv.CONFIG_AUTHN,
            constants.LDAPEnv.CONFIG_AUTHZ,
            constants.LDAPEnv.CONFIG_PROFILE,
        ):
            self.logger.debug(
                '%s:\n%s',
                k,
                '\n'.join(self.environment[k]),
            )

        if self.environment[constants.LDAPEnv.CACERT] is None:
            self.environment[constants.LDAPEnv.CONFIG_JKS] = None
        else:
            fd, name = tempfile.mkstemp()
            os.close(fd)
            os.unlink(name)
            try:
                self.execute(
                    args=(
                        os.path.join(
                            self.environment[
                                constants.CoreEnv.JAVA_HOME
                            ],
                            'bin',
                            'keytool',
                        ),
                        '-importcert',
                        '-noprompt',
                        '-trustcacerts',
                        '-alias', 'ca',
                        '-keystore', name,
                        '-storepass', 'changeit',
                    ),
                    stdin=self.environment[
                        constants.LDAPEnv.CACERT
                    ],
                )
                with open(name, 'rb') as f:
                    self.environment[constants.LDAPEnv.CONFIG_JKS] = f.read()
            finally:
                if os.path.exists(name):
                    os.unlink(name)

    @plugin.event(
        stage=plugin.Stages.STAGE_VALIDATION,
        priority=plugin.Stages.PRIORITY_HIGH,
        condition=lambda self: not self.environment[
            constants.LDAPEnv.CONFIG_OVERWRITE
        ],
    )
    def _validation(self):
        files = []
        for e in (
            constants.LDAPEnv.CONFIG_AUTHN_FILE_NAME,
            constants.LDAPEnv.CONFIG_AUTHZ_FILE_NAME,
            constants.LDAPEnv.CONFIG_PROFILE_FILE_NAME,
            constants.LDAPEnv.CONFIG_JKS_FILE_NAME,
        ):
            f = os.path.join(
                constants.FileLocations.ENGINE_ETC,
                self.environment[e],
            )
            if os.path.exists(f):
                files.append(f)
        if files:
            self.dialog.note(
                text=_('The following files are about to be overwritten:')
            )
            for f in files:
                self.dialog.note(
                    text=_('    {file}').format(
                        file=f,
                    )
                )

            if self.dialog.queryString(
                name='OVAAALDAP_LDAP_CONFIG_OVERWRITE',
                note=_('Continue and overwrite? (@VALUES@) [@DEFAULT@]: '),
                prompt=True,
                caseSensitive=False,
                validValues=(_('Yes'), _('No')),
                default=_('No'),
            ) == _('No').lower():
                raise RuntimeError(_('Aborted by user'))

    @plugin.event(
        stage=plugin.Stages.STAGE_MISC,
    )
    def _misc(self):
        for e in (
            {
                'nameKey': constants.LDAPEnv.CONFIG_AUTHN_FILE_NAME,
                'contentKey': constants.LDAPEnv.CONFIG_AUTHN,
                'mode': 0o644,
                'binary': False,
                'owner': None,
            },
            {
                'nameKey': constants.LDAPEnv.CONFIG_AUTHZ_FILE_NAME,
                'contentKey': constants.LDAPEnv.CONFIG_AUTHZ,
                'mode': 0o644,
                'binary': False,
                'owner': None,
            },
            {
                'nameKey': constants.LDAPEnv.CONFIG_PROFILE_FILE_NAME,
                'contentKey': constants.LDAPEnv.CONFIG_PROFILE,
                'mode': 0o600,
                'binary': False,
                'owner': self.environment[constants.CoreEnv.USER_OVIRT],
            },
            {
                'nameKey': constants.LDAPEnv.CONFIG_JKS_FILE_NAME,
                'contentKey': constants.LDAPEnv.CONFIG_JKS,
                'mode': 0o644,
                'binary': True,
                'owner': None,
            },
        ):
            if self.environment[e['contentKey']] is not None:
                self.environment[otopicons.CoreEnv.MAIN_TRANSACTION].append(
                    filetransaction.FileTransaction(
                        name=os.path.join(
                            constants.FileLocations.ENGINE_ETC,
                            self.environment[e['nameKey']],
                        ),
                        mode=e['mode'],
                        owner=e['owner'],
                        enforcePermissions=True,
                        content=self.environment[e['contentKey']],
                        binary=e['binary'],
                        modifiedList=self._files,
                    )
                )

        self.environment[
            otopicons.CoreEnv.MODIFIED_FILES
        ].extend(self._files)

    @plugin.event(
        stage=plugin.Stages.STAGE_CLOSEUP,
    )
    def _closeup(self):
        self.dialog.note(
            text=_('CONFIGURATION SUMMARY'),
        )
        self.dialog.note(
            text=_('Profile name is: {profile}').format(
                profile=self.environment[
                    constants.LDAPEnv.AAA_PROFILE_NAME
                ],
            ),
        )
        self.dialog.note(
            text=_('The following files were created:')
        )
        for f in self._files:
            self.dialog.note(
                text=_('    {name}').format(
                    name=f,
                ),
            )


# vim: expandtab tabstop=4 shiftwidth=4
