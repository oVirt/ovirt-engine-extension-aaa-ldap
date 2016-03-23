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

from otopi import plugin, util

from ovirt_engine_extension_aaa_ldap_setup import constants


def _(m):
    return gettext.dgettext(
        message=m,
        domain='ovirt-engine-extension-aaa-ldap-setup',
    )


@util.export
class Plugin(plugin.PluginBase):

    MY_PROFILES = (
        {
            'display': _('Active Directory'),
            'profile': 'ad',
        },
    )

    def _resolve(self):
        ret = True

        for e in (
            ('gc._msdcs.', _('Global Catalog')),
            ('', _('LDAP')),
        ):
            self.logger.info(
                _('Resolving {what} SRV record for {domain}').format(
                    what=e[1],
                    domain=self.environment[constants.LDAPEnv.DOMAIN],
                )
            )

            if not self.environment[constants.LDAPEnv.RESOLVER](
                plugin=self,
                record='SRV',
                what='_ldap._tcp.%s%s' % (
                    e[0],
                    self.environment[
                        constants.LDAPEnv.DOMAIN
                    ],
                )
            ):
                self.logger.warning(
                    _(
                        'Cannot resolve {what} SRV record for {domain}. '
                        'Please check you have entered correct Active '
                        'Directory forest name and check that forest '
                        'is resolvable by your system DNS servers'
                    ).format(
                        what=e[1],
                        domain=self.environment[constants.LDAPEnv.DOMAIN],
                    )
                )
                ret = False

        return ret

    def __init__(self, context):
        super(Plugin, self).__init__(context=context)

    @plugin.event(
        stage=plugin.Stages.STAGE_INIT,
        after=(
            constants.Stages.LDAP_COMMON_INIT,
        ),
    )
    def _init(self):
        self.environment[
            constants.LDAPEnv.AVAILABLE_PROFILES
        ].extend(self.MY_PROFILES)

    @plugin.event(
        stage=plugin.Stages.STAGE_CUSTOMIZATION,
        before=(
            constants.Stages.LDAP_COMMON_CUSTOMIZATION_LATE,
        ),
        after=(
            constants.Stages.LDAP_COMMON_CUSTOMIZATION_EARLY,
        ),
        condition=lambda self: self.environment[
            constants.LDAPEnv.PROFILE
        ] in [p['profile'] for p in self.MY_PROFILES],
    )
    def _customization(self):
        if self.environment[constants.LDAPEnv.DOMAIN] is None:
            self.environment[
                constants.LDAPEnv.DOMAIN
            ] = self.dialog.queryString(
                name='OVAAALDAP_LDAP_AD_DOMAIN',
                note=_('Please enter Active Directory Forest name: '),
                prompt=True,
            )
            if not self._resolve():
                raise RuntimeError(
                    _("Active Directory forest is not resolvable")
                )

        self.environment[
            constants.LDAPEnv.SERVERSET
        ] = 'srvrecord'
        self.environment[
            constants.LDAPEnv.USE_DNS
        ] = True


# vim: expandtab tabstop=4 shiftwidth=4
