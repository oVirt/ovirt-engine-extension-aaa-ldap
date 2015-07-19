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
import pwd
import grp

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

    def __init__(self, context):
        super(Plugin, self).__init__(context=context)

    @plugin.event(
        stage=plugin.Stages.STAGE_BOOT,
        before=(
            otopicons.Stages.CORE_LOG_INIT,
        ),
        priority=plugin.Stages.PRIORITY_HIGH - 10,
    )
    def _preinit(self):
        self.environment.setdefault(
            otopicons.CoreEnv.LOG_FILE_NAME_PREFIX,
            constants.FileLocations.LOG_PREFIX
        )

    @plugin.event(
        stage=plugin.Stages.STAGE_INIT,
    )
    def _init(self):
        self.logger.debug(
            'Package: %s-%s (%s)',
            constants.Const.PACKAGE_NAME,
            constants.Const.PACKAGE_VERSION,
            constants.Const.PACKAGE_DISPLAY_NAME,
        )

        self.environment.setdefault(
            constants.CoreEnv.DEVELOPER_MODE,
            None
        )

        if self.environment[constants.CoreEnv.DEVELOPER_MODE] is None:
            self.environment[constants.CoreEnv.DEVELOPER_MODE] = False
            if os.geteuid() != 0:
                if self.dialog.queryString(
                    name='OVAAALDAP_CORE_UNPRIVILEGED',
                    note=_(
                        'Setup was run under unprivileged user '
                        'this will produce development installation '
                        'do you wish to proceed? (@VALUES@) [@DEFAULT@]: '
                    ),
                    prompt=True,
                    validValues=(_('Yes'), _('No')),
                    default=_('No'),
                    caseSensitive=False,
                ) == _('No'):
                    raise RuntimeError(_('Aborted by user'))
                self.environment[constants.CoreEnv.DEVELOPER_MODE] = True

        if (
            not self.environment[constants.CoreEnv.DEVELOPER_MODE] and
            os.geteuid() != 0
        ):
            raise RuntimeError(
                _('Running as non root and not in development mode')
            )

        if self.environment[constants.CoreEnv.DEVELOPER_MODE]:
            ovirtUser = pwd.getpwuid(os.geteuid())[0]
            ovirtGroup = grp.getgrgid(os.getegid())[0]
        else:
            ovirtUser = constants.Defaults.DEFAULT_SYSTEM_USER_OVIRT
            ovirtGroup = constants.Defaults.DEFAULT_SYSTEM_GROUP_OVIRT

        self.environment.setdefault(
            constants.CoreEnv.USER_OVIRT,
            ovirtUser
        )
        self.environment.setdefault(
            constants.CoreEnv.GROUP_OVIRT,
            ovirtGroup
        )

    @plugin.event(
        stage=plugin.Stages.STAGE_CLEANUP,
    )
    def _cleanup(self):
        self.dialog.note(
            text=_('Log file is available at {name}:').format(
                name=self.environment[
                    otopicons.CoreEnv.LOG_FILE_NAME
                ],
            ),
        )


# vim: expandtab tabstop=4 shiftwidth=4
