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
        stage=plugin.Stages.STAGE_INIT,
    )
    def _init(self):
        self.environment.setdefault(
            constants.CoreEnv.JAVA_HOME,
            None
        )

    @plugin.event(
        stage=plugin.Stages.STAGE_SETUP,
    )
    def _setup(self):
        if self.environment[constants.CoreEnv.JAVA_HOME] is None:
            try:
                from ovirt_engine import java
                self.environment[
                    constants.CoreEnv.JAVA_HOME
                ] = java.Java().getJavaHome()
            except ImportError:
                self.logger.warning(
                    _('Using internal detection of JAVA_HOME')
                )
                self.environment[
                    constants.CoreEnv.JAVA_HOME
                ] = os.environ.get('JAVA_HOME', '/usr')


# vim: expandtab tabstop=4 shiftwidth=4
