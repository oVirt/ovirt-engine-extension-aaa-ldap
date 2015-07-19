#
# ovirt-engine-setup -- ovirt engine setup
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


from otopi import constants as otopicons
from otopi import packager, plugin, util


@util.export
class Plugin(plugin.PluginBase, packager.PackagerBase):
    """Offline packager."""
    def install(self, packages, ignoreErrors=False):
        pass

    def update(self, packages, ignoreErrors=False):
        pass

    def queryPackages(self, patterns=None):
        return []

    def __init__(self, context):
        super(Plugin, self).__init__(context=context)

    @plugin.event(
        stage=plugin.Stages.STAGE_INIT,
        after=(
            otopicons.Stages.PACKAGERS_DETECTION,
        ),
    )
    def _init(self):
        self.logger.debug('Registering offline packager')
        self.context.registerPackager(packager=self)


# vim: expandtab tabstop=4 shiftwidth=4
