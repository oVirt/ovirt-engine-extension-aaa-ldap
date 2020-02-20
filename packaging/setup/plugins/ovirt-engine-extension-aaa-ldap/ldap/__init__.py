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


from otopi import util


from . import ad
from . import common
from . import config
from . import simple
from . import tool


@util.export
def createPlugins(context):
    ad.Plugin(context=context)
    common.Plugin(context=context)
    config.Plugin(context=context)
    simple.Plugin(context=context)
    tool.Plugin(context=context)


# vim: expandtab tabstop=4 shiftwidth=4
