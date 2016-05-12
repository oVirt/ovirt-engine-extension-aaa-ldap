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

from otopi import util

from . import config


def _(m):
    return gettext.dgettext(
        message=m,
        domain='ovirt-engine-extension-aaa-setup',
    )


@util.export
class FileLocations(object):
    BIN_DIR = config.BIN_DIR
    SYSCONF_DIR = config.SYSCONF_DIR

    ENGINE_ETC = os.path.join(
        SYSCONF_DIR,
        'ovirt-engine',
    )

    LOG_PREFIX = 'ovirt-engine-extension-aaa-ldap-setup'

    SETUP_CONFIG_FILE = os.path.join(
        SYSCONF_DIR,
        'ovirt-engine-extension-aaa-ldap-setup.conf',
    )


@util.export
class Defaults(object):
    DEFAULT_SYSTEM_USER_OVIRT = 'ovirt'
    DEFAULT_SYSTEM_GROUP_OVIRT = 'ovirt'


@util.export
class Stages(object):
    LDAP_COMMON_INIT = 'ovaaaldap.ldap.common.init'
    LDAP_COMMON_CUSTOMIZATION_EARLY = \
        'ovaaaldap.ldap.common.customization.early'
    LDAP_COMMON_CUSTOMIZATION_LATE = \
        'ovaaaldap.ldap.common.customization.late'


@util.export
@util.codegen
class Const(object):
    PACKAGE_NAME = config.PACKAGE_NAME
    PACKAGE_VERSION = config.PACKAGE_VERSION
    PACKAGE_DISPLAY_NAME = config.PACKAGE_DISPLAY_NAME


@util.export
@util.codegen
class CoreEnv(object):
    DEVELOPER_MODE = 'OVAAALDAP_CORE/developerMode'
    USER_OVIRT = 'OVAAALDAP_CORE/userOvirt'
    GROUP_OVIRT = 'OVAAALDAP_CORE/groupOvirt'
    JAVA_HOME = 'OVAAALDAP_CORE/javaHome'


@util.export
@util.codegen
class LDAPEnv(object):

    RESOLVER = 'OVAAALDAP_LDAP/resolver'

    AVAILABLE_PROFILES = 'OVAAALDAP_LDAP/availableProfiles'
    PROFILE = 'OVAAALDAP_LDAP/profile'
    USE_DNS = 'OVAAALDAP_LDAP/useDNS'
    SERVERSET = 'OVAAALDAP_LDAP/serverset'
    DOMAIN = 'OVAAALDAP_LDAP/domain'
    HOSTS = 'OVAAALDAP_LDAP/hosts'
    PROTOCOL = 'OVAAALDAP_LDAP/protocol'
    CACERT = 'OVAAALDAP_LDAP/cacert'
    SYSTEM_CACERTS = 'OVAAALDAP_LDAP/systemCACerts'
    INSECURE = 'OVAAALDAP_LDAP/insecure'
    USER = 'OVAAALDAP_LDAP/user'
    PASSWORD = 'OVAAALDAP_LDAP/password'
    SOCKET_FACTORY = 'OVAAALDAP_LDAP/socketFactory'
    AAA_PROFILE_NAME = 'OVAAALDAP_LDAP/aaaProfileName'
    AAA_USE_VM_SSO = 'OVAAALDAP_LDAP/useVmSso'

    CONFIG_AUTHN_FILE_NAME = 'OVAAALDAP_LDAP/configAuthnFileName'
    CONFIG_AUTHZ_FILE_NAME = 'OVAAALDAP_LDAP/configAuthzFileName'
    CONFIG_PROFILE_FILE_NAME = 'OVAAALDAP_LDAP/configProfileFileName'
    CONFIG_JKS_FILE_NAME = 'OVAAALDAP_LDAP/configJKSFileName'
    CONFIG_AUTHN = 'OVAAALDAP_LDAP/configAuthn'
    CONFIG_AUTHZ = 'OVAAALDAP_LDAP/configAuthz'
    CONFIG_PROFILE = 'OVAAALDAP_LDAP/configProfile'
    CONFIG_JKS = 'OVAAALDAP_LDAP/configJKS'

    CONFIG_OVERWRITE = 'OVAAALDAP_LDAP/configOverwrite'
    TOOL_ENABLE = 'OVAAALDAP_LDAP/toolEnable'

# vim: expandtab tabstop=4 shiftwidth=4
