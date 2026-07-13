#!/bin/bash -xe

# Directory, where build artifacts will be stored, should be passed as the 1st parameter
ARTIFACTS_DIR=${1:-exported-artifacts}

# Extract version from Maven project (strip -SNAPSHOT suffix)
PACKAGE_RPM_VERSION=$(mvn help:evaluate -q -DforceStdout -Dexpression=project.version)
PACKAGE_RPM_VERSION=${PACKAGE_RPM_VERSION%-SNAPSHOT}

# Default RPM release
PACKAGE_RPM_RELEASE=${PACKAGE_RPM_RELEASE:-0.master}

# Prepare source archive
[[ -d rpmbuild/SOURCES ]] || mkdir -p rpmbuild/SOURCES
git archive --format=tar HEAD | gzip -9 > "rpmbuild/SOURCES/ovirt-engine-extension-aaa-ldap-${PACKAGE_RPM_VERSION}.tar.gz"

# Generate spec file
sed \
    -e "s|@PACKAGE_RPM_VERSION@|${PACKAGE_RPM_VERSION}|g" \
    -e "s|@PACKAGE_RPM_RELEASE@|${PACKAGE_RPM_RELEASE}|g" \
    < ovirt-engine-extension-aaa-ldap.spec.in \
    > ovirt-engine-extension-aaa-ldap.spec

# Build source package
[[ -n "${RELEASE_SUFFIX}" ]] && RELEASE_SUFFIX_ARGS=(--define "release_suffix ${RELEASE_SUFFIX}") || RELEASE_SUFFIX_ARGS=()
rpmbuild \
    --define "_topdir $(pwd)/rpmbuild" \
    "${RELEASE_SUFFIX_ARGS[@]}" \
    -bs ovirt-engine-extension-aaa-ldap.spec
