#!/bin/bash -xe

source "$(dirname "$(readlink -f "$0")")/build-srpm.sh"

# Install build dependencies
dnf builddep -y rpmbuild/SRPMS/*src.rpm

# Build binary package
[[ -n "${RELEASE_SUFFIX}" ]] && RELEASE_SUFFIX_ARGS=(--define "release_suffix ${RELEASE_SUFFIX}") || RELEASE_SUFFIX_ARGS=()
rpmbuild \
    --define "_topdir $(pwd)/rpmbuild" \
    --define "_rpmdir $(pwd)/rpmbuild" \
    "${RELEASE_SUFFIX_ARGS[@]}" \
    --rebuild rpmbuild/SRPMS/*src.rpm

# Move RPMs to exported artifacts
[[ -d "$ARTIFACTS_DIR" ]] || mkdir -p "$ARTIFACTS_DIR"
find rpmbuild -iname \*rpm | xargs mv -t "$ARTIFACTS_DIR"
