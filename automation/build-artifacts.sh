#!/bin/bash -xe

SUFFIX=".git$(git rev-parse --short HEAD)"

# Remove any previous artifacts
rm -rf output
rm -f ./*tar.gz
make clean

# Get the tarball
make dist

# Create the src.rpm
rpmbuild \
    -D "_srcrpmdir $PWD/output" \
    -D "_topmdir $PWD/rpmbuild" \
    -D "release_suffix ${SUFFIX}" \
    -ts ./*.gz

# Install any build requirements
yum-builddep output/*src.rpm

# Build RPMs
rpmbuild \
    -D "_rpmdir $PWD/output" \
    -D "_topmdir $PWD/rpmbuild" \
    -D "release_suffix ${SUFFIX}" \
    --rebuild output/*.src.rpm

# Store any relevant artifacts in exported-artifacts for the ci system to
# archive
[[ -d exported-artifacts ]] || mkdir -p exported-artifacts
find output -iname \*rpm -exec mv "{}" exported-artifacts/ \;
mv ./*tar.gz exported-artifacts/
