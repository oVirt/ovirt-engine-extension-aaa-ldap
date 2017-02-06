#!/bin/bash -xe

SUFFIX=".git$(git rev-parse --short HEAD)"

# remove any previous artifacts
rm -rf output
rm -f ./*tar.gz
make clean

# Get the tarball
make dist

# create the src.rpm
rpmbuild \
    -D "_srcrpmdir $PWD/output" \
    -D "_topmdir $PWD/rpmbuild" \
    -D "release_suffix ${SUFFIX}" \
    -ts ./*.gz

# install any build requirements
yum-builddep output/*src.rpm

# build minimal rpms for CI, only using single permutation
rpmbuild \
    -D "_rpmdir $PWD/output" \
    -D "_topmdir $PWD/rpmbuild" \
    -D "release_suffix ${SUFFIX}" \
    --rebuild output/*.src.rpm

