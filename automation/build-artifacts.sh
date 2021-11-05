#!/bin/bash -xe

MAVEN_SETTINGS="/etc/maven/settings.xml"

# Set the location of the JDK that will be used for maven
export JAVA_HOME="${JAVA_HOME:=/usr/lib/jvm/java-11}"

# Use ovirt mirror if able, fall back to central maven
mkdir -p "${MAVEN_SETTINGS%/*}"
cat >"$MAVEN_SETTINGS" <<EOS
<?xml version="1.0"?>
<settings xmlns="http://maven.apache.org/POM/4.0.0"
          xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
          xsi:schemaLocation="http://maven.apache.org/POM/4.0.0
          http://maven.apache.org/xsd/settings-1.0.0.xsd">

<mirrors>
        <mirror>
                <id>ovirt-maven-repository</id>
                <name>oVirt artifactory proxy</name>
                <url>http://artifactory.ovirt.org/artifactory/ovirt-mirror</url>
                <mirrorOf>*</mirrorOf>
        </mirror>
        <mirror>
                <id>root-maven-repository</id>
                <name>Official maven repo</name>
                <url>https://repo.maven.apache.org/maven2</url>
                <mirrorOf>*</mirrorOf>
        </mirror>
</mirrors>
</settings>
EOS

# Build RPMs
mvn help:evaluate -Dexpression=project.version -gs "$MAVEN_SETTINGS" # downloads and installs the necessary jars

# Prepare the version string (with support for SNAPSHOT versioning)
VERSION=$(mvn help:evaluate -Dexpression=project.version -gs "$MAVEN_SETTINGS" 2>/dev/null| grep -v "^\[")
VERSION=${VERSION/-SNAPSHOT/-0.$(git rev-list HEAD | wc -l).$(date +%04Y%02m%02d%02H%02M)}
IFS='-' read -ra VERSION <<< "$VERSION"
RELEASE=${VERSION[1]-1}

# Prepare source archive
[[ -d ${HOME}/rpmbuild/SOURCES ]] || mkdir -p ${HOME}/rpmbuild/SOURCES
git archive --format=tar HEAD | gzip -9 > ${HOME}/rpmbuild/SOURCES/ovirt-engine-extension-aaa-ldap-$VERSION.tar.gz

# Set version and release
sed \
    -e "s|@VERSION@|${VERSION}|g" \
    -e "s|@RELEASE@|${RELEASE}|g" \
    < ovirt-engine-extension-aaa-ldap.spec.in \
    > ovirt-engine-extension-aaa-ldap.spec

rpmbuild \
    --define "_topmdir $PWD/rpmbuild" \
    --define "_rpmdir $PWD/rpmbuild" \
    -ba --nodeps ovirt-engine-extension-aaa-ldap.spec

# Move RPMs to exported artifacts
[[ -d exported-artifacts ]] || mkdir -p exported-artifacts
find rpmbuild -iname \*rpm | xargs mv -t exported-artifacts
