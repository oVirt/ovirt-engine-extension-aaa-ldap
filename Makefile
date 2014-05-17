
PACKAGE_NAME=ovirt-engine-extension-aaa-ldap

ANT=ant
PREFIX=/usr/local
SYSCONF_DIR=$(PREFIX)/etc
DATA_DIR=$(PREFIX)/share
PKG_DATA_DIR=$(DATA_DIR)/$(PACKAGE_NAME)

all:
	$(MAKE) ant TARGET=all

clean:
	$(MAKE) ant TARGET=clean

install:
	$(MAKE) ant TARGET=install

install-no-build:
	$(MAKE) ant TARGET=install-no-build

dist:
	$(MAKE) ant TARGET=dist

ant:
	$(ANT) \
		-Ddir.prefix="$(PREFIX)" \
		-Ddir.sysconf="$(SYSCONF_DIR)" \
		-Ddir.data="$(DATA_DIR)" \
		-Ddir.pkgdata="$(PKG_DATA_DIR)" \
		-Ddir.destdir="$(DESTDIR)" \
		$(EXTRA_ANT_ARGS) \
		$(TARGET) \
		$(NULL)
