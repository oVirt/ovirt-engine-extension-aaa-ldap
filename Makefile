
PACKAGE_NAME=ovirt-engine-extension-aaa-ldap

ANT=ant
PYTHON=python

PREFIX=/usr/local
SYSCONF_DIR=$(PREFIX)/etc
BIN_DIR=$(PREFIX)/bin
DATA_DIR=$(PREFIX)/share
PKG_DATA_DIR=$(DATA_DIR)/$(PACKAGE_NAME)

PYTHON_SYS_DIR:=$(shell $(PYTHON) -c "from distutils.sysconfig import get_python_lib as f;print(f())")
DEV_PYTHON_DIR=

DEVMODE=0

all:
	$(MAKE) ant TARGET=all

clean:
	$(MAKE) ant TARGET=clean

install:
	$(MAKE) ant TARGET=install

install-dev:
	$(MAKE) install \
		DEVMODE=1 \
		DEV_PYTHON_DIR="$(PREFIX)$(PYTHON_SYS_DIR)" \
		$(NULL)

install-no-build:
	$(MAKE) ant TARGET=install-no-build

dist:
	$(MAKE) ant TARGET=dist

ant:
	$(ANT) \
		-Ddir.prefix="$(PREFIX)" \
		-Ddir.sysconf="$(SYSCONF_DIR)" \
		-Ddir.bin="$(BIN_DIR)" \
		-Ddir.data="$(DATA_DIR)" \
		-Ddir.pkgdata="$(PKG_DATA_DIR)" \
		-Ddir.destdir="$(DESTDIR)" \
		-Ddev.mode="$(DEVMODE)" \
		-Ddir.python.dev="$(DEV_PYTHON_DIR)" \
		$(EXTRA_ANT_ARGS) \
		$(TARGET) \
		$(NULL)
