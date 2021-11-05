.PHONY: installdeps srpm

installdeps:
	dnf -y install git java-11-openjdk-devel maven

srpm: installdeps
	./automation/build-copr.sh
	cp rpmbuild/SRPMS/*.src.rpm $(outdir)
