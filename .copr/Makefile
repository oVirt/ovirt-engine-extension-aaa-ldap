.PHONY: installdeps srpm

installdeps:
	dnf -y install git gzip java-11-openjdk-devel make maven rpm-build sed

srpm: installdeps
	./.automation/build-srpm.sh
	cp rpmbuild/SRPMS/*.src.rpm $(outdir)
