use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
	'NAME'            => 'Net::Whois::RIPE',
	'VERSION_FROM'    => 'RIPE.pm', # finds $VERSION
	'PREREQ_PM'       => {
		'IO'                   => 1.20,
	},
);


sub MY::postamble {
		return <<'MAKE_RPM';

# source for tarball for rpmbuild
SOURCEDIR = `pwd`

rpm:	dist
		sed -e 's/@VERSION@/$(VERSION)/' perl-$(DISTNAME).spec > perl-$(DISTNAME)-$(VERSION).spec
		rpmbuild --define "_sourcedir $(SOURCEDIR)" -ba perl-$(DISTNAME)-$(VERSION).spec
MAKE_RPM

}
