use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
	'NAME'            => 'Net::Whois::RIPE',
	'VERSION_FROM'    => 'RIPE.pm', # finds $VERSION
	'PREREQ_PM'       => {
		'IO'                   => 1.20,
	#	'IO::Socket'           => 1.1603,
	},
	'dist'            => { COMPRESS=> 'gzip -9f', SUFFIX=>'gz' },
);
