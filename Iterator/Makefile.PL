use ExtUtils::MakeMaker;


WriteMakefile(
	'NAME'            => 'Net::Whois::RIPE::Iterator',
	'VERSION_FROM'    => 'Iterator.pm', # finds $VERSION
	'PREREQ_PM'       => {'IO'=> 1.20, },
	'dist'            => { COMPRESS=> 'gzip -9f', SUFFIX=>'gz' },
);
