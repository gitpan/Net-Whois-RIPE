use ExtUtils::MakeMaker;

WriteMakefile(
	'NAME'	          => 'Net::Whois::RIPE::Object',
	'VERSION_FROM'    => 'Object.pm',
	'dist'            => { COMPRESS=> 'gzip -9f', SUFFIX=>'gz' },
);
