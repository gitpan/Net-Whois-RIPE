use ExtUtils::MakeMaker;

WriteMakefile(
	'NAME'	          => 'Net::Whois::RIPE::Object::Template',
	'VERSION_FROM'    => 'Template.pm',
	'dist'            => { COMPRESS=> 'gzip -9f', SUFFIX=>'gz' },
);
