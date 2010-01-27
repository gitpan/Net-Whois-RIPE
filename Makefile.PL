use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME                => 'Net::Whois::RIPE',
    AUTHOR              => 'Luis Motta Campos <lmc@cpan.org>',
    VERSION_FROM        => 'lib/Net/Whois/RIPE.pm',
    ABSTRACT_FROM       => 'lib/Net/Whois/RIPE.pm',
    PL_FILES            => {},
    PREREQ_PM => {
        'Test::More' => 0,
    },
    dist                => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean               => { FILES => 'net-whois-ripe-*' },
);
