use Test;
use Carp;
use strict;

BEGIN { require "t/common.pl", plan tests => 5 };

my $w;
my $DEBUG = 1;
use vars qw($HOST);

eval { require Net::Whois::RIPE; return 1;};
ok($@,'');
croak() if $@;  

ok($w = Net::Whois::RIPE->debug($DEBUG)==$DEBUG);
ok($w = Net::Whois::RIPE->debug(0)==0);

eval {
	$w = Net::Whois::RIPE->new($HOST);
	croak() unless $w;
};

skip(!defined($w),defined($w));

# these tests should fail.
ok(!($w = Net::Whois::RIPE->new));

exit 0;
