use strict;
use Carp;
use Test;

BEGIN { require "t/common.pl", plan tests => 507 };

eval { require Net::Whois::RIPE; return 1;};
ok($@,'');
croak() if $@;  

use vars qw($DEBUG $HOST $SOURCE);

$DEBUG=0;
my $w;

ok($w = Net::Whois::RIPE->new($HOST));

my $no_server = $w->connect() ? 0 : 1;

# skip most of the tests if no server found

skip($no_server,$w->source($SOURCE) eq $SOURCE);
skip($no_server,$w->type('domain') eq 'domain');
skip($no_server,$w->inverse_lookup('zone-c') eq 'zone-c');

# inverse query on DNS3-AP normally returns over 1100 objects 

my $iterator;

if ($no_server == 0) {
	skip($no_server,$iterator = $w->query_iterator('DNS3-AP'));
	my $i = 0;
	my $obj;
	while ($obj = $iterator->next) {
		last if $i++ > 500;	# only test up to 500
		ok($obj->attributes>0);
	}
} else {
	skip($no_server,1);
	my $i = 0;
	while (1) {
		last if $i++ > 500;	# only test up to 500
		skip($no_server,1);
	}
}
