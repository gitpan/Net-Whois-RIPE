BEGIN {$| = 1; print "1..500\n"; }
END {print "not ok 1\n" unless $loaded;}
use Net::Whois::RIPE;
$loaded = 1;
print "ok 1\n";

# util
sub test {
    local($^W) = 0;
    my($num, $true,$msg) = @_;
    print($true ? "ok $num\n" : "not ok $num $msg\n");
}

use strict;
use Carp;
use vars qw($DEBUG $HOST $SOURCE);

my $file = $0;	# load up DEBUG and HOST values
$file =~ s/\/.+\.t$/\/test_parms.pl/;
test(2,(do $file),"failed to do $file");

my $whois;
test(3,$whois = Net::Whois::RIPE->new($HOST),"new failed");
test(4,$whois->source($SOURCE) eq $SOURCE,"failed to set source to $SOURCE");
test(5,$whois->type('domain') eq 'domain',"failed to set type to domain");
test(6,$whois->inverse_lookup('zone-c') eq 'zone-c',
	"failed to set inverse_lookup to zone-c");

# inverse query on DNS3-AP normally returns over 1100 objects 

my $iterator;
test(7,$iterator = $whois->query_iterator('DNS3-AP'),
	"query iterator method failed");
test(8,$iterator->debug($DEBUG)==$DEBUG,"failed to set debug on iterator");

my $i = 9;
my $obj;
while ($obj = $iterator->next) {
	next if $i > 500;	# only test up to 500
	test($i++,$obj->attributes>0,"no attributes found on DNS3-AP query");
}
