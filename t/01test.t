BEGIN { $| = 1; print "1..7\n"; }
END {print "not ok 1\n" unless $loaded;}
use Net::Whois::RIPE;
$loaded = 1;
print "ok 1\n";

sub test {
	local($^W)=0;
	my($num,$true,$msg)=@_;
	print($true ? "ok $num\n" : "not ok $num $msg\n");
}

use strict;

use vars qw($DEBUG $HOST);

my $file = $0;
$file =~ s/\/.+\.t$/\/test_parms.pl/;
test(2,(do $file),"failed to do $file");

my $w;		# whois object

test(3,$w = Net::Whois::RIPE->debug($DEBUG)==$DEBUG,"debug method failed");

test(4,$w = Net::Whois::RIPE->new($HOST), "object constructor failed");
test(5,$w->server eq $HOST, "server method should return $HOST");

# these tests should fail.
test(6,!($w = Net::Whois::RIPE->new), 
	"object constructor should return undef when no host is supplied");
test(7,!($w = Net::Whois::RIPE->new('garbage')), "bad hostname");

exit 0;
