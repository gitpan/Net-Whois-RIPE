BEGIN { $| = 1; print "1..25\n"; }
END {print "not ok 1\n" unless $loaded;}
use Net::Whois::RIPE;
$loaded = 1;
print "ok 1\n";

sub test {
	local($^W)=0;
	my($num,$true,$msg)=@_;
	print($true ? "ok $num\n" : "not ok $num $msg\n");
}

################################################################################
# Paul's old tests
################################################################################

use strict;

use vars qw($DEBUG $HOST);

my $file = $0;
$file =~ s/\/.+\.t$/\/test_parms.pl/;
test(2,(do $file),"failed to do $file");
use strict;

use vars qw(
	$PROMPT
	$EXISTING_NIC_HDL
	$EXISTING_AS_NUM
	$EXISTING_MNTNER_NO_AUTH
	$EXISTING_MNTNER_WITH_AUTH
	$QUERY_THAT_SHOULD_FAIL
	);

# load vars specific to this test
$file = $0;
$file =~ s/\.t$/\.pl/;
test(3,(do $file),"failed to do $file");


my $i = 4;

test($i++,Net::Whois::RIPE->debug($DEBUG)==$DEBUG,"set debug failed");

# prompt routine to get test values (should this go in the Makefile.PL?)
# these all have defaults, sourced by the do in test 2

sub prompt {
	my $prompt = shift;
	my $default = shift;
	return $default unless $PROMPT;
	print STDERR "\n",$prompt," [",$default,"]: ";
	my $resp;
	chomp($resp = <STDIN>);
	$resp ||= $default;
	print STDERR "\nUsing value: $resp\n";
	return $resp;
}

$HOST = prompt("Enter the hostname of a whois server to test against",$HOST);
#$TYPE = prompt("What type of server is this (INTERNIC|RIPE) ",$TYPE);

my $s;
test($i++,$s = Net::Whois::RIPE->new($HOST),"Net::Whois::RIPE->new failed");
exit 1 unless $s;	# no use going any further

$EXISTING_NIC_HDL = prompt("Enter a NIC Handle that you know exists in the database",$EXISTING_NIC_HDL);

my $q;
test($i++,$q = $s->query($EXISTING_NIC_HDL),
	"query for nic-hdl [$EXISTING_NIC_HDL] failed");
test($i++,$q->success);
test($i++,$q->person,"person method failed");
if ($EXISTING_NIC_HDL eq 'PG6-AP') {
	test($i++,$q->person eq 'Paul Gampe',"person method failed");
}

# query a handle that should fail

test($i++,$q = $s->query($QUERY_THAT_SHOULD_FAIL));
test($i++,!$q->success,
	"query on [$QUERY_THAT_SHOULD_FAIL] should have failed");
if ($q->success and $DEBUG) {
	print STDERR "The query for [$QUERY_THAT_SHOULD_FAIL] should have failed\n";
	print STDERR "Dumping full response content...\n\n";
	print STDERR $q->content,"\n";
}

# query an existing as number

$EXISTING_AS_NUM = prompt ("Enter a AS Number that you know exists in the database",$EXISTING_AS_NUM);

test($i++,$q = $s->query($EXISTING_AS_NUM));
test($i++,$q->success);
test($i++,$q->aut_num eq $EXISTING_AS_NUM);

# query an existing mntner with no auth

$EXISTING_MNTNER_NO_AUTH = prompt("Enter a maintainer handle that you ".
	"know existsin the\n database and does not have any authorisation",
	$EXISTING_MNTNER_NO_AUTH);

test($i++,$q = $s->query($EXISTING_MNTNER_NO_AUTH));
test($i++,$q->success);
test($i++,$q->mntner eq $EXISTING_MNTNER_NO_AUTH);
test($i++,$q->auth eq 'NONE',
	"mntner [$EXISTING_MNTNER_NO_AUTH] auth type is not 'NONE'");

# query an existing mntner with auth

$EXISTING_MNTNER_WITH_AUTH = prompt("Enter a maintainer handle that you ".
	"know exists in the\n database and DOES have authorisation",
	$EXISTING_MNTNER_WITH_AUTH);

test($i++,$q = $s->query($EXISTING_MNTNER_WITH_AUTH));
test($i++,$q->success);
test($i++,$q->mntner eq $EXISTING_MNTNER_WITH_AUTH);
test($i++,$q->auth); # test a general attr method
print STDERR "authorisation type is: ", $q->auth, "\n" if $DEBUG;

# set the max read and overload it

test($i++,$s->max_read_size(200)==200);	# only allow 200 bytes
test($i++,$q = $s->query($EXISTING_NIC_HDL));
my @warn = $q->warning;
test($i++,$warn[0] eq 'exceeded maximum read size of 200 bytes. results may have been truncated.',"failed to match warning message for results truncation");

exit(0);
