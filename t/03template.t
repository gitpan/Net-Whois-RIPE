BEGIN { $| = 1; print "1..81\n"; }
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

my @TEMPLATES = qw(
	as-macro
	aut-num
	community
	domain
	dom-prefix
	inet6num
	inetnum
	inet-rtr
	key-cert
	mntner
	person
	role
	route
);

test(3,Net::Whois::RIPE->debug($DEBUG)==$DEBUG,"debug method failed");

my $i = 4;
$i = compare($i,'all');

# these are treated differently!
# it's because they match with the parser Net::Whois::RIPE::_query.
# should flag template calls so that it all goes to content.

foreach my $t (@TEMPLATES) {
	$i = compare($i,$t,1);	
}

# test a template that doesn't exist at all

$i = compare($i,'blah');	

# test passing no object to template
my $w;		# whois object
my @q;		# array for return of queries
test($i++,$w = Net::Whois::RIPE->new($HOST), "object constructor failed");
test($i++,@q = $w->template(), "template method suceeded with no parameters!");
test($i++,@q==0, "template method returned more an object with no parameters!");

# test 

# compare
# there is a 03template_$cmp.obj file for each item in the @TEMPLATES
# array. This is the saved response from a whois -t <template> query.
# query Net::Whois::RIPE and see if the results are the same.

# currently there is an issue with the Net::Whois::RIPE::_query
# method missing the last blank line of templates that look like objects.
# this may or may not be fixed in future versions. It is harmless, for
# now, we just pass a flag to say "disregard that last line" in the compare

sub compare {
	my ($i,$cmp,$treat_me_special) = @_;
	my $file = $0;
	$file =~ s/\.t/_$cmp.obj/;
	test($i++, open(FH,$file),"failed to open $file");
	my @match_template = <FH>;
	#  if not the 'all' template then we have to get rid of the
	# last line since Net::Whois::RIPE::_query doesn't presently
	# find that last line in the content. future versions might!
#	pop @match_template if $treat_me_special;	
	my $match = join('',@match_template);

	my $w;
	my @q;
	test($i++,$w = Net::Whois::RIPE->new($HOST), "object constructor failed");
	test($i++,@q = $w->template($cmp), "template method failed on [$cmp]");
	test($i++,@q==1, "template method returned more than 1 object on [$cmp]");
	if (@q > 1) {
		foreach my $j (1..$#q) {
			print "Object $j\n";
			print $q[$j]->content; 
		}
	}
	#print $q->content;
	test($i++,($match eq $q[0]->content), "template mismatch on [$cmp]");
	close FH;
	return $i;
}

exit 0;
