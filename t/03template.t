use strict;
use Test;

BEGIN { require "t/common.pl", plan tests => 98 };

eval { require Net::Whois::RIPE; return 1;};
ok($@,'');
croak() if $@;  

use vars qw($HOST @TEMPLATES);

my $w;
my $i;
my $DEBUG = 1;

foreach my $t (@TEMPLATES) { $i = compare($i,$t,1);	}

# test a template that does not exist at all
$i = compare($i,'blah');	

# test passing no object to template
my @q;		# array for return of queries
ok($w = Net::Whois::RIPE->new($HOST));

my $no_server = $w->connect() ? 0 : 1;

skip($no_server,@q = $w->template(),0);

# test 

# compare
# there is a 03template_$cmp.obj file for each item in the @TEMPLATES
# array. This is the saved response from a whois -t <template> query.
# query Net::Whois::RIPE and see if the results are the same.

sub compare {
	my ($i,$cmp) = @_;
	my $w;
	ok($w = Net::Whois::RIPE->new($HOST));
	my $no_server = $w->connect() ? 0 : 1;
	if ($no_server == 1) {
			skip(1,1);
			skip(1,1);
			skip(1,1);
			skip(1,1);
			return;
	} else {
		my $file = $0;
		$file =~ s/\.t/_$cmp.obj/;
		ok(open(FH,$file),1, "failed to open $file");
		my @match_template = <FH>;
		my $match = join('',@match_template);
		my @q;
		skip($no_server,@q = $w->template($cmp));
		skip($no_server,@q==1, 1, "template method returned more than 1 object on [$cmp]");
		if (@q > 1) {
			foreach my $j (1..$#q) {
				print "Object $j\n";
				print $q[$j]->content; 
			}
		}
		# ignore comment lines as they may change
		my $content = $q[0]->content;
		$content =~ s/%.*\n//g;
		$content =~ s/^\n//g;
		$content =~ s/\n\n//g;
		# print "content [$content]\n";
		# print "match [$match]\n";
		skip($no_server,$match eq $content);
		close FH;
		return $i;
	}
}

exit 0;
