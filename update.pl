#!/usr/bin/perl
use strict;

BEGIN { require "t/common.pl" };

use vars qw($HOST @TEMPLATES);

$|=1;

foreach my $t (@TEMPLATES) {
	print "fetching $t ... ";
	my $cmd = "whois -h $HOST -- -t $t";
	my $ret = `$cmd`;
	$ret =~ s/^\[.*\n//mg;
	$ret =~ s/^%.*\n//mg;
	$ret =~ s/^\n//mg;
	$ret =~ s/\n\n//mg;
	print "ok\n";
	my $file = "t/03template_$t.obj";
	print "writing $file ... ";
	open(FH,"> $file") or die("could not open $file\n");
	print FH $ret;
	close(FH);
	print "ok\n";
}


