BEGIN { $| = 1; print "1..8\n"; }
END {print "not ok 1\n" unless $loaded;}
use Net::Whois::RIPE::Object;
$loaded = 1;
print "ok 1\n";

sub test {
	local($^W)=0;
	my($num,$true,$msg)=@_;
	print($true ? "ok $num\n" : "not ok $num $msg\n");
}

my $o;

my $file = $0;
$file =~ s/\.t$/\.obj/;
test(2,open(FH,$file),"cannot open $file: $!");

my $cnt = 0;
my $success = 0;
my $attributes = 0;
my $person = 0;
while ($o = Net::Whois::RIPE::Object->new(\*FH)) {
	$cnt++;
	$success += ($o->success ? 1 : 0);	
	$attributes += ($o->attributes ? 1 : 0);	
	$person += ($o->person ? 1 : 0);	
}
# $i == 3+291 after this run
test(3,close(FH),"error closing file: $!");
test(4,!($cnt>291),"more than 291 person objects parsed");
test(5,!($cnt<291),"less than 291 person objects parsed");
test(6,($success==291),"not all objects parsed successfully");
test(7,($attributes==291),"not all objects parsed attributes successfully");
test(8,($person==291),"not all objects parsed person attribute successfully");

exit 0;
