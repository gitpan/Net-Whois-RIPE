BEGIN { $| = 1; print "1..29\n"; }
END {print "not ok 1\n" unless $loaded;}
use Net::Whois::RIPE::Object;
$loaded = 1;
print "ok 1\n";

sub test {
	local($^W)=0;
	my($num,$true,$msg)=@_;
	print($true ? "ok $num\n" : "not ok $num $msg\n");
}

# this test input that has text but only comments
# and garbage that doesn't match an /^([\w\-]+|\*\w\w):\s+(.*)$/)

my $o;
my $file = $0;
$file =~ s/\.t$/\.obj/;

# first suck the whole fiel in so we can match the content
test(2,open(FH,$file),"cannot open $file: $!");
undef $/;
my $match_content = <FH>;	# suck it all in
$/ = "\n";
test(3,close(FH),"unable to close file: $!");

test(4,open(FH,$file),"cannot open $file: $!");
test(5,$o = Net::Whois::RIPE::Object->new(\*FH),
	"object constructor failed".Net::Whois::RIPE::Object->errstr);
test(6,close(FH),"unable to close file: $!");
test(7,$o->success==1,"not successful");
test(8,$o->content eq $match_content,"content mismatch");

# attributes method on a new object, list context
test(9,$o->attributes==0,"attributes should be empty array");
@temp = $o->attributes;
test(10,@temp==0,"attributes should be empty array");

# warning method on a new object, scalar and list context
test(11,(scalar $o->warning eq ''),"scalar warning should be empty string");
test(12,($o->warning eq ''),"scalar warning should be empty string");
@temp = $o->warning;
test(13,@temp==0,"warning should be empty array");

# error method on a new object, scalar and list context
test(14,(scalar $o->error eq ''),"scalar error should be empty string");
test(15,($o->error eq ''),"scalar error should be empty string");
@temp = $o->error;
test(16,@temp==0,"error should be empty array");

# set some content and perform a scalar 'eq' check

test(17,$o->success==1,"success should be true since no errors");

# set some warnings
$o->_wrn('1st Warning');
$o->_wrn('2nd Warning');
$o->_wrn('3rd Warning');

# success should _still_ be true since no errors
test(18,$o->success==1,"success should be true since no errors");

# set some errors 
$o->_err('1st Error');
$o->_err('2nd Error');
$o->_err('3rd Error');

# success should be false now
test(19,$o->success==0,"success should be false since errors");

# get warnings 
my @warnings;
my $match_warn = "1st Warning\n2nd Warning\n3rd Warning";
test(20,($o->warning eq $match_warn),"scalar warning should be $match_warn");
test(21,@warnings = $o->warning,"warning should return array");
test(22,$warnings[0] eq '1st Warning',"warning mismatch");
test(23,$warnings[1] eq '2nd Warning',"warning mismatch");
test(24,$warnings[2] eq '3rd Warning',"warning mismatch");

# get errors
my @errors;
my $match_error = "1st Error\n2nd Error\n3rd Error";
test(25,($o->error eq $match_error),"scalar error should be $match_error");
test(26,@errors = $o->error,"error should return array");
test(27,$errors[0] eq '1st Error',"error mismatch");
test(28,$errors[1] eq '2nd Error',"error mismatch");
test(29,$errors[2] eq '3rd Error',"error mismatch");
