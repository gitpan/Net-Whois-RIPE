BEGIN { $| = 1; print "1..13\n"; }
END {print "not ok 1\n" unless $loaded;}
use Net::Whois::RIPE::Object;
$loaded = 1;
print "ok 1\n";

sub test {
	local($^W)=0;
	my($num,$true,$msg)=@_;
	print($true ? "ok $num\n" : "not ok $num $msg\n");
}

# this test tests an empty input handles


my $o;

# test case 1. totally empty 

my $file = $0;
$file =~ s/\.t$/1\.obj/;
test(2,open(FH,$file),"cannot open $file: $!");
test(3,!($o = Net::Whois::RIPE::Object->new(\*FH)),
	"object constructor should have failed");
test(4,close(FH),"unable to close file: $!");
test(5,Net::Whois::RIPE::Object->errstr eq "no lines read from handle",
	"mismatch on error message for empty file");

# test case 2. just newlines

$file = $0;
$file =~ s/\.t$/2\.obj/;
test(6,open(FH,$file),"cannot open $file: $!");
test(7,!($o = Net::Whois::RIPE::Object->new(\*FH)),
	"object constructor should have failed");
test(8,close(FH),"unable to close file: $!");
test(9,Net::Whois::RIPE::Object->errstr eq "content is all whitespace",
	"mismatch on error message for new lines only file");

# test case 3. just newlines, tabs and spaces

$file = $0;
$file =~ s/\.t$/3\.obj/;
test(10,open(FH,$file),"cannot open $file: $!");
test(11,!($o = Net::Whois::RIPE::Object->new(\*FH)),
	"object constructor should have failed");
test(12,close(FH),"unable to close file: $!");
test(13,Net::Whois::RIPE::Object->errstr eq "content is all whitespace",
	"mismatch on error message for newlines,tabs & whitespace file");

exit 0;
