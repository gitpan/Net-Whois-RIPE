BEGIN { $| = 1; print "1..30\n"; }
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
test(3,$o = Net::Whois::RIPE::Object->new(\*FH),
	"object constructor failed".Net::Whois::RIPE::Object->errstr);
test(4,close(FH),"error closing file: $!");
test(5,$o->success==1,"failed to parse $file");

# now pull all that back out
my @addy;

test(6,($o->person eq 'Paul Gampe'),"person method failed");
test(7,@addy = $o->address,"address method failed");
test(8,($addy[0] eq 'Level 1 - 33 Park Road'),"add method failed");
test(9,($addy[1] eq 'Milton, QLD, 4064'),"add method failed");
test(10,($o->country eq 'AU'),"country method failed");
test(11,($o->phone eq '+61-7-3367-0490'),"phone method failed");
test(12,($o->fax_no eq '+61-7-3367-0482'),"fax method failed");
test(13,($o->e_mail eq 'paulg@apnic.net'),"e_mail method failed");
test(14,($o->nic_hdl eq 'PG6-AP'),"nic_hdl method failed");
test(15,($o->remarks eq 'APNIC Technical Operations Team'),"remarks failed");
test(16,($o->notify eq 'paulg@apnic.net'),"notify method failed");
test(17,($o->mnt_by eq 'MAINT-APNIC-AP'),"mnt_by method failed");
test(18,($o->changed eq 'paulg@apnic.net 19990909'),"changed method failed");
test(19,($o->source eq 'APNIC'),"source method failed");

# try a method that should not exist

my @temp;
test(20,defined($o->blah)==0,"blah method succeeded!");

# try to add reserved attributes
test(21,defined($o->add('content','val'))==0,"added reserved attribute!");
test(22,defined($o->add('methods','val'))==0,"added reserved attribute!");
test(23,defined($o->add('attributes','va'))==0,"added reserved attribute!");
test(24,defined($o->add('warning','val'))==0,"added reserved attribute!");
test(25,defined($o->add('error','val'))==0,"added reserved attribute!");
test(26,defined($o->add('debug','val'))==0,"added reserved attribute!");
test(27,defined($o->add('_err','val'))==0,"added reserved attribute!");
test(28,defined($o->add('_wrn','val'))==0,"added reserved attribute!");
test(29,defined($o->add('_ok','val'))==0,"added reserved attribute!");
test(30,defined($o->add('parse','val'))==0,"added reserved attribute!");

exit 0;
