BEGIN {$| = 1; print "1..65\n"; }
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

use vars qw($EMAIL $SOURCE $PASSWORD 
	$CREATE_PERSON
	$OBJECT_THAT_IS_NOT_IN_WHOIS 
	$UPDATE_THAT_FAILS
	$BAD_DELETE
	$PRE_DELETE_MSG1
	$PRE_DELETE_MSG2
	$PRE_DELETE_MSG3
	$PRE_DELETE_MSG4
	$PRE_DELETE_MSG5
	$PRE_DELETE_MSG6
	);
$file = $0;	# load up update messages
$file =~ s/\.t$/\.obj/;
test(3,(do $file),"failed to load update messages from $file");


my $whois;
test(4,$whois = Net::Whois::RIPE->new($HOST),"new failed");
test(5,($whois->source($SOURCE) eq $SOURCE),"failed to set source to $SOURCE");

# ok pre delete all previous test items

test(6,($whois->type('person') eq 'person'),"failed to set type to 'person'");
foreach my $p ($whois->query('Kevin Baker')) {
	unless ($p->attributes) {
		carp "no attibutes found for person query" if $DEBUG;
		next;
	}

	# make sure we have a good match before we start deleting
	carp scalar $p->person, "\n" if $DEBUG;
	carp scalar $p->address, "\n" if $DEBUG;
	carp scalar $p->country, "\n" if $DEBUG;
	carp scalar $p->phone, "\n" if $DEBUG;
	carp scalar $p->e_mail, "\n" if $DEBUG;
	carp scalar $p->mnt_by, "\n" if $DEBUG;

	next unless scalar $p->person eq 'Kevin Baker';
	next unless scalar $p->address eq 'APNIC Milton';
	next unless scalar $p->country eq 'AU';
	next unless scalar $p->phone eq '+61-7-3846-3847';
	next unless scalar $p->e_mail eq $EMAIL;
	next unless scalar $p->mnt_by eq 'MAINT-TEST';

	carp "Deleting ",$p->content if $DEBUG;
	carp whois_delete($whois,$p) ? 'OK' : 'NOT OK', "\n" if $DEBUG;
}


# test case 1: create a person object

my @ret;
my $person;
my $nic_hdl;

test(7,@ret = $whois->update($CREATE_PERSON),"create person object failed");
test(8,@ret == 1,"create object should return only one object");
$person = $ret[0];
test(9,$person,"no person object from create");
exit 1 unless $person;
test(10,$person->success == 1,"cannot create person:\n".$person->content);
exit 1 unless $person->success;
test(11,$nic_hdl = $person->nic_hdl,
	"cannot find created nic_hdl:\n".$person->content);

# test case 2: query the object from test case 1

my $query;

test(12,$whois->type('person') eq 'person',"failed to set type to 'person'");
test(13,@ret = $whois->query($nic_hdl),"query failed to return any objects");
test(14,@ret == 1,"query should return only one object");
$query = $ret[0];
test(15,$query,"no query object from  whois");
exit 1 unless $query;
test(16,$query->attributes > 0,"person has attributes");
exit 1 unless $query->attributes;

# test case 3: delete the object from test case 1

my $text = '';

foreach my $attr ($query->attributes) {
	foreach my $val ($query->$attr()) {
		$text .= sprintf "%-13s%s\n",$attr.':',$val;
	}
}
$text .= "password:    ".$PASSWORD."\n";
$text .= "delete:      delete it\n";
$text .= "\n";
$text .= ".\n";
$text .= "\n";

my $dquery;

test(17,@ret = $whois->update($text),"update should return an object");;
test(18,@ret == 1,"update should return only one object");
$dquery = $ret[0];
test(19,$dquery,"no query object from whois delete");
exit 1 unless $dquery;
test(20,$dquery->attributes > 0,
	"person should have attributes: \n".$dquery->content);
exit 1 unless $dquery->attributes;
test(21,$dquery->success == 1,'cannot delete person: '.$dquery->error);
test(22,$dquery->nic_hdl eq $nic_hdl,"deleted nic_hdl does not match $nic_hdl");
test(23,$dquery->person eq $query->person,"deleted person does not match");

# test case 4: query a non-existent object. expect 'No entries found'

my $not;

test(24,$whois->type('') eq '',"failed to set type to 'person'");
test(25,@ret = $whois->query($OBJECT_THAT_IS_NOT_IN_WHOIS),
	"an object should be returned");
test(26,@ret == 1,"query should return only one object");
$not = $ret[0];
test(27,$not,"no query object from whois");
exit 1 unless $not;
test(28,$not->attributes == 0,"failed query should have no attributes");
exit 1 if $not->attributes;
test(29,$not->error eq 'No entries found',
	"expecting 'No entries found'; got:".$not->content);

# test case 5: do an update that fails on 'Unknown object type'.

my $unknown;


test(30,@ret = $whois->update($UPDATE_THAT_FAILS),
	"update should fail, but return an object");;
test(31,@ret == 1,"update should return only one object");
$unknown = $ret[0];
test(32,$unknown,"no query object from whois");
exit 1 unless $unknown;
test(33,$unknown->error eq 'Unknown object type',
	"expecting 'Unknown object type', but got:\n".$unknown->content);


# test case 6: create person again with the aim of processing an update

test(34,@ret = $whois->update($CREATE_PERSON),"create person object failed");
test(35,@ret == 1,"create object should return only one object");
$person = $ret[0];
test(36,$person,"no person object from create");
exit 1 unless $person;
test(37,$person->success == 1,"cannot create person:\n".$person->content);
exit 1 unless $person->success;
test(38,$nic_hdl = $person->nic_hdl,
	"cannot find created nic_hdl:\n".$person->content);


# test 7: query object from test case 6

@ret = ();
$query = undef;

test(39,$whois->type('person') eq 'person',"failed to set type to 'person'");
test(40,@ret = $whois->query($nic_hdl),"query failed to return any objects");
test(41,@ret == 1,"query should return only one object");
$query = $ret[0];
test(42,$query,"no query object from  whois");
exit 1 unless $query;
test(43,$query->attributes > 0,"person has attributes");
exit 1 unless $query->attributes;

# test case 8: update object from test case 6; add fax field

$text = '';
foreach my $attr ($query->attributes) {
	foreach my $val ($query->$attr()) {
		$text .= sprintf "%-13s%s\n",$attr.':',$val;
	}
	# add in fax after phone
	if ($attr eq 'phone') {
		$text .= sprintf "%-13s%s\n",'fax:','+61-7-3345-4656';
	}
	# add in a new changed field
	if ($attr eq 'changed') {
		$text .= sprintf "%-13s%s\n",'changed:',"$EMAIL 20000420"
	}
}
$text .= "password:    ".$PASSWORD."\n";
$text .= "\n";
$text .= ".\n";
$text .= "\n";

my $uquery;

test(44,@ret = $whois->update($text),"update should return an object");;
test(45,@ret == 1,"update should return only one object");
$uquery = $ret[0];
test(46,$uquery,"no query object from whois update");
exit 1 unless $uquery;
test(47,$uquery->attributes > 0,"person should have attributes");
exit 1 unless $uquery->attributes;
test(48,$uquery->success == 1,'cannot update person: '.$uquery->error);
test(49,$uquery->nic_hdl eq $nic_hdl,"updated nic_hdl does not match $nic_hdl");
test(50,$uquery->person eq $query->person,"updated person does not match");

# test case 9: query updated object, check fax field

@ret = ();
$query = undef;

test(51,$whois->type('person') eq 'person',"failed to set type to 'person'");
test(52,@ret = $whois->query($nic_hdl),"query failed to return any objects");
test(53,@ret == 1,"query should return only one object");
$query = $ret[0];
test(54,$query,"no query object from  whois");
test(55,$query->fax_no eq '+61-7-3345-4656',"fax number not updated");
exit 1 unless $query;

# test case 10: delete updated object

@ret = ();
$dquery = undef;
$text = '';

foreach my $attr ($query->attributes) {
	foreach my $val ($query->$attr()) {
		$text .= sprintf "%-13s%s\n",$attr.':',$val;
	}
}
$text .= "password:    ".$PASSWORD."\n";
$text .= "delete:      delete it\n";
$text .= "\n";
$text .= ".\n";
$text .= "\n";

test(56,@ret = $whois->update($text),"update should return an object");;
test(57,@ret == 1,"update should return only one object");
$dquery = $ret[0];
test(58,$dquery,"no query object from whois delete");
exit 1 unless $dquery;
test(59,$dquery->attributes > 0,"person should have attributes");
exit 1 unless $dquery->attributes;
test(60,$dquery->success == 1,'cannot delete person: '.$dquery->error);
test(61,$dquery->nic_hdl eq $nic_hdl,"deleted nic_hdl does not match $nic_hdl");
test(62,$dquery->person eq $query->person,"deleted person does not match");

# test case 11: mess up a delete, fail with unknown object type

@ret = ();
$dquery = undef;

test(63,@ret = $whois->update($BAD_DELETE),"update should return an object");;
test(64,@ret == 1,"update should return only one object");
$dquery = $ret[0];
test(65,$dquery->error eq 'Unknown object type',
	"expecting 'Unknown object type', but got:".$dquery->content);

exit 0;

################################################################################
# S U B
################################################################################

sub whois_delete
{
	my $whois  = shift;
	my $object = shift;

	return unless $object->attributes;

	my $text = '';
	foreach my $attr ($object->attributes) {
		foreach my $val ($object->$attr()) {
			$text .= sprintf "%-13s%s\n",$attr.':',$val;
		}
	}
	# tack on password and delete message
	$text .= <<DEL
password:    $PASSWORD
delete:      delete it

.

DEL
;
	my @resp = $whois->update($text);
	unless (@resp) {
		carp "No response from whois update!" if $DEBUG;
		return 0;
	}
	if ($DEBUG) {
		carp "More than one response from a delete!" if @resp > 1;
		carp "Response[0] content".$resp[0]->content;
	}
	my @errors = $resp[0]->error;
	carp $resp[0]->content if not $resp[0]->success;
	return @errors ? 0 : 1;
}
