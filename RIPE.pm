package Net::Whois::RIPE;

use strict;
use Carp;
use IO::Socket;
use Net::Whois::RIPE::Object;
use Net::Whois::RIPE::Object::Template;
use Net::Whois::RIPE::Iterator;


use constant MAX_RETRY_ATTEMPTS=> 3; # number of times to attempt connection
use constant SLEEP_INTERVAL=> 1;     # time interval between attempts


use vars qw($VERSION);
$VERSION = do {my @r=(q$Revision: 1.19 $=~/\d+/g); sprintf "%d."."%02d"x$#r,@r};

# class wide debug flag 0=off,1=on,2=on for IO::Socket
my $DEBUG=0;

# couple of regexs that may need attention
my $RE_WHOIS = '(?:whois\.apnic\.net)$';
my $RE_RIPE  = '(?:ripe|ra|apnic|mci|ans)\.net|isi\.edu|garr\.it$';

# version string to let whois know which client version it is talking to
my $VER_FLAG = '-VNWR'.$VERSION;


sub new 
{
	my $proto  = shift;
	my ($host,%arg) = @_;
	my $class = ref($proto) || $proto;

 	my $debug = exists $arg{Debug} ? $arg{Debug} : 0;
	unless ($host) {
		carp "new: no hostname found." if $DEBUG || $debug;
		return undef;
	}

	my $self = bless {
		# object fields
		SOCKET=> undef,	# unconnected
		TIMEOUT=> $arg{Timeout} || 30,	# default timeout
		MAX_READ_SIZE=> 0,	# no read size limit
 		DEBUG=> $debug,	# object debug

		# whois flags 
		FLAG_a=> 0,	# search all databases
		FLAG_F=> 0,	# fast raw output
		FLAG_g=> 0,	# used to sync databases. shouldn't be used for general use
		FLAG_h=> $host,# host to connect to
		FLAG_i=> '',	# do an inverse lookup for specified attributes
    FLAG_k=> 0, # for persistant socket connection
		FLAG_L=> 0,	# find all Less specific matches
		FLAG_m=> 0,	# find first level more specific matches
		FLAG_M=> 0,	# find all More specific matches
		FLAG_p=> $arg{Port} || 'whois',	# port, usually 43 for whois
		FLAG_r=> 0,	# turn off recursive lookups
		FLAG_R=> 0,	# do not trigger referral mechanism
		FLAG_s=> '',	# search databases with source 'source'
		FLAG_S=> 0,	# tell server to leave out 'syntactic sugar'
		FLAG_t=> '',	# requests template for object of type 'type'
		FLAG_T=> '',	# only look for objects of type 'type'
		FLAG_v=> '',	# request verbose template for object of type 'type'
		FLAG_V=> $VER_FLAG,	# client Version
	}, $class;

	# if host matches a server that accepts a
	# referral IP then add the remote addr to version 
	$self->{FLAG_V} = $VER_FLAG.",".$ENV{"REMOTE_ADDR"}
		if $self->{FLAG_h} =~ /$RE_WHOIS/oi and $ENV{"REMOTE_ADDR"};

	# connect to server
	unless ($self->_connect) {
		carp "new: whois connection failure." if $DEBUG || $debug;
		return undef;
	}
	return $self
}

sub query_iterator
{
	my $self = shift;
	my $query_key = shift;

	unless ($query_key) {
		carp "query: no QUERY_KEY found" if $self->debug;
		return undef;
	}

	# TODO - close the connection pseudo gracefully if the timeout value
	# expires. allow user to set timeouts?

	my $sock;
	unless ($sock = $self->_connect) {
		carp "query: unable to obtain socket" if $self->debug;	
		return undef;		
	}

	my $string;
   	unless ($string = $self->_options($query_key)) {
		carp "query: unable to parse options" if $self->debug;
		return undef;
	}

	return Net::Whois::RIPE::Iterator->new($self,$string."\n\n");
}

sub template 
{
	my $self     = shift; 
	my $template = shift;
	unless ($template) {
		carp "template: no WHOIS OBJECT NAME found" if $self->debug;
		return wantarray ? () : undef;
	}
	$self->{FLAG_t} = 1;			

	my $string;
   	unless ($string = $self->_options($template)) {
		carp "template: unable to parse options" if $self->debug;
		return undef;
	}

	return $self->_query($string."\n\n","Net::Whois::RIPE::Object::Template");
}

sub verbose_template 
{
	my $self     = shift; 
	my $template = shift;
	unless ($template) {
		carp "verbose_template: no WHOIS OBJECT NAME found" if $self->debug;
		return wantarray ? () : undef;
	}
	$self->{FLAG_v} = 1;

	my $string;
   	unless ($string = $self->_options($template)) {
		carp "verbose_template: unable to parse options" if $self->debug;
		return undef;
	}

	return $self->_query($string."\n\n","Net::Whois::RIPE::Object::Template");
}

sub query 
{
	my $self = shift;
	my $query_key = shift;

	unless ($query_key) {
		carp "query: no QUERY_KEY found" if $self->debug;
		return undef;
	}

	# TODO - close the connection pseudo gracefully if the timeout value
	# expires. allow user to set timeouts?

	my $sock;
	unless ($sock = $self->_connect) {
		carp "query: unable to obtain socket" if $self->debug;	
		return undef;		
	}

	my $string;
   	unless ($string = $self->_options($query_key)) {
		carp "query: unable to parse options" if $self->debug;
		return undef;
	}

	return $self->_query($string."\n", "Net::Whois::RIPE::Object");
}

sub update 
{
	my $self=shift;
	my $message=shift;

	unless ($message) {
		carp 'update: no TEXT message found' if $self->debug;
		return undef;
	}

	# pull out login and domain from the changed: line
	my ($login,$domain)= ($message =~ /changed:\s+(.+)@(.+)\n/);
	unless ($login and $domain) {
		carp "update: cannot find 'changed' attribute" if $self->debug;
		return undef;
	}

	my $string = $self->{FLAG_V}." -U $login $domain\n".$message;
	return $self->_query($string, "Net::Whois::RIPE::Object");
}

sub _query 
{
	my $self      = shift;
	my $string    = shift;
	my $ripe_type = shift;

	my $sock;
	unless ($sock = $self->_connect) {
		carp "_query: unable to obtain socket" if $self->debug;	
		return undef;		
	}

	unless (print $sock $string) {
		carp "_query: unable to print to socket:\n$string" if $self->debug;	
		return undef;		
	}

	$sock->flush;

	my $bytes = 0;
	my @objects;
	my $max = $self->max_read_size;

	while (my $t = $ripe_type->new($sock, $self->{FLAG_k})) {
    if ($t->size <= 2) {
     return wantarray ? @objects : $objects[0];
    }
		push @objects, $t;
		$bytes += $t->size;
		if ($max and $bytes > $max) {
			my $msg = "exceeded maximum read size of ".$max." bytes.".
				" results may have been truncated.";
			$t->push_warn($msg);
			carp "_query: ".$msg if $self->debug;
			last
		}
		last if $sock->eof or not wantarray
	}

  if ($sock and $self->{FLAG_k})
    { $sock->flush;
      $self->{SOCKET}->flush; }
  else
    {
    $self->_disconnect;
  }

	return wantarray ? @objects : $objects[0];
}


sub max_read_size 
{
	my $self=shift;
	@_ ? $self->{MAX_READ_SIZE} = 0+shift : $self->{MAX_READ_SIZE};
}

sub search_all     {$_[0]->{FLAG_a} = 1}
sub fast_raw       {$_[0]->{FLAG_F} = 1}
sub set_persistance {$_[0]->{FLAG_a} = 1}
sub find_less      {$_[0]->{FLAG_L} = 1}
sub find_more      {$_[0]->{FLAG_m} = 1}
sub find_all_more  {$_[0]->{FLAG_M} = 1}
sub no_recursive   {$_[0]->{FLAG_r} = 1}
sub no_referral    {$_[0]->{FLAG_R} = 1}
sub no_sugar       {$_[0]->{FLAG_S} = 1}
sub disconnect     {$_[0]->_disconnect;}

# sync is special and is here for completeness. it
# is not expected that it wil be used
sub sync           {my $self=shift; $self->{FLAG_g} = shift;}
sub inverse_lookup {my $self=shift; $self->{FLAG_i} = shift;}
sub source         {my $self=shift; $self->{FLAG_s} = shift;}
sub type           {my $self=shift; $self->{FLAG_T} = shift;}

sub port 
{
	my $self=shift;

	unless ($self->{FLAG_p}) {
		carp 'port: no port defined!' if $self->debug;
		return undef;
	}

	# trying to change port? not allowed
	if (@_) {
		carp "port: cannot switch port." if $self->debug;	
	}
	return $self->{FLAG_p}
}

sub server 
{
	my $self=shift; 

	unless ($self->{FLAG_h}) {
		carp 'server: no hostname found' if $self->debug;
		return undef;
	}

	# trying to change servers? not allowed
	if (@_) {
		carp "server: cannot switch server." if $self->debug;	
	}
	return $self->{FLAG_h}
}

sub debug 
{
	my $self = shift;
	if (@_) {
		ref($self) ? $self->{DEBUG} = shift : $DEBUG = shift;
	}
	return ref($self) ? ($DEBUG || $self->{DEBUG}) : $DEBUG;
}


sub DESTROY 
{
	my $self = shift;

	carp "Destroying ", ref($self) if $self->debug;
  if ($self->{SOCKET} and $self->{FLAG_k})
    { # $sock->flush;
      $self->{SOCKET}->flush; }
  else
    {
    $self->_disconnect;
  }
}

END 
{
	carp "All Net::Whois::RIPE objects are going away now." if $DEBUG;
}

###############################################################################
##            P R I V A T E   M E T H O D S
###############################################################################

sub _connect 
{
	my $self = shift;
	if ($self->{SOCKET} and $self->{SOCKET}->connected) {
		#carp 'already connected to '.$self->{SOCKET}->peerhost;
		return $self->{SOCKET};
	}

	my $sock;
	my $attempt = 0;
	my $connected = 0;
	while (!$connected and $attempt < MAX_RETRY_ATTEMPTS) {
		if ($attempt) {
			carp "_connect: to server ".$self->{FLAG_h}." failed, trying again..."
				if $self->debug;
			sleep SLEEP_INTERVAL;
		}
		$attempt++;	
		$connected = 1 
		if $sock = IO::Socket::INET->new(
			PeerAddr => $self->server,
			PeerPort => $self->port,
			Proto => 'tcp',
			Timeout  => $self->{TIMEOUT}
			);
		carp $@ if $@ and $self->debug > 1;
	}
	if (not $connected) {
		carp "Failed to connect to host [".$self->server."]" if $self->debug;
		return undef;
	}
	$sock->autoflush;			# on by default since IO 1.18, but anyhow
	return $self->{SOCKET} = $sock;
}

sub _disconnect 
{
	my $self = shift;
	my $sock = $self->{SOCKET};
	return unless $sock and $sock->connected;
	$sock->flush;			# probably not necessary
	carp "disconnecting from ".$self->{FLAG_h} if $self->debug;
	$sock->close;
	$self->{SOCKET} = undef;
}

sub _options 
{
	my $self = shift;
	my $key = shift;

	if ((!$key) &&
		(!$self->{FLAG_t}) &&
		(!$self->{FLAG_g}) &&
		(!$self->{FLAG_v}) &&
		(!(($self->{FLAG_g}) && ($self->{FLAG_t})))) {
		carp '_options: no search key or valid option found' if $self->debug;
		return undef;
	}

	if (!$self->{FLAG_h}) {
		carp "_options: no hostname found" if $self->debug;
		return undef;
	}

	if ($self->{FLAG_L}) {
		if ($self->debug) {
			carp "_options: warning -L overrides -m\n" if $self->{FLAG_m};
			carp "_options: warning -L overrides -M\n" if $self->{FLAG_M};
		}
		$self->{FLAG_m} = 0;
		$self->{FLAG_M} = 0;
	}

	if ($self->{FLAG_m}) {
		if ($self->debug) {
			carp "_options: warning -m overrides -M\n" if $self->{FLAG_M};
		}
		$self->{FLAG_M} = 0;
	}

	my $query = "";

	# tell the server what version of RIPE whois we are running,
	# but only if we are sure that we are talking to an
	# RIPE whois server

	if (($self->{FLAG_h} =~ /$RE_RIPE/oi) ||
		$self->{FLAG_a} || $self->{FLAG_g} || $self->{FLAG_F} || 
		$self->{FLAG_i} || $self->{FLAG_k} || $self->{FLAG_m} || $self->{FLAG_M} || 
		$self->{FLAG_R} || $self->{FLAG_L} || $self->{FLAG_r} || 
		$self->{FLAG_s} || $self->{FLAG_S} || $self->{FLAG_t} || 
		$self->{FLAG_v} || $self->{FLAG_T}) {

		$query.= $self->{FLAG_V}." ";
	}

  $query.="-k "                     if ($self->{FLAG_k});

	$query.="-a "                     if ($self->{FLAG_a});
	#  undocumented option, get specified updates:
	# -g Source:First-Last       get updates with 'Source' from 
	#                            serial 'First' till 'Last' (you may use LAST)
	$query.="-g ".$self->{FLAG_g}." " if ($self->{FLAG_g});
	$query.="-F "                     if ($self->{FLAG_F});
	$query.="-i ".$self->{FLAG_i}." " if ($self->{FLAG_i});
	$query.="-L "                     if ($self->{FLAG_L});
	$query.="-m "                     if ($self->{FLAG_m});
	$query.="-M "                     if ($self->{FLAG_M});
	$query.="-r "                     if ($self->{FLAG_r});
	$query.="-R "                     if ($self->{FLAG_R});
	$query.="-S "                     if ($self->{FLAG_S});
	$query.="-s ".$self->{FLAG_s}." " if ($self->{FLAG_s});
	$query.="-T ".$self->{FLAG_T}." " if ($self->{FLAG_T});
	$query.="-t "                     if ($self->{FLAG_t});
	$query.="-v "                     if ($self->{FLAG_v});
	

	$query.= $key;

	carp "_options: parsed query string: $query" if $self->debug;

	return $query;
}

1;
__END__
