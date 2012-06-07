use strict;
use warnings;
use Test::More qw( no_plan );
use Test::Exception;

# synchronizes the {error,standard} output of this test.
use IO::Handle;
STDOUT->autoflush(1);
STDERR->autoflush(1);

our $class;
BEGIN { $class = 'Net::Whois::Object'; use_ok $class; }

my  @lines = <DATA>; 
my $object = (Net::Whois::Object->new(@lines))[0];

isa_ok $object, "Net::Whois::Object::RtrSet";

# Inherited method from Net::Whois::Object;
can_ok $object,

    # Constructor
    qw( new ),

    # OO Support
    qw( query_filter filtered_attributes displayed_attributes );

can_ok $object, qw(rtr_set descr members mp_members mbrs_by_ref
admin_c tech_c mnt_by notify changed remarks source);

ok( !$object->can('bogusmethod'), "No AUTOLOAD interference with Net::Whois::Object::RtrSet tests" );

is ($object->rtr_set(),'RTRS-EXAMPLENET','rtr_set properly parsed');
$object->rtr_set('RTRS2-EXAMPLENET');
is ($object->rtr_set(),'RTRS2-EXAMPLENET','rtr_set properly set');

is_deeply ($object->descr(),[ 'Router set for', 'the company Example' ],'descr properly parsed');
$object->descr('Added descr');
is ($object->descr()->[2],'Added descr','descr properly added');

is_deeply ($object->members(),[ 'INET-RTR1', 'RTRS-SET3' ],'members properly parsed');
$object->members('RTRS-SET4');
is ($object->members()->[2],'RTRS-SET4','members properly added');

is_deeply ($object->mp_members(),[ '192.168.1.1',
        '2001:db8:85a3:8d3:1319:8a2e:370:7348',
        'INET-RTRV6',
        'RTRS-SET1'],'mp_members properly parsed');
$object->mp_members('RTRS-SET2');
is ($object->mp_members()->[4],'RTRS-SET2','mp_members properly added');

is_deeply ($object->mbrs_by_ref(),[ 'CPNY-MNTNER'],'mbrs_by_ref properly parsed');
$object->mbrs_by_ref('CPY2-MNTNER');
is ($object->mbrs_by_ref()->[1],'CPY2-MNTNER','mbrs_by_ref properly added');

is_deeply ($object->admin_c(),[ 'FR123-AP'],'admin_c properly parsed');
$object->admin_c('FR456-AP');
is ($object->admin_c()->[1],'FR456-AP','admin_c properly added');

is_deeply ($object->tech_c(),[ 'FR123-AP'],'tech_c properly parsed');
$object->tech_c('FR456-AP');
is ($object->tech_c()->[1],'FR456-AP','tech_c properly added');

is_deeply ($object->mnt_by(),[ 'MAINT-EXAMPLENET-AP'],'mnt_by properly parsed');
$object->mnt_by('MAINT2-EXAMPLENET-AP');
is ($object->mnt_by()->[1],'MAINT2-EXAMPLENET-AP','mnt_by properly added');

is_deeply ($object->notify(),[ 'watcher@example.com'],'notify properly parsed');
$object->notify('watcher2@example.com');
is ($object->notify()->[1],'watcher2@example.com','notify properly added');

is_deeply ($object->changed(),[ 'abc@examplenet.com 20101231'],'changed properly parsed');
$object->changed('abc@examplenet.com 20121231');
is ($object->changed()->[1],'abc@examplenet.com 20121231','changed properly added');

is_deeply ($object->remarks(),[ 'No remarks'],'remarks properly parsed');
$object->remarks('Added remarks');
is ($object->remarks()->[1],'Added remarks','remarks properly added');

is ($object->source(),'RIPE','source properly parsed');
$object->source('APNIC');
is ($object->source(),'APNIC','source properly set');

__DATA__
rtr-set:        RTRS-EXAMPLENET
descr:          Router set for
descr:          the company Example
members:        INET-RTR1
members:        RTRS-SET3
mp-members:     192.168.1.1
mp-members:     2001:db8:85a3:8d3:1319:8a2e:370:7348
mp-members:     INET-RTRV6
mp-members:     RTRS-SET1
mbrs-by-ref:    CPNY-MNTNER
admin-c:        FR123-AP
tech-c:         FR123-AP
mnt-by:         MAINT-EXAMPLENET-AP
notify:         watcher@example.com
changed:        abc@examplenet.com 20101231
remarks:        No remarks
source:         RIPE
