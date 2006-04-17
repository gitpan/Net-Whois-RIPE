use Module::Build;
use Test::More tests => 6;
use strict;

BEGIN { 
    use_ok('Net::Whois::RIPE');
    use_ok('Net::Whois::RIPE::Iterator');
    use_ok('Net::Whois::RIPE::Object');
    use_ok('Net::Whois::RIPE::Object::Template');
}

my $build = Module::Build->current;     # source test vars from M:B
my $HOST = $build->notes('host');


my $w = new Net::Whois::RIPE($HOST);
isa_ok($w, 'Net::Whois::RIPE', 'created a whois ripe object ok');

can_ok($w, qw(  connect query_iterator 
                template        verbose_template 
                query           update              max_read_size disconnect

                search_all      fast_raw            set_persistance
                find_less       find_more           find_all_more
                no_recursive    no_referral         no_sugar
                no_filtering    no_grouping

                persistant      sync                inverse_lookup
                primary_only    source              type
                port            server              debug
              ) 
      );
exit;
