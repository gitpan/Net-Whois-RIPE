use strict;
use warnings;
use Module::Build;

my $class = Module::Build->subclass( code => <<'RPM');
sub ACTION_rpm {
    my $self = shift;

    $self->depends_on('dist');

    # source for tarball for rpmbuild
    my $SOURCEDIR = $self->base_dir;
    my $DISTNAME  = $self->dist_name;
    my $VERSION   = $self->dist_version;

    $self->do_system(
"sed -e 's/\@VERSION\@/$VERSION/' perl-$DISTNAME.spec > perl-$DISTNAME-$VERSION.spec"
    );
    $self->do_system(
"rpmbuild --define \"_sourcedir $SOURCEDIR\" -ba perl-$DISTNAME-$VERSION.spec"
    );
}
RPM

my $build = $class->new(
    'module_name'  => 'Net::Whois::RIPE',
    'dist_version' => '1.31',
    'license'      => 'gpl',
    'requires'     => {
        'IO'         => 1.20,
        'Carp'       => undef,
        'Test::More' => undef,
    },
);
$build->create_build_script;

# This is the public RIPE Whois host. As this is a permanent service and very
# stable DNS name, I can safely put it here. TODO: prompt user here for a whois
# server to test against?
$build->notes( host => 'whois.ripe.net' );

