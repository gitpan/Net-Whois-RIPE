use strict;
use warnings;
use Module::Build;

my $class = Module::Build->subclass( code => <<'RPM');
    sub ACTION_rpm {
        my $self = shift;

        $self->depends_on('dist');

        # source for tarball for rpmbuild
        my $SOURCEDIR = $self->base_dir; 
        my $DISTNAME = $self->dist_name;
        my $VERSION = $self->dist_version;

		$self->do_system("sed -e 's/\@VERSION\@/$VERSION/' perl-$DISTNAME.spec > perl-$DISTNAME-$VERSION.spec");
		$self->do_system("rpmbuild --define \"_sourcedir $SOURCEDIR\" -ba perl-$DISTNAME-$VERSION.spec");
    }
RPM

my $build = $class->new(
    'module_name'  => 'Net::Whois::RIPE',
    'dist_version' => '1.23',
    'license'      => 'gpl',
    'requires'     => {
        'IO'         => 1.20,
        'Test::More' => undef,
    },
    'create_makefile_pl' => 'traditional',    # TODO: remove after 2005
);
$build->create_build_script;

# TODO prompt user here for a whois server to test against?
$build->notes(host => 'does not exist');
