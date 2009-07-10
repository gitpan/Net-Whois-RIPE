###############################################################################
# Net::Whois::RIPE - implementation of RIPE Whois.
# Copyright (C) 2009 Luis Motta Campos
# Copyright (C) 2005 Paul Gampe, Kevin Baker
# vim:tw=78:ts=4
###############################################################################
%define pkgname Net-Whois-RIPE
%define filelist %{pkgname}-%{version}-filelist
%define NVR %{pkgname}-%{version}-%{release}
%define maketest 0

name:      perl-Net-Whois-RIPE
summary:   Net-Whois-RIPE - Perl module
version:   @VERSION@
release:   1
vendor:    Luis Motta Campos
packager:  lmc@cpan.org
license:   Perl's Artistic License or GNU GPL
group:     Applications/CPAN
url:       http://www.cpan.org
buildroot: %{_tmppath}/%{name}-%{version}-%(id -u -n)
buildarch: noarch
prefix:    %(echo %{_prefix})
source:    Net-Whois-RIPE-%{version}.tar.gz

%description
Net::Whois::RIPE class implementing a RIPE whois client.

%prep
%setup -q -n %{pkgname}-%{version} 
chmod -R u+w %{_builddir}/%{pkgname}-%{version}

%build
grep -rsl '^#!.*perl' . |
grep -v '.bak$' |xargs --no-run-if-empty \
%__perl -MExtUtils::MakeMaker -e 'MY->fixin(@ARGV)'
CFLAGS="$RPM_OPT_FLAGS"
%{__perl} Makefile.PL `%{__perl} -MExtUtils::MakeMaker -e ' print qq|PREFIX=%{buildroot}%{_prefix}| if \$ExtUtils::MakeMaker::VERSION =~ /5\.9[1-6]|6\.0[0-5]/ '`
%{__make} 
%if %maketest
%{__make} test
%endif

%install
[ "%{buildroot}" != "/" ] && rm -rf %{buildroot}

%{makeinstall} `%{__perl} -MExtUtils::MakeMaker -e ' print \$ExtUtils::MakeMaker::VERSION <= 6.05 ? qq|PREFIX=%{buildroot}%{_prefix}| : qq|DESTDIR=%{buildroot}| '`

[ -x /usr/lib/rpm/brp-compress ] && /usr/lib/rpm/brp-compress

# SuSE Linux
if [ -e /etc/SuSE-release -o -e /etc/UnitedLinux-release ]
then
    %{__mkdir_p} %{buildroot}/var/adm/perl-modules
    %{__cat} `find %{buildroot} -name "perllocal.pod"`  \
        | %{__sed} -e s+%{buildroot}++g                 \
        > %{buildroot}/var/adm/perl-modules/%{name}
fi

# remove special files
find %{buildroot} -name "perllocal.pod" \
    -o -name ".packlist"                \
    -o -name "*.bs"                     \
    |xargs -i rm -f {}

# no empty directories
find %{buildroot}%{_prefix}             \
    -type d -depth                      \
    -exec rmdir {} \; 2>/dev/null

%{__perl} -MFile::Find -le '
    find({ wanted => \&wanted, no_chdir => 1}, "%{buildroot}");
    print "%doc ChangeLog README";
    for my $x (sort @dirs, @files) {
        push @ret, $x unless indirs($x);
        }
    print join "\n", sort @ret;

    sub wanted {
        return if /auto$/;

        local $_ = $File::Find::name;
        my $f = $_; s|^\Q%{buildroot}\E||;
        return unless length;
        return $files[@files] = $_ if -f $f;

        $d = $_;
        /\Q$d\E/ && return for reverse sort @INC;
        $d =~ /\Q$_\E/ && return
            for qw|/etc %_prefix/man %_prefix/bin %_prefix/share|;

        $dirs[@dirs] = $_;
        }

    sub indirs {
        my $x = shift;
        $x =~ /^\Q$_\E\// && $x ne $_ && return 1 for @dirs;
        }
    ' > %filelist

[ -z %filelist ] && {
    echo "ERROR: empty %files listing"
    exit -1
    }

%clean
[ "%{buildroot}" != "/" ] && rm -rf %{buildroot}

%files -f %filelist
%defattr(-,root,root)

%changelog
* Fri Jul 10 2009 lmc@cpan.org 1.232
- taking over package maintenance from Paul Gampe - thanks for your work,
  Paul. :)
- adding whois.ripe.net as the official host for package tests.
- applying the patch provided by Ulrich Zehl <ulrich@topfen.net> which allows
  Net::Whois::RIPE to correctly recognize answers from the whois.radb.net and
  whois.altdb.net instead of timming out.

* Tue Mar 13 2005 pgampe@users.sourceforge.net 1.231
- add caching, retry and fixes from Marco

* Mon Nov 8 2004 pgampe@users.sourceforge.net
- Initial build.
