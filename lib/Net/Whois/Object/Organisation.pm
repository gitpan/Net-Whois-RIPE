package Net::Whois::Object::Organisation;

use base qw/Net::Whois::Object/;

# From http://www.ripe.net/data-tools/support/organisation-object-in-the-ripe-database
#
# organisation:  [mandatory]  [single]     [primary/look-up key]
# org-name:      [mandatory]  [single]     [look-up key]
# org-type:      [mandatory]  [single]     [ ]
# descr:         [optional]   [multiple]   [ ]
# remarks:       [optional]   [multiple]   [ ]
# address:       [mandatory]  [multiple]   [ ]
# phone:         [optional]   [multiple]   [ ]
# fax-no:        [optional]   [multiple]   [ ]
# e-mail:        [mandatory]  [multiple]   [look-up key]
# org:           [optional]   [multiple]   [inverse key]
# admin-c:       [optional]   [multiple]   [inverse key]
# tech-c:        [optional]   [multiple]   [inverse key]
# ref-nfy:       [optional]   [multiple]   [inverse key]
# mnt-ref:       [mandatory]  [multiple]   [inverse key]
# notify:        [optional]   [multiple]   [inverse key]
# mnt-by:        [mandatory]  [multiple]   [inverse key]
# changed:       [mandatory]  [multiple]   [ ]
# source:        [mandatory]  [single]     [ ]
# 

=head1 NAME

Net::Whois::Object::Organisation - an object representation of the RPSL Organisation block

=head1 DESCRIPTION

The organisation object is designed to provide an easy way of mapping resources to a particular organisaiton.

=head1 METHODS

=head2 B<new( %options )>

Constructor for the Net::Whois::Object::Organisation class

=cut

sub new {
    my ( $class, %options ) = @_;

    my $self = bless {}, $class;

    for my $key ( keys %options ) {
        $self->$key( $options{$key} );
    }

    return $self;
}

=head2 B<organisation( [$organisation] )>

Accessor to the organisation attribute.
Accepts an optional organisation, always return the current organisation.

=cut

sub organisation {
    my ( $self, $organisation ) = @_;
    $self->{organisation} = $organisation if defined $organisation;
    return $self->{organisation};
}

=head2 B<org_name( [$org_name] )>

Accessor to the org_name attribute.
Accepts an optional org_name, always return the current org_name.

=cut

sub org_name {
    my ( $self, $org_name ) = @_;
    $self->{org_name} = $org_name if defined $org_name;
    return $self->{org_name};
}

=head2 B<org_type( [$org_type] )>

Accessor to the org_type attribute.
Accepts an optional org_type, always return the current org_type.

Possible values are :
IANA for Internet Assigned Numbers Authority, RIR for Regional Internet
Registries, NIR for National Internet Registries, LIR for Local Internet
Registries, and OTHER for all other organisations. 

=cut

sub org_type {
    my ( $self, $org_type ) = @_;
    $self->{org_type} = $org_type if defined $org_type;
    return $self->{org_type};
}

=head2 B<org( [$org] )>

Accessor to the org attribute.
Accepts an optional org, always return the current org.

=cut

sub org {
    my ( $self, $org ) = @_;
    $self->{org} = $role if defined $role;
    return $self->{org};
}

=head2 B<address( [$address] )>

Accessor to the address attribute.
Accepts an optional address line to be added to the address array,
always return the current address array.

=cut

sub address {
    my ( $self, $address ) = @_;
    push @{ $self->{address} }, $address if defined $address;
    return \@{ $self->{address} };
}

=head2 B<phone( [$phone] )>

Accessor to the phone attribute.
Accepts an optional phone number to be added to the phone array,
always return the current phone array.

=cut

sub phone {
    my ( $self, $phone ) = @_;
    push @{ $self->{phone} }, $phone if defined $phone;
    return \@{ $self->{phone} };
}

=head2 B<fax_no( [$fax_no] )>

Accessor to the fax_no attribute.
Accepts an optional fax_no to be added to the fax_no array,
always return the current fax_no array.

=cut

sub fax_no {
    my ( $self, $fax_no ) = @_;
    push @{ $self->{fax_no} }, $fax_no if defined $fax_no;
    return \@{ $self->{fax_no} };
}

=head2 B<e_mail( [$e_mail] )>

Accessor to the e_mail attribute.
Accepts an optional e_mail to be added to the e_mail array,
always return the current e_mail array.

=cut

sub e_mail {
    my ( $self, $e_mail ) = @_;
    push @{ $self->{e_mail} }, $e_mail if defined $e_mail;
    return \@{ $self->{e_mail} };
}

=head2 B<admin_c( [$contact] )>

Accessor to the admin_c attribute.
Accepts an optional contact to be added to the admin_c array,
always return the current admin_c array.

=cut

sub admin_c {
    my ( $self, $contact ) = @_;
    push @{ $self->{admin_c} }, $contact if defined $contact;
    return \@{ $self->{admin_c} };
}

=head2 B<tech_c( [$contact] )>

Accessor to the tech_c attribute.
Accepts an optional contact to be added to the tech_c array,
always return the current tech_c array.

=cut

sub tech_c {
    my ( $self, $contact ) = @_;
    push @{ $self->{tech_c} }, $contact if defined $contact;
    return \@{ $self->{tech_c} };
}

=head2 B<descr( [$descr] )>

Accessor to the descr attribute.
Accepts an optional descr line to be added to the descr array,
always return the current descr array.

=cut

sub descr {
    my ( $self, $descr ) = @_;
    push @{ $self->{descr} }, $descr if defined $descr;
    return \@{ $self->{descr} };
}

=head2 B<remarks( [$remark] )>

Accessor to the remarks attribute.
Accepts an optional remark to be added to the remarks array,
always return the current remarks array.

=cut

sub remarks {
    my ( $self, $remarks ) = @_;
    push @{ $self->{remarks} }, $remarks if defined $remarks;
    return \@{ $self->{remarks} };
}

=head2 B<notify( [$notify] )>

Accessor to the notify attribute.
Accepts an optional notify value to be added to the notify array,
always return the current notify array.

=cut

sub notify {
    my ( $self, $notify ) = @_;
    push @{ $self->{notify} }, $notify if defined $notify;
    return \@{ $self->{notify} };
}

=head2 B<mnt_by( [$mnt_by] )>

Accessor to the mnt_by attribute.
Accepts an optional mnt_by value to be added to the mnt_by array,
always return the current mnt_by array.

=cut

sub mnt_by {
    my ( $self, $mnt_by ) = @_;
    push @{ $self->{mnt_by} }, $mnt_by if defined $mnt_by;
    return \@{ $self->{mnt_by} };
}

=head2 B<changed( [$changed] )>

Accessor to the changed attribute.
Accepts an optional changed value to be added to the changed array,
always return the current changed array.

=cut

sub changed {
    my ( $self, $changed ) = @_;
    push @{ $self->{changed} }, $changed if defined $changed;
    return \@{ $self->{changed} };
}

=head2 B<source( [$source] )>

Accessor to the source attribute.
Accepts an optional source, always return the current source.

=cut

sub source {
    my ( $self, $source ) = @_;
    $self->{source} = $source if defined $source;
    return $self->{source};
}

=head2 B<ref_nfy( [$ref_nfy] )>

Accessor to the ref_nfy attribute.
Accepts an optional ref_nfy value to be added to the ref_nfy array,
always return the current ref_nfy array.

=cut

sub ref_nfy {
    my ( $self, $ref_nfy ) = @_;
    push @{ $self->{ref_nfy} }, $ref_nfy if defined $ref_nfy;
    return \@{ $self->{ref_nfy} };
}


=head2 B<mnt_ref( [$mnt_ref] )>

Accessor to the mnt_ref attribute.
Accepts an optional mnt_ref value to be added to the mnt_ref array,
always return the current mnt_ref array.

=cut

sub mnt_ref {
    my ( $self, $mnt_ref ) = @_;
    push @{ $self->{mnt_ref} }, $mnt_ref if defined $mnt_ref;
    return \@{ $self->{mnt_ref} };
}

1;
