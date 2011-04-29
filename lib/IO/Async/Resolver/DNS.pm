#  You may distribute under the terms of either the GNU General Public License
#  or the Artistic License (the same terms as Perl itself)
#
#  (C) Paul Evans, 2011 -- leonerd@leonerd.org.uk

package IO::Async::Resolver::DNS;

use strict;
use warnings;

our $VERSION = '0.02';

use IO::Async::Resolver;

use Carp;
use Net::DNS;

use List::UtilsBy qw( weighted_shuffle_by );

=head1 NAME

C<IO::Async::Resolver::DNS> - resolve DNS queries using C<IO::Async>

=head1 SYNOPSIS

 use IO::Async::Loop;
 use IO::Async::Resolver::DNS;
 
 my $loop = IO::Async::Loop->new;
 my $resolver = $loop->resolver;
 
 $resolver->res_query(
    dname => "cpan.org",
    type  => "MX",
    on_resolved => sub {
       my ( $pkt ) = @_;
 
       foreach my $mx ( $pkt->answer ) {
          next unless $mx->type eq "MX";
 
          printf "preference=%d exchange=%s\n",
             $mx->preference, $mx->exchange;
       }
       $loop->loop_stop;
    },
    on_error => sub { die "Cannot resolve - $_[-1]\n" },
 );
 
 $loop->loop_forever;

=head1 DESCRIPTION

This module extends the L<IO::Async::Resolver> class with extra methods and
resolver functions to perform DNS-specific resolver lookups. It does not
directly provide any methods or functions of its own.

These functions are provided for performing DNS-specific lookups, to obtain
C<MX> or C<SRV> records, for example. For regular name resolution, the usual
C<getaddrinfo> and C<getnameinfo> methods on the standard
C<IO::Async::Resolver> should be used.

If L<Net::LibResolv> is installed then it will be used for actually sending
and receiving DNS packets, in preference to a internally-constructed
L<Net::DNS::Resolver> object. C<Net::LibResolv> will be more efficient and
shares its implementation with the standard resolver used by the rest of the
system. C<Net::DNS::Resolver> reimplements the logic itself, so it may have
differences in behaviour from that provided by F<libresolv>. The ability to
use the latter is provided to allow for an XS-free dependency chain, or for
other situations where C<Net::LibResolv> is not available.

=head2 Record Extraction

If certain record type queries are made, extra information is returned to the
C<on_resolved> continuation, containing the results from the DNS packet in a
more useful form. This information will be in a list of extra values following
the packet value

 $on_resolved->( $pkt, @data )

The type of the elements in C<@data> will depend on the DNS record query type:

=over 4

=item * MX

The C<MX> records will be unpacked, in order of C<preference>, and returned in
a list of HASH references. Each HASH reference will contain keys called
C<exchange> and C<preference>. If the exchange domain name is included in the
DNS C<additional> data, then the HASH reference will also include a key called
C<address>, its value containing a list of C<A> and C<AAAA> record C<address>
fields.

 @data = ( { exchange   => "mail.example.com",
             preference => 10,
             address    => [ "10.0.0.1", "fd00:0:0:0:0:0:0:1" ] } );

=item * SRV

The C<SRV> records will be unpacked and sorted first by order of priority,
then by a weighted shuffle by weight, and returned in a list of HASH
references. Each HASH reference will contain keys called C<priority>,
C<weight>, C<target> and C<port>. If the target domain name is included in the
DNS C<additional> data, then the HASH reference will also contain a key called
C<address>, its value containing a list of C<A> and C<AAAA> record C<address>
fields.

 @data = ( { priority => 10,
             weight   => 10,
             target   => "server1.service.example.com",
             port     => 1234,
             address  => [ "10.0.1.1" ] } );

=back

=cut

sub _extract
{
   my ( $pkt, $type ) = @_;

   if( $type eq "MX" ) {
      my @mx;
      my %additional;

      foreach my $rr ( $pkt->additional ) {
         push @{ $additional{$rr->name}{address} }, $rr->address if $rr->type eq "A" or $rr->type eq "AAAA";
      }

      foreach my $ans ( sort { $a->preference <=> $b->preference } grep { $_->type eq "MX" } $pkt->answer ) {
         my $exchange = $ans->exchange;
         push @mx, { exchange => $exchange, preference => $ans->preference };
         $mx[-1]{address} = $additional{$exchange}{address} if $additional{$exchange}{address};
      }
      return ( $pkt, @mx );
   }
   elsif( $type eq "SRV" ) {
      my @srv;
      my %additional;

      foreach my $rr ( $pkt->additional ) {
         push @{ $additional{$rr->name}{address} }, $rr->address if $rr->type eq "A" or $rr->type eq "AAAA";
      }

      my %srv_by_prio;
      # Need to work in two phases. Split by priority then shuffle within
      foreach my $ans ( grep { $_->type eq "SRV" } $pkt->answer ) {
         push @{ $srv_by_prio{ $ans->priority } }, $ans;
      }

      foreach my $prio ( sort { $a <=> $b } keys %srv_by_prio ) {
         foreach my $ans ( weighted_shuffle_by { $_->weight || 1 } @{ $srv_by_prio{$prio} } ) {
            my $target = $ans->target;
            push @srv, { priority => $ans->priority,
                         weight   => $ans->weight,
                         target   => $target,
                         port     => $ans->port };
            $srv[-1]{address} = $additional{$target}{address} if $additional{$target}{address};
         }
      }
      return ( $pkt, @srv );
   }
   else {
      return ( $pkt );
   }
}

=head1 RESOLVER METHODS

=cut

=head2 $resolver->res_query( %params )

Performs a resolver query on the name, class and type, and invokes a
continuation when a result is obtained.

Takes the following named parameters:

=over 8

=item dname => STRING

Domain name to look up

=item type => STRING

Name of the record type to look up (e.g. C<MX>)

=item class => STRING

Name of the record class to look up. Defaults to C<IN> so normally this
argument is not required.

=item on_resolved => CODE

Continuation which is invoked after a successful lookup. Will be passed a
L<Net::DNS::Packet> object containing the result.

 $on_resolved->( $pkt )

For certain query types, this continuation may also be passed extra data in a
list after the C<$pkt>

 $on_resolved->( $pkt, @data )

See the B<Record Extraction> section above for more detail.

=item on_error => CODE

Continuation which is invoked after a failed lookup.

=back

=cut

sub IO::Async::Resolver::res_query
{
   my $self = shift;
   my %args = @_;

   my $dname = $args{dname} or croak "Expected 'dname'";
   my $class = $args{class} || "IN";
   my $type  = $args{type}  or croak "Expected 'type'";

   my $on_resolved = $args{on_resolved};
   ref $on_resolved or croak "Expected 'on_resolved' to be a reference";

   $self->resolve(
      type => "res_query",
      data => [ $dname, $class, $type ],
      on_resolved => sub {
         my ( $data ) = @_;
         my $pkt = Net::DNS::Packet->new( \$data );
         $on_resolved->( _extract( $pkt, $type ) );
      },
      on_error => $args{on_error},
   );
}

=head2 $resolver->res_search( %params )

Performs a resolver query on the name, class and type, and invokes a
continuation when a result is obtained. Identical to C<res_query> except that
it additionally implements the default domain name search behaviour.

=cut

sub IO::Async::Resolver::res_search
{
   my $self = shift;
   my %args = @_;

   my $dname = $args{dname} or croak "Expected 'dname'";
   my $class = $args{class} || "IN";
   my $type  = $args{type}  or croak "Expected 'type'";

   my $on_resolved = $args{on_resolved};
   ref $on_resolved or croak "Expected 'on_resolved' to be a reference";

   $self->resolve(
      type => "res_search",
      data => [ $dname, $class, $type ],
      on_resolved => sub {
         my ( $data ) = @_;
         my $pkt = Net::DNS::Packet->new( \$data );
         $on_resolved->( _extract( $pkt, $type ) );
      },
      on_error => $args{on_error},
   );
}

# We'd prefer to use libresolv to actually talk DNS as it'll be more efficient
# and more standard to the OS
my @impls = qw(
   LibResolvImpl
   NetDNSImpl
);

while( !defined &res_query ) {
   die "Unable to load an IO::Async::Resolver::DNS implementation\n" unless @impls;
   eval { require "IO/Async/Resolver/DNS/" . shift(@impls) . ".pm" };
}

IO::Async::Resolver::register_resolver res_query  => \&res_query;
IO::Async::Resolver::register_resolver res_search => \&res_search;

=head1 AUTHOR

Paul Evans <leonerd@leonerd.org.uk>

=cut

0x55AA;
