#  You may distribute under the terms of either the GNU General Public License
#  or the Artistic License (the same terms as Perl itself)
#
#  (C) Paul Evans, 2011 -- leonerd@leonerd.org.uk

package IO::Async::Resolver::DNS;

use strict;
use warnings;

our $VERSION = '0.01';

use IO::Async::Resolver;

use Carp;
use Net::DNS;

# We'd prefer to use libresolv to actually talk DNS as it'll be more efficient
# and more standard to the OS
BEGIN {
   if( eval { require Net::LibResolv } ) {
      Net::LibResolv->import(qw( res_query res_search ));

      *class_name2id = sub { return Net::LibResolv->${\"NS_C_$_[0]"} };
      *type_name2id  = sub { return Net::LibResolv->${\"NS_T_$_[0]"} };
   }
}

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

=cut

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
         $on_resolved->( Net::DNS::Packet->new( \$data ) );
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
         $on_resolved->( Net::DNS::Packet->new( \$data ) );
      },
      on_error => $args{on_error},
   );
}

if( defined &res_query ) {
   IO::Async::Resolver::register_resolver(
      res_query => sub {
         my ( $dname, $class, $type ) = @_;
         return res_query( $dname, class_name2id($class), type_name2id($type) );
      },
   );

   IO::Async::Resolver::register_resolver(
      res_search => sub {
         my ( $dname, $class, $type ) = @_;
         return res_search( $dname, class_name2id($class), type_name2id($type) );
      },
   );
}
else {
   # captured by resolver closures, used by child processes
   my $res;

   IO::Async::Resolver::register_resolver(
      res_query => sub {
         my ( $dname, $class, $type ) = @_;

         $res ||= Net::DNS::Resolver->new;

         my $pkt = $res->query( $dname, $type, $class ); # !order

         # placate Net::DNS::Packet bug
         $pkt->answer; $pkt->authority; $pkt->additional;

         return $pkt->data;
      },
   );

   IO::Async::Resolver::register_resolver(
      res_search => sub {
         my ( $dname, $class, $type ) = @_;

         $res ||= Net::DNS::Resolver->new;

         my $pkt = $res->search( $dname, $type, $class ); # !order

         # placate Net::DNS::Packet bug
         $pkt->answer; $pkt->authority; $pkt->additional;

         return $pkt->data;
      },
   );
}

=head1 AUTHOR

Paul Evans <leonerd@leonerd.org.uk>

=cut

0x55AA;
