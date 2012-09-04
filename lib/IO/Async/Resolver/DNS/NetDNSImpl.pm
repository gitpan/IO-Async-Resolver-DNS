#  You may distribute under the terms of either the GNU General Public License
#  or the Artistic License (the same terms as Perl itself)
#
#  (C) Paul Evans, 2011 -- leonerd@leonerd.org.uk

package IO::Async::Resolver::DNS::NetDNSImpl;

use strict;
use warnings;

our $VERSION = '0.03';

my $res;
sub _resolve
{
   my ( $method, $dname, $class, $type ) = @_;

   $res ||= Net::DNS::Resolver->new;

   my $pkt = $res->$method( $dname, $type, $class ); # !order
   if( !$pkt ) {
      my $errorstring = $res->errorstring;
      # Net::DNS::Resolver yields NOERROR for successful DNS queries that just
      # didn't yield any records of the type we wanted. Rewrite that into
      # NODATA instead
      die "NODATA\n" if $errorstring eq "NOERROR";
      die "$errorstring\n";
   }

   # placate Net::DNS::Packet bug
   $pkt->answer; $pkt->authority; $pkt->additional;

   return $pkt->data;
}


sub IO::Async::Resolver::DNS::res_query  { _resolve( query  => @_ ) }
sub IO::Async::Resolver::DNS::res_search { _resolve( search => @_ ) }

0x55AA;
