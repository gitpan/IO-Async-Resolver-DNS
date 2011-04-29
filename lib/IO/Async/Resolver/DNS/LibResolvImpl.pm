#  You may distribute under the terms of either the GNU General Public License
#  or the Artistic License (the same terms as Perl itself)
#
#  (C) Paul Evans, 2011 -- leonerd@leonerd.org.uk

package IO::Async::Resolver::DNS::LibResolvImpl;

use strict;
use warnings;

our $VERSION = '0.02';

use Net::LibResolv 0.03 qw( res_query res_search class_name2value type_name2value $h_errno );

sub _resolve
{
   my ( $func, $dname, $class, $type ) = @_;
   my $pkt = $func->( $dname, class_name2value($class), type_name2value($type) );
   # We can't easily detect NODATA errors here, so we'll have to let the
   # higher-level function do it
   die "$h_errno\n" if !defined $pkt;
   return $pkt;
}

sub IO::Async::Resolver::DNS::res_query  { _resolve( \&res_query,  @_ ) }
sub IO::Async::Resolver::DNS::res_search { _resolve( \&res_search, @_ ) }

0x55AA;
