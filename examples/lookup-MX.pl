#!/usr/bin/perl

use strict;
use warnings;

use IO::Async::Loop;
use IO::Async::Resolver::DNS;

my $loop = IO::Async::Loop->new;
my $resolver = $loop->resolver;

$resolver->res_query(
   dname => $ARGV[0],
   type  => "MX",
   on_resolved => sub {
      my ( $pkt, @mxes ) = @_;

      foreach my $mx ( @mxes ) {
         printf "preference=%d exchange=%s\n",
            $mx->{preference}, $mx->{exchange};
         if( my $addresses = $mx->{address} ) {
            printf "  address=%s\n", $_ for @$addresses;
         }
         else {
            print "  address unknown\n";
         }
      }
      $loop->stop;
   },
   on_error => sub { die "Cannot resolve - $_[-1]" },
);

$loop->run;
