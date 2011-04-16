#!/usr/bin/perl

use strict;
use warnings;

use IO::Async::Loop;
use IO::Async::Resolver::DNS;

my $loop = IO::Async::Loop->new;
my $resolver = $loop->resolver;

$resolver->res_query(
   dname => $ARGV[0],
   type  => "SRV",
   on_resolved => sub {
      my ( $pkt ) = @_;

      foreach my $srv ( $pkt->answer ) {
         next unless $srv->type eq "SRV";

         printf "priority=%d weight=%d target=%s port=%d\n",
            $srv->priority, $srv->weight, $srv->target, $srv->port;
      }
      $loop->loop_stop;
   },
   on_error => sub { die "Cannot resolve - $_[-1]\n" },
);

$loop->loop_forever;
