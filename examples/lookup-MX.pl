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
