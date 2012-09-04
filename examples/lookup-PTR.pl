#!/usr/bin/perl

use strict;
use warnings;

use IO::Async::Loop;
use IO::Async::Resolver::DNS;

my $loop = IO::Async::Loop->new;
my $resolver = $loop->resolver;

$resolver->res_query(
   dname => $ARGV[0],
   type  => "PTR",
   on_resolved => sub {
      my ( $pkt, @names ) = @_;

      foreach my $name ( @names ) {
         print "$name\n";
      }
      $loop->stop;
   },
   on_error => sub { die "Cannot resolve - $_[-1]" },
);

$loop->run;
