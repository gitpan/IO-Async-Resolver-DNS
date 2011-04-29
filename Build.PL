use strict;
use warnings;

use Module::Build;

my $build = Module::Build->new(
   module_name => 'IO::Async::Resolver::DNS',
   configure_requires => {
      'Module::Build' => 0,
   },
   requires => {
      'IO::Async::Resolver' => 0,
      'IO::Async::Loop' => '0.34', # ->resolver method
      'List::UtilsBy' => '0.07',
      'Net::DNS' => 0,
   },
   recommended => {
      'Net::LibResolv' => '0.03',
   },
   build_requires => {
      'Test::More' => 0,
   },
   license => 'perl',
   create_makefile_pl => 'traditional',
   create_license => 1,
   create_readme  => 1,
);

$build->create_build_script;
