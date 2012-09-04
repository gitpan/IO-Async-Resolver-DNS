use strict;
use warnings;

use Module::Build;

my $build = Module::Build->new(
   module_name => 'IO::Async::Resolver::DNS',
   requires => {
      'IO::Async::Resolver' => 0,
      'IO::Async::Loop' => '0.47', # ->resolver method, ->run
      'List::UtilsBy' => '0.07',
      'Net::DNS' => 0,
   },
   recommended => {
      'Net::LibResolv' => '0.03',
   },
   build_requires => {
      'Test::More' => 0,
   },
   auto_configure_requires => 0, # Don't add M::B to configure_requires
   license => 'perl',
   create_makefile_pl => 'traditional',
   create_license => 1,
   create_readme  => 1,
);

$build->create_build_script;
