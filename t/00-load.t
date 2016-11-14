#!perl -T
use 5.006;
use strict;
use warnings;
use Test::More;

plan tests => 1;

BEGIN {
    use_ok( 'App::Waf' ) || print "Bail out!\n";
}

diag( "Testing App::Waf $App::Waf::VERSION, Perl $], $^X" );
