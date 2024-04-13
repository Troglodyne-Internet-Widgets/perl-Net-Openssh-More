use strict;
use warnings;

use Test2::V0;
use Test2::Tools::Explain;
use Test2::Plugin::NoWarnings;
use Test::MockModule qw{strict};
use Carp::Always;

use FindBin;

use lib "$FindBin::Bin/../lib";

use Net::OpenSSH::More;

subtest "Live tests versus localhost" => sub {
    plan 'skip_all' => 'AUTHOR_TESTS not set in shell environment, skipping...' if !$ENV{'AUTHOR_TESTS'};
    my $obj = Net::OpenSSH::More->new( '127.0.0.1' );
    is( ref $obj, 'Net::OpenSSH::More', "Got right ref type for object upon instantiation (using IP)" );
    $obj = Net::OpenSSH::More->new( 'localhost' );
    is( ref $obj, 'Net::OpenSSH::More', "Got right ref type for object upon instantiation (using localhost)" );
};

# Mock based testing
subtest "Common tests using mocks" => sub {
    my $parent_mock = Test::MockModule->new('Net::OpenSSH');
    $parent_mock->redefine(
        'new'          => sub { bless {}, $_[0] },
        'check_master' => 1,
        'DESTROY'      => undef,
    );
    $Net::OpenSSH::More::disable_destructor = 1;
    my $obj = Net::OpenSSH::More->new( '127.0.0.1', retry_max => 1 );
    is( ref $obj, 'Net::OpenSSH::More', "Got right ref type for object upon instantiation" );
};

$Net::OpenSSH::More::disable_destructor = 0;
done_testing();
