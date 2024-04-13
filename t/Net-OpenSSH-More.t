use strict;
use warnings;

use Test2::V0;
use Test2::Tools::Explain;
use Test2::Tools::Subtest qw{subtest_streamed};
use Test2::Plugin::NoWarnings;
use Test::MockModule qw{strict};
use Carp::Always;

use FindBin;

use lib "$FindBin::Bin/../lib";

use Net::OpenSSH::More;

subtest_streamed "Live tests versus localhost" => sub {
    plan 'skip_all' => 'AUTHOR_TESTS not set in shell environment, skipping...' if !$ENV{'AUTHOR_TESTS'};
    local %Net::OpenSSH::More::cache;
    my $obj = Net::OpenSSH::More->new( 'host' => '127.0.0.1' );
    is( ref $obj, 'Net::OpenSSH::More', "Got right ref type for object upon instantiation (using IP)" );
    undef $obj;
    %Net::OpenSSH::More::cache = ();
    $obj = Net::OpenSSH::More->new( 'host' => 'localhost', 'output_prefix' => '# ' );
    is( ref $obj, 'Net::OpenSSH::More', "Got right ref type for object upon instantiation (using localhost)" );
    my @cmd_ret = $obj->cmd( { 'no_persist' => 1 }, 'echo "whee"' );
    is( \@cmd_ret, [ "whee", '', 0 ], "Got expected return (non-persistent shell)" );
    @cmd_ret = $obj->cmd( '/bin/true' );
    is( \@cmd_ret, [ '', '', 0 ], "Got expected return (persistent shell)" );
};

# Mock based testing
subtest_streamed "Common tests using mocks" => sub {
    local %Net::OpenSSH::More::cache;
    my $parent_mock = Test::MockModule->new('Net::OpenSSH');
    $parent_mock->redefine(
        'new'          => sub { bless {}, $_[0] },
        'check_master' => 1,
    );
    {
        # MockModule can't actually redefine destructors properly due to the mock also going out of scope.
        no warnings qw{redefine};
        *Net::OpenSSH::DESTROY = sub { undef };
    }
    my $obj = Net::OpenSSH::More->new( 'host' => '127.0.0.1', retry_max => 1, 'output_prefix' => '# ' );
    is( ref $obj, 'Net::OpenSSH::More', "Got right ref type for object upon instantiation" );
    is( $obj->diag("Whee"), undef, "You should see whee before this subtest" );
};

done_testing();
