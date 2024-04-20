use strict;
use warnings;

use Test2::V0;
use Test2::Tools::Explain;
use Test2::Tools::Subtest qw{subtest_streamed};
use Test2::Plugin::NoWarnings;
use Test::MockModule qw{strict};

use FindBin;

use lib "$FindBin::Bin/../lib";

use Net::OpenSSH::More::Linux;

subtest_streamed "Live tests versus localhost" => sub {
    plan 'skip_all' => 'AUTHOR_TESTS not set in shell environment, skipping...' if !$ENV{'AUTHOR_TESTS'};
    local %Net::OpenSSH::More::cache;
    my $obj = Net::OpenSSH::More::Linux->new(
        'host' => 'localhost', 'use_persistent_shell' => 0, 'retry_max' => 1,
    );
    is( ref $obj, 'Net::OpenSSH::More::Linux', "Got right ref type for object upon instantiation (using localhost)" );
    my $adapter = $obj->get_primary_adapter(1);
    ok( $adapter, "Got something back as the primary adapter (use_local)" );
    is( $obj->get_primary_adapter(), $adapter, "Got expected adapter (remote)" );
};

# Mock based testing
subtest_streamed "Common tests using mocks" => sub {
    local %Net::OpenSSH::More::cache;
    my $parent_mock = Test::MockModule->new('Net::OpenSSH::More');
    $parent_mock->redefine(
        'new'          => sub { bless {}, $_[0] },
        'check_master' => 1,
        'DESTROY'      => undef,
    );
    my $obj = Net::OpenSSH::More::Linux->new( 'host' => 'localhost', retry_max => 1 );
    is( ref $obj,           'Net::OpenSSH::More::Linux', "Got right ref type for object upon instantiation" );
};

done_testing();
