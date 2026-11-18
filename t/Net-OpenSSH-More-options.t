use strict;
use warnings;

use Test2::V0;
use Test2::Tools::Subtest qw{subtest_streamed};
use Test2::Plugin::NoWarnings;
use Test::MockModule qw{strict};

use IO::Socket::INET;

use FindBin;

use lib "$FindBin::Bin/../lib";

use Net::OpenSSH::More;

# Net::OpenSSH::More makes the control directory in TMPDIR and turns off
# strict_mode, because TMPDIR can have a parent that the group may write.
# Net::OpenSSH then refuses the directory unless strict_mode reaches it.
subtest_streamed "an option of 0 reaches Net::OpenSSH" => sub {
    local %Net::OpenSSH::More::cache;
    local $Net::OpenSSH::More::disable_destructor = 1;

    # The reachability check makes a real TCP connection first.
    my $listener = IO::Socket::INET->new(
        'LocalAddr' => '127.0.0.1',
        'Listen'    => 5,
        'Proto'     => 'tcp',
    );
    ok( $listener, "Bound a listener for the reachability check" ) or return;

    my %got;
    my $parent_mock = Test::MockModule->new('Net::OpenSSH');
    $parent_mock->redefine(
        'new'          => sub { my ( $class, %args ) = @_; %got = %args; return bless {}, $class; },
        'error'        => sub { return 0; },
        'check_master' => sub { return 1; },
    );
    {
        no warnings qw{redefine};
        *Net::OpenSSH::DESTROY = sub { undef };
    }

    my $obj = Net::OpenSSH::More->new(
        'host'       => '127.0.0.1',
        'port'       => $listener->sockport(),
        'password'   => 'mock',
        'batch_mode' => 0,
        'timeout'    => 0,
        'retry_max'  => 1,
        'no_cache'   => 1,
    );

    is( ref $obj, 'Net::OpenSSH::More', "Connected" );
    is( $got{'strict_mode'}, 0, "strict_mode => 0 reaches Net::OpenSSH, so a control directory under a parent that the group may write is accepted" );
    is( [ @got{qw{batch_mode timeout}} ], [ 0, 0 ], "and so does an option of 0 that the caller passed" );
    ok( !exists $got{'gateway'}, "but an option that nobody set is not passed, so the default of Net::OpenSSH applies" );
};

done_testing();
