use 5.014;
use strict;
use warnings;
use re '/aaxs';
no autovivification;

use Test2::V0;
use Test2::Tools::Subtest qw{subtest_streamed};
use Test2::Plugin::NoWarnings;
use Test::MockModule qw{strict};

use IO::Socket::INET;
use Capture::Tiny();
use Time::HiRes();

use Net::OpenSSH::More;

# Whether $got holds $wanted as written.  A regex would need every space of the
# message escaped.
sub contains {
    my ( $got, $wanted ) = @_;
    return index( $got, $wanted ) != -1;
}

# A connection that comes back with an error is taken by a `next` inside the
# retry loop, so anything sitting at the foot of that loop never runs for it.
# retry_interval was applied down there, which left every attempt running back
# to back against a host that was refusing them.
subtest_streamed "retry_interval is waited out between attempts" => sub {
    local %Net::OpenSSH::More::cache;
    local $Net::OpenSSH::More::disable_destructor = 1;

    # Each attempt insists on a real TCP connect before it will try to
    # authenticate, and the thing that does it is a lexical closure with no way
    # in. Give it something genuinely listening rather than resting on whether
    # this machine happens to run sshd.
    my $listener = IO::Socket::INET->new(
        'LocalAddr' => '127.0.0.1',
        'Listen'    => 5,
        'Proto'     => 'tcp',
    );
    ok( $listener, "Bound a listener for the reachability check" ) or return;

    my $attempts    = 0;
    my $parent_mock = Test::MockModule->new('Net::OpenSSH');
    $parent_mock->redefine(
        'new' => sub { $attempts++; return bless {}, $_[0]; },

        # Deliberately not a refused credential. Those are not retried at all
        # unless retry_on_auth_failure asks for it, and what is under test here
        # is the interval between attempts rather than which failures earn one.
        'error'        => sub { return $attempts <= 2 ? 'master would not come up' : 0; },
        'check_master' => sub { return $attempts > 2; },
        'DESTROY'      => sub { undef },
    );

    my $start = Time::HiRes::time();
    my $obj   = Net::OpenSSH::More->new(
        'host'           => '127.0.0.1',
        'port'           => $listener->sockport(),
        'password'       => 'mock',
        'retry_max'      => 5,
        'retry_interval' => 1,
        'no_cache'       => 1,
    );
    my $elapsed = int( Time::HiRes::time() - $start );

    is( ref $obj,  'Net::OpenSSH::More', "Retried a rejected connection rather than burning every attempt at once" );
    is( $attempts, 3,                    "Connected on the third attempt" );

    # Two retries at a second each.  Before the fix this came back instantly,
    # so the assertion that matters is that any waiting happened at all.
    ok( $elapsed >= 2, "Waited retry_interval between attempts (${elapsed}s across two retries)" );
};

# Every failed attempt used to be dropped without a word, and the final error
# said only how many there were.  A key that is refused and a host that resets
# the connection then look the same.
subtest_streamed "each failed attempt says why, and the last reason is in the error" => sub {
    local %Net::OpenSSH::More::cache;
    local $Net::OpenSSH::More::disable_destructor = 1;

    my $listener = IO::Socket::INET->new(
        'LocalAddr' => '127.0.0.1',
        'Listen'    => 5,
        'Proto'     => 'tcp',
    );
    ok( $listener, "Bound a listener for the reachability check" ) or return;

    my $attempts    = 0;
    my @errors      = ( 'Permission denied (publickey).', 'Permission denied (publickey).', "Connection reset\nby peer" );
    my $parent_mock = Test::MockModule->new('Net::OpenSSH');
    $parent_mock->redefine(
        'new'          => sub { $attempts++; return bless {}, $_[0]; },
        'error'        => sub { return $errors[ $attempts - 1 ]; },
        'check_master' => sub { return 0; },
        'DESTROY'      => sub { undef },
    );

    my $died;
    my $said = Capture::Tiny::capture_stdout(
        sub {
            $died = dies {
                Net::OpenSSH::More->new(
                    'host'                  => '127.0.0.1',
                    'port'                  => $listener->sockport(),
                    'password'              => 'mock',
                    'retry_max'             => 3,
                    'retry_interval'        => 0,
                    'retry_on_auth_failure' => 1,
                    'no_cache'              => 1,
                );
            };
        }
    );

    is( $attempts, 3, "Tried every attempt" );
    my @lines = grep { index( $_, 'failed:' ) != -1 } split( m/\n/, $said );
    is( scalar @lines, 2, "Said why twice, once for each reason, not once for each attempt" ) or diag $said;
    ok( contains( $lines[0], 'Attempt 1 of 3 to reach 127.0.0.1 failed: Permission denied (publickey).' ), "Said the first reason with its attempt" ) or diag $lines[0];
    ok( contains( $lines[1], 'Attempt 3 of 3 to reach 127.0.0.1 failed: Connection reset by peer' ),       "and the one that changed, on one line" )  or diag $lines[1];
    ok( contains( $died,     'after 3 attempts.  The last attempt said: Connection reset by peer.' ),      "The error says the last reason" )         or diag $died;
};

done_testing();

1;
