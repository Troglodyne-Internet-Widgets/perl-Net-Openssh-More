use 5.014;
use strict;
use warnings;
use re '/aaxs';

use Test2::V0;
use Test2::Tools::Subtest qw{subtest_streamed};
use Test2::Plugin::NoWarnings;
use Test::MockModule qw{strict};

use Net::OpenSSH::More::Linux;

subtest_streamed "Live tests versus localhost" => sub {
    plan 'skip_all' => 'AUTHOR_TESTS not set in shell environment, skipping...' if !$ENV{'AUTHOR_TESTS'};
    local %Net::OpenSSH::More::cache;
    my $obj = Net::OpenSSH::More::Linux->new(
        'host' => '127.0.0.1', 'output_prefix' => '# ', 'retry_max' => 1,
    );
    is( ref $obj, 'Net::OpenSSH::More::Linux', "Got right ref type for object upon instantiation (using localhost)" );
    my $adapter = $obj->get_primary_adapter(1);
    ok( $adapter, "Got something back as the primary adapter (use_local)" );
    is( $obj->get_primary_adapter(), $adapter, "Got expected adapter (remote)" );

    # Test backup/restore, first with existing
    $obj->cmd(qw{touch /tmp/howdy});
    $obj->backup_files('/tmp/howdy');
    $obj->cmd(qw{rm -f /tmp/howdy});
    $obj->restore_files();
    ok( $obj->sftp->test_e('/tmp/howdy'), "Created /tmp/howdy file restored via backup/restore methods" );
    $obj->cmd(qw{rm -f /tmp/howdy});

    # "Backup" non-existing file
    $obj->backup_files('/tmp/yeehaw');
    $obj->cmd(qw{touch /tmp/yeehaw});
    ok( $obj->sftp->test_e('/tmp/yeehaw'), "Created /tmp/yeehaw touch file for testing backup/restore" );
    $obj->DESTROY();
    $obj = Net::OpenSSH::More::Linux->new(
        'host' => 'localhost', 'use_persistent_shell' => 0, 'retry_max' => 1,
    );
    ok( !$obj->sftp->test_e('/tmp/yeehaw'), "File no longer exists after restored to original state via destructor" );
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
    is( ref $obj, 'Net::OpenSSH::More::Linux', "Got right ref type for object upon instantiation" );
};

subtest_streamed "get_remote_ips" => sub {
    my %ip_output = (
        'inet' => join(
            "\n",
            '2: fake0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000',
            '    inet 192.0.2.10/24 brd 192.0.2.255 scope global dynamic fake0',
            '       valid_lft 86000sec preferred_lft 86000sec',
            '    inet 192.0.2.11/24 brd 192.0.2.255 scope global secondary dynamic fake0',
            '       valid_lft 86000sec preferred_lft 86000sec',
        ),
        'inet6' => join(
            "\n",
            '2: fake0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP qlen 1000',
            '    inet6 2001:db8::10/64 scope global dynamic mngtmpaddr',
            '       valid_lft 86000sec preferred_lft 14000sec',
        ),
    );

    my @calls;
    my $parent_mock = Test::MockModule->new('Net::OpenSSH::More');
    $parent_mock->redefine(
        'new'  => sub { bless {}, $_[0] },
        'diag' => undef,
        'cmd'  => sub {
            my ( $self, @cmd ) = @_;
            push @calls, \@cmd;
            my ($proto) = "@cmd" =~ m/-f \s+ (\S+)/;
            return ( $ip_output{$proto}, '', 0 );
        },
    );
    my $obj = Net::OpenSSH::More::Linux->new( 'host' => 'localhost', retry_max => 1 );

    my %ips = $obj->get_remote_ips('fake0');
    is(
        \%ips,
        { 'v4' => [ '192.0.2.10', '192.0.2.11' ], 'v6' => ['2001:db8::10'] },
        "get_remote_ips parses the addresses out of the output of cmd, not its exit code",
    );
    is(
        \@calls,
        [
            [ qw{ip -f inet addr show fake0},  qw{scope global dynamic} ],
            [ qw{ip -f inet6 addr show fake0}, qw{scope global dynamic} ],
        ],
        "cmd gets the command as a list, so that it escapes the interface name",
    );
};

done_testing();

1;
