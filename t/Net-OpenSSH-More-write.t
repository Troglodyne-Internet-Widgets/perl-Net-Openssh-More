use 5.014;
use strict;
use warnings;
use re '/aaxs';
no autovivification;

use Test2::V0;
use Test2::Tools::Subtest qw{subtest_streamed};
use Test2::Plugin::NoWarnings;
use Test::MockModule qw{strict};

use Net::OpenSSH::More;

# Whether $got holds $wanted as written.  A regex would need every space of the
# message escaped.
sub contains {
    my ( $got, $wanted ) = @_;
    return index( $got, $wanted ) != -1;
}

# Run write() against an object with no connection behind it.  The SFTP
# object and cmd() are faked, so nothing leaves this process.  Returns what
# write() returned, the warnings it gave, and each command that it ran.
sub run_write {
    my (%args) = @_;

    local $Net::OpenSSH::More::disable_destructor = 1;

    my $sftp_mock = Test::MockModule->new('Net::SFTP::Foreign');
    $sftp_mock->redefine(
        'put_content' => sub { return 1; },

        # write() does not call this.  It is here so that a write() that goes
        # back to the SFTP chown fails on what it warns, not on a dead object.
        'chown'   => sub { return $args{'chown_ok'} ? 1 : undef; },
        'error'   => sub { return 'no such file'; },
        'DESTROY' => sub { return; },
    );

    my @commands;
    my $ssh_mock = Test::MockModule->new('Net::OpenSSH::More');
    $ssh_mock->redefine(
        'sftp' => sub { return bless {}, 'Net::SFTP::Foreign'; },
        'cmd'  => sub {
            my ( $self, @command ) = @_;
            push @commands, \@command;
            return $args{'chown_ok'} ? ( '', '', 0 ) : ( 'chown: invalid user', '', 1 );
        },
    );

    my $ssh = bless { '_opts' => { 'user' => 'deploy' } }, 'Net::OpenSSH::More';

    my @warnings;
    local $SIG{'__WARN__'} = sub { push @warnings, $_[0]; };
    my $ret = $ssh->write( '/bogus/f', 'content', undef, @{ $args{'ids'} } );

    return ( $ret, \@warnings, \@commands );
}

# The chown in write() warned when it worked and said nothing when it failed,
# because the test of its result was the wrong way round.
subtest_streamed "write warns when the chown fails, and only then" => sub {
    my ( $ret, $warnings ) = run_write( 'ids' => [ 'deploy', 'staff' ], 'chown_ok' => 0 );
    ok( !$ret, "write returns false when the chown fails" );
    is( scalar @$warnings, 1, "One warning when the chown fails" );
    ok( contains( $warnings->[0] // '', "Couldn't chown /bogus/f" ), "The warning names the file" );
    ok( contains( $warnings->[0] // '', 'chown: invalid user' ),     "The warning says why the chown failed" );

    ( $ret, $warnings ) = run_write( 'ids' => [ 'deploy', 'staff' ], 'chown_ok' => 1 );
    ok( $ret, "write returns true when the chown works" );
    is( $warnings, [], "No warning when the chown works" );
};

# Net::SFTP::Foreign's chown packs its arguments as numbers, so a name such as
# 'deploy' went over the wire as 0, and the file went to root.  The POD of
# write() says that owner and group are names, so the remote chown(1) must get
# them as they were given.
subtest_streamed "write gives the owner and group to the remote chown as names" => sub {
    my ( undef, undef, $commands ) = run_write( 'ids' => [ 'deploy', 'staff' ], 'chown_ok' => 1 );
    is( $commands, [ [ { 'use_persistent_shell' => 0 }, qw{chown -- deploy:staff /bogus/f} ] ], "chown ran with owner:group as given" );

    ( undef, undef, $commands ) = run_write( 'ids' => [ undef, 'staff' ], 'chown_ok' => 1 );
    is( $commands->[0][3], 'deploy:staff', "The owner defaults to the user of the connection" );

    ( undef, undef, $commands ) = run_write( 'ids' => ['deploy'], 'chown_ok' => 1 );
    is( $commands->[0][3], 'deploy:deploy', "The group defaults to the owner" );

    ( undef, undef, $commands ) = run_write( 'ids' => [], 'chown_ok' => 1 );
    is( $commands, [], "No chown when neither owner nor group is given" );
};

done_testing();

1;
