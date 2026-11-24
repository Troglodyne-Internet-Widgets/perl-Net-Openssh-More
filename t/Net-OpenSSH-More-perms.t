use 5.014;
use strict;
use warnings;
use re '/aaxs';
no autovivification;

use Test2::V0;
use Test2::Tools::Explain;
use Test2::Tools::Subtest qw{subtest_streamed};
use Test2::Plugin::NoWarnings;
use Test::MockModule qw{strict};

use File::Temp ();
use IO::Socket::INET;

use Net::OpenSSH::More;

# The rule is the one ssh applies: ~/.ssh and ~/.ssh/config must not be
# writable by the group or by others, and a private key must give them no
# access at all.  Any mode that ssh accepts is accepted here too.

# Nothing accepts these, so the backlog has to outlast every attempt below.
my $listener = IO::Socket::INET->new(
    'LocalAddr' => '127.0.0.1',
    'Listen'    => 50,
    'Proto'     => 'tcp',
);

sub make_file {
    my ( $path, $mode ) = @_;
    open( my $fh, '>', $path ) or die "Cannot write $path: $!";
    close($fh)                 or die "Cannot close $path: $!";
    chmod( $mode, $path )      or die "Cannot chmod $path: $!";
    return $path;
}

# A home of its own, with a .ssh of $ssh_mode, and a config of $config_mode
# when that is given.
sub make_home {
    my ( $ssh_mode, $config_mode ) = @_;
    my $home = File::Temp::tempdir( 'CLEANUP' => 1 );
    mkdir("$home/.ssh")              or die "Cannot make $home/.ssh: $!";
    chmod( $ssh_mode, "$home/.ssh" ) or die "Cannot chmod $home/.ssh: $!";
    make_file( "$home/.ssh/config", $config_mode ) if defined $config_mode;
    return $home;
}

# The error for a path that ends in $file, up to and including its $mode.
sub too_open {
    my ( $file, $mode ) = @_;
    my $path = qr/"[^"]*\Q$file\E"/;
    my $says = qr/are\ too\ open:\ mode\ is\ \Q$mode\E\b/;
    return qr/Permissions\ on\ $path\ $says/;
}

# Returns the object, or the error that new() died with.
sub connect_with {
    my (%opts) = @_;
    local %Net::OpenSSH::More::cache;
    local $Net::OpenSSH::More::disable_destructor = 1;

    my $parent_mock = Test::MockModule->new('Net::OpenSSH');
    $parent_mock->redefine(
        'new'          => sub { return bless {}, $_[0]; },
        'error'        => sub { return 0; },
        'check_master' => sub { return 1; },
        'DESTROY'      => sub { undef },
    );

    my $obj;
    my $died = dies {
        $obj = Net::OpenSSH::More->new(
            'host'      => '127.0.0.1',
            'port'      => $listener->sockport(),
            'retry_max' => 1,
            'no_cache'  => 1,
            %opts,
        );
    };
    return ( $obj, $died );
}

subtest_streamed "a ~/.ssh that the group or others may not write is accepted" => sub {
    plan 'skip_all' => 'could not bind a listener' if !$listener;
    foreach my $mode (qw{0700 0710 0750 0755}) {
        my ( $obj, $died ) = connect_with( 'home' => make_home( oct($mode) ), 'password' => 'mock' );
        is( ref $obj, 'Net::OpenSSH::More', "~/.ssh of $mode is accepted" ) or diag explain $died;
    }
};

subtest_streamed "a ~/.ssh that the group or others may write is refused" => sub {
    plan 'skip_all' => 'could not bind a listener' if !$listener;
    foreach my $mode (qw{0770 0757 0777}) {
        my ( $obj, $died ) = connect_with( 'home' => make_home( oct($mode) ), 'password' => 'mock' );
        ok( !$obj, "~/.ssh of $mode is refused" );
        like( $died, too_open( q{/.ssh}, $mode ), "and the error names the directory and its mode" ) or diag explain $died;
    }
    my ( undef, $died ) = connect_with( 'home' => make_home( oct('0770') ), 'password' => 'mock' );
    like( $died, qr/\b0020\b.*\bnot\ allowed\b/, "and says which bits are not allowed" ) or diag explain $died;
};

subtest_streamed "~/.ssh/config may be read by others but not written" => sub {
    plan 'skip_all' => 'could not bind a listener' if !$listener;
    foreach my $mode (qw{0600 0644}) {
        my ( $obj, $died ) = connect_with( 'home' => make_home( oct('0700'), oct($mode) ), 'password' => 'mock' );
        is( ref $obj, 'Net::OpenSSH::More', "a config of $mode is accepted" ) or diag explain $died;
    }
    my ( $obj, $died ) = connect_with( 'home' => make_home( oct('0700'), oct('0664') ), 'password' => 'mock' );
    ok( !$obj, "a config of 0664 is refused" );
    like( $died, too_open( q{/.ssh/config}, q{0664} ), "and the error names the config and its mode" ) or diag explain $died;
};

subtest_streamed "a private key must give the group and others no access" => sub {
    plan 'skip_all' => 'could not bind a listener' if !$listener;
    foreach my $mode (qw{0600 0400}) {
        my $home = make_home( oct('0700') );
        my ( $obj, $died ) = connect_with( 'home' => $home, 'key_path' => make_file( "$home/.ssh/id_test", oct($mode) ) );
        is( ref $obj, 'Net::OpenSSH::More', "a key of $mode is accepted" ) or diag explain $died;
    }
    foreach my $mode (qw{0640 0604}) {
        my $home = make_home( oct('0700') );
        my ( $obj, $died ) = connect_with( 'home' => $home, 'key_path' => make_file( "$home/.ssh/id_test", oct($mode) ) );
        ok( !$obj, "a key of $mode is refused" );
        like( $died, too_open( q{/id_test}, $mode ), "and the error names the key and its mode" ) or diag explain $died;
    }
};

done_testing();

1;
