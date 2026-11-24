use 5.014;
use strict;
use warnings;
use re '/aaxs';

use Test2::V0;
use Test2::Tools::Explain;
use Test2::Tools::Subtest qw{subtest_streamed};
use Test2::Plugin::NoWarnings;
use Test::MockModule qw{strict};

use File::Temp ();
use Net::DNS;
use Net::IP;

use Net::OpenSSH::More;

# A home of its own, so that the ~/.ssh of whoever runs this is never read.
my $home = File::Temp::tempdir( 'CLEANUP' => 1 );

# A resolver that answers from a table instead of the network. A name and type
# missing from the table gets what Net::DNS::Resolver::search gives for a name
# with no such record: nothing.
sub resolver_mock {
    my (%answers) = @_;
    my $mock = Test::MockModule->new('Net::DNS::Resolver');
    $mock->redefine(
        'search' => sub {
            my ( $self, $name, $type ) = @_;
            my $records = $answers{"$name $type"} or return;
            my $packet  = Net::DNS::Packet->new( $name, $type );
            my @answer;
            foreach my $record (@$records) {
                push @answer, Net::DNS::RR->new($record);
            }
            $packet->push( 'answer' => @answer );
            return $packet;
        },
    );
    return $mock;
}

# Resolution comes before anything is asked of ssh, so the attempt dies there
# and Net::OpenSSH is never reached.
sub connect_to {
    my ($host) = @_;
    local %Net::OpenSSH::More::cache;
    local $Net::OpenSSH::More::disable_destructor = 1;
    return dies {
        Net::OpenSSH::More->new(
            'host'      => $host,
            'home'      => $home,
            'password'  => 'mock',
            'retry_max' => 1,
            'no_cache'  => 1,
        );
    };
}

subtest_streamed "a name with no record says that it does not resolve" => sub {
    my $mock = resolver_mock();
    my $died = connect_to('nothing.test.test');
    like( $died, qr/nothing\.test\.test\ does\ not\ resolve/, "Named the host and said it does not resolve" ) or diag explain $died;
    like( $died, qr/\bA\b.*\bAAAA\b/,                         "Said which record types were asked for" );
    $mock->unmock_all();
};

subtest_streamed "a name whose A answer is only a CNAME to an IPv6-only name falls through to AAAA" => sub {
    my $mock = resolver_mock(
        'alias.test.test A'    => ['alias.test.test. 300 IN CNAME v6only.test.test.'],
        'alias.test.test AAAA' => [ 'alias.test.test. 300 IN CNAME v6only.test.test.', 'v6only.test.test. 300 IN AAAA 2001:db8::1' ],
    );

    # The knock is the first thing after the lookup. Stop there, rather than
    # wait out its timeout against an address that nothing answers.
    my $knock = Test::MockModule->new('IO::Socket::INET6');
    my $peer;
    $knock->redefine( 'new' => sub { my ( $class, %args ) = @_; $peer = $args{'PeerAddr'}; die "knocked\n"; } );
    my $died = connect_to('alias.test.test');

    is( $died,                                 "knocked\n",   "Got as far as the knock, rather than giving up on the name" ) or diag explain $died;
    is( $peer && Net::IP->new($peer)->short(), '2001:db8::1', "Knocked on the AAAA address" );
    $knock->unmock_all();
    $mock->unmock_all();
};

done_testing();

1;
