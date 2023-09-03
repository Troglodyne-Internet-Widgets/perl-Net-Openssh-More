use strict;
use warnings;

use Test2::V0;
use Test2::Tools::Explain;
use Test2::Plugin::NoWarnings;
use Test::MockModule qw{strict};

use FindBin;

use lib "$FindBin::Bin/../lib";

use Net::OpenSSH::More;

# Mock based testing
subtest "Common tests using mocks" => sub {
    my $parent_mock = Test::MockModule->new('Net::OpenSSH');
    $parent_mock->redefine(
        'new'     => sub { bless {}, $_[0] },
        'DESTROY' => undef,
    );
    my $obj = Net::OpenSSH::More->new( 'localhost' );
    is( ref $obj, 'Net::OpenSSH::More', "Got right ref type for object upon instantiation" );
};

subtest "Live tests versus localhost" => sub {
    plan 'skip_all' => 'AUTHOR_TESTS not set in shell environment, skipping...' if !$ENV{'AUTHOR_TESTS'};
    pass("Unimplemented for now");
};

done_testing();
