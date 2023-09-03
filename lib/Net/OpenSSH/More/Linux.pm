package Net::OpenSSH::More;

use strict;
use warnings;

use parent 'Net::OpenSSH::More';

use File::Slurper ();

=head1 ASSUMPTIONS

This module assumes that both the local and remote machine are some variant of GNU/Linux.

=head2 METHODS

=head3 B<get_primary_adapter>

Method to retrieve the primary device interface from /proc/net/route

Modified from /scripts/mainipcheck and t/lib/Test/GetPrimaryEth.pm

Optionally accepts a truthy arg to indicate whether you want this for the
local host instead of the remote host.

=cut

sub get_primary_adapter {
    my ( $self, $use_local ) = @_;
    my %interfaces;
    my $proc_route_path = do {
        if ($use_local) {
            File::Slurper::read_text('/proc/net/route');
        }
        else {
            $self->cmd( "cat /proc/net/route", 1 );
        }
    };
    foreach my $line ( split( /\n/, $proc_route_path ) ) {
        if ( $line =~ m/^(.+?)\s*0{8}\s.*?(\d+)\s+0{8}\s*(?:\d+\s*){3}$/ ) {
            my ( $interface, $metric ) = ( $1, $2 );
            push @{ $interfaces{$metric} }, $interface;
        }
    }

    my $lowest_metric = ( sort keys %interfaces )[0];
    my $interface     = $interfaces{$lowest_metric}[0];
    return $interface || 'eth0';
}

=head2 get_remote_ips

Returns HASH of the IPv4 & IPv6 SLAAC addresses of an optionally provided interface.
If no interfaces is provided, use the default interface.

CAVEATS: This uses the 'ip' tool, so if your system is too old for this, perhaps consider
writing your own getter for local IPs.

=cut

sub get_remote_ips {
    my ( $self, $interface ) = @_;
    return (
        'v4' => [ $get_addrs_for_iface->( $self, $interface, 'inet' ) ],
        'v6' => [ $get_addrs_for_iface->( $self, $interface, 'inet6' ) ],
    );
}

=head2 get_local_ips

Returns HASH of the IPv4 & IPv6 SLAAC addresses of an optionally provided interface.
If no interfaces is provided, use the default interface.
This one fetches it from the local machine and not the remote host, as sometimes
that can be useful (say in the context of a test where you need this info).
Same caveats that exist for get_remote_ips apply here.

=cut

sub get_local_ips {
    my ( $self, $interface ) = @_;
    return (
        'v4' => [ $get_addrs_for_iface->( $self, $interface, 'inet',  1 ) ],
        'v6' => [ $get_addrs_for_iface->( $self, $interface, 'inet6', 1 ) ],
    );
}

###################
# PRIVATE METHODS #
###################

my $get_addrs_for_iface = sub {
    my ( $self, $interface, $proto, $use_local ) = @_;
    $interface ||= $self->get_primary_adapter($use_local);
    $self->diag("Attempting to get $proto address for interface $interface");
    my $regex = $proto eq 'inet' ? '[\d\.]+' : '[\da-f:]+';    # Close enough

    my $cmd     = "ip -f $proto addr show $interface scope global dynamic";
    my $ip      = $use_local ? `$cmd` : $self->cmd($cmd);
    my @matches = $ip =~ m/$proto\s+($regex)/g;
    return @matches;
};

#######################
# END PRIVATE METHODS #
#######################

1;
