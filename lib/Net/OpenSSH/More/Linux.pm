package Net::OpenSSH::More::Linux;

#ABSTRACT: Useful subcommands for linux machines

use strict;
use warnings;

use parent 'Net::OpenSSH::More';

use File::Slurper ();

=head1 NAME

Net::OpenSSH::More::Linux

=head1 DESCRIPTION

This module contains useful methods to complement the parent's when in use on
all linux environments.

=head1 ASSUMPTIONS

This module assumes that both the local and remote machine are some variant of GNU/Linux.
Don't use this if that's not the case.

=cut

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

=head2 METHODS

=head3 B<get_primary_adapter>

So, on linux, there's no "primary" adapter, just the "correct" adapter
for whatever given route. As such, what's the best way to determine
this?

This is a method to guess the "best" device interface from /proc/net/route.
How does it determine this? By the "metric" stat -- the lower the better,
as the lower the cost, the higher the preference.
If you have set the metric improperly, you'll get bad results, but that's
nothing to do with the code here.

Optionally accepts a truthy arg to indicate whether you want this for the
local host instead of the remote host.

=cut

sub get_primary_adapter {
    my ( $self, $use_local ) = @_;
    my %interfaces;
    my $proc_route_path = $use_local ? File::Slurper::read_text('/proc/net/route') : $self->sftp->get_content('/proc/net/route');
    foreach my $line ( split( /\n/, $proc_route_path ) ) {

        #                                        Iface   Destination   Gateway       Flags RefCt Use   Metric  Mask          MTU   Wndow IRTT
        my ( $interface, $metric ) = $line =~ m/^(.+?)\s+[0-9A-F]{8}\s+[0-9A-F]{8}\s+\d+\s+\d+\s+\d+\s+(\d+)\s+[0-9A-F]{8}\s+\d+\s+\d+\s+\d+\s*$/;
        push @{ $interfaces{$metric} }, $interface if ( length $interface && defined $metric );
    }
    my $lowest_metric = ( sort keys %interfaces )[0];
    my $interface     = $interfaces{$lowest_metric}->[0] if defined $lowest_metric && $interfaces{$lowest_metric};
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

=head2 copy

Effectively the same thing as `cp $SOURCE $DEST` on the remote server.

=cut

sub copy {
    my ( $self, $SOURCE, $DEST ) = @_;
    return $self->cmd( qw{cp -a}, $SOURCE, $DEST );
}

1;
