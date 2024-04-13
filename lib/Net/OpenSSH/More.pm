package Net::OpenSSH::More;

use strict;
use warnings;

use parent 'Net::OpenSSH';

use Data::UUID         ();
use File::HomeDir      ();
use File::Temp         ();
use Fcntl              ();
use IO::Socket::INET   ();
use IO::Socket::INET6  ();
use List::Util qw{first};
use Net::DNS::Resolver ();
use Net::IP            ();
use Time::HiRes        ();

=head1 NAME

Net::OpenSSH::More

=head1 DESCRIPTION

Submodule of Net::OpenSSH that contains many methods that were
otherwise left "as an exercise to the reader" in the parent module.
Highlights:
* Persistent terminal via expect for very fast execution, less forking.
* Usage of File::Temp and auto-cleanup to prevent lingering ctl_path cruft.
* Ability to manipulate incoming text while streaming the output of commands.
* Run perl subroutine refs you write locally but execute remotely.
* Many shortcut methods for common system administration tasks
* Registration method for commands to run upon DESTROY/before disconnect.
* Automatic reconnection ability upon connection loss
* Easy SFTP accessor for file uploads/downloads.

=head1 SYNOPSIS

    use Net::OpenSSH::More;
    my $ssh = Net::OpenSSH::More->new(
		'host'     => 'some.host.test',
		'port'     => 69420,
        'user'     => 'azurediamond',
        'password' => 'hunter2',
    );
    ...

=head1 SEE ALSO

Net::OpenSSH
Net::OpenSSH::More::Linux

=head1 METHODS

=head2 new

Instantiate the object, establish the connection. Note here that I'm not allowing
a connection string like the parent module, and instead exploding these out into
opts to pass to the constructor. This is because we want to index certain things
under the hood by user, etc. and I *do not* want to use a regexp to pick out
your username, host, port, etc. when this problem is solved much more easily
by forcing that separation on the caller's end.

ACCEPTS:
* %opts - <HASH> A hash of key value pairs corresponding to the what you would normally pass in to Net::OpenSSH,
  along with the following keys:
  * use_persistent_shell - Whether or not to setup Expect to watch a persistent TTY. Less stable, but faster.
  * no_agent - Pass in a truthy value to disable the SSH agent. By default the agent is enabled.
  * die_on_drop - If, for some reason, the connection drops, just die instead of attempting reconnection.
  * output_prefix - If given, is what we will tack onto the beginning of any output via diag method.
    useful for streaming output to say, a TAP consumer (test) via passing in '# ' as prefix.
  * debug - Pass in a truthy value to enable certain diag statements I've added in the module and pass -v to ssh.
  * home - STRING corresponding to an absolute path to something that "looks like" a homedir. Defaults to the user's homedir.
    useful in cases where you say, want to load SSH keys from a different path without changing assumptions about where
    keys exist in a homedir on your average OpenSSH using system.
  * no_cache - Pass in a truthy value to disable caching the connection and object, indexed by host string.
    useful if for some reason you need many separate connections to test something. Make sure your MAX_SESSIONS is set sanely
    in sshd_config if you use this extensively.
  * retry_interval - In the case that sshd is not up on the remote host, how long to wait while before reattempting connection.
    defaults to 6s. We retry $RETRY_MAX times, so this means waiting a little over a minute for SSH to come up by default.
	If your situation requires longer intervals, pass in something longer.
  * retry_max - Number of times to retry when a connection fails. Defaults to 10.

RETURNS a Net::OpenSSH::More object.

=head3 A note on Authentication order

We attempt to authenticate using the following details, and in this order:
1) Use supplied key_path.
2) Use supplied password.
3) Use existing SSH agent (SSH_AUTH_SOCK environment variable)
4) Use keys that may exist in $HOME/.ssh - id_rsa, id_dsa and id_ecdsa (in that order).

If all methods therein fail, we will die, as nothing will likely work at that point.
It is important to be aware of this if your remove host has something like fail2ban or cPHulkd
enabled which monitors and blocks access based on failed login attempts. If this is you,
ensure that you have not configured things in a way as to accidentally lock yourself out
of the remote host just because you fatfingered a connection detail in the constructor.

=cut

my %defaults = (
    'user'                    => $ENV{'USER'} || getpwuid($>),
    'port'                    => 22,
    'use_persistent_shell'    => 0,
    'output_prefix'           => '',
    'home'                    => File::HomeDir->my_home,
	'retry_interval'          => 6,
	'retry_max'               => 10,
);

my %cache;
our $disable_destructor = 0;

###################
# PRIVATE METHODS #
###################

my $die_no_trace = sub {
    my ( $full_msg, $summary ) = @_;
    $summary ||= 'FATAL';
    my $carp = $INC{'Carp/Always.pm'} ? '' : ' - Use Carp::Always for full trace.';
    die "[$summary] ${full_msg}${carp}";
};

my $check_local_perms = sub {
    my ( $path, $expected_mode, $is_dir ) = @_;
    $is_dir //= 0;
    my @stat = stat($path);
    $die_no_trace->(qq{"$path" must be a directory that exists}) unless !$is_dir ^ -d _;
    $die_no_trace->(qq{"$path" must be a file that exists})      unless $is_dir ^ -f _;
    $die_no_trace->(qq{"$path" could not be read})               unless -r _;

    my $actual_mode = $stat[2] & 07777;
    $die_no_trace->(sprintf(qq{Permissions on "$path" are not correct: got=0%o, expected=0%o}, $actual_mode, $expected_mode)) unless $expected_mode eq $actual_mode;
    return 1;
};

my $resolve_login_method = sub {
    my ( $opts ) = @_;

    my $chosen = first { $opts->{$_} } qw{key_path password};
    $chosen //= '';
    undef $chosen if $chosen eq 'key_path' && !$check_local_perms->( $opts->{'key_path'}, 0600 );
    return $chosen if $chosen;
    return 'SSH_AUTH_SOCK' if $ENV{'SSH_AUTH_SOCK'};
    my $fallback_path = "$opts->{'home'}/.ssh/id";
    ( $opts->{'key_path'} ) = map { "${fallback_path}_$_" } ( first { -s "${fallback_path}_$_" } qw{dsa rsa ecdsa} );

    $die_no_trace->('No key_path or password specified and no active SSH agent; cannot connect') if !$opts->{'key_path'};
    $check_local_perms->( $opts->{'key_path'}, 0600 ) if $opts->{'key_path'};

    return $opts->{'key_path'};
};

my $get_dns_record_from_hostname = sub {
    my ( $hostname, $record_type ) = @_;
    $record_type ||= 'A';

    my $reply = Net::DNS::Resolver->new()->search( $hostname, $record_type );
	return unless $reply;
	return { map { $_->type() => $_->address() } grep { $_->type eq $record_type } ( $reply->answer() ) };
};

# Knock on the server till it responds, or doesn't. Try both ipv4 and ipv6.
my $ping = sub {
    my ( $opts ) = @_;

	my $timeout = 30;
    my ( $host_info, $ip, $r_type );
    if( my $ip_obj = Net::IP->new($opts->{'host'}) ) {
        $r_type = $ip_obj->ip_is_ipv4 ? 'A' : 'AAAA';
        $ip = $opts->{'host'};
    }
    else {
	    my $host_info = first { $get_dns_record_from_hostname->( $opts->{'host'}, $_ ) } qw{A AAAA};
	    ( $r_type ) = keys( %$host_info );
        $ip = $host_info->{$r_type};
    }
	my %family_map = ( 'A' => 'INET', 'AAAA' => 'INET6' );
	my $start = time;

	while ( ( time - $start ) <= $timeout ) {
		return 1 if "IO::Socket::$family_map{$r_type}"->new(
			'PeerAddr' => $ip,
			'PeerPort' => $opts->{'port'},
			'Proto'    => 'tcp',
			'Timeout'  => $timeout,
		);
		diag( { '_opts' => $opts }, "[DEBUG] Waiting for response on $ip:$opts->{'port'} ($r_type)..." ) if $opts->{'debug'};
		select undef, undef, undef, 0.5;    # there's no need to try more than 2 times per second
	}
    return 0;
};

my $init_ssh = sub {
    my ( $class, $opts ) = @_;

	# Always clear the cache if possible when we get here.
	if( $opts->{'_cache_index'} ) {
        local $disable_destructor = 1;
		undef $cache{$opts->{'_cache_index'}};
	}

    # Try not to have disallowed ENV chars. For now just transliterate . into _
    # XXX TODO This will be bad with some usernames/domains.
    # Maybe need to run host through punycode decoder, etc.?
    if( !$opts->{'_host_sock_key'} ) {
        $opts->{'_host_sock_key'} = "NET_OPENSSH_MASTER_$opts->{'host'}_$opts->{'user'}";
        $opts->{'_host_sock_key'} =~ tr/./_/;
    }

	# Make temp dir go out of scope with this object for ctl paths, etc.
	# Leave no trace!
	$opts->{'_tmp_obj'} = File::Temp->newdir() if !$opts->{'_tmp_obj'};
    my $tmp_dir = $opts->{'_tmp_obj'}->dirname();
    my $temp_fh;

    # Use an existing connection if possible, otherwise make one
    if ( $ENV{$opts->{'_host_sock_key'}} && -e $ENV{$opts->{'_host_sock_key'}} ) {
        $opts->{'external_master'} = 1;
        $opts->{'ctl_path'}        = $ENV{$opts->{'_host_sock_key'}};
    }
    else {
		if( !$opts->{'debug'} ) {
			open( $temp_fh, ">", "$tmp_dir/STDERR" ) or $die_no_trace->("Can't open $tmp_dir/STDERR for writing: $!");
			$opts->{'master_stderr_fh'} = $temp_fh;
		}
        $opts->{'ctl_dir'}     = $tmp_dir;
        $opts->{'strict_mode'} = 0;

        $opts->{'master_opts'} = [
            '-o' => 'StrictHostKeyChecking=no',
            '-o' => 'GSSAPIAuthentication=no',
            '-o' => 'UserKnownHostsFile=/dev/null',
            '-o' => 'ConnectTimeout=180',
            '-o' => 'TCPKeepAlive=no',
        ];
        push @{ $opts->{'master_opts'} }, '-v' if $opts->{'debug'};
        if ( $opts->{'key_path'} ) {
            push @{ $opts->{'master_opts'} }, '-o', 'IdentityAgent=none';
        }

        # Attempt to use the SSH agent if possible. This won't hurt if you use -k or -P.
        # Even if your sock doesn't work to get you in, you may want it to do something on the remote host.
        # Of course, you may want to disable this with no_agent if your system is stupidly configured
		# with lockout after 3 tries and you have 4 keys in agent.

		# Anyways, don't just kill the sock for your bash session, restore it in DESTROY
		$opts->{'_restore_auth_sock'} = delete $ENV{SSH_AUTH_SOCK} if $opts->{'no_agent'};
        $opts->{'forward_agent'} = 1 if $ENV{'SSH_AUTH_SOCK'};
    }

    my $status = 0;
    my $self;
    foreach my $attempt ( 1 .. $opts->{'retry_max'} ) {

		local $@;
        my $up = eval { $ping->($opts) };
        if ( !$up ) {
            $die_no_trace->("$opts->{'host'} is down!") if $opts->{die_on_drop};
            diag( { '_opts' => $opts }, "Waiting for host to bring up sshd, attempt $attempt..." );
            next;
        }

		# Now, per the POD of Net::OpenSSH, new will NEVER DIE, so just trust it.
        $self = $class->SUPER::new( delete $opts->{'host'}, %$opts );
		my $error = $self->error;
        next unless ref $self eq 'Net::OpenSSH::More' && !$error;

        if ( -s $temp_fh ) {
            seek( $temp_fh, 0, Fcntl::SEEK_SET );
            local $/;
            $error .= " " . readline($temp_fh);
        }

        if($error) {
            $die_no_trace->("Bad password passed, will not retry SSH connection: $error.") if ( $error =~ m{bad password}                       && $opts->{'password'} );
            $die_no_trace->("Bad key, will not retry SSH connection: $error.")             if ( $error =~ m{master process exited unexpectedly} && $opts->{'key_path'} );
            $die_no_trace->("Bad credentials, will not retry SSH connection: $error.")     if ( $error =~ m{Permission denied} );
        }

        if ( defined $self->error && $self->error ne "0" && $attempt == 1 ) {
            $self->diag( "SSH Connection could not be established to " . $self->{'host'} . " with the error:", $error, 'Will Retry 10 times.' );
        }
        if ( $status = $self->check_master() ) {
            $self->diag("Successfully established connection to " . $self->{'host'} . " on attempt #$attempt.") if $attempt gt 1;
            last;
        }

        sleep $opts->{'retry_interval'};
    }
    $die_no_trace->("Failed to establish SSH connection after $opts->{'retry_max'} attempts. Stopping here.") if ( !$status );

    # Setup connection caching if needed
    if ( !$opts->{'no_cache'} && !$opts->{'_host_sock_key'} ) {
        $self->{'master_pid'} = $self->disown_master();
        $ENV{$opts->{'_host_sock_key'}} = $self->get_ctl_path();
    }

    #Allow the user to unlink the host sock if we need to pop the cache for some reason
    $self->{'host_sock'} = $ENV{$opts->{'_host_sock_key'}};

    return $self;
};

my $connection_check = sub {
    my ( $self ) = @_;
	local $@;
    eval { $self = $init_ssh->($self->{'_opts'}) unless $self->check_master; };
    return $@ ? 0 : 1;
};

# Try calling the function.
# If it fails, then call _connection_check to reconnect if needed.
#
# The goal is to avoid calling _connection_check
# unless something goes wrong since it adds about
# 450ms to each ssh command.
#
# If the control socket has gone away, call
# _connection_check ahead of time to reconnect it.
my $call_ssh_reinit_if_check_fails = sub {
    my ( $self, $func, @args ) = @_;

    $self->_connection_check() if !-S $self->{'_ctl_path'};

    local $@;
    my @ret       = eval { $self->$func(@args) };
    my $ssh_error = $@ || $self->error;
    return @ret if !$ssh_error;

    $self->_connection_check();
    return ($self->$func(@args));
};

my $post_connect = sub {
    my ( $self, $opts ) = @_;

    $self->{'persistent_shell'}->close() if $self->{'persistent_shell'};
    undef $self->{'persistent_shell'};

    return;
};

my $trim = sub {
    my ( $string ) = @_;
    return '' unless length $string;
    $string =~ s/^\s+//;
    $string =~ s/\s+$//;
    return $string;
};

my $send = sub {
    my ( $self, $line_reader, @cmd ) = @_;
    my ( $pty, $err, $pid ) = $call_ssh_reinit_if_check_fails->( $self, 'open3pty', @cmd );
    $die_no_trace->("Net::OpenSSH::open3pty failed: $err") if( !defined $pid || $self->error() );

    $self->{'_out'} = "";
    $line_reader = sub {
        my ( $self, $out, $stash_param ) = @_;
        $out =~ s/[\r\n]{1,2}$//;
        $self->{$stash_param} .= "$out\n";
        return;
    } if ref $line_reader ne 'CODE';

    # TODO make this async so you can stream STDERR as well
    # That said, most only care about error if command fails, so...
    my $out;
    $line_reader->( $self, $out, '_out' ) while $out = $pty->getline;
    $pty->close;

    # only populate error if there's an error #
    $self->{'_err'} = '';
    $line_reader->( $self, $out, '_err' ) while $out = $err->getline;
    $err->close;

    $self->{'_pid'} = $pid;
    waitpid( $pid, 0 );
    return $? >> 8;
};

my $TERMINATOR = "\r\r";
my $send_persistent_cmd = sub {
    my ( $self, $cmd, $uuid ) = @_;

    $uuid //= Data::UUID->new()->create_str();

    #Use command on bash to ignore stuff like aliases so that we have a minimum level of PEBKAC errors due to aliasing cp to cp -i, etc.
    $self->{'expect'}->print("UUID='$uuid'; echo \"BEGIN \$UUID\"; command $cmd ; echo \"___\$?___\"; echo; echo \"EOF \$UUID\" $TERMINATOR");

    #Rather than take the approach of Cpanel::Expect::cmd_then_poll, it seemed more straightforward to echo unique strings before and after the command.
    #This made getting the return code somewhat more complicated, as you can see below.  That said, Cpanel::Expect appears to not concern itself with such things.

    $self->{'expect'}->expect( 30,                        '-re', qr/BEGIN $uuid/m );
    $self->{'expect'}->expect( $self->{'expect_timeout'}, '-re', qr/EOF $uuid/m );     #If nothing is printed in 2mins, give up

    #Get the actual output, remove terminal grunk
    my $message = $trim->( $self->{'expect'}->before() );
    $message =~ s/[\r\n]{1,2}$//;                                                      #Remove 'secret newline' control chars
    $message =~ s/\x{d}//g;                                                            #More control chars
    $message = Term::ANSIColor::colorstrip($message);                                  #Strip colors

    #Find the exit code
    my ($code) = $message =~ m/___(\d*)___$/;
    unless ( defined $code ) {

        #Tell the user if they've made a boo-boo
        my $possible_err = $trim->( $self->{'expect'}->before() );
        $possible_err =~ s/\s//g;
        $die_no_trace->("Runaway multi-line string detected.  Please adjust the command passed.") if $possible_err =~ m/\>/;

        $die_no_trace->("Could not determine exit code!
            It timed out (went 30s without printing anything).
            Run command outside of the persistent terminal please.
            (pass use_persistent_shell => 0 as opt to cmd)"
        );
    }
    $message =~ s/___(\d*)___$//g;

    return ( $message, $code );
};

# XXX TODO ALLOW ARRAY YOU BAG BITER
my $do_persistent_command = sub {
    my ( $self, $cmd, $no_stderr ) = @_;

    #XXX casting runes, but SSHControl & Cpanel::Expect do it...
    #local $| = 1;
    #local $ENV{'TERM'} = 'dumb';

    if ( !$self->{'persistent_shell'} ) {
        my ( $pty, $pid ) = $self->_call_ssh_reinit_if_check_fails( 'open2pty', 'bash' );

        #XXX this all seems to be waving a dead chicken, but SSHControl and Cpanel::Expect do it, so...
        $pty->set_raw();
        $pty->stty( 'raw', 'icrnl', '-echo' );
        $pty->slave->stty( 'raw', 'icrnl', '-echo' );

        #Hook in expect
        $self->{'expect'} = Expect->init($pty);
        $self->{'expect'}->restart_timeout_upon_receive(1);    #Logabandon by default
        $self->{'expect'}->print("export PS1=''; unset HISTFILE; stty raw icrnl -echo; echo 'EOF' $TERMINATOR");
        $self->{'expect'}->expect( 10, 'EOF' );
        $self->{'expect'}->clear_accum();
        $self->{'expect_timeout'} //= 30;

        #cache
        $self->{'persistent_shell'} = $pty;
        $self->{'persistent_pid'}   = $pid;
    }

    #execute the command
    my $uuid = Data::UUID->new()->create_str();
    $cmd .= " 2> /tmp/stderr_$uuid.out" unless $no_stderr;
    my ( $oot, $code ) = $send_persistent_cmd->( $self, $cmd, $uuid );
    $self->{'_out'} = $oot;

    unless ($no_stderr) {

        #Grab stderr
        ( $self->{'_err'} ) = $send_persistent_cmd->( $self, "cat /tmp/stderr_$uuid.out" );

        #Clean up
        $send_persistent_cmd->( $self, "rm -f /tmp/stderr_$uuid.out" );
    }

    return int($code);
};

#######################
# END PRIVATE METHODS #
#######################

sub new {
    my ( $class, $host, %opts ) = @_;
    $die_no_trace->( "No host given to $class.", 'PEBCAK' ) if !$host;

    # Set defaults, check if we can return early
    %opts = ( %defaults, %opts );
	$opts{'_cache_index'} = "$opts{'user'}_${host}_$opts{'port'}";
    return $cache{$opts{'_cache_index'}} unless $opts{'no_cache'} || !$cache{$opts{'_cache_index'}};

	# Figure out how we're gonna login
    $opts{'_login_method'} = $resolve_login_method->(\%opts);

    # check permissions on base files if we got here
    $check_local_perms->( "$opts{'home'}/.ssh",        0700, 1 ) if -e "$opts{'home'}/.ssh";
    $check_local_perms->( "$opts{'home'}/.ssh/config", 0600 )    if -e "$opts{'home'}/.ssh/config";

    # Make the connection
    $opts{'host'} = $host;
    my $self = $cache{$opts{'_cache_index'}} = $init_ssh->( $class, \%opts );

    # Stash the originating pid, as running the destructor when
    # you have forked past instantiation means you have a bad time
    $self->{'ppid'} = $$;

    # Stash opts for later
    $self->{'_opts'} = \%opts;

    # Establish persistent shell, etc.
    $post_connect->( $self, \%opts );

    return $self;
};

=head2 DESTROY

Noted in POD only because of some behavior differences between the
parent module and this. The following actions are taken *before*
the parent's destructor kicks in:
* Return early if you aren't the PID which created the object.

=cut

sub DESTROY {
    my ($self) = @_;
    return if !$self->{'ppid'} || $$ != $self->{'ppid'} || $disable_destructor;
	$ENV{SSH_AUTH_SOCK} = $self->{'_opts'}{'_restore_auth_sock'} if $self->{'_opts'}{'_restore_auth_sock'};
    $self->{'persistent_shell'}->close() if $self->{'persistent_shell'};

    return $self->SUPER::DESTROY();
}

=head2 diag

Print a diagnostic message to STDOUT.
Optionally prefixed by what you passed in as $opts{'output_prefix'} in the constructor.
I use this in several places when $opts{'debug'} is passed to the constructor.

ACCEPTS LIST of messages.

RETURNS undef.

=cut

sub diag {
    my ( $self, @msgs ) = @_;
    print STDOUT "$self->{'_opts'}{'output_prefix'}$_\n" for @msgs;
    return;
}

=head2 cmd

Execute specified command via SSH. If first arg is HASHREF, then it uses that as options.
Command is specifed as a LIST, as that's the easiest way to ensure escaping is done correctly.

$opts HASHREF:
C<no_persist> - Boolean - Whether or not to use persistent shell if that is enabled.
C<no_stderr> - Boolean - Whether or not to discard STDERR.

C<command> - LIST of components combined together to make a shell command.

Returns LIST STDOUT, STDERR, and exit code from executed command.

    my ($out,$err,$ret) = $ssh->cmd(qw{ip addr show});

If use_persistent_shell was truthy in the constructor,
then commands are executed in a persistent Expect session to cut down on forks,
and in general be more efficient.

However, some things can hang this up.
Unterminated Heredoc & strings, for instance.
Also, long running commands that emit no output will time out.
Also, be careful with changing directory;
this can cause unexpected side-effects in your code.
Changing shell with chsh will also be ignored;
the persistent shell is what you started with no matter what.
In those cases, you should pass no_persist as a true value to fork and execute the command by itself.

If the 'debug' opt to the constructor is set, every command executed hereby will be printed.

If no_stderr is passed, stderr will not be gathered (it takes writing/reading to a file, which is additional time cost).

BUGS:

In no_persist mode, stderr and stdout are merged, making the $err parameter returned less than useful.

=cut

sub cmd {
    my ( $self ) = shift;
	my $opts = ref $_[0] eq 'HASH' ? shift : {};
	my @cmd = @_;

    $die_no_trace->( 'No command specified', 'PEBCAK' ) if !@cmd;
    $self->diag("[DEBUG][$self->{'_opts'}{'host'}] EXEC " . join( " ", @cmd ) ) if $self->{'_opts'}{'debug'};

    my $ret = $opts->{'no_persist'} ? $send->( $self, undef, @cmd ) : $self->_do_persistent_command( \@cmd, $opts->{'no_stderr'} );
    chomp( my $out = $self->read );
    my $err = $self->error;

    $self->{'last_exit_code'} = $ret;
    return ( $out, $err, $ret );
}


=head1 AUTHORS

Thomas Andrew "Andy" Baugh <andy@troglodyne.net>
George S. Baugh <george@troglodyne.net>

=head1 SPECIAL THANKS

cPanel, L.L.C. - in particularly the QA department (which the authors once were in).
Many of the ideas for this module originated out of lessons learned from our time
writing a ssh based remote teststuite for testing cPanel & WHM.

Chris Eades - For the original module this evolved from at cPanel over the years.

bdraco (Nick Koston) - For optimization ideas and the general process needed for expect & persistent shell.

J.D. Lightsey - For the somewhat crazy but nonetheless very useful eval_full subroutine used
to execute subroutine references from the orchestrating server on the remote host's perl.

Brian M. Carlson - For the highly useful sftp shortcut method that utilizes Net::SFTP::Foreign.

Rikus Goodell - For shell escaping expertise

=head1 IN MEMORY OF

Paul Trost
Dan Stewart

=cut

1;
