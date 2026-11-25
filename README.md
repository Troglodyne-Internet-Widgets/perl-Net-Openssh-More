# NAME

Net::OpenSSH::More - Net::OpenSSH submodule with many useful features

# VERSION

version 1.08

# SYNOPSIS

```perl
use Net::OpenSSH::More;
my $ssh = Net::OpenSSH::More->new(
    'host'     => 'some.host.test',
    'port'     => 69420,
    'user'     => 'azurediamond',
    'password' => 'hunter2',
);
...
```

# DESCRIPTION

Submodule of Net::OpenSSH that contains many methods that were
otherwise left "as an exercise to the reader" in the parent module.

Highlights:

- Persistent terminal via expect for very fast execution, less forking.
- Usage of File::Temp and auto-cleanup to prevent lingering ctl\_path cruft.
- Ability to manipulate incoming text while streaming the output of commands.
- Run perl subroutine refs you write locally but execute remotely.
- Many shortcut methods for common system administration tasks
- Registration method for commands to run upon DESTROY/before disconnect.
- Automatic reconnection ability upon connection loss

# NAME

Net::OpenSSH::More

# METHODS

## new

Instantiate the object, establish the connection. Note here that I'm not allowing
a connection string like the parent module, and instead exploding these out into
opts to pass to the constructor. This is because we want to index certain things
under the hood by user, etc. and I \*do not\* want to use a regexp to pick out
your username, host, port, etc. when this problem is solved much more easily
by forcing that separation on the caller's end.

ACCEPTS:

- %opts - <HASH> A hash of key value pairs corresponding to the what you would normally pass in to Net::OpenSSH,
along with the following keys:
    - use\_persistent\_shell - Whether or not to setup Expect to watch a persistent TTY. Less stable, but faster.
    - expect\_timeout - When the above is active, how long should we wait before your program prints something
    before bailing out?
    - no\_agent - Pass in a truthy value to disable the SSH agent. By default the agent is enabled.
    - die\_on\_drop - If, for some reason, the connection drops, just die instead of attempting reconnection.
    - output\_prefix - If given, is what we will tack onto the beginning of any output via diag method.
    useful for streaming output to say, a TAP consumer (test) via passing in '# ' as prefix.
    - debug - Pass in a truthy value to enable certain diag statements I've added in the module and pass -v to ssh.
    - home - STRING corresponding to an absolute path to something that "looks like" a homedir. Defaults to the user's homedir.
    useful in cases where you say, want to load SSH keys from a different path without changing assumptions about where
    keys exist in a homedir on your average OpenSSH using system.
    - no\_cache - Pass in a truthy value to disable caching the connection and object, indexed by host string.
    useful if for some reason you need many separate connections to test something. Make sure your MAX\_SESSIONS is set sanely
    in sshd\_config if you use this extensively.

        Two things about that cache are worth knowing. Asking for the same user, host and
        port hands you back the object somebody else got, rather than a new connection.
        And a machine can be rebuilt or rebooted at an address between one call and the
        next, so a cached object is checked against its far end before you get it, and
        quietly replaced if the machine it was built for is no longer answering.

        Leaving the cache on also publishes this connection's control socket into the
        environment as NET\_OPENSSH\_MASTER\_&lt;host>\_&lt;user>, so that anything this program
        starts reuses the connection rather than opening one of its own. Sharing a master
        is the point of the arrangement rather than a consequence of it: against a host
        you are about to run thousands of ssh-based tests on, a connection per test costs
        a handshake, a key exchange and an authentication per test, and puts enough of
        them in flight at once to run sshd out of the session limit the paragraph above
        warns about. Shared, every connection after the first is a channel on the one
        already open.

        That is what disowning the master buys, and why it outlives the object that
        opened it: the things reusing the socket outlive that object too. Nothing reaps
        it for you afterwards, so pass no\_cache when what you want is a connection that
        goes away with the program.

    - retry\_interval - In the case that sshd is not up on the remote host, how long to wait while before reattempting connection.
    defaults to 6s. We retry $RETRY\_MAX times, so this means waiting a little over a minute for SSH to come up by default.
    your situation requires longer intervals, pass in something longer.
    - retry\_max - Number of times to retry when a connection fails. Defaults to 10.
    - retry\_on\_auth\_failure - Pass in a truthy value to retry when the far end refuses
    the credential, rather than giving up on the first refusal. Off by default,
    which is what you want nearly always: ssh offers every key in your agent on each
    attempt, so retrying a refusal presents the far end with retry\_max failures
    times however many keys you are carrying, and a host running fail2ban or cPHulkd
    will ban you for it. Turn it on when a refusal is expected to be temporary --
    waiting for a machine that is still being built, whose authorized\_keys is
    written well after sshd starts answering -- and lower retry\_max, or pass
    no\_agent, if that machine is also likely to be counting.

RETURNS a Net::OpenSSH::More object.

### A note on Authentication order

We attempt to authenticate using the following details, and in this order:
1) Use supplied key\_path.
2) Use supplied password.
3) Use existing SSH agent (SSH\_AUTH\_SOCK environment variable)
4) Use keys that may exist in $HOME/.ssh - id\_ed25519, id\_ecdsa, id\_rsa and id\_dsa (in that order).

If all methods therein fail, we will die, as nothing will likely work at that point.
It is important to be aware of this if your remove host has something like fail2ban or cPHulkd
enabled which monitors and blocks access based on failed login attempts. If this is you,
ensure that you have not configured things in a way as to accidentally lock yourself out
of the remote host just because you fatfingered a connection detail in the constructor.

### A note on file permissions

Before it connects, new() checks the permissions of the files that ssh will read.
It uses the same rule as ssh, so a mode that ssh accepts is accepted here too.
It dies, and names the file, its mode and the bits that are not allowed, if:

1) The .ssh directory in the home directory can be written by the group or by others (mode & 022).
2) The .ssh/config file can be written by the group or by others (mode & 022).
3) The private key can be read, written or run by the group or by others (mode & 077).

So a .ssh directory of 0700, 0710, 0750 or 0755 is accepted, and so is a config of 0644.
A key must be 0600, 0400 or stricter.

## use\_persistent\_shell

Pass "defined but falsy/truthy" to this to enable using the persistent shell or deactivate its' use.
Returns either the value you just set or the value it last had (if arg is not defined).

## copy

Copies $SOURCE file on the remote machine to $DEST on the remote machine.
If you want to sync/copy files from remote to local or vice/versa, use
the sftp accessor (Net::SFTP::Foreign) instead.

Dies in this module, as this varies on different platforms (GNU/LINUX, Windows, etc.)

## **backup\_files (FILES)**

Backs up files which you wish to later restore to their original state. If the file does
not currently exist then the method will still store a reference for later file deletion.
This may seem strange at first, but think of it in the context of preserving 'state' before
a test or scripted action is run. If no file existed prior to action, the way to restore
that state would be to delete the added file(s).

NOTE: Since copying files on the remote system to another location on the remote system
is in fact not something implemented by Net::SFTP::Foreign, this is necessarily going
to be a "non-portable" method -- use the Linux.pm subclass of this if you want to be able
to actually backup files without dying, or subclass your own for Windows, however they
choose to implement \`copy\` with their newfangled(?) SSH daemon.

`FILES` - LIST - File(s) to backup.

`STASH` - BOOL - mv files on backup instead of cp.  This will make sure FILES arg path no
                  longer exists at all so a fresh FILE can be written during run.

my $file = '/path/to/file.txt';
$ssh->backup\_files($file);

my @files = ( '/path/to/file.txt', '/path/to/file2.txt' );
$ssh->backup\_files(@files);

## **restore\_files (FILES)**

Restores specific file(s) backed up using backup\_files(), or all the backup files if none
are specified, to their previous state.

If the file in question DID NOT exist when backup\_files was last invoked for the file,
then the file will instead be deleted, as that was the state of the file previous to
actions taken in your test or script.

`FILES` - (Optional) - LIST - File(s) to restore.

my $file = '/path/to/file.txt';
$ssh->backup\_files($file);
$ssh->restore\_files();

## DESTROY

Noted in POD only because of some behavior differences between the
parent module and this. The following actions are taken \*before\*
the parent's destructor kicks in:
\* Return early if you aren't the PID which created the object.
\* Restore any files backed up with backup\_files earlier.

## diag

Print a diagnostic message to STDOUT.
Optionally prefixed by what you passed in as $opts{'output\_prefix'} in the constructor.
I use this in several places when $opts{'debug'} is passed to the constructor.

ACCEPTS LIST of messages.

RETURNS undef.

## cmd

Execute specified command via SSH. If first arg is HASHREF, then it uses that as options.
Command is specifed as a LIST, as that's the easiest way to ensure escaping is done correctly.

$opts HASHREF:
`no_stderr` - Boolean - Whether or not to discard STDERR.
`use_operistent_shell` - Boolean - Whether or not to use the persistent shell.

`command` - LIST of components combined together to make a shell command.

Returns LIST STDOUT, STDERR, and exit code from executed command.

```perl
my ($out,$err,$ret) = $ssh->cmd(qw{ip addr show});
```

If use\_persistent\_shell was truthy in the constructor (or you override via opts HR),
then commands are executed in a persistent Expect session to cut down on forks,
and in general be more efficient.

However, some things can hang this up.
Unterminated Heredoc & strings, for instance.
Also, long running commands that emit no output will time out.
Also, be careful with changing directory;
this can cause unexpected side-effects in your code.
Changing shell with chsh will also be ignored;
the persistent shell is what you started with no matter what.
In those cases, use\_persistent\_shell should be called to disable that before calling this.
Also note that persistent mode basically \*requires\* you to use bash.
I am not yet aware of how to make this better yet.

If the 'debug' opt to the constructor is set, every command executed hereby will be printed.

If no\_stderr is passed, stderr will not be gathered (it takes writing/reading to a file, which is additional time cost).

BUGS:

In no\_persist mode, stderr and stdout are merged, making the $err parameter returned less than useful.

## cmd\_exit\_code

Same thing as cmd but only returns the exit code.

### **write (FILE,CONTENT,\[MOD\],\[OWN\])**

Write a file.

`FILE` - Absolute path to file.
`CONTENT` - Content to write to file.
`MOD` - File mode.
`OWN` - File owner. Defaults to the user you connected as.
`GRP` - File group. Defaults to OWN.

Returns true if all actions are successful, otherwise warn/die about the error.

```
$ssh->write($filename,$content,'600','root');
```

### **eval\_full( options )**

Run Perl code on the remote system and return the results.
interpreter defaults to /usr/bin/perl.

**Input**

Input options are supplied as a hash with the following keys:

```
code - A coderef or string to execute on the remote system.
args - An optional arrayref of arguments to the code.
exe  - Path to perl executable. Optional.
```

**Output**

The output from eval\_full() is based on the return value of the input
coderef. Return context is preserved for the coderef.

All error states will generate exceptions.

**Caveats**

A coderef supplied to this function will be serialized by B::Deparse
and recreated on the remote server. This method of moving the code does
not support closing over variables, and any needed modules must
be loaded inside the coderef with `require`.

**Example**

```perl
my $greeting_message = $ssh->eval_full( code => sub { return "Hello $_[0]";}, args => [$name] );
```

### cmd\_stream

Pretty much the same as running cmd() with one important caveat --
all output is formatted with the configured prefix and \*streams\* to STDOUT.
Useful for remote test harness building.
Returns (exit\_code), as in this context that should be all you care about.

You may be asking, "well then why not use system?" That does not support
the prefixing I'm doing here. Essentially we provide a custom line reader
to 'send' which sends the output to STDOUT via 'diag' as well as doing
the "default" behavior (append the line to the relevant output vars).

NOTE: This uses send() exclusively, and will never invoke the persistent shell,
so if you want that, don't use this.

# SPECIAL THANKS

cPanel, L.L.C. - in particularly the QA department (which the authors once were in).
Many of the ideas for this module originated out of lessons learned from our time
writing a ssh based remote teststuite for testing cPanel & WHM.

Chris Eades - For the original module this evolved from at cPanel over the years.

bdraco (Nick Koston) - For optimization ideas and the general process needed for expect & persistent shell.

J.D. Lightsey - For the somewhat crazy looking but nonetheless very useful eval\_full subroutine used
to execute subroutine references from the orchestrating server on the remote host's perl.

Brian M. Carlson - For the highly useful sftp shortcut method that caches Net::SFTP::Foreign.

Rikus Goodell - For shell escaping expertise

# IN MEMORY OF

Paul Trost
Dan Stewart

# SEE ALSO

Please see those modules/websites for more information related to this module.

- [Net::OpenSSH](https://metacpan.org/pod/Net%3A%3AOpenSSH)
- [Net::OpenSSH::More::Linux](https://metacpan.org/pod/Net%3A%3AOpenSSH%3A%3AMore%3A%3ALinux)

# BUGS

Please report any bugs or feature requests on the bugtracker website
[https://github.com/Troglodyne-Internet-Widgets/perl-Net-Openssh-More/issues](https://github.com/Troglodyne-Internet-Widgets/perl-Net-Openssh-More/issues)

When submitting a bug or request, please include a test-file or a
patch to an existing test-file that illustrates the bug or desired
feature.

# AUTHORS

Current Maintainers:

- George S. Baugh <teodesian@gmail.com>

# CONTRIBUTORS

- Andy Baugh <andy@troglodyne.net>
- Troglodyne LLC Crash test Dummy <trogbot@troglodyne.net>
- Troglodyne L.L.C. LLM Bot <morpheus@troglodyne.net>

# COPYRIGHT AND LICENSE

Copyright (c) 2024 Troglodyne LLC

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
