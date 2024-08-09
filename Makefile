all: install-githooks depend

install-githooks:
	install githooks/* .git/hooks/

test: depend testdepend compilecheck
	prove -mv t/*.t

FILES2CHECK := $(shell find lib/ -name '*.pm')
compilecheck:
	$(foreach FILE,$(FILES2CHECK),perl -Ilib -c $(FILE) &&) /bin/true

tidy:
	$(foreach FILE,$(FILES2CHECK),perltidy -b $(FILE) &&) /bin/true
	perltidy -b t/*.t

depend:
	sudo cpanm Net::OpenSSH Net::SFTP::Foreign File::Slurper Data::UUID Expect File::HomeDir File::Temp IO::Pty IO::Socket::INET IO::Socket::INET6 IO::Stty List::Util Net::DNS::Resolver Net::IP Time::HiRes Term::ANSIColor

testdepend:
	sudo cpanm Test2::V0 Test2::Tools::Explain Test2::Tools::Subtest Test2::Plugin::NoWarnings Test::MockModule
.PHONY: compilecheck test tidy install-githooks depend testdepend
