# CLAUDE.md

This file is the procedure for work in this repository.

`Net::OpenSSH::More` is a subclass of `Net::OpenSSH`. It adds a cache of connections, retries, a persistent shell, and some helper methods. `Net::OpenSSH::More::Linux` adds the helpers for a Linux host. Both modules are in `lib/`. The tests are in `t/`.

## Which skills, and when

The hooks of the perl-slop plugin hold you to the procedure. They refuse an edit to Perl until you load `perl-slop:reading-perl`. They refuse a commit of Perl until you load `data-perl`, `testing-perl` and `reviewing-perl`, each one after the last commit. A refusal names the skills that are missing.

Before you answer a question about the code, or look for something in it, load `perl-slop:reading-perl`. The hooks cannot see that case.

Write Markdown, POD and `Changes` with `simple-english:simple-english`. The file `.perl-slop.json` makes the hooks ask for it.

## Read the code before you change it

Most of the code here is older than the conversation about it. A line that looks pointless is usually the scar of something that went wrong once. The reason is in the commit, not in the file. Read the commit before the first edit.

## How the code is written

The files `.perlcriticrc` and `.perltidyrc` set the style. The pre-commit hook in `git-hooks/` enforces both. Turn a policy off only with a comment that gives the reason. Do not turn one off to make a commit pass.

## Set up a clone

`dzil` builds the distribution. `dist.ini` lists what the build needs, and the code says what the modules need. Install both with `cpanm`:

```
dzil authordeps --missing | cpanm --notest
dzil listdeps --missing | cpanm --notest
```

In each clone that you commit from, install the hooks once. Git does not install them for you:

```
cp git-hooks/pre-commit git-hooks/post-commit git-hooks/post-merge \
   git-hooks/post-rewrite git-hooks/refresh-coverage .git/hooks/
```

## Tests

Run the tests with `prove -lm -j8 t/`. A test must not need a real ssh server. A test that needs one skips unless `AUTHOR_TESTS` is set.
