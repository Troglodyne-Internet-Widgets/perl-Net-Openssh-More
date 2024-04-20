test: compilecheck
	prove -mv t/*.t

FILES2CHECK = $(shell find lib/ -name '*.pm')
compilecheck:
	$(foreach FILE,$(FILES2CHECK),perl -Ilib -c $(FILE);)
