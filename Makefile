test: compilecheck
	prove -mv t/*.t

FILES2CHECK := $(shell find lib/ -name '*.pm')
compilecheck:
	$(foreach FILE,$(FILES2CHECK),perl -Ilib -c $(FILE) &&) /bin/true

tidy:
	$(foreach FILE,$(FILES2CHECK),perltidy -b $(FILE) &&) /bin/true
	perltidy -b t/*.t

.PHONY: compilecheck test tidy
