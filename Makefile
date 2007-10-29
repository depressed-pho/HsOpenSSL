CABAL_FILE = HsOpenSSL.cabal
GHC = ghc

build: .setup-config Setup
	./Setup build

run: build
	@echo ".:.:. Let's go .:.:."
	$(MAKE) -C examples run

.setup-config: $(CABAL_FILE) configure Setup
	./Setup configure -p

configure: aclocal.m4 configure.ac
	autoconf

aclocal.m4:
	aclocal

Setup: Setup.hs
	$(GHC) --make Setup

clean:
	rm -rf dist Setup Setup.o Setup.hi .setup-config *.buildinfo
	find . -name '*~' -exec rm -f {} \;
	$(MAKE) -C examples clean

doc: .setup-config Setup
	./Setup haddock

install: build
	sudo ./Setup install

sdist: Setup
	./Setup sdist

.PHONY: build run clean install doc sdist
