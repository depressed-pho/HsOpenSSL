CABAL_FILE = HsOpenSSL.cabal
GHC = ghc

build: .setup-config Setup
	./Setup build

run: build
	@echo ".:.:. Let's go .:.:."
	$(MAKE) -C examples run

.setup-config: $(CABAL_FILE) Setup
	./Setup configure

Setup: Setup.hs
	$(GHC) --make Setup

clean:
	rm -rf dist Setup Setup.o Setup.hi .setup-config
	find . -name '*~' -exec rm -f {} \;
	$(MAKE) -C examples clean

doc: .setup-config Setup
	./Setup haddock

install: build
	./Setup install

sdist: Setup
	./Setup sdist

.PHONY: build run clean install doc sdist
