GHCFLAGS = -O2 -fglasgow-exts

build:
	ghc $(GHCFLAGS) --make GenRSAKey
	ghc $(GHCFLAGS) --make HelloWorld
	ghc $(GHCFLAGS) --make PKCS7

run: build
	./PKCS7
#	./HelloWorld

clean:
	rm -f HelloWorld GenRSAKey PKCS7 *.hi *.o

.PHONY: build run clean
