build:
	ghc --make GenRSAKey -fglasgow-exts
	ghc --make HelloWorld -fglasgow-exts
	ghc --make PKCS7 -fglasgow-exts

run: build
	./PKCS7
#	./HelloWorld

clean:
	rm -f HelloWorld GenRSAKey PKCS7 *.hi *.o

.PHONY: build run clean
