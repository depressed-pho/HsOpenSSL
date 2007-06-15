build:
	ghc --make GenRSAKey -fglasgow-exts
	ghc --make HelloWorld -fglasgow-exts

run: build
	./HelloWorld

clean:
	rm -f HelloWorld *.hi *.o

.PHONY: build run clean
