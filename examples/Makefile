build:
	ghc --make HelloWorld -threaded -fglasgow-exts -O3

run: build
	./HelloWorld

clean:
	rm -f HelloWorld *.hi *.o

.PHONY: build run clean