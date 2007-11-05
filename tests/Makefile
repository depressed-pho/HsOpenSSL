TESTS = \
	Base64 \
	Cipher \
	DSA \
	$(NULL)

test:
	for i in $(TESTS); do ghc --make $$i; ./$$i; done

clean:
	rm -f *.hi *.o $(TESTS)
