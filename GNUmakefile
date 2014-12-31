RUN_COMMAND = $(MAKE) -C examples run

CONFIGURE_ARGS = \
	--enable-tests \
	-O2 \
	-p \
	--extra-include-dirs=/usr/pkg/include \
	--extra-lib-dirs=/usr/pkg/lib

include cabal-package.mk
