GCCV44 := $(shell expr `gcc -dumpversion` \>= 4.4)
YASM := $(shell which yasm)

AESIN = aes.o openssl/ossl_aes.o
SUBDIRS = openssl
ifeq "$(GCCV44)" "1"
	ifneq "$(YASM)" ""
		ifdef AESNI_ARCH
			AESIN += aesni/*.o
			SUBDIRS += aesni
			AESNI_DEC = -DAESNI_IN_USE=1
		endif
	endif
endif

aes.o: aes.c aes.h aes_func.h
	$(CC) $(CFLAGS) $(AESNI_DEC) -c aes.c -o aes.o

.PHONY: subdirs $(SUBDIRS)

subdirs: $(SUBDIRS)

$(SUBDIRS):
	$(MAKE) -C $@ all

aes.a: $(SUBDIRS) aes.o
	ar -r $@ $(AESIN)

default: aes.a
all: aes.a

clean:
	find . -iname \*.a -exec rm {} \;
	find . -iname \*.o -exec rm {} \;
