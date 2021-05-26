Our source tree includes ClamAV unrar code which is non-free.  Distros can build
without it using --without-unrar option to configure (crippling the RAR v3
formats a little).  Simply deleting src/unrar*.[ch] before running configure
will infer that option as well.

--

Here's how to build a CPU-fallback chain (with OpenMP fallback too) for
distros. See params.h for some background detail. The only actually tricky
part is escaping the quotes enough to survive just long enough.

We set the shared directory to /usr/local/share/john in this example, and the
path to executables to /usr/local/bin. The default private directory is ~/.john
and it will be created at runtime if it doesn't exist. Note that no make
target currently does the actual copy to final destination, we do that manually.

The user should always simply run "john" which in this case is AVX512 but will
seamlessly fallback to john-avx2 -> john-xop -> john-avx -> john-sse4.1 ->
john-ssse3 -> john-sse2 and finally to any of them with -non-omp, if
appropriate.

	./configure --disable-native-tests CPPFLAGS='-DJOHN_SYSTEMWIDE -DJOHN_SYSTEMWIDE_EXEC="\"/usr/local/bin\"" -DJOHN_SYSTEMWIDE_HOME="\"/usr/local/share/john\""' --disable-openmp &&
	make -s clean && make -sj4 strip &&
	mv ../run/john ../run/john-sse2-non-omp &&
	./configure --disable-native-tests CPPFLAGS='-DJOHN_SYSTEMWIDE -DJOHN_SYSTEMWIDE_EXEC="\"/usr/local/bin\"" -DJOHN_SYSTEMWIDE_HOME="\"/usr/local/share/john\"" -DOMP_FALLBACK -DOMP_FALLBACK_BINARY="\"john-sse2-non-omp\""' &&
	make -s clean && make -sj4 strip &&
	mv ../run/john ../run/john-sse2 &&
	rm -rf ../run/*.dSYM &&
	sudo mv ../run/{john-*,*2john,unshadow,unique,undrop,unafs,base64conv,tgtsnarf,mkvcalcproba,genmkvpwd,calc_stat,raw2dyna,cprepair,SIPdump} /usr/local/bin &&
	./configure --enable-simd=ssse3 --disable-openmp &&
	make -s clean && make -sj4 strip &&
	mv ../run/john ../run/john-ssse3-non-omp &&
	./configure --enable-simd=ssse3 CPPFLAGS='-DJOHN_SYSTEMWIDE -DJOHN_SYSTEMWIDE_EXEC="\"/usr/local/bin\"" -DJOHN_SYSTEMWIDE_HOME="\"/usr/local/share/john\"" -DOMP_FALLBACK -DOMP_FALLBACK_BINARY="\"john-ssse3-non-omp\"" -DCPU_FALLBACK -DCPU_FALLBACK_BINARY="\"john-sse2\""' &&
	make -s clean && make -sj4 strip &&
	mv ../run/john ../run/john-ssse3 &&
	./configure --enable-simd=sse4.1 --disable-openmp &&
	make -s clean && make -sj4 strip &&
	mv ../run/john ../run/john-sse4.1-non-omp &&
	./configure --enable-simd=sse4.1 CPPFLAGS='-DJOHN_SYSTEMWIDE -DJOHN_SYSTEMWIDE_EXEC="\"/usr/local/bin\"" -DJOHN_SYSTEMWIDE_HOME="\"/usr/local/share/john\"" -DOMP_FALLBACK -DOMP_FALLBACK_BINARY="\"john-sse4.1-non-omp\"" -DCPU_FALLBACK -DCPU_FALLBACK_BINARY="\"john-ssse3\""' &&
	make -s clean && make -sj4 strip &&
	mv ../run/john ../run/john-sse4.1 &&
	./configure --enable-simd=avx --disable-openmp &&
	make -s clean && make -sj4 strip &&
	mv ../run/john ../run/john-avx-non-omp &&
	./configure --enable-simd=avx CPPFLAGS='-DJOHN_SYSTEMWIDE -DJOHN_SYSTEMWIDE_EXEC="\"/usr/local/bin\"" -DJOHN_SYSTEMWIDE_HOME="\"/usr/local/share/john\"" -DOMP_FALLBACK -DOMP_FALLBACK_BINARY="\"john-avx-non-omp\"" -DCPU_FALLBACK -DCPU_FALLBACK_BINARY="\"john-sse4.1\""' &&
	make -s clean && make -sj4 strip &&
	mv ../run/john ../run/john-avx &&
	./configure --enable-simd=xop --disable-openmp &&
	make -s clean && make -sj4 strip &&
	mv ../run/john ../run/john-xop-non-omp &&
	./configure --enable-simd=xop CPPFLAGS='-DJOHN_SYSTEMWIDE -DJOHN_SYSTEMWIDE_EXEC="\"/usr/local/bin\"" -DJOHN_SYSTEMWIDE_HOME="\"/usr/local/share/john\"" -DOMP_FALLBACK -DOMP_FALLBACK_BINARY="\"john-xop-non-omp\"" -DCPU_FALLBACK -DCPU_FALLBACK_BINARY="\"john-avx\""' &&
	make -s clean && make -sj4 strip &&
	mv ../run/john ../run/john-xop &&
	./configure --enable-simd=avx2 --disable-openmp &&
	make -s clean && make -sj4 strip &&
	mv ../run/john ../run/john-avx2-non-omp &&
	./configure --enable-simd=avx2 CPPFLAGS='-DJOHN_SYSTEMWIDE -DJOHN_SYSTEMWIDE_EXEC="\"/usr/local/bin\"" -DJOHN_SYSTEMWIDE_HOME="\"/usr/local/share/john\"" -DOMP_FALLBACK -DOMP_FALLBACK_BINARY="\"john-avx2-non-omp\"" -DCPU_FALLBACK -DCPU_FALLBACK_BINARY="\"john-xop\""' &&
	make -s clean && make -sj4 strip &&
	mv ../run/john ../run/john-avx2 &&
	./configure --enable-simd=avx512f --disable-openmp &&
	make -s clean && make -sj4 strip &&
	mv ../run/john ../run/john-avx512f-non-omp &&
	./configure --enable-simd=avx512f CPPFLAGS='-DJOHN_SYSTEMWIDE -DJOHN_SYSTEMWIDE_EXEC="\"/usr/local/bin\"" -DJOHN_SYSTEMWIDE_HOME="\"/usr/local/share/john\"" -DOMP_FALLBACK -DOMP_FALLBACK_BINARY="\"john-avx512f-non-omp\"" -DCPU_FALLBACK -DCPU_FALLBACK_BINARY="\"john-avx2\""' &&
	make -s clean && make -sj4 strip &&
	mv ../run/john ../run/john-avx512f &&
	./configure --enable-simd=avx512bw --disable-openmp &&
	make -s clean && make -sj4 strip &&
	mv ../run/john ../run/john-non-omp &&
	./configure --enable-simd=avx512bw CPPFLAGS='-DJOHN_SYSTEMWIDE -DJOHN_SYSTEMWIDE_EXEC="\"/usr/local/bin\"" -DJOHN_SYSTEMWIDE_HOME="\"/usr/local/share/john\"" -DOMP_FALLBACK -DOMP_FALLBACK_BINARY="\"john-non-omp\"" -DCPU_FALLBACK -DCPU_FALLBACK_BINARY="\"john-avx512f\""' &&
	make -s clean && make -sj4 strip &&
	rm -rf ../run/*.dSYM &&
	sudo mv ../run/{john,john-*} /usr/local/bin &&
	sudo mkdir -p /usr/local/share/john &&
	sudo cp -a ../run/* /usr/local/share/john &&
	sudo mv /usr/local/share/john/*.{pl,py,rb} /usr/local/share/john/{relbench,benchmark-unify,mailer,makechr} /usr/local/bin &&
	echo All Done

PLEASE NOTE: You should definitely consider:

	sudo make shell-completion

Or something to that end - depending on what your tree looks like you might
simply want to symlink /usr/local/share/john/john.*_completion into
/etc/bash_completion.d instead.
