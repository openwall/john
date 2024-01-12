John the Ripper now supports Armory wallet password recovery, working off data
extract files produced by btcrecover extract-scripts/extract-armory-privkey.py
from https://github.com/gurnec/btcrecover

It only supports CPUs, but unlike btcrecover it is able to use SIMD for great
speedup (especially on CPUs with AVX-512).

Recommended system tuning includes setting GOMP_CPU_AFFINITY to cover the
entire range of logical CPUs and explicitly allocating huge pages.  Such tuning
is especially important on large systems and with large memory settings of the
target wallets.

Example speeds when cracking our test 32 MiB, 3 iterations wallet on AWS
c7i.48xlarge running our "John the Ripper in the cloud" AMI (based on Amazon
Linux 2), but with John the Ripper itself freshly pulled from GitHub and
rebuilt (as the version in the AMI does not yet include Armory support), with
settings tuned as suggested above:

# sysctl -w vm.nr_hugepages=24576

$ GOMP_CPU_AFFINITY=0-191 ./john -w=w pw
Using default input encoding: UTF-8
Loaded 1 password hash (armory, Armory wallet [SHA512/AES/secp256k1/SHA256/RIPEMD160 512/512 AVX512BW 8x])
Cost 1 (memory) is 33554432 for all loaded hashes
Cost 2 (iterations) is 3 for all loaded hashes
Will run 192 OpenMP threads
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
a3q92wz8         (?)
1g 0:00:01:00 DONE (2024-01-12 19:42) 0.01646g/s 758.6p/s 758.6c/s 758.6C/s milkmilk..160582

This test wallet is about 6 times slower to test candidate passwords against,
and it needs 4 times more memory, than our default "--test" benchmark's data
extracts.  The run shown above uses about 50 GB of RAM.

For reference, here are the speeds for our default "--test" benchmark on the
same machine configured in the same way:

$ GOMP_CPU_AFFINITY=0-191 ./john --test --format=armory
Will run 192 OpenMP threads
Benchmarking: armory, Armory wallet [SHA512/AES/secp256k1/SHA256/RIPEMD160 512/512 AVX512BW 8x]... (192xOMP) DONE
Speed for cost 1 (memory) of 8388608, cost 2 (iterations) of 2
Raw:    4452 c/s real, 23.4 c/s virtual

For comparison, here's how the speed reduces without explicit huge pages:

Raw:    4326 c/s real, 23.2 c/s virtual

and also without CPU affinity (the speed then varies between runs more):

Raw:    3989 c/s real, 23.0 c/s virtual

That's not too bad.  The effect of huge pages was greater for the 32 MiB, 3
iterations test, where without them we had 550 to 600 c/s vs. 750 with them.

So for more typical wallet settings and running the attack e.g. on a laptop,
the tuning won't matter nearly as much, but is still desirable - with much
lower values to specify in those commands according to the hardware and the
target wallet's settings.

Since our built-in test vectors currently include 32 MiB test wallet data
extracts, the self-test at startup will potentially (depending on number
of threads and SIMD) consume a lot of memory (and take much time, too).
If this is a problem (perhaps if you're on a system supporting a lot of
hardware threads, but having little RAM), you may remove some test
vectors from the "tests" array in armory_fmt_plug.c and re-run "make".
