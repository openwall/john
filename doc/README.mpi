====================
CAUTION:
====================
    Please note that MPI is only for multi-machine clusters with shared
    network storage.  Merely having it compiled in (even if unused) may have
    security and reliability drawbacks.  Most users should read up on the
    --fork options instead, which gets compiled in automagically if your
    system supports it.

====================
PRELUDE:
====================
    The original implementation was ca. 2004 by Ryan Lim as an academic
    project.  It was later picked up and maintained at bindshell.net, adding
    fixes for the JtR 1.7 releases and various cipher patches.

    In 2008, it was picked up by AoZ and stripped back down to the original
    MPI-only changes to improve its compatibility with the 'jumbo' patchsets,
    which had better-maintained alternate cipher support. Up to this point,
    the patch only worked for Incremental mode.

    In 2010, it was extended by magnum to support all cracking modes. It was
    far from perfect (with the exception of Markov mode and some cases of
    Wordlist mode use) but worked just fine. From version 1.7.7-Jumbo-5, the
    patch was incorporated in the main tree.

    In 2013, core John got support for node/fork and MPI was unified with this
    code. This means significantly better QA and also better scaling in some
    cases. Note that the new -fork option deprecates MPI for use on a single
    host! MPI works exactly like -fork except you can span the processes over
    several remote hosts.

====================
COMPILING:
====================
    You must have an operational MPI environment prior to both compiling and
    using the MPI version. Configuring one is outside the scope of this
    document but it's trivial. What is most important is that all nodes see
    the same working directory - normally you'd use NFS but other alternatives
    exist (file locking needs to be properly supported though). The nodes may
    use different binaries if required (eg. compiled for different CPU archs)
    as long as they are the exact same John version. But the config files
    SHOULD be shared over the network, and the directory where session
    (.rec) files and log files are created MUST be a shared network one.

    For a single, multi-core, host you don't need much configuration. MPICH2
    or OpenMPI does the job fine, for example. Most testing of MPI is now
    made using the version of OpenMPI included with latest LTE Ubuntu.

    Debian/Ubuntu/Mint Linux example for installing OpenMPI:
    sudo apt-get -y install libopenmpi-dev openmpi-bin

    The new autconf (./configure) system does not build MPI unless told so.
    It should detect and enable MPI if it's installed properly and you supply
    the "--enable-mpi" option. Normally this should do:
        ./configure --enable-mpi

    Note that MPI works just fine together with OpenMP (a.k.a OMP) enabled
    as well.  When MPI is in use (with more than one process), OMP is
    automagically disabled. Advanced users may want to change this setting
    (change MPIOMPmutex to N in john.conf) and start one MPI node per
    multi-core host, letting OMP do the rest. Warnings are printed; these
    can be muted in john.conf too.

====================
USAGE:
====================
    Typical invocation is as follows (mpiexec is usually synonym to mpirun):
        mpirun -np 4 -host host1[,host2...] ./john pwfile

    The above will launch four parallel processes that will split the job in
    a more-or-less even fashion. If no -host is given, it will run all
    processes on your local host (and -fork=4 would be a better option then).

    Using "mpirun -np <num> ./john ..." can be seen as functionally equivalent
    to "./john -fork=<num> ..." in that it will start the same number of
    processes and parse the optional "-node" option equally. The main
    practical difference is that -fork can only run on your local host, while
    MPI can run partly or solely on one or more remote hosts.

    Actually, MPI and -fork are so similar, and MPI "fakes" the -fork option
    in the session file, so you can start a session as MPI and later resume
    it without MPI - it will then use fork instead. Or vice versa.

    Both these will start nodes 1-4 out of 4 total:
	./john -fork=4 ...
	mpirun -np 4 ./john ...

    All these will start nodes 5-8 out of 12 total:
	./john -fork=4 -node=5/12 ...
	./john -fork=4 -node=5-8/12 ...
	mpirun -np 4 ./john -node=5/12 ...
	mpirun -np 4 ./john -node=5-8/12 ...

    All these will refuse to run (-node parameter ambigous):
	./john -node=2
	./john -fork=4 -node=2
	mpirun -np 4 ./john -node=2

    This will start node 7 out of 12, or nodes 3-4 (but using just one process)
    out of 16, MPI build or not:
        ./john -node=7/12 ...
        ./john -node=3-4/16 ...

    This will start node 7/12 on a remote node:
        mpirun -host hostname -np 1 ./john -node=7/12 ...

    This will start nodes 3-4/16 (using just one process) on a remote node:
        mpirun -host hostname -np 1 ./john -node=3-4/16 ...

    The following is rejected - you can't use -fork and mpirun [with -np > 1]
    at the same time:
        mpirun -np 4 ./john -fork=...

    This is somewhat more advanced, it will start 1-4/4 on one remote node:
        mpirun -host hostname -np 1 ./john -fork=4 ...

    This will do the same as above, but somewhat less efficiently:
        mpirun -host hostname -np 4 ./john ...


    In INCREMENTAL mode, the job is automagically split as evenly as possible
    without performance loss. This is not perfect so in some cases, some nodes
    will complete earlier than others.

    In MARKOV mode, the range is automagically split evenly across the nodes,
    just like you could do manually. This does not introduce any overhead,
    assuming job runs to completion.

    The single and wordlist modes scale well and cleartexts will not be tried
    by more than one node (except when different word + rule combinations
    result in the same candidate, but that problem is not MPI specific).

    In SINGLE mode, and sometimes in Wordlist mode (see below), john will
    distribute the rules (after preprocessor expansion). This works very well
    but will not likely result in a perfectly even workload across nodes.

    WORDLIST mode with rules will work the same way. Without rules, or when
    rules can no longer be split across the nodes, john will switch to
    distributing words instead.

    If the --mem-file-size parameter (default 5000000 [bytes]) will allow the
    file to be loaded in memory, this will be preferred and each node will
    only load its own share of words. In this case, there is no further
    distribution and no other overhead. Note that the limit is per node, so
    using the default and four nodes, a 16 MB file WILL be loaded to memory,
    with 4 MB on each node. To enforce this regardless of wordlist size, use
    -mem-file-size=0.

    In EXTERNAL mode, john will distribute candidates in the same way as in
    Wordlist mode without rules. When attacking very fast formats, this scales
    poorly.


    You may send a USR1 signal to the parent MPI process (or HUP to all
    individual processes) to cause the subprocesses to print out their status.
    Be aware that they may not appear in order, because they blindly share the
    same terminal.

    skill -USR1 -c mpirun
    - or -
    pkill -USR1 mpirun

    Another approach would be to do a normal status print. This is now done
    without mpirun, all nodes will be printed:

    ./john --status

    This will dump the status of each process as recorded in the .rec files.


    You may send a USR2 signal to the parent MPI process (or to all individual
    processes) for manually requesting a "pot file sync". All nodes will
    re-read the pot file and stop attacking any hashes (and salts!) that some
    other node (or independant job) had already cracked.  Current code handles
    this automagically with default config and no user intervention.


====================
MISC TIPS:
====================
    All MPI nodes must share the same working directory, usually over NFS. When
    a larger number of nodes is in use, the overhead for writing to the log
    file (which includes file locking) may become an overhead. Use the -nolog
    option to disable logging or -verb=2 option to reduce chatter.

====================
CAVEATS:
====================
    - This implementation does not account for heterogeneous clusters or nodes
      that come and go.
    - Benchmark virtual c/s will appear inflated if launching more processes
      than cores available. It will basically indicate what the speed would be
      with that many real cores.
    - Aborting a job using ctrl-c may kill nodes without updating state
      files and logs. I have tried to mitigate this but it is still a good
      idea to send a -USR1 to the parent before killing them. You should
      lower the SAVE parameter in john.conf to 60 (seconds) if running MPI,
      this will be the maximum time of repeated work after resuming.

============================================================
Following is the verbatim original content of this file:
============================================================

This distribution of John the Ripper (1.6.36) requires MPI to compile.

If you don't have MPI, download and install it before proceeeding.

Any bugs, patches, comments or love letters should be sent to
jtr-mpi@hash.ryanlim.com. Hate mail, death threates should be sent to
/dev/null.

Enjoy.
--
Ryan Lim <jtr-mpi@hash.ryanlim.com>
