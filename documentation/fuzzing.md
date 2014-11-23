Fuzzing
=======

The code path that receives and parses the iSNS PDUs can be
fuzz-tested with `test-isns-fuzzing`.

The `test-isns-fuzzing` utility reads an iSNS PDU from the standard
input and invokes the same function that `target-isns` uses to handle
the iSNS PDUs it receives.

    $ tests/test-isns-fuzzing < ../tests/data/oi_DevAttrRegRsp.bin 
    0.000001 I: iSNS server is 127.0.0.1:3205
    0.009665 D: got header DevAttrRegRsp: len = 316, flags = 0x4c00, tx = 66, seq = 0
    0.009752 D: registration period is now 86400 seconds
    0.009788 D: iqn.2003-01.org.linux-iscsi.trantor.x8664:sn.a70fe8f804d4 is a target
    $ echo $?
    0

This program can be invoked by a fuzzer to perform fuzz testing. One
such fuzzer is "American fuzzy lop" (afl-fuzz). This document
describes how to perform "iSNS fuzzing" with `afl-fuzz`.

Build test-isns-fuzzing for afl-fuzz
------------------------------------

Grab the sources of afl-fuzz and follow the instructions of the README
to build it.

  http://lcamtuf.coredump.cx/afl/

Build target-isns with the `afl-gcc` wrapper to generate an
instrumented `test-isns-fuzzing` binary.

    $ mkdir build-afl
    $ cd build-afl
    $ cmake .. -DCMAKE_C_COMPILER=/home/tof/dl/afl-1.12b/afl-gcc
    $ make

Run test-isns-fuzzing with afl-fuzz
-----------------------------------

Invoke `afl-fuzz` and specify the directory that contains the initial
testcases and the output directory:

    $ cd tests
    $ afl-fuzz -i ../../tests/data/ -o output ./test-isns-fuzzing
