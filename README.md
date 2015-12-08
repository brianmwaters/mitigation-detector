# mitigation-detector

#### What is mitigation-detector?

mitigation-detector is a tool that detects operating system-based exploit
mitigations.

#### What isn't mitigation-detector?

mitigation-detector doesn't detect toolchain-based exploit mitigations such as
GCC's `-fstack-protector` or Visual Studio's `/GS`.

#### How does it work?

mitigation-detector works by spawning a number of child processes to determine
how the underlying operating system handles different situations. It does not
attempt to infer what mitigations are enabled by querying the operating system's
configuration or version number; rather, it verifies that mitigations are
actually working by measuring the operating system's response to different
events.

#### What is currently implemented?

Currently, mitigation-detector detects non-executable stack, heap, data, and
BSS segments on i386 and x86-64 Linux systems.

#### How does one use it?

Running `make` or `make CC=gcc` in the working directory will produce an
executable called `mitigation-detector`. The data execution prevention
detections spawn child processes which place shellcode in various parts of the
address space and attempt to execute it. Successful execution of the shellcode
means that a given mitigation is not enabled; a segfault means that it is.
However, this strategy is vulnerable to a particular kind of false positive: a
segfault caused by a bug on an untested platform will appear to be a working
exploit mitigation.  Therefore, it is necessary to first compile a control
version of mitigation-detector with toolchain support for DEP turned off, and
then verify that the shellcode is successfully executed in each test. This can
be acheived by changing

```
LDFLAGS = -z noexecstack
```

to

```
LDFLAGS = -z execstack
```

in `Makefile`, or, if `execstack` is available, by running

```
execstack --set-execstack mitigation-detector
```

on the default executable. `./mitigation-detector` should then fail with the
following output:

```
FAIL: Stack segment execution prevention
FAIL: Heap segment execution prevention
FAIL: Data segment execution prevention
FAIL: BSS segment execution prevention
```

Once this has been verified, mitigation-detector can be recompiled and run with
the default settings.
