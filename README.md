Erebos/C++
==========

Library implementing the Erebos identity management, decentralized messaging
and synchronization protocol, along with local storage. Specification being
created at:

[http://erebosprotocol.net](http://erebosprotocol.net)

Erebos identity is based on locally stored cryptographic keys, all
communication is end-to-end encrypted. Multiple devices can be attached to the
same identity, after which they function interchangeably, without any one being
in any way "primary"; messages and other state data are then synchronized
automatically whenever the devices are able to connect with one another.

Status
------

This is experimental implementation of yet unfinished specification, so
changes, especially in the library API, are expected. Storage format and
network protocol should generally remain backward compatible, with their
respective versions to be increased in case of incompatible changes, to allow
for interoperability even in that case.

Build
-----

This library uses CMake for building:

```
cmake -B build
cmake --build build
```

Usage
-----

The API is currently experimental and without documentation; some example of
usage can be found in the test executable (`src/main.cpp`).
