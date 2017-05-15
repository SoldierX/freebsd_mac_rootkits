freebsd_mac_rootkits
====================

This repo provides Proof-of-Concept (PoC) rootkits for FreeBSD. The
rootkits abuse the MAC framework for various nefarious purposes.

This repo is meant to be used and studied with the soon-to-be-released
SoldierX tutorial covering writing FreeBSD rootkits.

Prerequisites
-------------

1. A FreeBSD system
1. /usr/src on the FreeBSD system populated with the sources that
   match the installed world/kernel.
1. Knowledge of C

Building
--------

```
# make depend
# make all
# make install
```
