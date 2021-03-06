.. 
   Copyright (C) Internet Systems Consortium, Inc. ("ISC")
   
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/.
   
   See the COPYRIGHT file distributed with this work for additional
   information regarding copyright ownership.

Notes for BIND 9.17.2
---------------------

Security Fixes
~~~~~~~~~~~~~~

-  To prevent exhaustion of server resources by a maliciously configured
   domain, the number of recursive queries that can be triggered by a
   request before aborting recursion has been further limited. Root and
   top-level domain servers are no longer exempt from the
   ``max-recursion-queries`` limit. Fetches for missing name server
   address records are limited to 4 for any domain. This issue was
   disclosed in CVE-2020-8616. [GL #1388]

-  Replaying a TSIG BADTIME response as a request could trigger an
   assertion failure. This was disclosed in CVE-2020-8617. [GL #1703]

Known Issues
~~~~~~~~~~~~

-  In this release, the build system has been significantly changed (see
   below), and there is a number of unresolved issues to be aware of
   when using a development release. Please refer to `GitLab issue #4`_
   for a list of not yet resolved issues that will be fixed in the
   following releases. [GL #4]

.. _GitLab issue #4: https://gitlab.isc.org/isc-projects/bind9/-/issues/4

-  BIND crashes on startup when linked against libuv 1.36. This issue
   is related to ``recvmmsg()`` support in libuv which was first
   included in libuv 1.35. The problem was addressed in libuv 1.37, but
   the relevant libuv code change requires a special flag to be set
   during library initialization in order for ``recvmmsg()`` support to
   be enabled. This BIND release sets that special flag when required,
   so ``recvmmsg()`` support is now enabled when BIND is compiled
   against either libuv 1.35 or libuv 1.37+; libuv 1.36 is still not
   usable with BIND. [GL #1761] [GL #1797]

New Features
~~~~~~~~~~~~

-  The BIND 9 build system has been changed to use a typical
   autoconf+automake+libtool stack. This should not make any difference
   for people building BIND 9 from release tarballs, but when building
   BIND 9 from the Git repository, ``autoreconf -fi`` needs to be run
   first. Extra attention is also needed when using non-standard
   ``./configure`` options. [GL #4]

-  Added a new logging category ``rpz-passthru`` which allows RPZ
   passthru actions to be logged into a separate channel. [GL #54]

-  Zone timers are now exported via statistics channel. For primary
   zones, only the load time is exported. For secondary zones, exported
   timers also include expire and refresh times. Contributed by Paul
   Frieden, Verizon Media. [GL #1232]

-  ``dig`` and other tools can now print the Extended DNS Error (EDE)
   option when it appears in a request or response. [GL #1834]

-  Per-type record count limits can now be specified in ``update-policy``
   statements, to limit the number of records of a particular type
   that can be added to a domain name via dynamic update. [GL #1657]

Feature Changes
~~~~~~~~~~~~~~~

-  BIND 9 no longer sets receive/send buffer sizes for UDP sockets,
   relying on system defaults instead. [GL #1713]

-  The default rwlock implementation has been changed back to the native
   BIND 9 rwlock implementation. [GL #1753]

-  The native PKCS#11 EdDSA implementation has been updated to PKCS#11
   v3.0 and thus made operational again. Contributed by Aaron Thompson.
   [GL !3326]

-  The OpenSSL ECDSA implementation has been updated to support PKCS#11
   via OpenSSL engine (see engine_pkcs11 from libp11 project). [GL
   #1534]

-  The OpenSSL EdDSA implementation has been updated to support PKCS#11
   via OpenSSL engine. Please note that an EdDSA-capable OpenSSL engine
   is required and thus this code is only a proof-of-concept for the
   time being. Contributed by Aaron Thompson. [GL #1763]

-  Message IDs in inbound AXFR transfers are now checked for
   consistency. Log messages are emitted for streams with inconsistent
   message IDs. [GL #1674]

Bug Fixes
~~~~~~~~~

-  A bug in dnstap initialization could prevent some dnstap data from
   being logged, especially on recursive resolvers. [GL #1795]

-  When running on a system with support for Linux capabilities,
   ``named`` drops root privileges very soon after system startup. This
   was causing a spurious log message, *unable to set effective uid to
   0: Operation not permitted*, which has now been silenced. [GL #1042]
   [GL #1090]

-  When ``named-checkconf -z`` was run, it would sometimes incorrectly
   set its exit code. It reflected the status of the last view found; if
   zone-loading errors were found in earlier configured views but not in
   the last one, the exit code indicated success. Thanks to Graham
   Clinch. [GL #1807]

-  When built without LMDB support, ``named`` failed to restart after a
   zone with a double quote (") in its name was added with ``rndc
   addzone``. Thanks to Alberto Fernández. [GL #1695]
