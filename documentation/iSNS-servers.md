iSNS servers and target-isns
============================

Target-isns is tested with the following iSNS servers:

 * Microsoft 2012 R2 iSNS server
 * OpenIndiana iSNS server

If you use another iSNS server, please tell us if target-isns works
for you.

With different iSNS servers come different behaviors. This document
describes the difference observed so far while testing target-isns
with several iSNS servers.

iSNS registration period
------------------------

For a description of the iSNS registration period please refer to
section "6.2.6 Registration Period" of RFC 4171:

 * [RFC 4171, 6.2.6](http://tools.ietf.org/html/rfc4171#section-6.2.6)

The default registration period of the Microsoft iSNS server is 15
minutes (900 seconds) whereas the default registration period of the
OpenIndiana iSNS server is 1 day (86400 seconds).

Target-isns uses a registration period of 5 minutes (300 seconds). It
sends this value to the iSNS server and it also queries the server
registration period. We observe that the Microsoft iSNS server changes
its registration period to use our value but it does not report its
registration period to us. On the other hand, the OpenIndiana iSNS
server changes its registration period only if it is greater than its
default registration period. Moreover, the OpenIndiana iSNS server
correctly reports the value of its registration period to target-isns.
As a consequence, target-isns can update its registration period to
use the same value as the server.

Thus, target-isns uses the following registration periods depending on
the iSNS server:

* Microsoft iSNS server: 5 minutes (target-isns default value)
* OpenIndiana iSNS server: 1 day (OpenIndiana default value)
