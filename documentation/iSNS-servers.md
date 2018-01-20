iSNS servers and target-isns
============================

Target-isns is tested with the following iSNS servers:

* Open-iSNS
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

Default registration periods:

* Open-iSNS: 10 minutes (set in isnsd.conf)
* Microsoft iSNS server: 15 minutes
* OpenIndiana iSNS server: 1 day

Target-isns uses a registration period of 5 minutes (300 seconds). It
sends this value to the iSNS server and it also queries the server
registration period. We observe that Open-iSNS reports its
registration period, allowing target-isns to use the same value. The
Microsoft iSNS server changes its registration period to use our value
but it does not report its registration period to us. On the other
hand, the OpenIndiana iSNS server changes its registration period only
if it is greater than its default registration period. Moreover, the
OpenIndiana iSNS server correctly reports the value of its
registration period to target-isns.  As a consequence, target-isns can
update its registration period to use the same value as the server.

Thus, target-isns uses the following registration periods depending on
the iSNS server:

* Open-iSNS: 10 minutes (Open-iSNS default value)
* Microsoft iSNS server: 5 minutes (target-isns default value)
* OpenIndiana iSNS server: 1 day (OpenIndiana default value)

Portal registration
-------------------

The Microsoft iSNS server returns an error when an iSCSI portal is
listed more than once in the operating attributes of an iSNS
DevAttrReg message. The Microsoft iSNS server probably enforces the
following requirement from RFC 4171:

  5.6.5.1. Device Attribute Registration Request (DevAttrReg)

  "A given object may only appear a maximum of once in the Operating
   Attributes of a message"

Moreover, the Microsoft iSNS server returns an "invalid update" error
if a DevAttrReg request registers a portal that was already registered
by a previous DevAttrReg request.

The OpenIndiana iSNS server has no problem with duplicate portals in a
DevAttrReg message or repetitive registration of a portal by several
DevAttrReg messages.
