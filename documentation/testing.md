Testing
=======

Testing target-isns with Open-iSNS
----------------------------------

The easiest way to test target-isns is to install Open-iSNS on the
same machine.

On a first terminal, start the iSNS daemon in foreground and enable
all debugging facilities:

    $ sudo /usr/sbin/isnsd --foreground --debug all

Then, on a second terminal, start the iSNS client also in foreground
and set the IP address of the iSNS server to localhost:

    $ ./src/target-isns --isns-server 127.0.0.1 --debug
    0.000000 I: target-isns version 0.6.3 started
    0.000036 I: iSNS server is 127.0.0.1:3205

The iSNS client should register your iSCSI targets to the iSNS server
and keep them registered (i.e. refreshing their registration before
the registration period expires). If you hit Ctrl + C, target-isns
deregisters the iSCSI targets and exits.


Testing with fake iSCSI configurations
--------------------------------------

By default, target-isns works by watching the iSCSI configfs directory
that contains the configuration of the Linux kernel target's subsystem
(also known as LIO). This configuration is visible under
`/sys/kernel/config/target/iscsi`.

For testing purposes, you can create a fake configfs hierarchy that
look the same and ask target-isns to browse it. Below is a minimal
fake configfs hierarchy that allows to register a single iSCSI target
containing a single target portal group:

    $ mkdir -p fake-iscsi-path/iqn.2018-01.org.example:disk1
    $ mkdir -p fake-iscsi-path/iqn.2018-01.org.example:disk1/tpgt_1
    $ mkdir -p fake-iscsi-path/iqn.2018-01.org.example:disk1/tpgt_1/np
    $ mkdir -p fake-iscsi-path/iqn.2018-01.org.example:disk1/tpgt_1/np/0.0.0.0:3260
    $ echo 1 > fake-iscsi-path/iqn.2018-01.org.example:disk1/tpgt_1/enable

Then, you can start target-isns with the `--configfs-iscsi-path`
option pointing to the fake configfs hierarchy:

    $ ./src/target-isns --isns-server 127.0.0.1 --debug --configfs-iscsi-path fake-iscsi-path/

With this method, you can emulate large iSCSI configurations with many
iSCSI targets and target portal groups.
