#!/bin/sh
cp /etc/resolv.conf rootfs/etc/resolv.conf
./ns-persistent
rm -f rootfs/etc/resolv.conf
chmod -R og+rx rootfs
