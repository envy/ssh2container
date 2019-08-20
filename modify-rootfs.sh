#!/bin/sh
cp /etc/resolv.conf rootfs/etc/resolv.conf
./ns-persistent
chmod -R og+rx rootfs
rm -f rootfs/etc/resolv.conf
