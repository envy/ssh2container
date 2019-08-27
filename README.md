ssh2container
=============

Useable as a login shell which spawns a container for each login. Containers are ephemeral and live completely in memory.
This uses user, mount, IPC, PID and UTS namespaces, a tmpfs and a tiny rootfs (e.g. alpine linux) as a base image. It does not require root.
Certain system calls are filtered with seccomp and capabilities are dropped with libcap.


How to use
----------

0. The code assumes that the rootfs is located in /var/lib/ssh2container/rootfs. Other locations have to be specified by changing the defines. Also you need `libcap` and `libseccomp`.
1. Download a rootfs from somewhere, e.g. find the alpine image on Dockerhub, click on latest and download the tar.gz. (e.g. https://github.com/alpinelinux/docker-alpine/tree/v3.10/x86_64)
2. Extract the rootfs into the `rootfs` folder.
3. Modify the defines in ns.c to point to the correct rootfs.
4. Use `./modify-rootfs.sh` to install whatever you want into your base image.
5. Test by executing `ns`.
6. `make install`
6. Switch the login shell of some user to the `/usr/bin/ssh2container` binary.


FAQ
---

Q: Why?
A: Why not? Mainly to learn how to use namespaces without fancy container engines.

Q: This already exists: https://github.com/Yelp/dockersh
A: Yes, but dockersh uses Docker and does not use user namespaces. Also this was mainly done as a learning experience.

Q: This already exists: https://firejail.wordpress.com
A: Yes, but firejail is using setuid and not chroot instead of pivot\_root. chroot is not meant for sandboxing. Also this was mainly done as a learning experience.

Q: This already exists: FreeBSD jails
A: Yes, but this work on linux. Also this was mainly done as a learning experience.

Q: Is this secure?
A: I don't know. Maybe, maybe not. You should probably not run this in production without audting the code.

Q: Why no network namespaces?
A: You can easily add a `CLONE_NET` to the unshare call. However, then your container will not have network functionality which maybe is something you want. If you wat network namespaces and connectivity then a veth pair and bridge on the host side would be required. Probably also a DHCP server. This is too much hassle imho.

Q: Why no cgroups?
A: Because I have not figured out yet how to tell systemd on Debian 10 to only mount cgroups2 and then use the user-slice. There is some experimental code there that is not called and also not working.

Q: Isn't there a risk of DDOS if all containers live in memory and every login spawns a new container?
A: Yes. But even if they would live on the filesystem then at some point the disk would run full with enough simultaneous logins.

Q: Do other rootfs beside alpine work?
A: Probably, I have not tested any. There is no reason why they shouldn't work as long as they have a shell binary.

Q: What does the binary name `ns` stand for?
A: NameSpace.

Q: Do `rsync` and `scp` work?
A: Yes.

