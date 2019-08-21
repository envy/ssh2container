ssh2container
=============

1. Download a rootfs from somewhere, e.g. find the alpine image on Dockerhub, click on latest and download the tar.gz.
2. Extract the rootfs into a `rootfs` folder.
3. Use `./modify-rootfs.sh` to install whatever you want into your base image.
4. Switch the login shell of some user to the `ns` binary.

