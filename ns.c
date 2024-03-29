#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <sched.h>
#include <seccomp.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/capability.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <systemd/sd-bus.h>
#include <unistd.h>

#define TMP_DIR_NAME "/tmp/container."
#define ROOTFS_PREFIX "/var/lib/ssh2container"
#define ROOTFS_FOLDER "rootfs"
#define ROOTFS_LOCATION ROOTFS_PREFIX "/" ROOTFS_FOLDER
#define ROOTFS_SIZE "150m"
#define ROOTFS_INODES "15k"
#define CGROUP_BASE "/sys/fs/cgroup"
#define MEMORY (1024ll * 1024 * 1024) // 1GB
//#define MEMORY 4096
#define SHELL "/bin/sh"
#define INIT "/sbin/tini"

#ifndef ROOTFS_PERSISTENT
#define ROOTFS_PERSISTENT 0
#endif

#ifndef USE_TINI
#define USE_TINI 1
#endif

#ifndef DEBUG
#define DEBUG 0
#endif
void debug(const char *format, ...)
#if DEBUG
{
	va_list args;
	va_start(args, format);
	vprintf(format, args);
	fflush(stdout);
	va_end(args);
}
#else
{
	(void)format;
}
#endif

int pivot_root(const char *new_root, const char *put_old)
{
	return syscall(SYS_pivot_root, new_root, put_old);
}

static sd_bus_error bus_error = SD_BUS_ERROR_NULL;
static sd_bus *bus = NULL;

void cleanup()
{
	sd_bus_error_free(&bus_error);
	sd_bus_unref(bus);
}

void setup_dbus()
{
	debug("=> Connecting to D-Bus... ");

	int r = 0;

	if (getuid() == 0)
	{
		if ((r = sd_bus_open_system(&bus)) < 0)
		{
			fprintf(stderr, "sd_bus_open_system: %s\n", strerror(-r));
			exit(1);
		}
		goto after_connect;
	}

	if ((r = sd_bus_open_user(&bus)) < 0)
	{
		fprintf(stderr, "sd_bus_default: %s\n", strerror(-r));
		exit(1);
	}

after_connect:;
	// Now create a transient slice
	char *slicename;
	asprintf(&slicename, "ssh2container-%d.slice", getpid());
	debug("Creating slice %s...", slicename);

	sd_bus_message *msg = NULL;
	if ((r = sd_bus_call_method(bus, "org.freedesktop.systemd1", "/org/freedesktop/systemd1", "org.freedesktop.systemd1.Manager", "StartTransientUnit", &bus_error, &msg,
	                            "ssa(sv)a(sa(sv))",
	                            slicename,
	                            "fail",
	                            1,
	                            "Description", "s", "ssh2container slice",
//	                            "CPUAccounting", "b", 1,
//	                            "MemoryAccounting", "b", 1,
	                            0)) < 0)
	{
		fprintf(stderr, "call StartTransientUnit: %s / %s: %s\n", strerror(-r), bus_error.name, bus_error.message);
		exit(1);
	}

	const char *path;
	if ((r = sd_bus_message_read(msg, "o", &path)) < 0)
	{
		fprintf(stderr, "read StartTransientUnit: %s\n", strerror(-r));
		exit(1);
	}
	sd_bus_message_unref(msg);

	char *servicename;
	asprintf(&servicename, "ssh2container-%d.scope", getpid());
	debug("Creating scope %s...", servicename);
	if ((r = sd_bus_call_method(bus, "org.freedesktop.systemd1", "/org/freedesktop/systemd1", "org.freedesktop.systemd1.Manager", "StartTransientUnit", &bus_error, &msg,
	                            "ssa(sv)a(sa(sv))",
	                            servicename,
	                            "fail",
	                            4,
	                            "Description", "s", "ssh2container scope",
	                            "Delegate", "b", 1,
	                            "Slice", "s", slicename,
	                            "PIDs", "au", 1, getpid(),
	                            0)) < 0)
	{
		fprintf(stderr, "call StartTransientUnit: %s / %s: %s\n", strerror(-r), bus_error.name, bus_error.message);
		exit(1);
	}

	if ((r = sd_bus_message_read(msg, "o", &path)) < 0)
	{
		fprintf(stderr, "read StartTransientUnit: %s\n", strerror(-r));
		exit(1);
	}

	sd_bus_message_unref(msg);

	free(slicename);
	free(servicename);
	debug("done\n");
}

void setup_namespaces()
{
	int namespaces = 0;
	namespaces |= CLONE_NEWUTS; // New UTS namespace
	namespaces |= CLONE_NEWPID; // New PID namespace
	namespaces |= CLONE_NEWIPC; // New IPC namespace
	namespaces |= CLONE_NEWNS; // New mount namespace
	namespaces |= CLONE_NEWUSER; // New user namespace

	debug("=> Creating namespaces... ");

	if (unshare(namespaces) != 0)
	{
		perror("unshare");
		exit(1);
	}

	debug("done\n");
}

void write_to_file(const char *path, const char *content)
{
	int fd = open(path, O_RDWR);
	if (fd < 0)
	{
		debug("Could not open %s\n", path);
		perror("open");
		exit(1);
	}

	errno = 0;
	int offset = 0, last = 0, length = strlen(content);
	while ((last = write(fd, content + offset, length - offset)) > 0)
	{
		offset += last;
		if (offset == length)
		{
			break;
		}
	}
	if (last <= 0)
	{
		if (errno != 0)
		{
			debug("Error writing to %s\n", path);
			perror("write");
			exit(1);
		}
	}

	close(fd);
}

void setup_cgroups(uid_t uid)
{
	debug("=> Setting up cgroups2... ");

	char path[1024] = {};
	if (uid == 0)
	{
		if (snprintf(path, 1024, CGROUP_BASE "/ssh2container.slice/ssh2container-%d.slice", getpid()) < 0)
		{
			perror("snprintf cgroups path");
			exit(1);
		}
	}
	else
	{
		if (snprintf(path, 1024, CGROUP_BASE "/user.slice/user-%d.slice/user@%d.service/ssh2container.slice/ssh2container-%d.slice", uid, uid, getpid()) < 0)
		{
			perror("snprintf cgroups path");
			exit(1);
		}
	}

	char scopepath[1024] = {};
	if (snprintf(scopepath, 1024, "%s/ssh2container-%d.scope", path, getpid()) < 0)
	{
		perror("snprintf cgroups scope path");
		exit(1);
	}

	debug("Waiting for scope ");
	while (1)
	{
		DIR *dir = opendir(scopepath);
		if (dir)
		{
			debug("\n");
			break;
		}
		else if (ENOENT == errno)
		{
			debug(".");
		}
	}

	debug("cgroups base path: %s\n", path);

	char *curpath = NULL;
	// enable memory controller
	debug("Enabling memory controller\n");
	free(curpath);
	asprintf(&curpath, "%s/cgroup.subtree_control", path);
	char *controllerstring;
	asprintf(&controllerstring, "+memory\n");
	write_to_file(curpath, controllerstring);
	free(controllerstring);

	// set high
	debug("Setting high memory: %llu\n", MEMORY);
	free(curpath);
	asprintf(&curpath, "%s/ssh2container-%d.scope/memory.high", path, getpid());
	char *highmemorystring;
	asprintf(&highmemorystring, "%llu\n", MEMORY);
	write_to_file(curpath, highmemorystring);
	free(highmemorystring);

	// set maximum
	debug("Setting maximum memory: %llu\n", MEMORY);
	free(curpath);
	asprintf(&curpath, "%s/ssh2container-%d.scope/memory.max", path, getpid());
	char *maxmemorystring;
	asprintf(&maxmemorystring, "%llu\n", MEMORY);
	write_to_file(curpath, maxmemorystring);
	free(maxmemorystring);

	if (unshare(CLONE_NEWCGROUP) != 0)
	{
		perror("unshare cgroup");
		exit(1);
	}

	free(curpath);
	debug("done\n");
}

void setup_cgroups_2()
{
	debug("Finish cgroups setup... ");


	if (mkdir("/sys", 0755) < 0)
	{
		if (errno != EEXIST)
		{
			perror("mkdir /sys");
			exit(1);
		}
	}

	if (mkdir("/sys/fs", 0755) < 0)
	{
		if (errno != EEXIST)
		{
			perror("mkdir /sys/fs");
			exit(1);
		}
	}

	if (mkdir("/sys/fs/cgroup", 0755) < 0)
	{
		if (errno != EEXIST)
		{
			perror("mkdir /sys/fs/cgroup");
			exit(1);
		}
	}

	if (mount("sandbox-cgroup", "/sys/fs/cgroup", "cgroup2", 0, NULL) < 0)
	{
		perror("mount cgroup");
		exit(1);
	}

	debug("done\n");
}

// Taken from here: https://stackoverflow.com/a/2180788
int cp(const char *to, const char *from)
{
	int fd_to, fd_from;
	char buf[4096];
	ssize_t nread;
	int saved_errno;

	fd_from = open(from, O_RDONLY);
	if (fd_from < 0)
		return -1;

	fd_to = open(to, O_WRONLY | O_CREAT | O_EXCL, 0666);
	if (fd_to < 0)
		goto out_error;

	while (nread = read(fd_from, buf, sizeof buf), nread > 0)
	{
		char *out_ptr = buf;
		ssize_t nwritten;

		do
		{
			nwritten = write(fd_to, out_ptr, nread);

			if (nwritten >= 0)
			{
				nread -= nwritten;
				out_ptr += nwritten;
			}
			else if (errno != EINTR)
			{
				goto out_error;
			}
		} while (nread > 0);
	}

	if (nread == 0)
	{
		if (close(fd_to) < 0)
		{
			fd_to = -1;
			goto out_error;
		}
		close(fd_from);

		/* Success! */
		return 0;
	}

out_error:
	saved_errno = errno;

	close(fd_from);
	if (fd_to >= 0)
		close(fd_to);

	errno = saved_errno;
	return -1;
}

/*
 * Linked list implementation needed for remembering which hardlinks have already been copied and where to.
 */

typedef struct __link_list
{
	struct __link_list *next;
	ino_t inode;
	char path[256];
} link_list_t;

link_list_t *link_list = NULL;

void link_list_add(ino_t inode, const char *path)
{
	link_list_t *new_elem = calloc(1, sizeof(link_list_t));
	new_elem->inode = inode;
	strncpy(new_elem->path, path, 256);

	if (link_list == NULL)
	{
		link_list = new_elem;
		return;
	}

	link_list_t *it = link_list;
	while (it->next != NULL)
	{
		it = it->next;
	}

	it->next = new_elem;
}

link_list_t *link_list_find(ino_t inode)
{
	if (link_list == NULL)
	{
		return NULL;
	}

	link_list_t *it = link_list;
	while (it != NULL && it->inode != inode)
	{
		it = it->next;
	}

	return it;
}

void link_list_clear()
{
	link_list_t *it = link_list;
	link_list = NULL;
	while (it != NULL)
	{
		link_list_t *temp = it;
		it = it->next;
		free(temp);
	}
}

/*
 * Copies the rootfs from its on-disk location into the created tmpfs.
 */
void copy_rootfs(const char *source, char *dest)
{
	DIR *dir = opendir(source);
	if (dir == NULL)
	{
		perror("opendir copy rootfs");
		exit(1);
	}
	char path[PATH_MAX] = {0}, *endptr = path;
	struct dirent *e;
	int res = 0;
	if ((res = snprintf(path, PATH_MAX, "%s/", source)) >= PATH_MAX || res < 0)
	{
		// String was truncated or error
		perror("snprintf copy rootfs");
		exit(1);
	}
	endptr += strlen(source) + 1;
	while ((e = readdir(dir)) != NULL)
	{
		struct stat info;
		if (strncmp(e->d_name, ".", 1) == 0 || strncmp(e->d_name, "..", 2) == 0)
		{
			// Don't get cought in a directory loop..
			continue;
		}
		strncpy(endptr, e->d_name, PATH_MAX - strlen(source) - 2); // minus two to ensure a NUL byte at the end
		if (!lstat(path, &info))
		{
			bool add_hardlink = false;
			char dpath[PATH_MAX] = {0}, *dendptr = dpath;
			if ((res = snprintf(dpath, PATH_MAX, "%s/", dest)) >= PATH_MAX || res < 0)
			{
				perror("snprintf copy rootfs dest");
				exit(1);
			}
			dendptr += strlen(dest) + 1;
			strncpy(dendptr, e->d_name, PATH_MAX - strlen(dest) - 2); // same here as above

			// Check if more than one hardlink exists
			if (info.st_nlink > 1)
			{
				// Check if we already have copiedthe links destination
				link_list_t *file = link_list_find(info.st_ino);
				if (file != NULL)
				{
					// We have, create a link
					link(file->path, dpath);
					continue;
				}
				else
				{
					add_hardlink = true;
				}
			}

			if (S_ISLNK(info.st_mode))
			{
				// File is a symlink, create that
				char target[256] = {0};
				if (readlink(path, target, 256) < 0)
				{
					perror("readlink");
					exit(1);
				}
				if (symlink(target, dpath) < 0)
				{
					debug("Could not create symlink form %s to %s\n", dpath, target);
					perror("symlink");
					exit(1);
				}
			}
			else if (S_ISDIR(info.st_mode))
			{
				if (mkdir(dpath, 0755) < 0)
				{
					perror("mkdir");
					exit(1);
				}
				copy_rootfs(path, dpath);
				if (chmod(dpath, info.st_mode) < 0)
				{
					perror("chmod copy rootfs");
					exit(1);
				}
			}
			else if (S_ISREG(info.st_mode))
			{
				if (cp(dpath, path) < 0)
				{
					debug("could not copy %s to %s\n", path, dpath);
					perror("cp");
					exit(1);
				}
				if (chmod(dpath, info.st_mode) < 0)
				{
					perror("chmod copy rootfs");
					exit(1);
				}
				if (add_hardlink)
				{
					link_list_add(info.st_ino, dpath);
				}
			}
		}
	}
}

void setup_sandbox(const char *rootfs, const char *username)
{
	debug("=> Remounting / as private and mounting rootfs... ");

	// mount / as private (--make-rpivate) to not leak changes upward
	if (mount("none", "/", NULL, MS_REC | MS_PRIVATE, NULL) < 0) // NULL as first argument also works
	{
		perror("mount /");
		exit(1);
	}

#if ROOTFS_PERSISTENT
	(void)username;

	if (mount(rootfs, rootfs, NULL, MS_BIND | MS_NOSUID, NULL) < 0)
	{
		perror("mount rootfs");
		exit(1);
	}

	// change to rootfs
	if (chdir(rootfs))
	{
		perror("chdir rootfs");
		exit(1);
	}
#else
	char mount_dir[PATH_MAX] = {0};
	int res = 0;
	// creating the temp directory
	if ((res = snprintf(mount_dir, PATH_MAX, "%s%s", TMP_DIR_NAME, username)) >= PATH_MAX || res < 0)
	{
		perror("snprintf setup sendbox");
		exit(1);
	}

	// check if folder exists
	struct stat s;
	if (lstat(mount_dir, &s) < 0)
	{
		if (errno != ENOENT)
		{
			perror("lstat");
			exit(1);
		}

		if (mkdir(mount_dir, 0755) < 0)
		{
			perror("mkdir");
			exit(1);
		}
	}

	// mount a tmpfs onto mount_dir for our rootfs
	if (mount("sandbox-rootfs-tmpfs", mount_dir, "tmpfs", 0, "size=" ROOTFS_SIZE ",mode=755,nr_inodes=" ROOTFS_INODES) < 0)
	{
		perror("mount rootfs tmpfs");
		exit(1);
	}

	debug("copying rootfs... ");
	copy_rootfs(rootfs, mount_dir);
	link_list_clear();

	// copy /etc/resolv.conf
	char path[PATH_MAX] = {0};
	if ((res = snprintf(path, PATH_MAX, "%s/etc/resolv.conf", mount_dir)) >= PATH_MAX || res < 0)
	{
		perror("snprintf resolv.conf");
		exit(1);
	}
	if (cp(path, "/etc/resolv.conf") != 0)
	{
		perror("cp resolv.conf");
	}

	if (mount(mount_dir, mount_dir, NULL, MS_BIND | MS_REMOUNT | MS_NOSUID, NULL) < 0)
	{
		perror("mount rootfs");
		exit(1);
	}

	// change to rootfs
	if (chdir(mount_dir))
	{
		perror("chdir rootfs");
		exit(1);
	}
#endif

	debug("done\n");
}

void setup_id_maps(uid_t uid, gid_t gid)
{
	char buf[1024];
	int res = 0;
	uid_t newuid = 0;
	gid_t newgid = 0;

	debug("=> Mapping %d/%d to 0/0... ", uid, gid);

	// map new UID/GID to outer UID/GID
	if ((res = snprintf(buf, 1024, "%d %d 1\n", newuid, uid)) >= 1024 || res < 0)
	{
		perror("snprintf uidmap");
		exit(1);
	}

	int fd = open("/proc/self/uid_map", O_WRONLY);
	if (fd < 0)
	{
		perror("open uidmap");
		exit(1);
	}
	if (write(fd, buf, strlen(buf)) < 0)
	{
		perror("write uidmap");
		exit(1);
	}
	if (close(fd) < 0)
	{
		perror("close uidmap");
		exit(1);
	}

	// must disallow setgroups() before writing to gid_map on
	// versions of linux with this feature:
	if ((fd = open("/proc/self/setgroups", O_WRONLY)) >= 0)
	{
		write(fd, "deny", 4);
		close(fd);
	}
	if ((res = snprintf(buf, 1024, "%d %d 1\n", newgid, gid)) >= 1024 || res < 0)
	{
		perror("snprintf gidmap");
		exit(1);
	}

	fd = open("/proc/self/gid_map", O_WRONLY);
	if (fd < 0)
	{
		perror("open gidmap");
		exit(1);
	}
	if (write(fd, buf, strlen(buf)) < 0)
	{
		perror("write gidmap");
		exit(1);
	}
	if (close(fd) < 0)
	{
		perror("close gidmap");
		exit(1);
	}

	//initially we're nobody, change to newgid/newuid
	if (setresgid(newgid, newgid, newgid) < 0)
	{
		perror("setresgid");
		exit(1);
	}
	if (setresuid(newuid, newuid, newuid) < 0)
	{
		perror("setresgid");
		exit(1);
	}

	debug("done\n");
}

void setup_fake_dev()
{
	debug("=> Creating minimal /dev... ");

	// Delete and recreate dev
	if (rmdir("dev") < 0)
	{
		if (errno != ENOENT)
		{
			perror("rmdir dev");
			exit(1);
		}
	}
	if (mkdir("dev", 0755) < 0)
	{
		perror("mkdir dev");
		exit(1);
	}

	if (mount("sandbox-dev", "dev", "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_NOATIME, "size=64k,nr_inodes=16,mode=755") < 0)
	{
		perror("mount dev");
		exit(1);
	}

	// Create nodes
	if (mknod("dev/null", S_IFREG | 0666, 0) < 0)
	{
		perror("mknod dev/null");
		exit(1);
	}
	if (mknod("dev/zero", S_IFREG | 0666, 0) < 0)
	{
		perror("mknod dev/zero");
		exit(1);
	}
	if (mknod("dev/full", S_IFREG | 0666, 0) < 0)
	{
		perror("mknod dev/full");
		exit(1);
	}
	if (mknod("dev/random", S_IFREG | 0666, 0) < 0)
	{
		perror("mknod dev/random");
		exit(1);
	}
	if (mknod("dev/urandom", S_IFREG | 0666, 0) < 0)
	{
		perror("mknod dev/urandom");
		exit(1);
	}

	// Now mount the dev devices
	if (mount("/dev/null", "dev/null", NULL, MS_BIND, NULL) < 0)
	{
		perror("mount /dev/null");
		exit(1);
	}
	if (mount("/dev/zero", "dev/zero", NULL, MS_BIND, NULL) < 0)
	{
		perror("mount /dev/zero");
		exit(1);
	}
	if (mount("/dev/full", "dev/full", NULL, MS_BIND, NULL) < 0)
	{
		perror("mount /dev/full");
		exit(1);
	}
	if (mount("/dev/random", "dev/random", NULL, MS_BIND, NULL) < 0)
	{
		perror("mount /dev/random");
		exit(1);
	}
	if (mount("/dev/urandom", "dev/urandom", NULL, MS_BIND, NULL) < 0)
	{
		perror("mount /dev/urandom");
		exit(1);
	}

	// Also link some others
	if (symlink("/proc/self/fd/0", "dev/stdin"))
	{
		perror("symlink /dev/stdin");
		exit(1);
	}
	if (symlink("/proc/self/fd/1", "dev/stdout"))
	{
		perror("symlink /dev/stdin");
		exit(1);
	}
	if (symlink("/proc/self/fd/1", "dev/stderr"))
	{
		perror("symlink /dev/stdin");
		exit(1);
	}

	// and remount readonly
	if (mount("sandbox-dev", "dev", NULL, MS_REMOUNT | MS_BIND | MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_NOATIME | MS_RDONLY, NULL) < 0)
	{
		perror("remount dev");
		exit(1);
	}

	debug("done\n");
}

void setup_tmp()
{
	debug("=> Creating /tmp... ");

	if (rmdir("tmp") < 0)
	{
		if (errno != ENOENT)
		{
			perror("rmdir tmp");
			exit(1);
		}
	}

	if (mkdir("tmp", 0770) < 0)
	{
		perror("mkdir tmp");
		exit(1);
	}

	if (mount("sandbox-tmp", "tmp", "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_NOATIME, "size=16m,nr_inodes=4k,mode=770") < 0)
	{
		perror("mount tmp");
		exit(1);
	}

	debug("done\n");
}

void setup_home()
{
	debug("=> Mounting home... ");

	char *home = getenv("HOME");
	if (home == NULL)
	{
		// User has no home?
		debug("user has no home.\n");
		return;
	}

	if (mount(home, "root", NULL, MS_BIND, NULL) < 0)
	{
		perror("mount home");
		exit(1);
	}

	debug("done\n");
}

void setup_mnt()
{
	debug("=> Mounting /mnt... ");

	struct stat st;
	if (lstat("/mnt", &st) != 0)
	{
		if (errno == ENOENT)
		{
			// mnt doesn't exist, don't mount it into container
			debug("does not exist\n");
			return;
		}
		perror("lstat mnt");
		exit(1);
	}

	if (mount("/mnt", "mnt", NULL, MS_BIND | MS_RDONLY, NULL) < 0)
	{
		perror("mount mnt");
		exit(1);
	}

	debug("done\n");
}

void setup_proc()
{
	debug("=> Mounting old /proc... ");

	if (rmdir(".oldproc") < 0)
	{
		if (errno != ENOENT)
		{
			perror("rmdir oldproc");
			exit(1);
		}
	}
	if (rmdir("proc") < 0)
	{
		if (errno != ENOENT)
		{
			perror("rmdir proc");
			exit(1);
		}
	}

	if (mkdir(".oldproc", 0755) < 0) // We need the old proc to mount our new proc
	{
		perror("mkdir oldproc");
		exit(1);
	}
	if (mkdir("proc", 0755) < 0)
	{
		perror("mkdir proc");
		exit(1);
	}

	if (mount("/proc", ".oldproc", NULL, MS_BIND | MS_REC, NULL) < 0)
	{
		perror("mount proc");
		exit(1);
	}

	debug("done\n");
}

void setup_root()
{
	debug("=> Pivoting root... ");

	// delete old dirs and create new ones
	if (rmdir(".oldroot") < 0)
	{
		if (errno != ENOENT)
		{
			perror("rmdir oldroot");
			exit(1);
		}
	}
	if (mkdir(".oldroot", 0755) < 0)
	{
		perror("mkdir oldroot");
		exit(1);
	}

	// Change root, keep old one
	if (pivot_root(".", ".oldroot") < 0)
	{
		perror("pivot_root");
		exit(1);
	}

	if (umount2(".oldroot", MNT_DETACH) < 0)
	{
		perror("umount2 oldroot");
		exit(1);
	}

	if (rmdir(".oldroot") < 0)
	{
		if (errno != ENOENT)
		{
			perror("rmdir oldroot");
			exit(1);
		}
	}

	debug("done\n");
}

void setup_proc_2()
{
	debug("=> Mounting new /proc... ");

	// mount proc for correct pids
	if (mount("sandbox-proc", "/proc", "proc", MS_NOSUID | MS_NOEXEC | MS_NODEV | MS_RDONLY, NULL) < 0)
	{
		perror("mount proc");
		exit(1);
	}

	// unmount old proc
	if (umount2("/.oldproc", MNT_DETACH) < 0)
	{
		perror("umount oldproc");
		exit(1);
	}
	if (rmdir("/.oldproc") < 0)
	{
		perror("delete oldproc");
		exit(1);
	}

	debug("done\n");
}

void setup_root_2()
{
	debug("=> Really mounting rootfs now... ");

	if (mount("/", "/", NULL, MS_BIND | MS_REMOUNT, NULL) < 0)
	{
		perror("mount new root");
		exit(1);
	}

	debug("done\n");
}

void mask_proc()
{
	debug("=> Masking sensitive proc files... ");

	if (mount("/dev/null", "/proc/sched_debug", NULL, MS_BIND, NULL) < 0)
	{
		perror("sched_debug mask");
		exit(1);
	}

	debug("done\n");
}

#define SCMP_FAIL SCMP_ACT_ERRNO(EPERM)
void filter_syscalls()
{
	scmp_filter_ctx ctx = NULL;
	int rc = 0;
	debug("=> Filtering system calls... ");

	if (!(ctx = seccomp_init(SCMP_ACT_ALLOW)))
	{
		perror("seccomp init");
		exit(1);
	}

	if (0
	    // Do not allow setuid/setgid bit setting
	    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(chmod), 1, SCMP_A1(SCMP_CMP_MASKED_EQ, S_ISUID, S_ISUID)) //.
	    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(chmod), 1, SCMP_A1(SCMP_CMP_MASKED_EQ, S_ISGID, S_ISGID)) //.
	    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(fchmod), 1, SCMP_A1(SCMP_CMP_MASKED_EQ, S_ISUID, S_ISUID)) //.
	    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(fchmod), 1, SCMP_A1(SCMP_CMP_MASKED_EQ, S_ISGID, S_ISGID)) //.
	    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(fchmodat), 1, SCMP_A2(SCMP_CMP_MASKED_EQ, S_ISUID, S_ISUID)) //.
	    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(fchmodat), 1, SCMP_A2(SCMP_CMP_MASKED_EQ, S_ISGID, S_ISGID)) //.
	    // Do not allow creation of new user namespaces
	    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(unshare), 1, SCMP_A0(SCMP_CMP_MASKED_EQ, CLONE_NEWUSER, CLONE_NEWUSER)) //.
	    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(clone), 1, SCMP_A2(SCMP_CMP_MASKED_EQ, CLONE_NEWUSER, CLONE_NEWUSER)) //.
	    // Prevent joining other namespaces
	    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(setns), 0) //.
	    // Do not allow the TIOCSTI ioctl
	    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(ioctl), 1, SCMP_A1(SCMP_CMP_EQ, TIOCSTI)) //.
	    // Prevent access to kernel keyring
	    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(keyctl), 0) //.
	    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(add_key), 0) //.
	    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(request_key), 0) //.
	    // Prevent ptrace
	    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(ptrace), 0) //.
	    // Prevent access to NUMA syscalls
	    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(mbind), 0) //.
	    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(migrate_pages), 0) //.
	    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(move_pages), 0) //.
	    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(set_mempolicy), 0) //.
	    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(get_mempolicy), 0) //.
	    // Prevent user mode page fault handlers
	    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(userfaultfd), 0) //.
	    // Prevent perf in case of perf_event_paranoid < 2
	    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(perf_event_open), 0) //.
	    // Prevent accounting
	    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(acct), 0) //.
	    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(quotactl), 0) //.
	    // Prevent bpf
	    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(bpf), 0) //.
	    // Prevent setting time/date
	    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(settimeofday), 0) //.
	    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(stime), 0) //.
	    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(clock_adjtime), 0) //.
	    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(clock_settime), 0) //.
	    // Prevent modifications to kernel modules
	    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(init_module), 0) //.
	    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(create_module), 0) //.
	    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(delete_module), 0) //.
	    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(finit_module), 0) //.
	    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(query_module), 0) //.
	    // Prevent access to kernel symbols
	    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(get_kernel_syms), 0) //.
	    // Prevent modifications of kernel io privilege levels
	    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(iopl), 0) //.
	    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(ioperm), 0) //.
	    // Prevent process inspection
	    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(kcmp), 0) //.
	    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(lookup_dcookie), 0) //.
	    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(process_vm_readv), 0) //.
	    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(process_vm_writev), 0) //.
	    // Prevent loding new kernels
	    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(kexec_file_load), 0) //.
	    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(kexec_load), 0) //.
	    // Prevent mount/umount
	    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(mount), 0) //.
	    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(umount), 0) //.
	    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(umount2), 0) //.
	    // Prevent old container exploits
	    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(name_to_handle_at), 0) //.
	    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(open_by_handle_at), 0) //.
	    // Prevent access to nfs kernel daemon
	    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(nfsservctl), 0) //.
	    // Prevent BSD emulation
	    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(personality), 0) //.
	    // Prevent pivot_root
	    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(pivot_root), 0) //.
	    // Prevent reboot
	    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(reboot), 0) //.
	    // Prevent swap control
	    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(swapon), 0) //.
	    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(swapoff), 0) //.
	    // Prevent obsolete syscalls
	    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(sysfs), 0) //.
	    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(_sysctl), 0) //.
	    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(ustat), 0) //.
	    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(uselib), 0) //.
	    // Prevent access to in-kernel x86 real mode vm
	    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(vm86), 0) //.
	    || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(vm86old), 0) //.
	    // Prevent setuid/setcap binaries form executing
	    || seccomp_attr_set(ctx, SCMP_FLTATR_CTL_NNP, 0) //.
	)
	{
		seccomp_release(ctx);
		perror("seccomp rule add");
		exit(1);
	}

	if ((rc = seccomp_load(ctx)) < 0)
	{
		printf("seccomp load: %s\n", strerror(-rc));
		exit(1);
	}

	seccomp_release(ctx);
	debug("done\n");
}

void drop_capabilities()
{
	debug("=> Dropping capabilities... ");

	int drop_caps[] = {
	    CAP_AUDIT_CONTROL,
	    CAP_AUDIT_READ,
	    CAP_AUDIT_WRITE,
	    CAP_BLOCK_SUSPEND,
	    CAP_DAC_READ_SEARCH,
	    CAP_FSETID,
	    CAP_IPC_LOCK,
	    CAP_MAC_ADMIN,
	    CAP_MAC_OVERRIDE,
	    CAP_MKNOD,
	    CAP_SETFCAP,
	    CAP_SYSLOG,
	    CAP_SYS_BOOT,
	    CAP_SYS_ADMIN,
	    CAP_SYS_BOOT,
	    CAP_SYS_MODULE,
	    CAP_SYS_NICE,
	    CAP_SYS_PACCT,
	    CAP_SYS_PTRACE,
	    CAP_SYS_RAWIO,
	    CAP_SYS_RESOURCE,
	    CAP_SYS_TIME,
	    CAP_WAKE_ALARM};

	size_t num_caps = sizeof(drop_caps) / sizeof(*drop_caps);
	debug("bounding... ");
	for (size_t i = 0; i < num_caps; i++)
	{
		if (prctl(PR_CAPBSET_DROP, drop_caps[i], 0, 0, 0))
		{
			perror("prctl");
			exit(1);
		}
	}

	debug("inheritable... ");
	cap_t caps = NULL;
	if (!(caps = cap_get_proc()) || cap_set_flag(caps, CAP_INHERITABLE, num_caps, drop_caps, CAP_CLEAR) || cap_set_proc(caps))
	{
		perror("cap_*");
		if (caps)
		{
			cap_free(caps);
		}
		exit(1);
	}
	cap_free(caps);

	debug("done\n");
}

void run_command(char **argv)
{
	pid_t pid = fork();
	if (pid < 0)
	{
		perror("fork run command");
		exit(1);
	}
	if (pid == 0)
	{
		// child
		if (execve(argv[0], argv, NULL) < 0)
		{
			perror("execve");
		}
		exit(1);
	}
	// else: parent, wait for child
	waitpid(pid, NULL, 0);
}

int main(int argc, char **argv)
{
	(void)argc;
	(void)argv;
	pid_t childpid;
	uid_t uid = getuid();
	gid_t gid = getgid();
	struct passwd *pw = getpwuid(uid);
	if (pw == NULL)
	{
		perror("getpwuid");
		exit(1);
	}
	char *username = strdup(pw->pw_name);
	if (username == NULL)
	{
		perror("strdup username");
		exit(1);
	}

	atexit(cleanup);

	char *rootfs;
	rootfs = ROOTFS_LOCATION;

	if (rootfs[0] != '/')
	{
		// path is relative, add binary storage directory
		char *prefix = calloc(1, 256);
		readlink("/proc/self/exe", prefix, 256);
		while (prefix[strlen(prefix) - 1] != '/')
		{
			prefix[strlen(prefix) - 1] = 0;
		}
		asprintf(&rootfs, "%s%s", prefix, ROOTFS_LOCATION);
	}

#if DEBUG
	char **a = argv;
	while (*a != NULL)
	{
		debug("[%s] ", *a);
		a++;
	}
	debug("\n");
#endif

	// setup dbus
	setup_dbus();

	// setup namespaces
	setup_namespaces();

	// setup id maps
	setup_id_maps(uid, gid);

#if !ROOTFS_PERSISTENT
	// setup cgroups
	setup_cgroups(uid);
#endif

	// setup sandbox
	setup_sandbox(rootfs, username);

	// setup minmal dev
	setup_fake_dev();

	// setup tmp
	setup_tmp();

	// setup proc
	setup_proc();

	// setup home
	setup_home();

	// setup mnt
	setup_mnt();

	// pivot to rootfs
	setup_root();

	// Now fork!
	childpid = fork();
	if (childpid < 0)
	{
		perror("fork container");
		exit(1);
	}

	if (childpid == 0) // We are in child
	{
		// Finish proc mount
		setup_proc_2();

		// Make proc more secure by masking some files
		mask_proc();

		// Finish rootfs mount
		setup_root_2();

		// set hostname
		if (sethostname("container", 9) != 0)
		{
			perror("hostname");
			exit(1);
		}

#if !ROOTFS_PERSISTENT
		setup_cgroups_2();
#endif

		filter_syscalls();

		drop_capabilities();

		// sanitize environment
		char *envp[6];
		envp[0] = "PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin";
		envp[1] = "LANG=en_US.UTF-8";
		envp[2] = "TERM=xterm-256color";
		envp[3] = "HOME=/root";
		envp[4] = "PAGER=less";
		envp[5] = NULL;

		// set working directory to home
		if (chdir("/root") < 0)
		{
			perror("chdir home");
			// This is ok, we are still inside the container, just not inside the home
		}

		// check if there is a .SHELL symlink in the users home
		char *shell = SHELL;
#if !ROOTFS_PERSISTENT
		struct stat s;
		if (lstat(".SHELL", &s) < 0)
		{
			if (errno != ENOENT)
			{
				perror("lstat .SHELL");
				exit(1);
			}
			goto no_shell;
		}

		if (S_ISLNK(s.st_mode))
		{
			char target[256] = {0};
			if (readlink(".SHELL", target, 256) < 0)
			{
				perror("readlink");
				exit(1);
			}
			shell = strdup(target);
			if (shell == NULL)
			{
				perror("strdup shell");
				exit(1);
			}
		}
	no_shell:
#endif
#if USE_TINI
		// merge argv into _argv
		argv++; // jump over binary name
		char **it = argv;
		char **_argv;
		if (*it == NULL)
		{
			// no arguments given, use normal shell
			_argv = calloc(4, sizeof(char *));
			_argv[0] = INIT;
			_argv[1] = "--";
			_argv[2] = shell;
		}
		else
		{
			// first, find out how many slots we need
			int num = 4; // 3 for tini, -- and shell and 1 for trailing NULL
			while (*it != NULL)
			{
				num++;
				it++;
			}
			_argv = calloc(num, sizeof(char *));
			num = 3;
			_argv[0] = INIT;
			_argv[1] = "--";
			_argv[2] = shell;
			it = argv;
			while (*it != NULL)
			{
				_argv[num++] = *it;
				it++;
			}
		}
#else
		argv++;
		char *_argv[] = {shell, NULL};
#endif

		// and execute!
		debug("=> Executing %s, see you on the other side\n", _argv[0]);
		if (execve(_argv[0], _argv, envp) < 0)
		{
			perror("execve");
		}
		exit(1);
	}
	// else we are in parent

	debug("-- Now executing child %d\n", childpid);

	waitpid(childpid, NULL, 0); // Wait for child termination

	return 0;
}
