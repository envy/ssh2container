#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <sys/capability.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <seccomp.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <dirent.h>

#define TMP_DIR_NAME "/tmp/container.XXXXXX"
#define MEMORY 1024*1024*1024 // 1GB
#define SHELL "/bin/ash"

char *mount_path;

int pivot_root(const char *new_root, const char *put_old)
{
    return syscall(SYS_pivot_root, new_root, put_old);
}

void setup_namespaces()
{
    int namespaces = 0;
    namespaces |= CLONE_NEWUTS;  // New UTS namespace (hostname, domainname)
    namespaces |= CLONE_NEWPID;  // New PID namespace, requires CAP_SYS_ADMIN
    namespaces |= CLONE_NEWIPC;  // New IPC namespace, requires CAP_SYS_ADMIN
    namespaces |= CLONE_NEWNS;   // New mount namespace, requires CAP_SYS_ADMIN
    namespaces |= CLONE_NEWUSER; // New user namespace, reqires CAP_SYS_ADMIN
    //namespaces |= CLONE_NEWCGROUP; // New cgroup namespace
    //namespaces |= CLONE_NEWNET;  // New network namespace, requires CAP_SYS_ADMIN

    printf("=> Creating namespaces... ");fflush(stdout);

    if (unshare(namespaces) != 0)
    {
        perror("");
        exit(1);
    }

    printf("done\n");
}

void remove_dir(const char *source);

void remove_tmp_dir()
{
	remove_dir(mount_path);
	free(mount_path);
}

void remove_dir(const char *source)
{
	DIR *dir = opendir(source);
	if (dir == NULL)
	{
		perror("opendir");
		printf("%s\n", source);
		exit(1);
	}
	char path[256] = {0}, *endptr = path;
	struct dirent *e;
	strcpy(path, source);
	strcat(path, "/");
	endptr += strlen(source)+1;
	while ((e = readdir(dir)) != NULL)
	{
		struct stat info;
		if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
		{
			continue;
		}
		strcpy(endptr, e->d_name);
		if (!lstat(path, &info))
		{
			if (S_ISLNK(info.st_mode))
			{
				unlink(path);
			}
			else if (S_ISDIR(info.st_mode))
			{
				remove_dir(path);
			}
			else if (S_ISREG(info.st_mode))
			{
				unlink(path);
			}
		}
	}
	if (rmdir(source))
	{
		perror("rmdir");
		exit(1);
	}
	closedir(dir);

}

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

        do {
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

void copy_rootfs(const char *source, char *dest)
{
	DIR *dir = opendir(source);
	if (dir == NULL)
	{
		perror("opendir");
		exit(1);
	}
	char path[256] = {0}, *endptr = path;
	struct dirent *e;
	strcpy(path, source);
	strcat(path, "/");
	endptr += strlen(source)+1;
	while ((e = readdir(dir)) != NULL)
	{
		struct stat info;
		if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
		{
			continue;
		}
		strcpy(endptr, e->d_name);
		if (!lstat(path, &info))
		{
			char dpath[256] = {0}, *dendptr = dpath;
			strcpy(dpath, dest);
			strcat(dpath, "/");
			dendptr += strlen(dest)+1;
			strcpy(dendptr, e->d_name);
			if (S_ISLNK(info.st_mode))
			{
				char target[256] = {0};
				readlink(path, target, 256);
				symlink(target, dpath);
				// create link
			}
			else if (S_ISDIR(info.st_mode))
			{
				mkdir(dpath, 0755);
				copy_rootfs(path, dpath);
				chmod(dpath, info.st_mode);
			}
			else if (S_ISREG(info.st_mode))
			{
				cp(dpath, path);
				chmod(dpath, info.st_mode);
			}
		}
	}
}

void setup_sandbox(const char *rootfs, char **mount_dir)
{
    printf("=> Remounting / as private and mounting rootfs... ");fflush(stdout);

    // mount / as private (--make-rpivate) to not leak changes upward
    if (mount("none", "/", NULL, MS_REC | MS_PRIVATE, NULL)) // NULL as first argument also works
    {
        perror("mount /");
        exit(1);
    }

	// creating the upper directory for the overlay
	*mount_dir = malloc(strlen(TMP_DIR_NAME)+1);
    strcpy(*mount_dir, TMP_DIR_NAME);

    if (!mkdtemp(*mount_dir))
    {
        perror("mkdtemp");
        exit(1);
    }


	
    copy_rootfs(rootfs, *mount_dir);

    // copy /etc/resolv.conf
    char path[256] = {0};
    snprintf(path, 256, "%s/etc/resolv.conf", *mount_dir);
    cp(path, "/etc/resolv.conf");

    if (mount(*mount_dir, *mount_dir, NULL, MS_BIND | MS_NOSUID, NULL) < 0)
    {
        perror("mount rootfs");
        exit(1);
	}

    // change to rootfs
    if (chdir(*mount_dir))
    {
        perror("chdir rootfs");
        exit(1);
    }

    printf("done\n");
}

void setup_id_maps(uid_t uid, gid_t gid)
{
    char buf[1024];
    uid_t newuid = 0;
    gid_t newgid = 0;

    printf("=> Mapping %d/%d to 0/0... ", uid, gid);fflush(stdout);

    // map new UID/GID to outer UID/GID
    sprintf(buf, "%d %d 1\n", newuid, uid);
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
    if ((fd = open("/proc/self/setgroups", O_WRONLY)) >= 0) {
        write(fd, "deny", 4);
        close(fd);
    }
    sprintf(buf, "%d %d 1\n", newgid, gid);
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
    setresgid(newgid, newgid, newgid);
    setresuid(newuid, newuid, newuid);

    printf("done\n");
}

void setup_fake_dev()
{
    printf("=> Creating minimal /dev... ");fflush(stdout);

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

    if (mount("sandbox-dev", "dev", NULL, MS_REMOUNT | MS_BIND | MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_NOATIME | MS_RDONLY, NULL) < 0)
    {
        perror("remount dev");
        exit(1);
    }

    printf("done\n");
}


void setup_tmp()
{
    printf("=> Creating /tmp... ");fflush(stdout);

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

    printf("done\n");
}

void setup_home()
{
	printf("=> Mounting home... ");fflush(stdout);

	char *home = getenv("HOME");
	if (home == NULL)
	{
		// User has no home?
		printf("user has no home.\n");
		return;
	}

	if (mount(home, "root", NULL, MS_BIND, NULL))
	{
		perror("mount home");
		exit(1);
	}

	printf("done\n");
}

void setup_proc()
{
    printf("=> Mounting old /proc... ");fflush(stdout);

    rmdir(".oldproc");
    rmdir("proc");

    mkdir(".oldproc", 0755); // We need the old proc to mount our new proc
    mkdir("proc", 0755);

    if (mount("/proc", ".oldproc", NULL, MS_BIND | MS_REC, NULL) < 0)
    {
        perror("");
        exit(1);
    }

    printf("done\n");
}

void setup_root()
{
    printf("=> Pivoting root... ");fflush(stdout);

    // delete old dirs and create new ones
    rmdir(".oldroot");
    mkdir(".oldroot", 0755);

    // Change root, keep old one
    if (pivot_root(".", ".oldroot") < 0)
    {
        perror("pivot_root");
        exit(1);
    }

    umount2(".oldroot", MNT_DETACH);
    rmdir(".oldroot");

    printf("done\n");
}

void setup_proc_2()
{
    printf("=> Mounting new /proc... "); fflush(stdout);

    // mount proc for correct pids
    if (mount("sandbox-proc", "/proc", "proc", MS_NOSUID | MS_NOEXEC | MS_NODEV, NULL) < 0)
    {
        perror("mount proc");
        exit(1);
    }

    // unmount old proc
    if (umount2("/.oldproc", MNT_DETACH) < 0)
    {
        perror("umount oldproc");
    }
    if (rmdir("/.oldproc") < 0)
    {
        perror("delete oldproc");
    }

    printf("done\n");
}

void setup_root_2()
{
    printf("=> Really mounting rootfs now... ");fflush(stdout);

    if (mount("/", "/", NULL, MS_BIND | MS_REMOUNT, NULL) < 0)
    {
        perror("mount new root");
        exit(1);
    }

    printf("done\n");
}

void mask_proc()
{
    printf("=> Masking sensitive proc files... ");fflush(stdout);

    if(mount("/dev/null", "/proc/sched_debug", NULL, MS_BIND, NULL) < 0)
    {
        perror("sched_debug mask");
        exit(1);
    }

    printf("done\n");
}

void restrict_resources()
{
    printf("=> Restricting resource usage... ");fflush(stdout);

    struct rlimit memlimit;
    memlimit.rlim_cur = MEMORY;
    memlimit.rlim_max = MEMORY;

    if(setrlimit(RLIMIT_AS, &memlimit) < 0)
    {
        perror("setrlimit");
    }
    if(setrlimit(RLIMIT_DATA, &memlimit) < 0)
    {
        perror("setrlimit");
    }

    printf("done\n");
}

#define SCMP_FAIL SCMP_ACT_ERRNO(EPERM)
void filter_syscalls()
{
    scmp_filter_ctx ctx = NULL;
    int rc = 0;
    printf("=> Filtering system calls... ");fflush(stdout);

    if (!(ctx = seccomp_init(SCMP_ACT_ALLOW)))
    {
        perror("seccomp init");
        exit(1);
    }

    if (0
        // Do not allow ???
        || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(chmod), 1, SCMP_A1(SCMP_CMP_MASKED_EQ, S_ISUID, S_ISUID))
        || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(chmod), 1, SCMP_A1(SCMP_CMP_MASKED_EQ, S_ISGID, S_ISGID))
        || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(fchmod), 1, SCMP_A1(SCMP_CMP_MASKED_EQ, S_ISUID, S_ISUID))
        || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(fchmod), 1, SCMP_A1(SCMP_CMP_MASKED_EQ, S_ISGID, S_ISGID))
        || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(fchmodat), 1, SCMP_A2(SCMP_CMP_MASKED_EQ, S_ISUID, S_ISUID))
        || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(fchmodat), 1, SCMP_A2(SCMP_CMP_MASKED_EQ, S_ISGID, S_ISGID))
        // Do not allow creationg of new user namespaces
        || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(unshare), 1, SCMP_A0(SCMP_CMP_MASKED_EQ, CLONE_NEWUSER, CLONE_NEWUSER))
        || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(clone), 1, SCMP_A2(SCMP_CMP_MASKED_EQ, CLONE_NEWUSER, CLONE_NEWUSER))
        // Do not allow the TIOCSTI ioctl
        || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(ioctl), 1, SCMP_A1(SCMP_CMP_EQ, TIOCSTI))
        // Prevent access to kernel keyring
        || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(keyctl), 0)
        || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(add_key), 0)
        || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(request_key), 0)
        // Prevent ptrace as kernel < 4.8
        || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(ptrace), 0)
        // Prevent access to NUMA syscalls
        || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(mbind), 0)
        || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(migrate_pages), 0)
        || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(move_pages), 0)
        || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(set_mempolicy), 0)
        // Prevent user mode page fault handlers
        || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(userfaultfd), 0)
        // Prevent perf in case of perf_event_paranoid < 2
        || seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(perf_event_open), 0)
        // Prevent setuid/setcap binaries form executing
        || seccomp_attr_set(ctx, SCMP_FLTATR_CTL_NNP, 0)
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
    printf("done\n");
}

void drop_capabilities()
{
    printf("=> Dropping capabilities... "); fflush(stdout);

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
        CAP_SYS_ADMIN,
        CAP_SYS_BOOT,
        CAP_SYS_MODULE,
        CAP_SYS_NICE,
        CAP_SYS_RAWIO,
        CAP_SYS_RESOURCE,
        CAP_SYS_TIME,
        CAP_WAKE_ALARM
    };

    size_t num_caps = sizeof(drop_caps) / sizeof(*drop_caps);
    printf("bounding... "); fflush(stdout);
    for (size_t i = 0; i < num_caps; i++)
    {
        if (prctl(PR_CAPBSET_DROP, drop_caps[i], 0, 0, 0))
        {
            perror("prctl");
            exit(1);
        }
    }

    printf("inheritable... "); fflush(stdout);
    cap_t caps = NULL;
    if (!(caps = cap_get_proc())
        || cap_set_flag(caps, CAP_INHERITABLE, num_caps, drop_caps, CAP_CLEAR)
        || cap_set_proc(caps))
    {
        perror("cap_*");
        if (caps)
            cap_free(caps);
        exit(1);
    }
    cap_free(caps);

    printf("done\n");
}

void run_command(char **argv)
{
	pid_t pid = fork();
	if (pid < 0)
	{
		perror("fork");
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

void install_init()
{
	printf("=> Installing tini... ");fflush(stdout);

	char *argv[] = { "/sbin/apk", "add", "--no-cache", "tini", NULL };
	run_command(argv);

	printf("done\n");
}

int main(int argc, char **argv)
{
	(void)argc;
	(void)argv;
    pid_t childpid;
    uid_t uid = getuid();
    gid_t gid = getgid();
    char *rootfs;
    rootfs = "/opt/ns/rootfs"; // rootfs is our first argument
    // the rest contains the binary to start and their arguments

    // setup namespaces
    setup_namespaces();

    // setup sandbox
    setup_sandbox(rootfs, &mount_path);

    // setup id maps
    setup_id_maps(uid, gid);

    // setup minmal dev
    setup_fake_dev();

    // setup tmp
    setup_tmp();

    // setup proc
    setup_proc();

	// setup home
	setup_home();

    // pivot to rootfs
    setup_root();

    // Now fork!
    childpid = fork();
    if (childpid < 0) {
        perror("fork");
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

        restrict_resources(); // remove for materials

        filter_syscalls(); // remove for materials

        drop_capabilities(); // remove for materials

        // sanitize environment
        char *envp[5];
        envp[0] = "PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin";
        envp[1] = "LANG=en_US.UTF-8";
        envp[2] = "TERM=xterm-256color";
        envp[5] = "HOME=/root";
        envp[4] = NULL;

        // set working directory to home
        if (chdir("/root") < 0)
		{
			perror("chdir home");
			// This is ok, we are still inside the container, just not inside the home
		}

		install_init();

        // and execute!
        printf("=> Executing, see you on the other side\n");
        //extern char **environ;
        char *_argv[] = { "/sbin/tini", "--", SHELL, NULL };
        if (execve(_argv[0], _argv, envp) < 0)
		{
			perror("execve");
		}
        exit(1);
    }
    // else we are in parent

    printf("-- Now executing child %d\n", childpid);

    waitpid(childpid, NULL, 0); // Wait for child termination

	remove_tmp_dir();

	return 0;
}

