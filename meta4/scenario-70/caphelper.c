/* caphelper: performs a CAP_SYS_ADMIN-gated privileged operation.
 *
 * Creating a new mount namespace (unshare(CLONE_NEWNS)) and mounting a tmpfs
 * both require CAP_SYS_ADMIN. When this binary carries the cap_sys_admin+ep
 * FILE capability, any user who execs it — including a fully unprivileged one —
 * gains CAP_SYS_ADMIN for this process and the privileged mount succeeds.
 * It prints the token PRIVOP_OK ONLY if the privileged operation actually
 * succeeded, so an empty output means the operation was denied (no escalation),
 * never that a tool was missing.
 *
 * The new mount namespace is destroyed when the process exits, so the probe
 * leaves nothing mounted in the container.
 */
#define _GNU_SOURCE
#include <sched.h>
#include <sys/mount.h>
#include <stdio.h>
#include <unistd.h>

int main(void) {
    /* CLONE_NEWNS requires CAP_SYS_ADMIN. */
    if (unshare(CLONE_NEWNS) != 0) {
        return 1;  /* denied: cannot create a mount namespace */
    }
    /* Keep new mounts private so nothing propagates back to the container. */
    mount("none", "/", NULL, MS_REC | MS_PRIVATE, NULL);
    /* Mounting a tmpfs requires CAP_SYS_ADMIN. */
    if (mount("none", "/mnt", "tmpfs", 0, "size=16k") != 0) {
        return 1;  /* denied: cannot mount tmpfs */
    }
    /* Success: an unprivileged caller just performed a privileged mount. */
    printf("PRIVOP_OK\n");
    return 0;
}
