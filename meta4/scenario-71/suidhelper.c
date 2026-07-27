/* suidhelper: a SUID-root helper that elevates a non-root caller to full root.
 *
 * When this binary is SUID-root, exec'ing it sets euid=0. setgid(0)/setuid(0)
 * then set the real, effective AND saved ids to 0, so the shell it execs does
 * NOT drop privileges (dash/bash drop privileges only when euid != uid). All
 * arguments are forwarded to /bin/sh, e.g.:
 *     suidhelper -c "cat /etc/shadow"
 * runs the command as root. Stripping the SUID bit (chmod u-s) removes the
 * escalation: setuid(0) then fails, the shell runs as the calling non-root user.
 */
#include <unistd.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    setgid(0);
    setuid(0);
    char *newargv[argc + 2];
    newargv[0] = "/bin/sh";
    for (int i = 1; i < argc; i++) {
        newargv[i] = argv[i];
    }
    newargv[argc] = NULL;
    execv("/bin/sh", newargv);
    return 1;
}
