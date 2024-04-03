
// info
//
// setccomp man: https://man7.org/linux/man-pages/man3/seccomp_init.3.html
//
// if we want to kill the process upon a bad syscall, use SCMP_ACT_KILL
// if we only want to invalidate and set errno, use SCMP_ACT_ERRNO(EPERM); for more errnos see https://man7.org/linux/man-pages/man3/errno.3.html
// if we want to do nothing use SCMP_ACT_ALLOW

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <seccomp.h>
#include <errno.h>

#define PREFIX "SETCCOMP: "

#define DISABLE_NETWORKING 1

int main(int argc, char *argv[]){

    // parse cmdline

    if(argc == 1){
        perror(PREFIX "you need to pass the application that you want to be run in the sandbox\n");
        exit(-1);
    }

    // set up filtering rules

    // allow all syscalls by default
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);

    if(DISABLE_NETWORKING){
        // https://linasm.sourceforge.net/docs/syscalls/network.php

        // misc
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(socket), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(socketpair), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(setsockopt), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(getsockopt), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(getsockname), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(getpeername), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(sethostname), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(setdomainname), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(bpf), 0);

        // inbound init
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(bind), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(listen), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(accept), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(accept4), 0);
        // inbound
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(recvfrom), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(recvmsg), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(recvmmsg), 0);

        // outbound init
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(connect), 0);
        // outbound
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(sendto), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(sendmsg), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(sendmmsg), 0);
    }

    if (seccomp_load(ctx) < 0) {
        perror(PREFIX "seccomp_load failed");
        exit(-1);
    }

    // start requested process

    {
        char *process_to_run = argv[1];
        char **process_args = argv + 1;

        execvp(process_to_run, process_args);
        perror(PREFIX "could not start process");
        exit(-1);
    }

    // this 

    printf("sex\n");

    seccomp_release(ctx);

    return 0;
}