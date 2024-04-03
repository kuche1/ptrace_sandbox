
// info
//
// setccomp man
// https://man7.org/linux/man-pages/man3/seccomp_init.3.html
// https://man7.org/linux/man-pages/man3/seccomp_rule_add.3.html
// https://man7.org/linux/man-pages/man7/address_families.7.html
// https://man7.org/linux/man-pages/man3/errno.3.html
//
// if we want to kill the process upon a bad syscall, use SCMP_ACT_KILL
// if we only want to invalidate and set errno, use SCMP_ACT_ERRNO(EPERM); for more errnos see https://man7.org/linux/man-pages/man3/errno.3.html
// if we want to do nothing use SCMP_ACT_ALLOW

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <seccomp.h>
#include <errno.h>
#include <sys/socket.h>
#include <limits.h>

#define PREFIX "SETCCOMP: "

#define DISABLE_NETWORKING 1

#define DOMAIN_TYPE_MAX 100 // let's hope that there will never be more than 100 different AF_XYZ added

#define RET_IS_0(fnc, ...) { \
    if(fnc(__VA_ARGS__) != 0){ \
        perror(PREFIX "bad return code"); \
        exit(-1); \
    } \
}

int main(int argc, char *argv[]){

    // parse cmdline

    if(argc == 1){
        perror(PREFIX "you need to pass the application that you want to be run in the sandbox\n");
        exit(-1);
    }

    // set up filtering rules

    // allow all syscalls by default
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW); // SCMP_ACT_ALLOW SCMP_ACT_LOG

    if(ctx == NULL){
        perror(PREFIX "seccomp_init failed");
        exit(-1);
    }

    // do not send SIGSYS upon coming across an invalid syscall
    RET_IS_0(
        seccomp_attr_set,
        ctx,
        SCMP_FLTATR_ACT_BADARCH,
        SCMP_ACT_ALLOW
    );

    // set rules

    // printf(PREFIX "settings rules...\n");

    if(DISABLE_NETWORKING){
        // https://linasm.sourceforge.net/docs/syscalls/network.php

        // // misc
        // seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(socket), 0);
        // seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(socketpair), 0);
        // seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(setsockopt), 0);
        // seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(getsockopt), 0);
        // seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(getsockname), 0);
        // seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(getpeername), 0);
        // seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(sethostname), 0);
        // seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(setdomainname), 0);
        // seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(bpf), 0);

        // // inbound init
        // seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(bind), 0);
        // seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(listen), 0);
        // seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(accept), 0);
        // seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(accept4), 0);
        // // inbound
        // seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(recvfrom), 0);
        // seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(recvmsg), 0);
        // seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(recvmmsg), 0);

        // // outbound init
        // seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(connect), 0);
        // // outbound
        // seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(sendto), 0);
        // seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(sendmsg), 0);
        // seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(sendmmsg), 0);



        // // block ipv4
        // seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(socket),     1, SCMP_A0(SCMP_CMP_EQ, AF_INET));
        // seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(socketpair), 1, SCMP_A0(SCMP_CMP_EQ, AF_INET));

        // // block ipv6
        // seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(socket),     1, SCMP_A0(SCMP_CMP_EQ, AF_INET6));
        // seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(socketpair), 1, SCMP_A0(SCMP_CMP_EQ, AF_INET6));



        // disable ipv4 and ipv6
        // you can test this with:
        //     python3 -c 'import socket; sock = socket.socket(socket.AF_UNIX)'
        //     python3 -c 'import socket; sock = socket.socket(socket.AF_INET)'
        //     python3 -c 'import socket; sock = socket.socket(socket.AF_INET6)'

        // RET_IS_0(
        //     seccomp_rule_add,
        //     ctx,
        //     SCMP_ACT_ERRNO(EPERM),
        //     SCMP_SYS(socket),
        //     1,
        //     SCMP_A0(SCMP_CMP_EQ, AF_INET)
        // );

        // RET_IS_0(
        //     seccomp_rule_add,
        //     ctx,
        //     SCMP_ACT_ERRNO(EPERM),
        //     SCMP_SYS(socketpair),
        //     1,
        //     SCMP_A0(SCMP_CMP_EQ, AF_INET)
        // );

        // RET_IS_0(
        //     seccomp_rule_add,
        //     ctx,
        //     SCMP_ACT_ERRNO(EPERM),
        //     SCMP_SYS(socket),
        //     1,
        //     SCMP_A0(SCMP_CMP_EQ, AF_INET6)
        // );

        // RET_IS_0(
        //     seccomp_rule_add,
        //     ctx,
        //     SCMP_ACT_ERRNO(EPERM),
        //     SCMP_SYS(socketpair),
        //     1,
        //     SCMP_A0(SCMP_CMP_EQ, AF_INET6)
        // );


        // disable everything but local sockets
        // you can test this with:
        //     python3 -c 'import socket; sock = socket.socket(socket.AF_UNIX)'
        //     python3 -c 'import socket; sock = socket.socket(socket.AF_INET)'
        //     python3 -c 'import socket; sock = socket.socket(socket.AF_INET6)'

        for(int domain_type=0; domain_type<DOMAIN_TYPE_MAX; ++domain_type){

            switch(domain_type){
                case AF_LOCAL: // AF_LOCAL also convers AF_UNIX
                case AF_BRIDGE:
                case AF_NETLINK:
                    continue;
            }

            RET_IS_0(
                seccomp_rule_add,
                ctx,
                SCMP_ACT_ERRNO(EPERM),
                SCMP_SYS(socket),
                1,
                SCMP_A0(SCMP_CMP_EQ, domain_type)
            );

            RET_IS_0(
                seccomp_rule_add,
                ctx,
                SCMP_ACT_ERRNO(EPERM),
                SCMP_SYS(socketpair),
                1,
                SCMP_A0(SCMP_CMP_EQ, domain_type)
            );
        }

    }

    if(seccomp_load(ctx) != 0){
        perror(PREFIX "seccomp_load failed");
        exit(-1);
    }

    // printf(PREFIX "rules set\n");

    // start requested process

    {
        char *process_to_run = argv[1];
        char **process_args = argv + 1;

        execvp(process_to_run, process_args);
        perror(PREFIX "execvp failed");
        exit(-1);
    }

    // unreachable 

    // printf("asdfg\n");

    // seccomp_release(ctx);

    return 0;
}