
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
//
// some network syscalls
// https://linasm.sourceforge.net/docs/syscalls/network.php

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <seccomp.h>
#include <errno.h>
#include <sys/socket.h>

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

    if(DISABLE_NETWORKING){

        // disable everything but local sockets
        // you can test this with:
        //     python3 -c 'import socket; sock = socket.socket(socket.AF_UNIX)'
        //     python3 -c 'import socket; sock = socket.socket(socket.AF_INET)'
        //     python3 -c 'import socket; sock = socket.socket(socket.AF_INET6)'

        for(int domain_type=0; domain_type<DOMAIN_TYPE_MAX; ++domain_type){

            switch(domain_type){
                case AF_LOCAL: // AF_LOCAL also covers AF_UNIX
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

    // start requested process

    {
        char *process_to_run = argv[1];
        char **process_args = argv + 1;

        execvp(process_to_run, process_args);
        perror(PREFIX "execvp failed");
        exit(-1);
    }

    // if we were to lift the restrictions, we would use this
    // seccomp_release(ctx);

    return 0;
}
