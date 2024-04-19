
// info
//
// man pages:
// https://man7.org/linux/man-pages/man2/ptrace.2.html
//
// PTRACE_SYSCALL means: stop at the nextsyscall
// PTRACE_CONT means: stop at the next signal
//
// list of signals
// https://www-uxsup.csx.cam.ac.uk/courses/moved.Building/signals.pdf

#include <sys/ptrace.h> // sudo apt install libc6-dev
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <string.h>
#include <syscall.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <seccomp.h> // sudo apt install libseccomp-dev
#include <errno.h>
#include <linux/types.h>
#include <fcntl.h>

////// CPU registers

#if __WORDSIZE == 64
#define REG_SYSCALL_ID(reg) reg.orig_rax // we use this is we want to modify the syscall ID before execution
#define REG_SYSCALL_ARG0(reg) reg.rdi // TODO tova se si mislq 4e trqbva da e orig_rdi
#define REG_SYSCALL_ARG1(reg) reg.rsi
#define REG_SYSCALL_ARG2(reg) reg.rdx
#define REG_SYSCALL_ARG3(reg) reg.r10
#define REG_SYSCALL_RET(reg) reg.rax // we use this if we want to change the return code
#else
#error only 64bit is supported
#endif

////// printing

#define PREFIX "SANDBOX_BOTH: " // all prints should start with this
#define PRINT_BLOCKED_SYSCALLS 1

////// defines will rarely get changed

#define PATH_MAXLEN (4096+100)

////// defines that might often get changed

#define DISABLE_NETWORKING 1
#define DISABLE_OPENING 1 // TODO this actually does not work

////// macro functions

#define ASSERT_0(value) { \
    if(value != 0){ \
        fprintf(stderr, PREFIX "assert failed, file `%s`, line %d\n", __FILE__, __LINE__); \
        exit(-1); \
    } \
}

#define ASSERT(value){ \
    ASSERT_0(!(value)); \
}

// -EACCES - The rule conflicts with the filter (for example, the rule action equals the default action of the filter).
#define ASSERT_0_EACCES(value) { \
    if((value != 0) && (value != -EACCES)){ \
        ASSERT_0(1); \
    } \
}

////// extremely inappropriate includes

// yeah, this is bad, but I don't care
#include "get_syscall_name.c"
#include "filter_syscalls.c"

////// funcions

void set_seccomp_rules(){
    // allow all syscalls by default
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW); // SCMP_ACT_ALLOW SCMP_ACT_LOG SCMP_ACT_TRACE(69)
    if(ctx == NULL){
        perror(PREFIX "seccomp_init failed");
        exit(-1);
    }

    // do not send SIGSYS upon coming across an invalid syscall
    ASSERT_0(
        seccomp_attr_set(ctx, SCMP_FLTATR_ACT_BADARCH, SCMP_ACT_ALLOW)
    );

    // rules: IO

    if(DISABLE_OPENING){
        ASSERT_0_EACCES(
            seccomp_rule_add(ctx, SCMP_ACT_TRACE(69), SCMP_SYS(open), 0)
        );

        ASSERT_0_EACCES(
            seccomp_rule_add(ctx, SCMP_ACT_TRACE(69), SCMP_SYS(openat), 0)
        );
    }

    // rules: networking

    if(DISABLE_NETWORKING){
        // https://linasm.sourceforge.net/docs/syscalls/network.php

        ASSERT_0_EACCES(
            seccomp_rule_add(ctx, SCMP_ACT_TRACE(69), SCMP_SYS(socket), 0)
        );

        ASSERT_0_EACCES(
            seccomp_rule_add(ctx, SCMP_ACT_TRACE(69), SCMP_SYS(socketpair), 0)
        );

    }

    // rules: harmless by themselves

    ASSERT_0_EACCES(
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0)
    );
    ASSERT_0_EACCES(
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0)
    );

    // rules: harmless clean up

    ASSERT_0_EACCES(
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0)
    );
    ASSERT_0_EACCES(
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0)
    );

    // load rules

    ASSERT_0(
        seccomp_load(ctx)
    );

}

void run_sandboxed_process(char *process_to_run, char **process_args){
    pid_t child = fork();

    if(child < 0){
        perror(PREFIX "could not start child process");
        exit(-1);

    }else if(child == 0){

        ASSERT_0(
            ptrace(PTRACE_TRACEME, 0, NULL, NULL)
            // this does NOT pause execution
        );

        ASSERT_0(
            raise(SIGSTOP)
            // pausing execution since TRACEME won't do that by itself
        );

        set_seccomp_rules();

        // // signify that we need to start filtering the syscalls
        // ASSERT_0(
        //     raise(SIGSTOP)
        // );
        // // worst case scenario: a malicious program sends the signal before this line, which is going to
        // // cause the syscall filtering to happen earlier, which might cause the child to terminate early (so nothing too bad)

        execvp(process_to_run, process_args);
        perror(PREFIX "fail: execvp");
        exit(-1);
    }

    {
        int status;
        waitpid(child, &status, 0); // wait for the SIGSTOP
        ASSERT(
            WIFSTOPPED(status)
        );
        ASSERT(
            WSTOPSIG(status) == SIGSTOP
        );
    }

    ASSERT_0(
        ptrace(
            PTRACE_SETOPTIONS,
            child,
            0,
            PTRACE_O_EXITKILL | // make sure to kill the child if the parent exits
            PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | // trace any new processes created by the child
            PTRACE_O_TRACEEXIT | // get notified when a process exits
            PTRACE_O_TRACESECCOMP // trace syscalls based on seccomp rules
        )
    );

    ASSERT_0(
        ptrace(PTRACE_CONT, child, NULL, NULL)
        // kill(child, SIGCONT)
    );

    // TODO
    // allow everything up to execvp

    // for(;;){

    //     int status;
    //     waitpid(child, &status, 0);

    //     if(WIFSTOPPED(status)){
    //         int signal = WSTOPSIG(status);

    //         printf("child was stopped by delivery of a signal %d SIGSTOP=%d\n", signal, SIGSTOP);

    //         ASSERT_0(
    //             ptrace(PTRACE_CONT, child, NULL, NULL)
    //         );

    //         if(signal == SIGSTOP){
    //             break;
    //         }
    //     }
    // }

    // allow the execvp

    // {
    //     int status;
    //     waitpid(child, &status, 0); // this should be the execvp

    //     ASSERT(
    //         WIFSTOPPED(status)
    //     );

    //     ASSERT(
    //         WSTOPSIG(status) == SIGTRAP
    //     );

    //     ASSERT_0(
    //         ptrace(PTRACE_CONT, child, NULL, NULL)
    //     );
    // }
}

int main(int argc, char *argv[]){

    // check args

    if(argc == 1){
        perror(PREFIX "you need to pass the application that you want to be run in the sandbox");
        exit(-1);
    }

    // run sandboxed process

    char *process_to_run = argv[1];
    char **process_args = argv + 1;
    run_sandboxed_process(process_to_run, process_args);

    // filter syscalls

    int return_code = filter_syscalls();

    // return

    return return_code;
}
