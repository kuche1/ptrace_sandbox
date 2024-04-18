
// info
//
// man pages:
// https://man7.org/linux/man-pages/man2/ptrace.2.html
//
// PTRACE_SYSCALL means: stop at the nextsyscall
// PTRACE_CONT means: stop at the next signal

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

#if __WORDSIZE == 64
#define REG_SYSCALL_ID(reg) reg.orig_rax // we use this is we want to modify the syscall ID before execution
#define REG_SYSCALL_ARG0(reg) reg.rdi // TODO tova se si mislq 4e trqbva da e orig_rdi
#define REG_SYSCALL_ARG1(reg) reg.rsi
// #define REG_SYSCALL_ARG2(reg) reg.rdx
// #define REG_SYSCALL_ARG3(reg) reg.r10
#define REG_SYSCALL_RET(reg) reg.rax // we use this if we want to change the return code
#else
#error only 64bit is supported
#endif

#define PREFIX "SANDBOX_BOTH: " // all prints should start with this
#define PRINT_BLOCKED_SYSCALLS 0

#define DOMAIN_TYPE_MAX 100 // let's hope that there will never be more than 100 different AF_XYZ added
#define PATH_MAXLEN (4096+100)

#define DISABLE_NETWORKING 1
#define DISABLE_OPENING 1 // TODO this actually does not work

////// function macros

#define ASSERT_0(value) { \
    if(value != 0){ \
        fprintf(stderr, PREFIX "assert failed, file `%s`, line %d\n", __FILE__, __LINE__); \
        exit(-1); \
    } \
}

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
        ASSERT_0(
            seccomp_rule_add(ctx, SCMP_ACT_TRACE(69), SCMP_SYS(open), 0)
        );

        ASSERT_0(
            seccomp_rule_add(ctx, SCMP_ACT_TRACE(69), SCMP_SYS(openat), 0)
        );
    }

    // rules: networking

    if(DISABLE_NETWORKING){
        // https://linasm.sourceforge.net/docs/syscalls/network.php

        ASSERT_0(
            seccomp_rule_add(ctx, SCMP_ACT_TRACE(69), SCMP_SYS(socket), 0)
        );

        ASSERT_0(
            seccomp_rule_add(ctx, SCMP_ACT_TRACE(69), SCMP_SYS(socketpair), 0)
        );

    }

    // // rules: harmless by themselves

    // ASSERT_0(
    //     seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0)
    // );
    // ASSERT_0(
    //     seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0)
    // );

    // // rules: clean up

    // ASSERT_0(
    //     seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0)
    // );

    // load rules

    // printf("sleep b4 rule load\n");
    // sleep(2);

    printf("b4 load rules\n");

    ASSERT_0(
        seccomp_load(ctx)
    );

    printf("after load rules\n");
}

void run_sandboxed_process(char *process_to_run, char **process_args){
    pid_t child = fork();

    if(child < 0){
        perror(PREFIX "could not start child process");
        exit(-1);

    }else if(child == 0){

        printf("b4 traceme\n");

        ASSERT_0(
            ptrace(PTRACE_TRACEME, 0, NULL, NULL)
            // this does NOT pause execution
        );

        ASSERT_0(
            raise(SIGSTOP)
            // pausing execution since TRACEME won't do that by itself
        );

        printf("aftr traceme; b4 seccomp rules set\n");

        set_seccomp_rules();

        printf("after seccomp rules set; b4 execvp\n");

        execvp(process_to_run, process_args);
        perror(PREFIX "fail: execvp");
        exit(-1);
    }

    printf("b4 waitpid\n");

    waitpid(child, 0, 0); // wait for out SIGSTOP // TODO check that is really is our SIGSTOP

    printf("aftr waitpid; b4 ptrace set opts\n");

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
    );

    // TODO allow everything up to execvp
}

int filter_syscalls(){
    int return_code = 0;
    int running_processes = 1;
    int syscalls_blocked = 0; // careful, this might overflow

    while(1){

        int status;
        pid_t pid = waitpid(-1, &status, 0); // the first argument being -1 means: wait for any child process


        if(
            ( status>>8 == (SIGTRAP | (PTRACE_EVENT_CLONE<<8)) ) ||
            ( status>>8 == (SIGTRAP | (PTRACE_EVENT_FORK<<8))  ) ||
            ( status>>8 == (SIGTRAP | (PTRACE_EVENT_VFORK<<8)) )
        ){
            // new process created
            // printf(PREFIX "new process spawned\n");
            running_processes += 1;
            ptrace(PTRACE_CONT, pid, NULL, NULL);
            continue;


        }else if(status>>8 == (SIGTRAP | (PTRACE_EVENT_EXIT<<8))){
            // process died

            // printf(PREFIX "process despawned\n");

            running_processes -= 1;

            unsigned long event_message;
            ptrace(PTRACE_GETEVENTMSG, pid, NULL, &event_message);

            if(event_message){
                // there's something wrong with the code that gets the return code
                // so we won't return the thread's code
                return_code = 1;
            }

            ptrace(PTRACE_CONT, pid, NULL, NULL);

            if(running_processes <= 0){
                break;
            }
            continue;


        }else if(status>>8 == (SIGTRAP | (PTRACE_EVENT_SECCOMP<<8))){
            // syscall that we need to trace
            // printf("need to trace\n");


        }else{
            // still no idea what this is; it keeps happening sometimes
            // printf("wtf status>>8=%x SIGTRAP=%x pid=%d hui0=%d\n", status>>8, SIGTRAP, pid,   status>>8 == (SIGTRAP | (PTRACE_EVENT_VFORK_DONE<<8))   );
            // printf("wtf\n");
            ptrace(PTRACE_CONT, pid, NULL, NULL);
            continue;
        }


        struct user_regs_struct regs;
        ptrace(PTRACE_GETREGS, pid, NULL, &regs);

        long syscall_id = REG_SYSCALL_ID(regs);
        __attribute__((unused)) char *syscall_desc = "no description";
        int syscall_allow = 0;

        // printf(PREFIX "filtering syscall %ld\n", syscall_id);

        switch(syscall_id){

            case SYS_socket:
            case SYS_socketpair:{
                    // https://man7.org/linux/man-pages/man2/socket.2.html

                    int domain = REG_SYSCALL_ARG0(regs);

                    switch(domain){
                        case AF_LOCAL: // this also includes AF_UNIX
                        case AF_BRIDGE:
                        case AF_NETLINK:
                            syscall_allow = 1;
                            syscall_desc = "socket creation: non-internet";
                            break;
                        
                        case AF_INET:
                        case AF_DECnet:
                        case AF_ROSE:
                            syscall_desc = "socket creation: internet";
                            break;

                        default:
                            syscall_desc = "socket creation: unknown (probably internet)";
                            printf(PREFIX "unknown socket creation of domain %d\n", domain);
                            break;
                    }
            }
            break;
            
            // TODO SYS_open
            case SYS_openat:{
                syscall_allow = 1;

                int dirfd = REG_SYSCALL_ARG0(regs);
                char *pidmem_filename = (char *)REG_SYSCALL_ARG1(regs);
                // int flags = REG_SYSCALL_ARG2(regs);
                // umode_t mode = REG_SYSCALL_ARG3(regs);

                // get actual filename
                char filename[PATH_MAXLEN+1] = {0}; // we don't need to compensate for the long here, we've already done that in the macro definition
                size_t filename_len = 0;

                for(char *mem_to_read = pidmem_filename;;){

                    errno = 0;
                    long chunk = ptrace(PTRACE_PEEKDATA, pid, mem_to_read, NULL);
                    if(errno != 0){
                        // TODO this sucks, if this fails probably the process has exited
                        perror(PREFIX "PTRACE_PEEKDATA error; this needs to be fixed at some point");
                        exit(-1);
                    }

                    if(sizeof(filename) - filename_len -1 < sizeof(chunk)){
                        // TODO this sucks because someone could fill a buffer with bullshit just to fuck with us
                        perror(PREFIX "not enough mem; this needs to be fixed at some point");
                        exit(-1);
                    }

                    memcpy(filename+filename_len, &chunk, sizeof(chunk)); // copy the whole chunk because I don't care
                    filename_len += sizeof(chunk);
                    mem_to_read += sizeof(chunk);

                    char *chunk_str = (char *)&chunk;
                    int reached_the_end = 0;

                    for(size_t i=0; i<sizeof(chunk); ++i){
                        char ch = chunk_str[i];
                        // printf(PREFIX "ch=%c\n", ch);
                        if(ch == 0){
                            reached_the_end = 1;
                            break;
                        }
                    }

                    if(reached_the_end){
                        break;
                    }
                }

                printf(PREFIX "SYS_openat: dirfd=%d filename=%s\n", dirfd, filename);
            }
            break;

            default:{
                printf(PREFIX "unknown syscall with id %ld\n", syscall_id);
            }
            break;
        }

        if(!syscall_allow){

            ++syscalls_blocked;

#if PRINT_BLOCKED_SYSCALLS
            printf(PREFIX "blocked syscall with id %ld; description: %s\n", syscall_id, syscall_desc);
#endif

            // TODO I think there was a way to invalidate the syscall quicker
            REG_SYSCALL_ID(regs) = -1; // invalidate the syscall by changing the id to some garbage
            ptrace(PTRACE_SETREGS, pid, NULL, &regs);
        }

        ptrace(PTRACE_CONT, pid, NULL, NULL);

    }

    printf("\n");
    printf(PREFIX "syscalls blocked: %d\n", syscalls_blocked);

    return return_code;
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
