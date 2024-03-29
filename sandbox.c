
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <stdbool.h>
#include <string.h>
#include <syscall.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

#if __WORDSIZE == 64
#define REG_SYSCALL_ID(reg) reg.orig_rax // we use this is we want to modify the syscall ID before execution
#define REG_SYSCALL_RET(reg) reg.rax // we use this if we want to change the return code
#else
#error only 64bit is supported
#endif

#define PREFIX "SANDBOX: "

// files / dirs
//
#define ALLOW_OPEN 1
#define ALLOW_READ 1
#define ALLOW_WRITE 1
//
#define ALLOW_DELETING 1
#define ALLOW_CHDIR 1 // disabling this wouldn't be of much help since there are many other syscalls such as `openat` and `unlinkat`
#define ALLOW_FILE_UTILS 1

// networking
#define ALLOW_NETWORKING 1

// threading
#define ALLOW_THREADING 1

#define ALLOW_MEMORY_ALLOCATION 1
#define ALLOW_EXECUTE_OTHER_PROGRAMS 1
#define ALLOW_CHECK_PERMISSIONS_AND_INFO 1
#define ALLOW_FUTEX 1 // I don't see why we would ever want to disable this
#define ALLOW_SET_MEMORY_PROTECTION 1 // gives processes the ability to change it's own memory protection
#define ALLOW_SIGNALS 1
#define ALLOW_IOCTL 1 // disabling this seems silly
#define ALLOW_RESOURCE_LIMITS 1
#define ALLOW_RANDOM 1
#define ALLOW_RSEQ 1 // I have no idea what this is
#define ALLOW_SETUID 1 // setts the user id of a process
#define ALLOW_POLL 1
#define ALLOW_CLEAN_UP 1 // various syscalls used for cleaning up, example: close; disallowing this seems crazy
#define ALLOW_PIPE 1
#define ALLOW_WAIT 1
#define ALLOW_UNKNOWN 1 // what to do if we get a syscall that we don't know

int main(int argc, char* argv[]) {   
    pid_t child;

    if (argc == 1) {
        printf(PREFIX "0 arguments passed\n");
        exit(-1);
    }

    char* chargs[argc];
    int i = 0;

    while (i < argc - 1) {
        chargs[i] = argv[i+1];
        i++;
    }
    chargs[i] = NULL;

    child = fork();
    if(child == 0) {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execvp(chargs[0], chargs);
        printf(PREFIX "could not start child process\n");
        return -2; // this should be unreachable
    }


    int status;

    while(waitpid(child, &status, 0) && ! WIFEXITED(status)) {

        struct user_regs_struct regs;
        ptrace(PTRACE_GETREGS, child, NULL, &regs);

        long syscall_id = REG_SYSCALL_ID(regs);

        bool whitelisted = 0;
        switch(syscall_id){

            case SYS_brk:
            case SYS_mmap:
                whitelisted = ALLOW_MEMORY_ALLOCATION;
                break;

            case SYS_execve:
                whitelisted = ALLOW_EXECUTE_OTHER_PROGRAMS;
                break;

            case SYS_access:
            case SYS_fstat:
            case SYS_getuid:
            case SYS_getgid:
            case SYS_geteuid:
            case SYS_getegid:
            case SYS_uname:
            case SYS_newfstatat:
            case SYS_getpid:
            case SYS_getppid:
            case SYS_getpgrp:
            case SYS_fstatfs:
                whitelisted = ALLOW_CHECK_PERMISSIONS_AND_INFO;
                break;

            case SYS_chdir:
                whitelisted = ALLOW_CHDIR;
                break;

            case SYS_openat:
                whitelisted = ALLOW_OPEN;
                break;

            case SYS_dup:
            case SYS_dup2:
            case SYS_fcntl:
            case SYS_lseek:
                whitelisted = ALLOW_FILE_UTILS;
                break;

            case SYS_read:
            case SYS_pread64:
            case SYS_getdents64:                
                whitelisted = ALLOW_READ;
                break;
            
            case SYS_write:
                whitelisted = ALLOW_WRITE;
                break;

            case SYS_close:
            case SYS_munmap:
            case SYS_exit_group:
                whitelisted = ALLOW_CLEAN_UP;
                break;

            case SYS_arch_prctl:
            case SYS_set_tid_address:
            case SYS_prctl:
            case SYS_capget:
            case SYS_capset:
            case SYS_clone:
                whitelisted = ALLOW_THREADING;
                break;

            case SYS_set_robust_list:
            case SYS_futex:
                whitelisted = ALLOW_FUTEX;
                break;

            case SYS_mprotect:
                whitelisted = ALLOW_SET_MEMORY_PROTECTION;
                break;

            case SYS_rt_sigprocmask:
            case SYS_rt_sigaction:
            case SYS_pause:
                whitelisted = ALLOW_SIGNALS;
                break;

            case SYS_ioctl:
                whitelisted = ALLOW_IOCTL;
                break;

            case SYS_getpeername:
            case SYS_socket:
            case SYS_connect:
            case SYS_setsockopt:
            case SYS_sendmmsg:
            case SYS_recvfrom:
            case SYS_getsockname:
            case SYS_recvmsg:
            case SYS_sendto:
            case SYS_getsockopt:
            case SYS_bind:
                whitelisted = ALLOW_NETWORKING;
                break;

            case SYS_prlimit64:
                whitelisted = ALLOW_RESOURCE_LIMITS;
                break;

            case SYS_getrandom:
                whitelisted = ALLOW_RANDOM;
                break;

            case SYS_rseq:
                whitelisted = ALLOW_RSEQ;
                break;

            case SYS_setuid:
                whitelisted = ALLOW_SETUID;
                break;

            case SYS_poll:
            case SYS_ppoll:
                whitelisted = ALLOW_POLL;
                break;
            
            case SYS_pipe2:
                whitelisted = ALLOW_PIPE;
                break;
            
            case SYS_wait4:
                whitelisted = ALLOW_WAIT;
                break;
            
            case SYS_rmdir:
            case SYS_unlinkat:
                whitelisted = ALLOW_DELETING;
                break;

            // case -1:
            // case SYS_write:
            //     {
            //         unsigned int fd = regs.rdi;
            //         // char *buf = (char *)regs.rsi; // we actually can't read this memory
            //         size_t count = regs.rdx;

            //         printf("from pid %d: SYS_write; fd=%u count=%lu\n", child, fd, count);
            //     }
            //     break;

            // this is probably caused by us
            case -1:
                whitelisted = 1;
                break;
            
            default:
                printf(PREFIX "unknown syscall with id %ld\n", syscall_id);
                whitelisted = ALLOW_UNKNOWN;
                break;
        }

        if(!whitelisted){
            printf(PREFIX "blocked syscall with id %ld\n", syscall_id);
            REG_SYSCALL_ID(regs) = -1; // invalidate the syscall by changing the id to some garbage
            ptrace(PTRACE_SETREGS, child, NULL, &regs);
        }

        ptrace(PTRACE_SYSCALL, child, NULL, NULL);
    }

    int child_exit_status = WEXITSTATUS(status);

    return child_exit_status;
}
