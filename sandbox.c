
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
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

#define ERR_BAD_CMDLINE -1
#define ERR_CANT_START_PROCESS -2
#define ERR_MALLOC -3
#define ERR_BAD_ENVVAR -4

////// rules

// files / dirs
//
#define ALLOW_OPEN 1
#define ALLOW_READ 1
#define ALLOW_WRITE 1
//
#define ALLOW_DELETING 1
#define ALLOW_CHDIR_GETCWD 1 // disabling this wouldn't be of much help since there are many other syscalls such as `openat` and `unlinkat`
#define ALLOW_FILE_UTILS 1
#define ALLOW_CHOWN 1
#define ALLOW_RENAME 1

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
#define ALLOW_SETUID 1 // changes the user id
#define ALLOW_POLL_SELECT 1
#define ALLOW_CLEAN_UP 1 // various syscalls used for cleaning up, example: close; disallowing this seems crazy
#define ALLOW_PIPE 1
#define ALLOW_WAIT 1

////// funcions

int get_intbool_env(char *name, int default_){

    char *value = NULL;

    {
        int name_len = strlen(name);

        char *prefix = "SANDBOX_";
        int prefix_len = strlen(prefix);

        char *actual_name = malloc(prefix_len + name_len + 1);
        if(!actual_name){
            exit(ERR_MALLOC);
        }
        memcpy(actual_name, prefix, prefix_len);
        memcpy(actual_name + prefix_len, name, name_len);
        actual_name[prefix_len + name_len] = 0;

        value = getenv(actual_name);
        free(actual_name);
    }

    if(!value){
        return default_;
    }

    if(strcmp(value, "y") == 0){
        return 1;
    }else if(strcmp(value, "n") == 0){
        return 0;
    }else{
        printf(PREFIX "invalid value for %s: `%s`\n", name, value);
        exit(ERR_BAD_ENVVAR);
    }

    return  atoi(value); // this sucks; too bad I don't care;
}

int main(int argc, char *argv[]){

    // parse args

    if(argc == 1){
        printf(PREFIX "you need to pass the application that you want to be run in the sandbox\n");
        exit(ERR_BAD_CMDLINE);
    }

    int allow_networking = get_intbool_env("NETWORKING", 0);
    printf(PREFIX "networking: %d\n", allow_networking);

    // this covers unknown syscalls
    int allow_unknown = get_intbool_env("UNKNOWN", 1);
    printf(PREFIX "unknown: %d\n", allow_unknown);

    // run sandboxed process

    char *process_to_run = argv[1];
    char **process_args = argv + 1;

    pid_t child = fork();
    if(child == 0){
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execvp(process_to_run, process_args);
        printf(PREFIX "could not start process `%s`\n", process_to_run);
        return ERR_CANT_START_PROCESS;
    }

    // filter syscalls

    int status;

    while(waitpid(child, &status, 0) && ! WIFEXITED(status)){

        struct user_regs_struct regs;
        ptrace(PTRACE_GETREGS, child, NULL, &regs);

        long syscall_id = REG_SYSCALL_ID(regs);
        char *syscall_desc = "no description";
        int whitelisted = 0;

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
            case SYS_readlink:
                whitelisted = ALLOW_CHECK_PERMISSIONS_AND_INFO;
                break;

            case SYS_chdir:
            case SYS_getcwd:
                whitelisted = ALLOW_CHDIR_GETCWD;
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
            case SYS_gettid:
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
                whitelisted = allow_networking;
                syscall_desc = "networking";
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
            case SYS_setfsuid:
            case SYS_setfsgid:
                whitelisted = ALLOW_SETUID;
                break;

            case SYS_poll:
            case SYS_ppoll:
            case SYS_pselect6:
            case SYS_epoll_create1:
                whitelisted = ALLOW_POLL_SELECT;
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
            
            case SYS_chown:
                whitelisted = ALLOW_CHOWN;
                break;
            
            case SYS_rename:
                whitelisted = ALLOW_RENAME;
                break;

            // this is probably caused by us
            case -1:
                whitelisted = 1;
                break;
            
            default:
                printf(PREFIX "unknown syscall with id %ld\n", syscall_id);
                whitelisted = allow_unknown;
                break;
        }

        if(!whitelisted){
            printf(PREFIX "blocked syscall with id %ld; description: %s\n", syscall_id, syscall_desc);
            REG_SYSCALL_ID(regs) = -1; // invalidate the syscall by changing the id to some garbage
            ptrace(PTRACE_SETREGS, child, NULL, &regs);
        }

        ptrace(PTRACE_SYSCALL, child, NULL, NULL);
    }

    int child_exit_status = WEXITSTATUS(status);

    return child_exit_status;
}
