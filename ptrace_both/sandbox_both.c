
// info
//
// man page: https://man7.org/linux/man-pages/man2/ptrace.2.html
//
// PTRACE_SYSCALL means: stop at the nextsyscall
// PTRACE_CONT means: stop at the next signal

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <string.h>
#include <syscall.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>

#if __WORDSIZE == 64
#define REG_SYSCALL_ID(reg) reg.orig_rax // we use this is we want to modify the syscall ID before execution
#define REG_SYSCALL_ARG0(reg) reg.rdi // TODO tova se si mislq 4e trqbva da e orig_rdi
#define REG_SYSCALL_RET(reg) reg.rax // we use this if we want to change the return code
#else
#error only 64bit is supported
#endif

#define PREFIX "SANDBOX_PTRACE: "
#define PRINT_BLOCKED 1
#define PRINT_UNKNOWN 0

#define ERR_BAD_CMDLINE -1
#define ERR_CANT_START_PROCESS -2
#define ERR_MALLOC -3
#define ERR_BAD_ENVVAR -4
#define ERR_CANT_START_CHILD -5
#define ERR_PTRACE_SET_OPTIONS -6
#define ERR_PTRACE_CANT_CONT -7
#define ERR_PTRACE_TRACEME -8

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
//
#define ALLOW_MKDIR 1
#define ALLOW_MKNOD 1
#define ALLOW_SYMLINK 1

// networking
#define ALLOW_NETWORKING_MISC 1

// threading
#define ALLOW_THREADING_CTL 1 // functions that don't start new threads but controll the current thread

#define ALLOW_MEMORY_OPERATIONS 1
#define ALLOW_EXECUTE_OTHER_PROGRAMS 1
#define ALLOW_CHECK_PERMISSIONS_AND_INFO 1
#define ALLOW_SET_PERMISSIONS 1
#define ALLOW_FUTEX 1 // I don't see why we would ever want to disable this
#define ALLOW_SET_MEMORY_PROTECTION 1 // gives processes the ability to change it's own memory protection
#define ALLOW_SIGNALS 1 // note that this also includes SIGTERM and SIGKILL
#define ALLOW_IOCTL 1 // disabling this seems silly
#define ALLOW_RESOURCE_LIMITS 1
#define ALLOW_RANDOM 1
#define ALLOW_RSEQ 1 // I have no idea what this is
#define ALLOW_SETUID 1 // changes the user id
#define ALLOW_POLL_SELECT 1
#define ALLOW_CLEAN_UP 1 // various syscalls used for cleaning up, example: close; disallowing this seems crazy
#define ALLOW_PIPE 1
#define ALLOW_WAIT 1
#define ALLOW_LOADING_UNLOADING_KERNEL_MODULES 1
#define ALLOW_SLEEP 1
#define ALLOW_GET_SCHED 1
#define ALLOW_SET_SCHED 1
#define ALLOW_SCHED_YIELD 1
#define ALLOW_RESTART_SYSCALL 1 // restart syscall after interrupt
#define ALLOW_BPF 1 // something to do with filtering

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

        printf(PREFIX "%s: ", actual_name);

        value = getenv(actual_name);
        free(actual_name);
    }

    if(!value){
        printf("%s (using default value since env var is not set)\n", (default_ ? "y" : "n") );
        return default_;
    }

    printf("%s\n", value);

    if(strcmp(value, "y") == 0){
        return 1;
    }else if(strcmp(value, "n") == 0){
        return 0;
    }else{
        printf(PREFIX "invalid value for environment variable `%s` of `%s`; the only valid values are `y` and `n`\n", name, value);
        exit(ERR_BAD_ENVVAR);
    }
}

void run_sandboxed_process(char *process_to_run, char **process_args){
    pid_t child = fork();

    if(child < 0){

        printf(PREFIX "could not start child process\n");
        exit(ERR_CANT_START_CHILD);

    }else if(child == 0){

        {
            long err = ptrace(PTRACE_TRACEME, 0, NULL, NULL); // code execution will be paused until parent allows us to continue
            if(err){
                printf(PREFIX "could not PTRACE_TRACEME\n");
                exit(ERR_PTRACE_TRACEME);
            }
        }

        // TODO seccomp code, this might actually fuck with the code below in case of a syscall

        execvp(process_to_run, process_args);
        printf(PREFIX "could not start process `%s`\n", process_to_run);
        exit(ERR_CANT_START_PROCESS);
    }

    // 1. do not filter the child's call to `execvp`
    // 2. `PTRACE_SETOPTIONS`
    waitpid(child, 0, 0);

    {
        long err = ptrace(
            PTRACE_SETOPTIONS,
            child,
            0,
            PTRACE_O_EXITKILL | // make sure to kill the child if the parent exits
            PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | // trace any new processes created by the child
            PTRACE_O_TRACEEXIT // get notified when a process exits
        );

        if(err){
            printf(PREFIX "could not set ptrace options\n");
            exit(ERR_PTRACE_SET_OPTIONS);
        }
    }

    {
        long err = ptrace(PTRACE_SYSCALL, child, NULL, NULL);
        if(err){
            printf(PREFIX "could not continue ptrace\n");
            exit(ERR_PTRACE_CANT_CONT);
        }
    }
}

int main(int argc, char *argv[]){

    // parse args

    if(argc == 1){
        printf(PREFIX "you need to pass the application that you want to be run in the sandbox\n");
        exit(ERR_BAD_CMDLINE);
    }

    int allow_networking = get_intbool_env("NETWORKING", 0);
    int allow_unknown = get_intbool_env("UNKNOWN", 1); // this covers unknown syscalls
    int allow_threading = get_intbool_env("THREADING", 1);

    printf("\n");

    // run sandboxed process

    {

        char *process_to_run = argv[1];
        char **process_args = argv + 1;

        run_sandboxed_process(process_to_run, process_args);
    }

    // filter syscalls

    int return_code = 0;
    int running_processes = 1;
    int at_least_1_syscall_was_blocked = 0;

    // while(waitpid(child, &status, 0) && ! WIFEXITED(status)){
    while(1){

        int status;
        pid_t pid = waitpid(-1, &status, 0); // it kinda sucks that we're waiting for anyone, would be better if we actually traced the pids

        if(status>>8 == (SIGTRAP | (PTRACE_EVENT_EXIT<<8))){

            running_processes -= 1;

            unsigned long event_message;
            ptrace(PTRACE_GETEVENTMSG, pid, NULL, &event_message);

            if(event_message){
                // there's something wrong with the code that gets the return code
                // so we won't return the thread's code
                return_code = 1;
            }

            ptrace(PTRACE_SYSCALL, pid, NULL, NULL);

            if(running_processes <= 0){
                break;
            }
            continue;
        }

        if(
            ( status>>8 == (SIGTRAP | (PTRACE_EVENT_CLONE<<8)) ) ||
            ( status>>8 == (SIGTRAP | (PTRACE_EVENT_FORK<<8))  ) ||
            ( status>>8 == (SIGTRAP | (PTRACE_EVENT_VFORK<<8)) )
        ){
            running_processes += 1;
            ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
            continue;
        }

        // if(WIFEXITED(status)){
        //     printf(PREFIX "child %d exited\n", pid);
        //     getchar();
        //     continue;
        // }

        struct user_regs_struct regs;
        ptrace(PTRACE_GETREGS, pid, NULL, &regs);

        long syscall_id = REG_SYSCALL_ID(regs);
        char *syscall_desc = "no description";
        int whitelisted = 0;

        // printf(PREFIX "filtering syscall %ld\n", syscall_id);

        switch(syscall_id){

            case SYS_brk:
            case SYS_mmap:
            case SYS_mremap:
            case SYS_mlock:
            case SYS_mlock2:
            case SYS_munlock:
            case SYS_mlockall:
            case SYS_munlockall:
            case SYS_writev:
                whitelisted = ALLOW_MEMORY_OPERATIONS;
                break;

            case SYS_execve:
                whitelisted = ALLOW_EXECUTE_OTHER_PROGRAMS;
                syscall_desc = "exec";
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
            case SYS_readlinkat:
            case SYS_stat:
            case SYS_lstat:
            case SYS_getresuid:
            case SYS_getresgid:
            case SYS_statx:
            case SYS_faccessat2:
            case SYS_sysinfo:
            case SYS_getxattr:
                whitelisted = ALLOW_CHECK_PERMISSIONS_AND_INFO;
                break;

            case SYS_chdir:
            case SYS_fchdir:
            case SYS_getcwd:
                whitelisted = ALLOW_CHDIR_GETCWD;
                break;

            case SYS_openat:
            case SYS_open:
            case SYS_umask:
            case SYS_fadvise64:
            case SYS_name_to_handle_at:
            case SYS_open_by_handle_at:
                whitelisted = ALLOW_OPEN;
                break;

            case SYS_dup:
            case SYS_dup2:
            case SYS_fcntl:
            case SYS_lseek:
            case SYS_copy_file_range:
            case SYS_flock:
                whitelisted = ALLOW_FILE_UTILS;
                break;

            case SYS_read:
            case SYS_pread64:
            case SYS_getdents64:                
                whitelisted = ALLOW_READ;
                break;
            
            case SYS_write:
                whitelisted = ALLOW_WRITE;
                syscall_desc = "write";
                break;

            case SYS_close:
            case SYS_munmap:
            case SYS_exit_group:
            case SYS_exit:
                whitelisted = ALLOW_CLEAN_UP;
                break;

            case SYS_gettid:
            case SYS_prctl:
            case SYS_capget:
            case SYS_capset:
            case SYS_clone:
            case SYS_clone3:
            case SYS_process_vm_readv:
            case SYS_process_vm_writev:
                whitelisted = allow_threading;
                syscall_desc = "threading";
                break;

            case SYS_arch_prctl:
            case SYS_set_tid_address:
                whitelisted = ALLOW_THREADING_CTL;
                syscall_desc = "threading ctl";
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
            case SYS_kill:
            case SYS_tgkill:
            case SYS_sigaltstack:
                whitelisted = ALLOW_SIGNALS;
                break;

            case SYS_ioctl:
                whitelisted = ALLOW_IOCTL;
                break;

            // https://linasm.sourceforge.net/docs/syscalls/network.php

            case SYS_socket:
            case SYS_socketpair:
                // https://man7.org/linux/man-pages/man2/socket.2.html
                {
                    int domain = REG_SYSCALL_ARG0(regs);
                    if(allow_networking){
                        whitelisted = 1;
                        syscall_desc = "create socket";
                    }else{

                        switch(domain){

                            case AF_LOCAL: // this also includes AF_UNIX
                            case AF_BRIDGE:
                            case AF_NETLINK:
                                whitelisted = 1;
                                syscall_desc = "create socket; local";
                                break;
                            
                            case AF_INET:
                            case AF_DECnet:
                            case AF_ROSE:
                                break;

                            default:
                                printf(PREFIX "blocked non-local create socket of domain %d\n", domain);
                                syscall_desc = "create socket; non-local";
                                break;
                        }
                    }
                }
                break;

            case SYS_sethostname:
            case SYS_setdomainname:
                whitelisted = allow_networking;
                syscall_desc = "networking";
                break;

            case SYS_bind:
            case SYS_listen:
            case SYS_accept:
            case SYS_accept4:
            case SYS_sendto:
            case SYS_sendmsg:
            case SYS_sendmmsg:
            case SYS_recvfrom:
            case SYS_recvmsg:
            case SYS_recvmmsg:
            case SYS_setsockopt:
            case SYS_getsockopt:
            case SYS_getsockname:
            case SYS_getpeername:
            case SYS_connect: // this is dependent on the socket creation
                whitelisted = ALLOW_NETWORKING_MISC;
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
            case SYS_setreuid:
            case SYS_setregid:
                whitelisted = ALLOW_SETUID;
                break;

            case SYS_poll:
            case SYS_ppoll:
            case SYS_pselect6:
            case SYS_epoll_create1:
            case SYS_epoll_wait:
            case SYS_epoll_ctl:
                whitelisted = ALLOW_POLL_SELECT;
                break;
            
            case SYS_pipe2:
                whitelisted = ALLOW_PIPE;
                break;
            
            case SYS_wait4:
                whitelisted = ALLOW_WAIT;
                break;
            
            case SYS_rmdir:
            case SYS_unlink:
            case SYS_unlinkat:
                whitelisted = ALLOW_DELETING;
                break;
            
            case SYS_chown:
                whitelisted = ALLOW_CHOWN;
                break;
            
            case SYS_rename:
                whitelisted = ALLOW_RENAME;
                break;
            
            case SYS_mkdir:
                whitelisted = ALLOW_MKDIR;
                break;

            case SYS_symlink:
                whitelisted = ALLOW_SYMLINK;
                break;
            
            case SYS_chmod:
                whitelisted = ALLOW_SET_PERMISSIONS;
                break;
            
            case SYS_init_module:
            case SYS_delete_module:
            case SYS_create_module:
                whitelisted = ALLOW_LOADING_UNLOADING_KERNEL_MODULES;
                break;
            
            case SYS_clock_nanosleep:
                whitelisted = ALLOW_SLEEP;
                break;

            case SYS_ioprio_get:
            case SYS_sched_getaffinity:
            case SYS_sched_getscheduler:
            case SYS_sched_get_priority_max:
            case SYS_sched_get_priority_min:
            case SYS_sched_rr_get_interval:
                whitelisted = ALLOW_GET_SCHED;
                break;

            case SYS_ioprio_set:
            case SYS_sched_setaffinity:
                whitelisted = ALLOW_SET_SCHED;
                break;

            case SYS_sched_yield:
                whitelisted = ALLOW_SCHED_YIELD;
                break;
            
            case SYS_restart_syscall:
                whitelisted = ALLOW_RESTART_SYSCALL;
                break;
            
            case SYS_mknod:
            case SYS_mknodat:
                whitelisted = ALLOW_MKNOD;
                break;
            
            case SYS_bpf:
                whitelisted = ALLOW_BPF;
                break;

            // this is probably caused by us
            case -1:
                whitelisted = 1;
                break;
            
            default:
#if PRINT_UNKNOWN
                printf(PREFIX "unknown syscall with id %ld\n", syscall_id);
#endif
                whitelisted = allow_unknown;
                break;
        }

        if(!whitelisted){
            at_least_1_syscall_was_blocked = 1;
#if PRINT_BLOCKED
            printf(PREFIX "blocked syscall with id %ld; description: %s\n", syscall_id, syscall_desc);
#endif
            REG_SYSCALL_ID(regs) = -1; // invalidate the syscall by changing the id to some garbage
            ptrace(PTRACE_SETREGS, pid, NULL, &regs);
        }

        ptrace(PTRACE_SYSCALL, pid, NULL, NULL);

        syscall_desc = syscall_desc; // stop the compiler from complaining
    }

    // int child_exit_status = WEXITSTATUS(status);

    printf("\n");
    printf(PREFIX "at least 1 syscall blocked: %d\n", at_least_1_syscall_was_blocked);

    return return_code;
}
