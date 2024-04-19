
// `mode` really should be `umode_t` but it seems that I can't access this since I'm in user space
void handle_syscall_openat(pid_t pid, int dir_fd, char *pidmem_filename, int flags, mode_t mode){

    // https://man7.org/linux/man-pages/man2/openat.2.html

    // `flags` must include one of these: O_RDONLY (read only), O_WRONLY (write only), O_RDWR (read and write)
    // other flags can be bitwise ORed

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

    printf(PREFIX "SYS_openat: dir_fd=%d flags=%d mode=%d filename=%s\n", dir_fd, flags, mode, filename);
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
            
            case SYS_open:{
                syscall_allow = 1;

                char *filename = (char *) REG_SYSCALL_ARG0(regs);
                int flags = REG_SYSCALL_ARG1(regs);
                mode_t mode = REG_SYSCALL_ARG2(regs);

                handle_syscall_openat(pid, AT_FDCWD, filename, flags, mode);
            }
            break;

            case SYS_openat:{
                syscall_allow = 1;

                int dir_fd = REG_SYSCALL_ARG0(regs);
                char *filename = (char *)REG_SYSCALL_ARG1(regs);
                int flags = REG_SYSCALL_ARG2(regs);
                mode_t mode = REG_SYSCALL_ARG3(regs);

                handle_syscall_openat(pid, dir_fd, filename, flags, mode);
            }
            break;

            default:{
                char *name = get_syscall_name(syscall_id);
                printf(PREFIX "unhandled syscall `%s` with id %ld\n", name, syscall_id);
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
