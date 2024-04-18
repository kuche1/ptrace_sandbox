
char *get_syscall_name(long syscall_id){
    switch(syscall_id){
        case SYS_write:
            return "write";
        case SYS_dup:
            return "dup";
        case SYS_execve:
            return "execve";
    }
    return "unknown";
}
