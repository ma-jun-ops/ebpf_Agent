#include "../include/common.bpf.h"
#include <bpf/bpf_tracing.h>
#include "../include/common.h"
#include "../include/vmlinux.h"


char LICENSE[] SEC("license") = "GPL";



SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct process_event *e;
    u64 pid_tgid;
    long ret;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    //清零结构体process_event
    __builtin_memset(e, 0, sizeof(*e));

    e->type = EVENT_EXECVE;

    //63                     32 31                  0
    //+-----------------------+---------------------+
    //|        TGID           |        PID          |
    //+-----------------------+---------------------+
    pid_tgid = bpf_get_current_pid_tgid();

    e->pid  = (u32)pid_tgid;
    e->tgid = pid_tgid >> 32;

    //指令名 ls bash
    bpf_get_current_comm(e->comm, sizeof(e->comm));

    //获取执行路径
    ret = bpf_probe_read_user_str(
            e->filename,
            sizeof(e->filename),
            (void *)ctx->args[0]);

    if (ret < 0)
        e->filename[0] = '\0';

    bpf_ringbuf_submit(e, 0);

    return 0;
}