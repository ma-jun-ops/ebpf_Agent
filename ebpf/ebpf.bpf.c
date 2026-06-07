#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "common.h"

char LICENSE[] SEC("license") = "GPL";


//Ringbuffer
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256*1024);
} rb SEC(".maps");



SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct process_event *e;
    u64 pid_tgid;
    long ret;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        bpf_printk("ringbuf reserve failed\n");
        return 0;
    }

    //清零结构体process_event
    __builtin_memset(e, 0, sizeof(*e));

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

    bpf_printk(
        "[EXEC] tgid=%d pid=%d comm=%s path=%s\n",
        e->tgid,
        e->pid,
        e->comm,
        e->filename
    );

    bpf_ringbuf_submit(e, 0);

    return 0;
}