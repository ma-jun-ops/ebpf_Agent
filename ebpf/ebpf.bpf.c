#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
    u64 pid_tgid;
    u32 pid;
    char comm[16];

    pid_tgid = bpf_get_current_pid_tgid();
    pid = pid_tgid >> 32;

    bpf_get_current_comm(comm, sizeof(comm));

    bpf_printk(
        "[EXEC] pid=%d comm=%s",
        pid,
        comm
    );

    return 0;
}