// 公共头文件：包含 vmlinux.h、bpf_helpers.h 以及统一的 ringbuffer 定义
#include "../include/common.bpf.h"
// bpf_tracing.h：提供 tracepoint 相关辅助宏
#include <bpf/bpf_tracing.h>
// 公共数据结构定义（process_event 等）
#include "../include/common.h"

// BPF 程序许可证声明
char LICENSE[] SEC("license") = "GPL";

// 追踪 openat 系统调用：捕获进程打开文件的事件
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx)
{
    struct process_event *e;
    u64 pid_tgid;

    // 从 ringbuffer 中申请一块内存，用于存放事件数据
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    // 清零事件结构体，防止脏数据
    __builtin_memset(e, 0, sizeof(*e));

    // 设置事件类型为文件打开
    e->type = EVENT_OPENAT;

    // 获取当前进程的 PID 和 TGID
    // 高 32 位为 TGID（线程组 ID），低 32 位为 PID
    pid_tgid = bpf_get_current_pid_tgid();

    e->pid  = (u32)pid_tgid;
    e->tgid = pid_tgid >> 32;

    // 获取当前进程的命令名（如 ls、bash）
    bpf_get_current_comm(e->comm, sizeof(e->comm));

    // 从系统调用参数中读取文件路径（ctx->args[1] 为 openat 的第二个参数：路径名）
    bpf_probe_read_user_str(
        e->filename,
        sizeof(e->filename),
        (void *)ctx->args[1]
    );

    // 提交事件到 ringbuffer，通知用户态程序读取
    bpf_ringbuf_submit(e, 0);

    return 0;
}

// 追踪 unlinkat 系统调用：捕获进程删除文件的事件
SEC("tracepoint/syscalls/sys_enter_unlinkat")
int trace_unlinkat(struct trace_event_raw_sys_enter *ctx)
{
    struct process_event *e;
    u64 pid_tgid;

    // 从 ringbuffer 中申请一块内存，用于存放事件数据
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    // 清零事件结构体，防止脏数据
    __builtin_memset(e, 0, sizeof(*e));

    // 设置事件类型为文件删除
    e->type = EVENT_UNLINK;

    // 获取当前进程的 PID 和 TGID
    // 高 32 位为 TGID（线程组 ID），低 32 位为 PID
    pid_tgid = bpf_get_current_pid_tgid();

    e->pid  = (u32)pid_tgid;
    e->tgid = pid_tgid >> 32;

    // 获取当前进程的命令名
    bpf_get_current_comm(e->comm, sizeof(e->comm));

    // 从系统调用参数中读取被删除的文件路径（ctx->args[1] 为 unlinkat 的第二个参数：路径名）
    bpf_probe_read_user_str(
        e->filename,
        sizeof(e->filename),
        (void *)ctx->args[1]
    );

    // 提交事件到 ringbuffer，通知用户态程序读取
    bpf_ringbuf_submit(e, 0);

    return 0;
}