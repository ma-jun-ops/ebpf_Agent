// 公共头文件：包含 vmlinux.h、bpf_helpers.h 以及统一的 ringbuffer 定义
#include "../include/common.bpf.h"
// bpf_tracing.h：提供 tracepoint 相关辅助宏
#include <bpf/bpf_tracing.h>
// 公共数据结构定义（process_event 等）
#include "../include/common.h"

// BPF 程序许可证声明
char LICENSE[] SEC("license") = "GPL";

// 追踪 connect 系统调用：捕获进程发起网络连接的事件
SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter *ctx)
{
    struct process_event *e;
    struct sockaddr_in addr;
    u64 pid_tgid;

    // 从 ringbuffer 中申请一块内存，用于存放事件数据
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    // 清零事件结构体，防止脏数据
    __builtin_memset(e, 0, sizeof(*e));

    // 设置事件类型为网络连接
    e->type = EVENT_CONNECT;

    // 获取当前进程的 PID 和 TGID
    // 高 32 位为 TGID（线程组 ID），低 32 位为 PID
    pid_tgid = bpf_get_current_pid_tgid();

    e->pid  = (u32)pid_tgid;
    e->tgid = pid_tgid >> 32;

    // 获取当前进程的命令名
    bpf_get_current_comm(e->comm, sizeof(e->comm));

    // 从系统调用参数中读取目标地址（ctx->args[1] 为 connect 的第二个参数：sockaddr 结构体）
    if (bpf_probe_read_user(
            &addr,
            sizeof(addr),
            (void *)ctx->args[1]) == 0)
    {
        // 仅处理 IPv4 连接
        if (addr.sin_family == AF_INET) {
            // 目标 IP 地址（网络字节序）
            e->ip = addr.sin_addr.s_addr;

            // 目标端口（从网络字节序转换为主机字节序）
            e->port =
                ((addr.sin_port & 0xff) << 8) |
                ((addr.sin_port >> 8) & 0xff);
        }
    }

    // 提交事件到 ringbuffer，通知用户态程序读取
    bpf_ringbuf_submit(e, 0);

    return 0;
}
