#include "ebpf.skel.h"
#include "file.skel.h"
#include "net.skel.h"
#include <unistd.h>
#include <stdio.h>
#include <bpf/libbpf.h>
#include "common.h"
#include <stdarg.h>

//日至
static int libbpf_print_fn(enum libbpf_print_level level,
                           const char *format,
                           va_list args)
{
    return vfprintf(stderr, format, args);
}

//回调函数
static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct process_event *e = data;
    switch (e->type) {
        case EVENT_EXECVE:
            printf(
                "[EXECVE] "
                "TGID=%u PID=%u COMM=%s PATH=%s\n",
                e->tgid,
                e->pid,
                e->comm,
                e->filename
            );
            break;
        case EVENT_OPENAT:
            printf(
                "[OPEN] "
                "TGID=%u PID=%u COMM=%s FILE=%s\n",
                e->tgid,
                e->pid,
                e->comm,
                e->filename
            );
            break;
        case EVENT_UNLINK:
            printf(
                "[DELETE] "
                "TGID=%u PID=%u COMM=%s FILE=%s\n",
                e->tgid,
                e->pid,
                e->comm,
                e->filename
            );
            break;
        case EVENT_CONNECT:
        {
            unsigned int ip = e->ip;
            printf(
                "[CONNECT] "
                "PID=%u COMM=%s "
                "IP=%u.%u.%u.%u "
                "PORT=%u\n",
                e->tgid,
                e->comm,

                ip & 0xff,
                (ip >> 8) & 0xff,
                (ip >> 16) & 0xff,
                (ip >> 24) & 0xff,
                e->port
            );
            break;
        }
        default:
            printf(
                "[UNKNOWN] "
                "type=%u pid=%u comm=%s\n",
                e->type,
                e->tgid,
                e->comm
            );
            break;
    }
    fflush(stdout);
    return 0;
}

int main()
{
    libbpf_set_print(libbpf_print_fn);
    struct ebpf_bpf *skel_ebpf = NULL;
    struct file_bpf *skel_file = NULL;
    struct net_bpf *skel_net = NULL;
    struct ring_buffer *rb = NULL;
    int err;

    // 1. 加载第一个 skeleton（ebpf.bpf.o），创建并 pin ringbuffer
    skel_ebpf = ebpf_bpf__open_and_load();
    if (!skel_ebpf) {
        fprintf(stderr, "[ERROR] Failed to load ebpf skeleton\n");
        return 1;
    }

    err = ebpf_bpf__attach(skel_ebpf);
    if (err) {
        fprintf(stderr, "[ERROR] ebpf attach failed: %d\n", err);
        goto cleanup_ebpf;
    }

    // 2. 加载第二个 skeleton（file.bpf.o），复用已有的 ringbuffer
    skel_file = file_bpf__open();
    if (!skel_file) {
        fprintf(stderr, "[ERROR] Failed to open file skeleton\n");
        goto cleanup_ebpf;
    }

    bpf_map__reuse_fd(skel_file->maps.rb, bpf_map__fd(skel_ebpf->maps.rb));

    err = file_bpf__load(skel_file);
    if (err) {
        fprintf(stderr, "[ERROR] file skeleton load failed: %d\n", err);
        goto cleanup_file;
    }

    err = file_bpf__attach(skel_file);
    if (err) {
        fprintf(stderr, "[ERROR] file attach failed: %d\n", err);
        goto cleanup_file;
    }

    // 3. 加载第三个 skeleton（net.bpf.o），复用已有的 ringbuffer
    skel_net = net_bpf__open();
    if (!skel_net) {
        fprintf(stderr, "[ERROR] Failed to open net skeleton\n");
        goto cleanup_file;
    }

    bpf_map__reuse_fd(skel_net->maps.rb, bpf_map__fd(skel_ebpf->maps.rb));

    err = net_bpf__load(skel_net);
    if (err) {
        fprintf(stderr, "[ERROR] net skeleton load failed: %d\n", err);
        goto cleanup_net;
    }

    err = net_bpf__attach(skel_net);
    if (err) {
        fprintf(stderr, "[ERROR] net attach failed: %d\n", err);
        goto cleanup_net;
    }

    // 4. 创建用户态 ring_buffer 消费者（三个程序共享同一个 ringbuffer）
    rb = ring_buffer__new(
        bpf_map__fd(skel_ebpf->maps.rb),
        handle_event, NULL, NULL);

    if (!rb) {
        fprintf(stderr, "[ERROR] Failed to create ring buffer\n");
        goto cleanup_net;
    }

    printf("Successfully started! Monitoring syscalls...\n");

    while (1) {
        err = ring_buffer__poll(rb, 100);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
    }

    ring_buffer__free(rb);

cleanup_net:
    net_bpf__destroy(skel_net);

cleanup_file:
    file_bpf__destroy(skel_file);

cleanup_ebpf:
    ebpf_bpf__destroy(skel_ebpf);

    return 0;
}
