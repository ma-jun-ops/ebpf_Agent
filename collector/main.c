#include "ebpf.skel.h"
#include <unistd.h>
#include <stdio.h>
#include <bpf/libbpf.h>
#include "../ebpf/common.h"
#include <stdarg.h>

//日至
static int libbpf_print_fn(enum libbpf_print_level level,
                           const char *format,
                           va_list args)
{
    return vfprintf(stderr, format, args);
}

//回调函数
static int handle_event(void *ctx,void *data,size_t data_sz) {
    printf("EVENT ARRIVED\n");
    fflush(stdout);
    const struct process_event *e =data;
    printf("[EXECVE EVENT] PID: %d | TID: %d | Comn: %s | Path: %s\n", e->tgid,e->pid,e->comm,e->filename);
    //todo analyzer
    return 0;
}

int main()
{
    libbpf_set_print(libbpf_print_fn);
    struct ebpf_bpf *skel=NULL;
    struct ring_buffer *rb=NULL;
    int err;

    // printf("STEP1\n");

    skel = ebpf_bpf__open_and_load();//读取.o 创建map 创建rb Verifer检查

    // printf("STEP2\n");

    if (!skel) {
        fprintf(stderr,"[ERROR] Failed to load skelette\n");
        return 1;
    }

    // printf("STEP3\n");

    err = ebpf_bpf__attach(skel);

    // printf("STEP4 err=%d\n", err);

    if (err) {
        fprintf(stderr,
                "[ERROR] attach failed: %d\n",
                err);
        return 1;
    }

    // printf("STEP5\n");

    rb=ring_buffer__new(
        bpf_map__fd(skel->maps.rb),
        handle_event,NULL,NULL
        );

    // printf("STEP6 rb=%p\n", rb);

    if (!rb) {
        fprintf(stderr,"[ERROR] Failed to create rb\n");
        ebpf_bpf__destroy(skel);
        return 1;
    }
    // printf("STEP7\n");

    printf("Successfully started! Monitoring execve syscalls...\\n");

    while (1){
        err = ring_buffer__poll(rb, 100);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
    }

    ring_buffer__free(rb);
    ebpf_bpf__destroy(skel);
    return 0;
}
