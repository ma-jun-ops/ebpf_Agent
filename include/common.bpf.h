#include "vmlinux.h"
#include <bpf/bpf_helpers.h>



struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rb SEC(".maps");