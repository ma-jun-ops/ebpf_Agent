#include "ebpf.skel.h"
#include <unistd.h>


int main()
{
    struct ebpf_bpf *skel;

    skel = ebpf_bpf__open_and_load();

    if (!skel)
        return 1;

    if (ebpf_bpf__attach(skel))
        return 1;

    while (1)
        sleep(1);
}
