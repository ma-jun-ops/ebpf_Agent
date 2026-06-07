#ifndef __COMMON_H__
#define __COMMON_H__

#define TASK_COMM_LEN 16

struct exec_event {
    unsigned int pid;
    char comm[TASK_COMM_LEN];
    char filename[256];
};

#endif