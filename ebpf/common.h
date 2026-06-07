#ifndef __COMMON_H
#define __COMMON_H

#define TASK_COMM_LEN 16
#define PATH_LEN      256

struct process_event {
    unsigned int pid;      // 线程ID
    unsigned int tgid;     // 进程ID

    char comm[TASK_COMM_LEN];
    char filename[PATH_LEN];
};

#endif