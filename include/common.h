#ifndef __COMMON_H
#define __COMMON_H

#define TASK_COMM_LEN 16
#define PATH_LEN      256
#define AF_INET       2

enum event_type {
    EVENT_EXECVE = 1,
    EVENT_OPENAT,
    EVENT_UNLINK,
    EVENT_CONNECT,
};

struct process_event {
    unsigned int type;

    unsigned int pid;
    unsigned int tgid;

    char comm[TASK_COMM_LEN];

    char filename[PATH_LEN];

    unsigned int ip;
    unsigned short port;
};

#endif