// 分析器 —— 接收 eBPF 采集的事件，按规则生成安全告警
#include "analyzer.h"

#include <stdio.h>
#include <string.h>

// verbose 模式开关：1 表示打印所有原始事件，0 表示只输出告警
static int verbose;

// 设置 verbose 模式（由 main.c 通过命令行参数传入）
void analyzer_set_verbose(int v)
{
    verbose = v;
}

// 规则1：检测 shell 进程启动另一个 shell（用户手动执行 bash/sh/zsh 时触发）
static void analyze_exec(const struct process_event *e)
{
    // 从完整路径中提取文件名（如 /usr/bin/bash → bash）
    const char *name = strrchr(e->filename, '/');
    name = name ? name + 1 : e->filename;

    // 被执行的文件是否为 shell
    int is_target = !strcmp(name, "bash") ||
                    !strcmp(name, "sh") ||
                    !strcmp(name, "zsh");

    // 执行者是否为 shell（只有 shell 启动 shell 才算用户手动操作，
    // 过滤 node/python 等后台进程调用 sh 执行脚本的噪声）
    int is_shell_parent = !strcmp(e->comm, "bash") ||
                          !strcmp(e->comm, "sh") ||
                          !strcmp(e->comm, "zsh");

    // 两个条件同时满足才告警
    if (is_target && is_shell_parent)
    {
        // TODO: 可扩展检查 PPID 链，防止 shell 逃逸攻击
        printf(
            "[ALERT] SHELL SPAWN "
            "PID=%u PATH=%s\n",
            e->tgid,
            e->filename
        );
    }
}

// 规则2：检测敏感文件访问（打开或删除）
static void analyze_file(const struct process_event *e)
{
    // 检测 shadow 文件访问（可能为提权或密码窃取）
    if (strstr(e->filename, "/etc/shadow"))
    {
        printf(
            "[ALERT] SHADOW ACCESS "
            "PID=%u\n",
            e->tgid
        );
    }

    // 检测 SSH 密钥访问（可能为横向移动凭证窃取）
    if (strstr(e->filename, "/root/.ssh"))
    {
        printf(
            "[ALERT] SSH KEY ACCESS "
            "PID=%u\n",
            e->tgid
        );
    }

    // TODO: 可扩展更多敏感路径（如 /etc/passwd、/var/log/auth.log 等）
}

// 规则3：检测异常外联（后续升级：10秒连接100次 => ALERT API STORM）
static void analyze_net(const struct process_event *e)
{
    // TODO: 统计连接频率，10秒内超过100次触发 ALERT API STORM
}

// 事件分发入口 —— 由 handle_event 回调调用
void analyzer_process(const struct process_event *e)
{
    // verbose 模式：打印所有原始事件，便于调试和观察
    if (verbose) {
        // 根据事件类型确定标签
        const char *label = "UNKN";
        switch (e->type) {
            case EVENT_EXECVE:  label = "EXEC"; break;
            case EVENT_OPENAT:  label = "OPEN"; break;
            case EVENT_UNLINK:  label = "DELE"; break;
            case EVENT_CONNECT: {
                // 网络连接事件打印 IP 和端口
                unsigned int ip = e->ip;
                printf("[CONN] PID=%u COMM=%s IP=%u.%u.%u.%u PORT=%u\n",
                       e->pid, e->comm,
                       ip & 0xff, (ip >> 8) & 0xff,
                       (ip >> 16) & 0xff, (ip >> 24) & 0xff,
                       e->port);
                break;
            }
        }
        // 文件类事件打印路径
        if (e->type != EVENT_CONNECT) {
            printf("[%s] PID=%u COMM=%s PATH=%s\n",
                   label, e->pid, e->comm, e->filename);
        }
    }

    // 规则匹配：按事件类型调用对应的分析函数
    switch (e->type)
    {
        case EVENT_EXECVE:
            analyze_exec(e);
            break;

        case EVENT_OPENAT:
        case EVENT_UNLINK:
            analyze_file(e);
            break;

        case EVENT_CONNECT:
            analyze_net(e);
            break;
    }
}
