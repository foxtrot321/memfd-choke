#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_core_read.h"
#define TASK_COMM_LEN 16
char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct event {
    int pid;
    char comm[TASK_COMM_LEN];
    bool success;
};

//passing messages from kernel to user
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");


SEC("tp/syscalls/sys_enter_memfd_create")
int memfdd(struct trace_event_raw_sys_enter *ctx)
{
    long ret = 0;
    size_t pid_tgid = bpf_get_current_pid_tgid();
    int pid = pid_tgid >> 32;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    int ppid = BPF_CORE_READ(task, real_parent, tgid);
        
    // Send signal. 9 == SIGKILL
    ret = bpf_send_signal(9);

    // Logging event
    struct event *e;
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (e) {
        e->success = (ret == 0);
        e->pid = pid;
        bpf_get_current_comm(&e->comm, sizeof(e->comm));
        bpf_ringbuf_submit(e, 0);
    }

    return 0;
}
