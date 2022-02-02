#include <unistd.h>
#include "memfdd.skel.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <signal.h>
#include <sys/resource.h>
#include <errno.h>
#include <fcntl.h>
#define TASK_COMM_LEN 16
#define FILE_LEN 50
#define TEXT_LEN 20

struct event {
    int pid;
    char comm[TASK_COMM_LEN];
    bool success;
};

struct tr_file {
    char filename[FILE_LEN];
    unsigned int filename_len;
};

struct tr_text {
    char text[TEXT_LEN];
    unsigned int text_len;
};


static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct event *e = data;
    if (e->success)
        printf("Killed PID %d (%s) for trying to use memfd syscall\n", e->pid, e->comm);
    else
        printf("Failed to kill PID %d (%s) for trying to use memfd syscall\n", e->pid, e->comm);
    return 0;
}

static volatile sig_atomic_t exiting;

void sig_int(int signo)
{
    exiting = 1;
}

static bool setup_sig_handler() {
    __sighandler_t sighandler = signal(SIGINT, sig_int);
    if (sighandler == SIG_ERR) {
        fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
        return false;
    }
    sighandler = signal(SIGTERM, sig_int);
    if (sighandler == SIG_ERR) {
        fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
        return false;
    }
    return true;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}
static bool bump_memlock_rlimit(void)
{
    struct rlimit rlim_new = {
        .rlim_cur    = RLIM_INFINITY,
        .rlim_max    = RLIM_INFINITY,
    };

    if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
        fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit! (hint: run as root)\n");
        return false;
    }
    return true;
}
int main(int argc, char **argv)
{
    struct ring_buffer *rb = NULL;
    struct memfdd_bpf *skel;
    int err;

    libbpf_set_print(libbpf_print_fn);
    if (!bump_memlock_rlimit()) {
        return false;
    };

    setup_sig_handler();
    // Opening BPF application 
    skel = memfdd_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF program: %s\n", strerror(errno));
        return 1;
    }

    // Verifying and loading program
    err = memfdd_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

    // Attaching tracepoint handler 
    err = memfdd_bpf__attach( skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF program: %s\n", strerror(errno));
        goto cleanup;
    }

    // Setting up ring buffer
    rb = ring_buffer__new(bpf_map__fd( skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    printf("Successfully started!\n");
    printf("Monitoring memfd_create() \n");
    while (!exiting) {
        err = ring_buffer__poll(rb, 100 /* timeout, ms */);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            printf("Error polling perf buffer: %d\n", err);
            break;
        }
    }
cleanup:
    memfdd_bpf__destroy( skel);
    return -err;
}
