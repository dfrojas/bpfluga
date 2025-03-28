#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "python_tracer.skel.h"

/* Data structure matching the BPF program's event */
struct event {
    unsigned int pid;
    char function_name[64];
    int args_count;
    __u64 timestamp;
};

static volatile bool exiting = false;

static void sig_handler(int sig)
{
    exiting = true;
}

/* Callback function for ringbuffer events */
static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct event *e = data;
    struct tm *tm;
    char ts[32];
    time_t t;

    /* Prepare timestamp */
    time(&t);
    tm = localtime(&t);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);
    
    /* Print event details */
    printf("%-8s %-5d %-16s args: %d\n",
           ts, e->pid, e->function_name, e->args_count);

    return 0;
}

int main(int argc, char **argv)
{
    struct python_tracer_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err;
    
    /* Set up Ctrl-C handler */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    
    /* Open and load BPF program */
    skel = python_tracer_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }
    
    /* Get Python interpreter path 
     * Note: This path must be adjusted based on the actual location
     * of the Python interpreter on the system where this runs.
     * Use 'which python3' command to find the path.
     */
    char *python_path = "/usr/bin/python3";
    
    /* Attach BPF program to Python interpreter */
    printf("Attaching to Python interpreter at %s...\n", python_path);
    
    /* Attach the uprobe at the PyEval_EvalFrameEx function */
    int fd = skel->progs.trace_python_function.prog_fd;
    if (fd < 0) {
        fprintf(stderr, "Failed to get program FD\n");
        goto cleanup;
    }
    
    /* Attach uprobe */
    /* Note: The actual offset of PyEval_EvalFrameEx will depend on the specific Python version.
     * You may need to find this using 'readelf -s /usr/bin/python3 | grep PyEval_EvalFrameEx'
     * or 'nm -D /usr/bin/python3 | grep PyEval_EvalFrameEx'
     */
    int uprobe_fd = bpf_program__attach_uprobe(skel->progs.trace_python_function,
                                              false, /* not a return probe */
                                              -1,    /* any process */
                                              python_path,
                                              0x4468c8); /* Replace with actual offset */
    
    if (uprobe_fd < 0) {
        fprintf(stderr, "Failed to attach uprobe: %d\n", uprobe_fd);
        goto cleanup;
    }
    
    /* Set up ring buffer polling */
    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }
    
    printf("Successfully started! Tracing Python functions...\n");
    printf("%-8s %-5s %-16s %s\n", "TIME", "PID", "FUNCTION", "ARGS");
    
    /* Main polling loop */
    while (!exiting) {
        err = ring_buffer__poll(rb, 100 /* timeout, ms */);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
        /* Optional: sleep a bit if needed */
        /* usleep(100000); */
    }
    
cleanup:
    /* Clean up */
    ring_buffer__free(rb);
    python_tracer_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}