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
    
    /* Attach to Python interpreter */
    printf("Attaching to Python 3.12 interpreter at %s...\n", python_path);
    
    /* Find the Python shared library if python_path is a script or shebang */
    /* For Python 3.12, we need to locate libpython3.12.so */
    char *python_lib = "/usr/lib/libpython3.12.so.1.0";
    
    /* Check if library exists, otherwise try alternate locations */
    if (access(python_lib, F_OK) != 0) {
        /* Try to find the actual path with dynamic lookup */
        FILE *cmd = popen("ldd $(which python3) | grep libpython | awk '{print $3}'", "r");
        if (cmd) {
            char buf[256];
            if (fgets(buf, sizeof(buf), cmd) != NULL) {
                /* Remove newline if present */
                size_t len = strlen(buf);
                if (len > 0 && buf[len-1] == '\n')
                    buf[len-1] = '\0';
                
                if (strlen(buf) > 0) {
                    python_lib = strdup(buf);
                    printf("Found Python library at: %s\n", python_lib);
                }
            }
            pclose(cmd);
        }
    }
    
    /* Attach the uprobe at _PyEval_EvalFrameDefault function for Python 3.12 */
    int fd = skel->progs.trace_python_function.prog_fd;
    if (fd < 0) {
        fprintf(stderr, "Failed to get program FD\n");
        goto cleanup;
    }
    
    /* Attach uprobe to Python library */
    /* Note: For Python 3.12, we need to attach to _PyEval_EvalFrameDefault */
    int uprobe_fd = bpf_program__attach_uprobe(skel->progs.trace_python_function,
                                              false, /* not a return probe */
                                              -1,    /* any process */
                                              python_lib,
                                              0); /* Use 0 for symbols, or find offset with objdump */
    
    if (uprobe_fd < 0) {
        fprintf(stderr, "Failed to attach uprobe: %d. This could be due to:\n", uprobe_fd);
        fprintf(stderr, "1. Symbol not found - try finding it with: objdump -T %s | grep _PyEval_EvalFrameDefault\n", python_lib);
        fprintf(stderr, "2. Missing permissions - make sure you're running as root\n");
        fprintf(stderr, "3. Trying different Python library paths\n");
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