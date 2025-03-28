#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <signal.h>
#include <inttypes.h>  // Fixes PRIu64 warning
#include "python_lag.skel.h"

volatile bool exiting = false;

// Handle Ctrl+C to exit
void sig_handler(int signo) {
    exiting = true;
}

// Structure for receiving events
struct python_event {
    __u32 pid;
    __u64 call_count;
    char comm[16];  // Process name
};

// Callback function to process ring buffer events
static int handle_event(void *ctx, void *data, size_t data_sz) {
    struct python_event *event = data;
    printf("[eBPF] PID: %d, Function Calls: %llu, Process: %s\n",
           event->pid, event->call_count, event->comm);
    return 0;
}

// Function to get the correct Python binary
void get_python_binary(char *path, size_t size) {
    FILE *cmd = popen("which python3", "r");
    if (cmd) {
        fgets(path, size, cmd);
        path[strcspn(path, "\n")] = 0;  // Remove newline
        pclose(cmd);
    }
    if (strlen(path) == 0) {
        strcpy(path, "/usr/bin/python3");  // Fallback
    }
}

int main() {
    struct python_lag_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err;

    // Handle Ctrl+C
    signal(SIGINT, sig_handler);

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    // Load the eBPF program
    skel = python_lag_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    // Get Python binary dynamically
    char python_path[256] = {0};
    get_python_binary(python_path, sizeof(python_path));
    printf("[+] Using Python binary: %s\n", python_path);

    // Attach uprobe
    struct bpf_link *link;
    unsigned long offset = 0x4c4510;  // Offset for _PyEval_EvalFrameDefault (Python 3.11+)

    link = bpf_program__attach_uprobe(
        skel->progs.profile_python_function,
        false, // Not a return probe
        -1,    // Attach to all PIDs
        python_path,
        offset
    );

    if (!link) {
        fprintf(stderr, "[ERROR] Failed to attach uprobe to %s at offset: 0x%lx\n", python_path, offset);
        goto cleanup;
    } else {
        printf("[+] Successfully attached uprobe to %s at offset: 0x%lx\n", python_path, offset);
    }

    // Set up ring buffer polling
    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    // Poll events and print them to console
    while (!exiting) {
        err = ring_buffer__poll(rb, 100);
        if (err == 0) {
            // printf("No events received yet...\n");
            // fflush(stdout);
        }
    }

cleanup:
    ring_buffer__free(rb);
    python_lag_bpf__destroy(skel);
    return 0;
}
