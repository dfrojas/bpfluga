// kafka_process.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "kafka_pid.skel.h"

int main() {
    struct kafka_pid_bpf *skel;
    int err;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    // Open, load, and attach BPF program
    skel = kafka_pid_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    err = kafka_pid_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF program\n");
        goto cleanup;
    }

    err = kafka_pid_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF program\n");
        goto cleanup;
    }

    printf("Kafka Process Monitor Running. Press Ctrl+C to stop.\n");

    // Read and print eBPF logs from trace_pipe
    system("sudo cat /sys/kernel/debug/tracing/trace_pipe");

cleanup:
    kafka_pid_bpf__destroy(skel);
    return err;
}
