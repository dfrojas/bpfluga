// kafka_lag.c
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <signal.h>
#include <sys/types.h>
#include <bpf/libbpf.h>
#include "kafka_lag.skel.h"


#define TASK_COMM_LEN 16  // Max length of process name

// Define event struct to match the one in BPF program
struct event {
    __u32 pid;
    __u64 lag_ns;
    char comm[TASK_COMM_LEN];
};

// Handle perf buffer output
//static int handle_event(void *ctx, void *data, size_t data_sz) {
static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz) {
    struct event *e = data;
    // printf("Kafka Consumer %s[%d], Lag=%llu ns\n", e->comm, e->pid, e->lag_ns);
    printf("Processs %s with PID %d had a lag of %llu ns\n", e->comm, e->pid, e->lag_ns);
}

int find_kafka_pid() {
    // FILE *fp = popen("pgrep -f java", "r");
    FILE *fp = popen("(ps aux | grep 'kafka.Kafka' | grep -v grep | awk '{print $2}')", "r");
    if (!fp) return -1;
    int pid;
    if (fscanf(fp, "%d", &pid) != 1) {
        pclose(fp);
        return -1;
    }
    pclose(fp);
    return pid;
}

int main(int argc, char **argv)
{
    struct kafka_lag_bpf *skel;
    int err, kafka_pid;

    kafka_pid = find_kafka_pid();
    // if (kafka_pid < 0) {
    //     fprintf(stderr, "Kafka process not found!\n");
    //     return 1;
    // }

    printf("Monitoring Kafka process PID=%d\n", kafka_pid);
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    skel = kafka_lag_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    skel->rodata->kafka_pid = kafka_pid;  // Set Kafka PID in eBPF

    err = kafka_lag_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF program\n");
        goto cleanup;
    }

    err = kafka_lag_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF program\n");
        goto cleanup;
    }

    printf("Kafka Lag eBPF Running. Press Ctrl+C to stop.\n");

    // Setup perf buffer reading
    struct perf_buffer *pb = perf_buffer__new(bpf_map__fd(skel->maps.events), 8, handle_event, NULL, NULL, NULL);
    if (!pb) {
        fprintf(stderr, "Failed to create perf buffer\n");
        goto cleanup;
    }

    while (1) {
        perf_buffer__poll(pb, 100);
    }

    cleanup:
        kafka_lag_bpf__destroy(skel);
        return err;

//     // Configura libbpf para modo estricto (buenas prácticas)
//     libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

//     // 1. Cargar skeleton
//     skel = kafka_lag_bpf__open();
//     if (!skel) {
//         fprintf(stderr, "Error abriendo skeleton\n");
//         return 1;
//     }

//     // 2. Cargar programa eBPF en kernel
//     err = kafka_lag_bpf__load(skel);
//     if (err) {
//         fprintf(stderr, "Error al cargar eBPF: %d\n", err);
//         goto cleanup;
//     }

//     // 3. Adjuntar
//     err = kafka_lag_bpf__attach(skel);
//     if (err) {
//         fprintf(stderr, "Error al adjuntar eBPF: %d\n", err);
//         goto cleanup;
//     }

//     printf("Kafka Lag eBPF corriendo. Logs en /sys/kernel/debug/tracing/trace_pipe\n");
//     printf("Presiona Ctrl+C para salir...\n");

//     // Loop infinito
//     while (1) {
//         sleep(1);
//     }

// cleanup:
//     kafka_lag_bpf__destroy(skel);
//     return 0;
}
