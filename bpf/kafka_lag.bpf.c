// kafka_lag.bpf.c
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN 16  // Max length of process name

// Global variable for filtering by Kafka PID
const volatile uint32_t kafka_pid = 0;

// Mapa: pid -> último timestamp
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, u64);
} recv_ts SEC(".maps");

// Perf buffer for user-space events
struct event {
    u32 pid;
    u64 lag_ns;
    char comm[TASK_COMM_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
    __uint(max_entries, 1024);
} events SEC(".maps");

// SEC("tracepoint/syscalls/sys_enter_recvfrom")
SEC("tracepoint/syscalls/sys_enter_execve")
int handle_recvfrom_enter(struct trace_event_raw_sys_enter *ctx)
{
    
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));
    
    // Only track Java processes (Kafka clients)
    if (bpf_strncmp(comm, "java", 4) == 0) {
        bpf_printk("Detected Kafka client process: PID=%d, Name=%s\n", pid, comm);
    }

    // Filter: Only process Kafka-related syscalls
    // if (kafka_pid && pid != kafka_pid) {
    //     return 0;
    // }

    u64 ts = bpf_ktime_get_ns();

    bpf_map_update_elem(&recv_ts, &pid, &ts, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_recvfrom")
int handle_recvfrom_exit(struct trace_event_raw_sys_exit *ctx)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 *prev_ts, now = bpf_ktime_get_ns();

    // if (kafka_pid && pid != kafka_pid) {
    //     return 0;
    // }

    // Busca el último timestamp
    prev_ts = bpf_map_lookup_elem(&recv_ts, &pid);
    if (prev_ts) {
        // Calcula delta (nanosegundos)
        u64 delta = now - *prev_ts;

        struct event evt = {};
        evt.pid = pid;
        evt.lag_ns = delta;
        bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));

        // Imprime en el kernel trace
        // bpf_printk("Consumer PID=%d, Lag=%llu ns\n", pid, delta);

        // Actualiza el nuevo timestamp
        bpf_map_update_elem(&recv_ts, &pid, &now, BPF_ANY);
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
