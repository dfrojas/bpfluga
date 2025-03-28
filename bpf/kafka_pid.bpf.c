// kafka_process.bpf.c
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    char comm[TASK_COMM_LEN];

    bpf_get_current_comm(&comm, sizeof(comm));

    bpf_printk("Detected Kafka-related process: PID=%d, Name=%s\n", pid, comm);

    // Print only Java processes (Kafka clients run under Java)
    if (__builtin_memcmp(comm, "java", 4) == 0) {
        bpf_printk("Detected Kafka-related process: PID=%d, Name=%s\n", pid, comm);
    }

    return 0;
}
