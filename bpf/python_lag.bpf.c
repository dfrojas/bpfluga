#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

// Structure for sending events to user-space
struct python_event {
    u32 pid;
    u64 call_count;
    char comm[16];  // Process name
};

// BPF Map to track function calls per process
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, u64);
} call_count SEC(".maps");

// Ring buffer to send events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

// Uprobe: Runs every time a Python function is executed
SEC("uprobe/_PyEval_EvalFrameDefault")
int profile_python_function(struct pt_regs *ctx) {
    // u32 pid = bpf_get_current_pid_tgid() >> 32;
    // bpf_printk("eBPF function hit! PID=%d", pid);
    // u64 *count, new_count = 1;

    // // Lookup current count
    // count = bpf_map_lookup_elem(&call_count, &pid);
    // if (count) {
    //     new_count = *count + 1;
    // }
    // bpf_map_update_elem(&call_count, &pid, &new_count, BPF_ANY);

    // // Send event to user-space
    // struct python_event *event = bpf_ringbuf_reserve(&rb, sizeof(struct python_event), 0);
    // if (!event) {
    //     bpf_printk("Ring buffer reservation failed");
    //     return 0;
    // }

    // event->pid = pid;
    // event->call_count = new_count;
    // bpf_get_current_comm(&event->comm, sizeof(event->comm));
    // bpf_ringbuf_submit(event, 0);

    // bpf_printk("Event submitted: PID=%d, Calls=%llu", pid, new_count);
    // return 0;
    bpf_printk("Uprobe triggered");
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    // First debug message
    bpf_printk("Uprobe triggered: PID=%d", pid);

    // Try reserving space in the ring buffer
    struct python_event *event = bpf_ringbuf_reserve(&rb, sizeof(struct python_event), 0);
    if (!event) {
        bpf_printk("Ring buffer reservation failed!");
        return 0;
    }

    // Filling event
    event->pid = pid;
    bpf_printk("Event created: PID=%d", pid);

    // Submitting event
    bpf_ringbuf_submit(event, 0);
    bpf_printk("Event submitted: PID=%d", pid);

    return 0;
}
