#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/* Define the data structure to pass between kernel and user space */
struct event {
    unsigned int pid;
    char function_name[64];
    int args_count;
    __u64 timestamp;
};

/* Create a BPF ringbuffer map to pass events to userspace */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

/* Attach to the Python function execution tracepoint (uprobes) */
SEC("uprobe/PyEval_EvalFrameEx")
int BPF_KPROBE(trace_python_function, struct _frame *frame)
{
    /* Get current process info */
    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;
    
    /* Get frame code object */
    void *code_obj = NULL;
    bpf_probe_read(&code_obj, sizeof(code_obj), &frame->f_code);
    if (!code_obj)
        return 0;

    /* Reserve space in the ringbuffer */
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e)
        return 0;
        
    /* Fill the event data */
    e->pid = pid;
    e->timestamp = bpf_ktime_get_ns();
    
    /* Try to get the function name from code object */
    void *name_obj = NULL;
    bpf_probe_read(&name_obj, sizeof(name_obj), code_obj + 8); // Offset for co_name
    
    /* Set a default name if we can't read it */
    char default_name[64] = "<unknown>";
    if (!name_obj) {
        bpf_probe_read_str(e->function_name, sizeof(e->function_name), default_name);
    } else {
        /* Read the actual function name string */
        bpf_probe_read_str(e->function_name, sizeof(e->function_name), name_obj + 16); // String data
    }
    
    /* Get argument count */
    bpf_probe_read(&e->args_count, sizeof(e->args_count), &frame->f_code->co_argcount);
    
    /* Submit the event to userspace */
    bpf_ringbuf_submit(e, 0);
    
    return 0;
}

char LICENSE[] SEC("license") = "GPL";