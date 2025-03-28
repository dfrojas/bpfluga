#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/* Define Python frame structure for Python 3.12 */
struct py_frame {
    void *ob_type;
    void *f_back;
    void *f_code;
    void *f_builtins;
    void *f_globals;
    void *f_locals;
    void *f_valuestack;
    void *f_stacktop;
    void *f_trace;
    void *f_exc_type;
    void *f_exc_value;
    void *f_exc_traceback;
    int f_lasti;
    int f_lineno;
    int f_iblock;
    /* More fields follow but we don't need them */
};

/* Define Python code object structure (simplified) */
struct py_code_object {
    void *ob_type;
    int co_argcount;
    int co_posonlyargcount;
    int co_kwonlyargcount;
    int co_nlocals;
    int co_stacksize;
    int co_flags;
    void *co_code;
    void *co_consts;
    void *co_names;
    void *co_varnames;
    void *co_freevars;
    void *co_cellvars;
    void *co_filename;
    void *co_name;     /* Function name */
    int co_firstlineno;
    void *co_lnotab;
};

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
SEC("uprobe/_PyEval_EvalFrameDefault")
int BPF_UPROBE(trace_python_function, struct py_frame *frame)
{
    /* Get current process info */
    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;
    
    /* Get frame code object */
    struct py_code_object *code_obj = NULL;
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
    bpf_probe_read(&name_obj, sizeof(name_obj), &code_obj->co_name);
    
    /* Set a default name if we can't read it */
    char default_name[64] = "<unknown>";
    if (!name_obj) {
        bpf_probe_read_str(e->function_name, sizeof(e->function_name), default_name);
    } else {
        /* Read the actual function name string */
        /* Python strings have their character data at an offset from the string object */
        /* This offset may vary depending on Python version - typically 16-24 bytes */
        bpf_probe_read_str(e->function_name, sizeof(e->function_name), name_obj + 24);
    }
    
    /* Get argument count */
    bpf_probe_read(&e->args_count, sizeof(e->args_count), &code_obj->co_argcount);
    
    /* Submit the event to userspace */
    bpf_ringbuf_submit(e, 0);
    
    return 0;
}

char LICENSE[] SEC("license") = "GPL";