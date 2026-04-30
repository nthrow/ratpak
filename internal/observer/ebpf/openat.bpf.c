// SPDX-License-Identifier: GPL-2.0
//go:build ignore

#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>

#define TASK_COMM_LEN 16
#define MAX_PATH      256

struct event {
    __u32 pid;
    __u32 tgid;
    char  comm[TASK_COMM_LEN];
    char  path[MAX_PATH];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

// Per-tid scratch: filename pointer captured at sys_enter, consumed at
// sys_exit. LRU so a SIGKILL between enter and exit doesn't leak entries.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, __u32);
    __type(value, __u64);
} pending SEC(".maps");

// sys_enter_* tracepoint context: 8B common header, then a stable
// (long syscall_nr; unsigned long args[6]) layout.
struct sys_enter_args {
    __u64 _unused;
    long  syscall_nr;
    unsigned long args[6];
};

// sys_exit_* tracepoint context: 8B common header, then syscall_nr (4B
// padded to 8) and the syscall return value (long).
struct sys_exit_args {
    __u64 _unused;
    __s32 syscall_nr;
    __u32 _pad;
    long  ret;
};

static __always_inline int on_enter(struct sys_enter_args *ctx, int filename_arg_idx)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    __u64 fnp = (__u64)ctx->args[filename_arg_idx];
    bpf_map_update_elem(&pending, &tid, &fnp, BPF_ANY);
    return 0;
}

static __always_inline int on_exit(struct sys_exit_args *ctx)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    __u64 *fnp = bpf_map_lookup_elem(&pending, &tid);
    if (!fnp)
        return 0;

    if (ctx->ret < 0) {
        bpf_map_delete_elem(&pending, &tid);
        return 0;
    }

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        bpf_map_delete_elem(&pending, &tid);
        return 0;
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->tgid = pid_tgid >> 32;
    e->pid  = (__u32)pid_tgid;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_probe_read_user_str(&e->path, sizeof(e->path), (const char *)*fnp);

    bpf_ringbuf_submit(e, 0);
    bpf_map_delete_elem(&pending, &tid);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat_enter(struct sys_enter_args *ctx)  { return on_enter(ctx, 1); }

SEC("tracepoint/syscalls/sys_exit_openat")
int trace_openat_exit(struct sys_exit_args *ctx)    { return on_exit(ctx); }

SEC("tracepoint/syscalls/sys_enter_openat2")
int trace_openat2_enter(struct sys_enter_args *ctx) { return on_enter(ctx, 1); }

SEC("tracepoint/syscalls/sys_exit_openat2")
int trace_openat2_exit(struct sys_exit_args *ctx)   { return on_exit(ctx); }

char LICENSE[] SEC("license") = "GPL";
