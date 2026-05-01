// SPDX-License-Identifier: GPL-2.0
//go:build ignore

#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

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

// Tracked TIDs (kernel pids, not userspace TGIDs). Userspace seeds the map
// with a root TID; the sched_process_fork hook below propagates membership
// to every child thread/process, and sched_process_exit reaps entries on
// task exit. The openat enter/exit hooks early-exit when the calling TID
// isn't in this set, dropping host-side flatpak setup events before they
// hit userspace.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, __u32);
    __type(value, __u32);
} tracked_pids SEC(".maps");

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

// sched/sched_process_fork tracepoint context. Layout is per the kernel's
// /sys/kernel/tracing/events/sched/sched_process_fork/format: comm fields
// are __data_loc-encoded (4-byte offset/length references into a per-event
// data buffer), NOT inline TASK_COMM_LEN strings — so parent_pid lives at
// offset 12, not 24. Different sched_* tracepoints use different layouts
// (e.g. sched_process_exit uses inline char[16]); always check the format
// file for the specific tracepoint.
struct sched_fork_args {
    __u64 _unused;                 // common header, 8 bytes
    __u32 __data_loc_parent_comm;  // offset 8
    __s32 parent_pid;              // offset 12
    __u32 __data_loc_child_comm;   // offset 16
    __s32 child_pid;               // offset 20
};

// sched/sched_process_exit tracepoint context. This one DOES use inline
// char[16] for comm (offset 8), with pid at offset 24, prio at 28.
struct sched_exit_args {
    __u64 _unused;                  // common header, 8 bytes
    char  comm[TASK_COMM_LEN];      // offset 8, 16 bytes
    __s32 pid;                      // offset 24
    __s32 prio;                     // offset 28
};

// Minimal task_struct chain for extracting the current mount-namespace
// inode number. preserve_access_index tells clang to emit CO-RE relocations
// for field accesses; libbpf / cilium-ebpf rewrites them at load time using
// the running kernel's BTF, so the local layout below is irrelevant —
// only field names matter, and only the named fields need to be present.
struct ns_common {
    unsigned int inum;
} __attribute__((preserve_access_index));

struct mnt_namespace {
    struct ns_common ns;
} __attribute__((preserve_access_index));

struct nsproxy {
    struct mnt_namespace *mnt_ns;
} __attribute__((preserve_access_index));

struct task_struct {
    struct nsproxy *nsproxy;
} __attribute__((preserve_access_index));

// Set by userspace via cilium/ebpf RewriteConstants() before load. Holds the
// inode number of the mount namespace ratpak itself runs in (i.e. the host
// mntns). Events from this mntns are filtered out — they're flatpak setup
// work that runs before bwrap unshares.
const volatile __u32 host_mntns_inum = 0;

static __always_inline __u32 current_mntns(void)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    return BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
}

// should_emit returns true iff the current task is in the tracked set AND
// in a different mount namespace from the host — i.e. inside a flatpak
// sandbox after bwrap has unshared.
static __always_inline int should_emit(void)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    if (!bpf_map_lookup_elem(&tracked_pids, &tid))
        return 0;
    return current_mntns() != host_mntns_inum;
}

static __always_inline int on_enter(struct sys_enter_args *ctx, int filename_arg_idx)
{
    if (!should_emit())
        return 0;
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    __u64 fnp = (__u64)ctx->args[filename_arg_idx];
    bpf_map_update_elem(&pending, &tid, &fnp, BPF_ANY);
    return 0;
}

static __always_inline int on_exit(struct sys_exit_args *ctx)
{
    if (!should_emit())
        return 0;
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

// Propagate tracked-set membership across fork/clone. Runs in the parent's
// context, so bpf_get_current_pid_tgid() would also work — but the
// tracepoint hands us parent_pid directly, which is what we want anyway.
// child_pid is the new task's TID for both process and thread clones; for
// process forks it equals the new TGID, for thread forks it's a new TID
// belonging to the parent's TGID. Either way, tracking by TID is correct
// because openat events filter by the calling thread's TID.
// Propagate tracked-set membership across fork/clone. child_pid is the new
// task's TID for both process and thread clones; for process forks it equals
// the new TGID, for thread forks it's a new TID belonging to the parent's
// TGID. Either way, tracking by TID is correct because openat events filter
// by the calling thread's TID.
SEC("tracepoint/sched/sched_process_fork")
int trace_sched_fork(struct sched_fork_args *ctx)
{
    __u32 parent = (__u32)ctx->parent_pid;
    if (!bpf_map_lookup_elem(&tracked_pids, &parent))
        return 0;
    __u32 child = (__u32)ctx->child_pid;
    __u32 mark  = 1;
    bpf_map_update_elem(&tracked_pids, &child, &mark, BPF_ANY);
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int trace_sched_exit(struct sched_exit_args *ctx)
{
    __u32 pid = (__u32)ctx->pid;
    bpf_map_delete_elem(&tracked_pids, &pid);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
