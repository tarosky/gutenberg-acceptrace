// +build ignore

#include "asm/unistd_64.h"
#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define AT_FDCWD -100
#define PATH_MAX 1024 // 4096
#define TASK_COMM_LEN 16

char __license[] SEC("license") = "Dual MIT/GPL";

struct event {
  u32 syscall;
  u32 pid;
  s32 fd;
  s32 ret;
  u64 start_time;
  u64 end_time;
  u8 comm[TASK_COMM_LEN];
  u8 path[PATH_MAX];
};

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24);
} events SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, int);
  __type(value, struct event);
} store SEC(".maps");

// Force emitting struct event into the ELF.
const struct event *unused __attribute__((unused));

const volatile char phpfpm_comm[TASK_COMM_LEN] = "code";

static int is_task_comm_equal(const void *s1, const void *s2) {
  u64 *ss1 = (u64 *)s1;
  u64 *ss2 = (u64 *)s2;
#pragma unroll
  for (int i = 0; i < TASK_COMM_LEN / 8; i++) {
    if (ss1[i] != ss2[i]) {
      return 0;
    }
  }
  return 1;
}

static struct event *get_event(u32 syscall) {
  char comm[TASK_COMM_LEN];
  bpf_get_current_comm(comm, TASK_COMM_LEN);
  if (!is_task_comm_equal(comm, (void *)phpfpm_comm)) {
    return NULL;
  }

  const int key = 0;
  struct event *t = bpf_map_lookup_elem(&store, &key);
  if (t == NULL) {
    return NULL;
  }

  t->start_time = bpf_ktime_get_ns();
  t->syscall = syscall;
  bpf_get_current_comm(&t->comm, TASK_COMM_LEN);

  u64 id = bpf_get_current_pid_tgid();
  t->pid = id >> 32;

  return t;
}

static int submit_event(struct pt_regs *regs) {
  const int key = 0;
  struct event *t = bpf_map_lookup_elem(&store, &key);
  if (t == NULL) {
    return 0;
  }

  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id >> 32;
  if (pid != t->pid) {
    return 0;
  }

  t->end_time = bpf_ktime_get_ns();
  bpf_probe_read_kernel(&t->ret, sizeof(t->ret), (void *)PT_REGS_RC_CORE(regs));
  bpf_ringbuf_output(&events, t, sizeof(struct event), 0);

  return 0;
}

////////////////////////////////////////////////////////////////////////////////

SEC("fentry/__x64_sys_openat")
int BPF_PROG(sys_openat, struct pt_regs *regs) {
  struct event *t = get_event(__NR_openat);
  if (t == NULL) {
    return 0;
  }

  t->fd = PT_REGS_PARM1_CORE(regs);
  bpf_probe_read_user(t->path, sizeof(t->path), (void *)PT_REGS_PARM2_CORE(regs));

  return 0;
}

SEC("fexit/__x64_sys_openat")
int BPF_PROG(syse_openat, struct pt_regs *regs) { return submit_event(regs); }

SEC("fentry/__x64_sys_close")
int BPF_PROG(sys_close, struct pt_regs *regs) {
  struct event *t = get_event(__NR_close);
  if (t == NULL) {
    return 0;
  }

  t->fd = PT_REGS_PARM1_CORE(regs);
  t->path[0] = '\0';

  return 0;
}

SEC("fexit/__x64_sys_close")
int BPF_PROG(syse_close, struct pt_regs *regs) { return submit_event(regs); }
