#include <asm/unistd_64.h>
#include <linux/fs.h>
#include <linux/sched.h>

struct data_t {
  u32 syscall;
  u32 debug;
  u64 pid; // PID as in the userspace term (i.e. task->tgid in kernel)
  u64 start_time;
  u64 end_time;
  char comm[TASK_COMM_LEN];

  char path[PATH_MAX];
} __attribute__((__packed__)) __attribute__((__aligned__(8)));

BPF_PERF_OUTPUT(events);
BPF_HASH(evt_syscall, u64, struct data_t);
BPF_PERCPU_ARRAY(store, struct data_t, 1);

static __always_inline int is_equal8(const void *s1, const void *s2, int wlen) {
  u64 *ss1 = (u64 *)s1;
  u64 *ss2 = (u64 *)s2;
#pragma unroll
  for (int i = 0; i < wlen; i++) {
    if (ss1[i] != ss2[i]) {
      return 0;
    }
  }
  return 1;
}

static __always_inline int is_equal1(const void *s1, const void *s2, int blen) {
  char *ss1 = (char *)s1;
  char *ss2 = (char *)s2;
#pragma unroll
  for (int i = 0; i < blen; i++) {
    if (ss1[i] != ss2[i]) {
      return 0;
    }
  }
  return 1;
}

static __always_inline void copy_command_name(char *name) {
  bpf_get_current_comm(name, TASK_COMM_LEN);
}

static __always_inline void copy_time(u64 *time) { *time = bpf_ktime_get_ns(); }

static __always_inline struct data_t *get_data(u32 syscall) {
  int zero = 0;
  struct data_t *data = store.lookup(&zero);
  if (data == NULL) {
    return 0;
  }
  data->syscall = syscall;
  return data;
}

static __always_inline int enter_common(struct pt_regs *ctx, u32 syscall) {
  struct data_t *data = get_data(syscall);
  if (data == NULL) {
    return 0;
  }
  u64 ptg_id = bpf_get_current_pid_tgid();

  // Copy command name
  //
  copy_command_name(data->comm);

  // Copy pid
  //
  data->pid = ptg_id >> 32;

  // Copy start time
  //
  copy_time(&data->start_time);

  evt_syscall.update(&ptg_id, data);

  return 0;
}

static __always_inline int return_common(struct pt_regs *ctx) {
  u64 ptg_id = bpf_get_current_pid_tgid();
  struct data_t *data = evt_syscall.lookup(&ptg_id);
  if (data == NULL) {
    return 0;
  }
  evt_syscall.delete(&ptg_id);

  // Copy start time
  //
  copy_time(&data->end_time);

  data->debug = 0;
  events.perf_submit(ctx, data, sizeof(struct data_t));

  return 0;
}

////////////////////////////////////////////////////////////////////////////////

int enter___syscall___unlink(struct pt_regs *ctx, const char __user *pathname) {
  return enter_common(ctx, __NR_unlink);
}

int enter___syscall___unlinkat(struct pt_regs *ctx, int dfd, const char __user *pathname,
                               int flag) {
  return enter_common(ctx, __NR_unlinkat);
}

int return___syscall___unlink(struct pt_regs *ctx) { return return_common(ctx); }
int return___syscall___unlinkat(struct pt_regs *ctx) { return return_common(ctx); }

////////////////////////////////////////////////////////////////////////////////

int enter___syscall___rename(struct pt_regs *ctx, const char __user *oldname,
                             const char __user *newname) {
  return enter_common(ctx, __NR_rename);
}

int enter___syscall___renameat(struct pt_regs *ctx, int olddfd,
                               const char __user *oldname, int newdfd,
                               const char __user *newname) {
  return enter_common(ctx, __NR_renameat);
}

int enter___syscall___renameat2(struct pt_regs *ctx, int olddfd,
                                const char __user *oldname, int newdfd,
                                const char __user *newname, unsigned int flags) {
  return enter_common(ctx, __NR_renameat2);
}

int return___syscall___rename(struct pt_regs *ctx) { return return_common(ctx); }
int return___syscall___renameat(struct pt_regs *ctx) { return return_common(ctx); }
int return___syscall___renameat2(struct pt_regs *ctx) { return return_common(ctx); }

////////////////////////////////////////////////////////////////////////////////

int enter___syscall___chmod(struct pt_regs *ctx, const char __user *filename,
                            umode_t mode) {
  return enter_common(ctx, __NR_chmod);
}

int enter___syscall___fchmod(struct pt_regs *ctx, unsigned int fd, umode_t mode) {
  return enter_common(ctx, __NR_fchmod);
}

int enter___syscall___fchmodat(struct pt_regs *ctx, int dfd, const char __user *filename,
                               umode_t mode) {
  return enter_common(ctx, __NR_fchmodat);
}

int return___syscall___chmod(struct pt_regs *ctx) { return return_common(ctx); }
int return___syscall___fchmod(struct pt_regs *ctx) { return return_common(ctx); }
int return___syscall___fchmodat(struct pt_regs *ctx) { return return_common(ctx); }

////////////////////////////////////////////////////////////////////////////////

int enter___syscall___chown(struct pt_regs *ctx, const char __user *filename, uid_t user,
                            gid_t group) {
  return enter_common(ctx, __NR_chown);
}

int enter___syscall___fchown(struct pt_regs *ctx, unsigned int fd, uid_t user,
                             gid_t group) {
  return enter_common(ctx, __NR_fchown);
}

int enter___syscall___fchownat(struct pt_regs *ctx, int dfd, const char __user *filename,
                               uid_t user, gid_t group, int flag) {
  return enter_common(ctx, __NR_fchownat);
}

int enter___syscall___lchown(struct pt_regs *ctx, const char __user *filename, uid_t user,
                             gid_t group) {
  return enter_common(ctx, __NR_lchown);
}

int return___syscall___chown(struct pt_regs *ctx) { return return_common(ctx); }
int return___syscall___fchown(struct pt_regs *ctx) { return return_common(ctx); }
int return___syscall___fchownat(struct pt_regs *ctx) { return return_common(ctx); }
int return___syscall___lchown(struct pt_regs *ctx) { return return_common(ctx); }

////////////////////////////////////////////////////////////////////////////////

int enter___syscall___sync(struct pt_regs *ctx) { return enter_common(ctx, __NR_sync); }

int return___syscall___sync(struct pt_regs *ctx) { return return_common(ctx); }

////////////////////////////////////////////////////////////////////////////////

int enter___syscall___syncfs(struct pt_regs *ctx, int fd) {
  return enter_common(ctx, __NR_syncfs);
}

int return___syscall___syncfs(struct pt_regs *ctx) { return return_common(ctx); }

////////////////////////////////////////////////////////////////////////////////

int enter___syscall___fsync(struct pt_regs *ctx, unsigned int fd) {
  return enter_common(ctx, __NR_fsync);
}

int enter___syscall___fdatasync(struct pt_regs *ctx, unsigned int fd) {
  return enter_common(ctx, __NR_fdatasync);
}

int return___syscall___fsync(struct pt_regs *ctx) { return return_common(ctx); }
int return___syscall___fdatasync(struct pt_regs *ctx) { return return_common(ctx); }

////////////////////////////////////////////////////////////////////////////////

int enter___syscall___truncate(struct pt_regs *ctx, const char __user *path,
                               long length) {
  return enter_common(ctx, __NR_truncate);
}

int return___syscall___truncate(struct pt_regs *ctx) { return return_common(ctx); }

////////////////////////////////////////////////////////////////////////////////

int enter___syscall___link(struct pt_regs *ctx, const char __user *oldname,
                           const char __user *newname) {
  return enter_common(ctx, __NR_link);
}

int enter___syscall___linkat(struct pt_regs *ctx, int olddfd, const char __user *oldname,
                             int newdfd, const char __user *newname, int flags) {
  return enter_common(ctx, __NR_linkat);
}

int return___syscall___link(struct pt_regs *ctx) { return return_common(ctx); }
int return___syscall___linkat(struct pt_regs *ctx) { return return_common(ctx); }

////////////////////////////////////////////////////////////////////////////////

int enter___syscall___symlink(struct pt_regs *ctx, const char __user *oldname,
                              const char __user *newname) {
  return enter_common(ctx, __NR_symlink);
}

int enter___syscall___symlinkat(struct pt_regs *ctx, int olddfd,
                                const char __user *oldname, int newdfd,
                                const char __user *newname, int flags) {
  return enter_common(ctx, __NR_symlinkat);
}

int return___syscall___symlink(struct pt_regs *ctx) { return return_common(ctx); }
int return___syscall___symlinkat(struct pt_regs *ctx) { return return_common(ctx); }
