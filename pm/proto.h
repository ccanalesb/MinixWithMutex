/* Function prototypes. */

struct mproc;

#include <minix/timers.h>
#include "global.h"

/* alarm.c */
int do_itimer(void);
void set_alarm(struct mproc *rmp, clock_t ticks);
void check_vtimer(int proc_nr, int sig);

/* exec.c */
int do_exec(void);
int do_newexec(void);
int do_execrestart(void);
void exec_restart(struct mproc *rmp, int result, vir_bytes pc, vir_bytes sp,
	vir_bytes ps_str);

/* forkexit.c */
int do_fork(void);
int do_srv_fork(void);
int do_exit(void);
void exit_proc(struct mproc *rmp, int exit_status, int dump_core);
void exit_restart(struct mproc *rmp, int dump_core);
int do_wait4(void);
int wait_test(struct mproc *rmp, struct mproc *child);

/* getset.c */
int do_get(void);
int do_set(void);

/* main.c */
int main(void);
void reply(int proc_nr, int result);

/* mcontext.c */
int do_getmcontext(void);
int do_setmcontext(void);

/* misc.c */
int do_reboot(void);
int do_sysuname(void);
int do_getsysinfo(void);
int do_getprocnr(void);
int do_getepinfo(void);
int do_svrctl(void);
int do_getsetpriority(void);
int do_getrusage(void);
int do_mycall(void);
int do_mutex_init(void);
int do_mutex_destroy(void);
int do_mutex_lock(void);
int do_mutex_unlock(void);

/* schedule.c */
void sched_init(void);
int sched_start_user(endpoint_t ep, struct mproc *rmp);
int sched_nice(struct mproc *rmp, int nice);

/* profile.c */
int do_sprofile(void);

/* signal.c */
int do_kill(void);
int do_srv_kill(void);
int process_ksig(endpoint_t proc_nr_e, int signo);
int check_sig(pid_t proc_id, int signo, int ksig);
void sig_proc(struct mproc *rmp, int signo, int trace, int ksig);
int do_sigaction(void);
int do_sigpending(void);
int do_sigprocmask(void);
int do_sigreturn(void);
int do_sigsuspend(void);
void check_pending(struct mproc *rmp);
void restart_sigs(struct mproc *rmp);
void vm_notify_sig_wrapper(endpoint_t ep);

/* time.c */
int do_stime(void);
int do_time(void);
int do_getres(void);
int do_gettime(void);
int do_settime(void);

/* trace.c */
int do_trace(void);
void trace_stop(struct mproc *rmp, int signo);

/* utility.c */
pid_t get_free_pid(void);
char *find_param(const char *key);
struct mproc *find_proc(pid_t lpid);
int nice_to_priority(int nice, unsigned *new_q);
int pm_isokendpt(int ep, int *proc);
void tell_vfs(struct mproc *rmp, message *m_ptr);
void set_rusage_times(struct rusage *r_usage, clock_t user_time,
	clock_t sys_time);

#ifndef __MTHREAD_PROTO_H__
#define __MTHREAD_PROTO_H__

/* allocate.c */
mthread_tcb_t * mthread_find_tcb(int thread);
void mthread_thread_reset(int thread);

/* attribute.c */
void mthread_init_valid_attributes(void);
#ifdef MDEBUG
int mthread_attr_verify(void);
#endif

/* cond.c */
void mthread_init_valid_conditions(void);
#ifdef MDEBUG
int mthread_cond_verify(void);
#endif

/* key.c */
void mthread_init_keys(void);
void mthread_cleanup_values(void);

/* misc.c */
#ifdef MDEBUG
#define mthread_panic(m) mthread_panic_f(__FILE__, __LINE__, (m))
void mthread_panic_f(const char *file, int line, const char *msg);
#define mthread_debug(m) mthread_debug_f(__FILE__, __LINE__, (m))
void mthread_debug_f(const char *file, int line, const char *msg);
#else
__dead void mthread_panic_s(void);
# define mthread_panic(m) mthread_panic_s()
# define mthread_debug(m)
#endif

/* mutex.c */
void mthread_init_valid_mutexes(void);

#ifdef MTHREAD_STRICT
int mthread_mutex_valid(mthread_mutex_t *mutex);
#else
# define mthread_mutex_valid(x) ((*x)->mm_magic == MTHREAD_INIT_MAGIC)
#endif

#ifdef MDEBUG
int mthread_mutex_verify(void);
#endif

/* schedule.c */
int mthread_getcontext(ucontext_t *ctxt);
void mthread_init_scheduler(void);
void mthread_schedule(void);
void mthread_suspend(mthread_state_t state);
void mthread_unsuspend(int thread);

/* queue.c */
#ifdef MDEBUG
void mthread_dump_queue(int *queue);
#endif
void mthread_queue_init(int *queue);
void mthread_queue_add(int *queue, int thread);
int mthread_queue_remove(int *queue);
int mthread_queue_isempty(int *queue);

#endif

#ifndef __MTHREAD_PROTO_H__
#define __MTHREAD_PROTO_H__

/* allocate.c */
mthread_tcb_t * mthread_find_tcb(int thread);
void mthread_thread_reset(int thread);

/* attribute.c */
void mthread_init_valid_attributes(void);
#ifdef MDEBUG
int mthread_attr_verify(void);
#endif

/* cond.c */
void mthread_init_valid_conditions(void);
#ifdef MDEBUG
int mthread_cond_verify(void);
#endif

/* key.c */
void mthread_init_keys(void);
void mthread_cleanup_values(void);

/* misc.c */
#ifdef MDEBUG
#define mthread_panic(m) mthread_panic_f(__FILE__, __LINE__, (m))
void mthread_panic_f(const char *file, int line, const char *msg);
#define mthread_debug(m) mthread_debug_f(__FILE__, __LINE__, (m))
void mthread_debug_f(const char *file, int line, const char *msg);
#else
__dead void mthread_panic_s(void);
# define mthread_panic(m) mthread_panic_s()
# define mthread_debug(m)
#endif

/* mutex.c */
void mthread_init_valid_mutexes(void);

#ifdef MTHREAD_STRICT
int mthread_mutex_valid(mthread_mutex_t *mutex);
#else
# define mthread_mutex_valid(x) ((*x)->mm_magic == MTHREAD_INIT_MAGIC)
#endif

#ifdef MDEBUG
int mthread_mutex_verify(void);
#endif

/* schedule.c */
int mthread_getcontext(ucontext_t *ctxt);
void mthread_init_scheduler(void);
void mthread_schedule(void);
void mthread_suspend(mthread_state_t state);
void mthread_unsuspend(int thread);

/* queue.c */
#ifdef MDEBUG
void mthread_dump_queue(int *queue);
#endif
void mthread_queue_init(int *queue);
void mthread_queue_add(int *queue, int thread);
int mthread_queue_remove(int *queue);
int mthread_queue_isempty(int *queue);

#endif
