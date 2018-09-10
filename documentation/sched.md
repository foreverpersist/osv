# Sched

	Process Schedule

## pid, ppid, tid, tgid, pgid, sid

	There is only process in linux, thread is emulated with process

	In Kernel View

| Name | Description |
| :--- | :---------- |
| pid  | Unique process identifier |
| ppid | Parent pid |

	In User View

| Name | Process | Thread |
| :--- | :------ | :----- |
| tid  | Kernel pid  | Kernel pid          |
| tgid | Kernel pid  | Parent Process pid  |
| pgid | Leader pid  | Parent Process pgid |
| sid  | Leader pid  | Parent Process sid  |

	In Data Structure

> * pid
> * ppid
> * tgid
> * pgid
> * sid


```
	Thread    Process    Process Group    Session
	*****      -----         ######        $$$$$
	| T |      | P |         # PG #        $ S $
	*****      -----         ######        $$$$$

	$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$
	$                                                   $
	$ ############ ########## ######################### $
	$ #          # #        # #                       # $
	$ # -------- # # ------ # # --------------------- # $
	$ # |      | # # |    | # # |                   | # $
	$ # |      | # # | P2 | # # | ****** ********** | # $
	$ $ |      | # # |    | # # | *    * *        * | # $
	$ # |      | # # ------ # # | *    * * ****** * | # $
	$ # |  P1  | # #        # # | * T1 * * * T3 * * | # $
	$ # |      | # # ------ # # | *    * * ****** * | # $
	$ # |      | # # |    | # # | *    * *   T2   * | # $
	$ # |      | # # | P3 | # # | ****** ********** | # $
	$ # |      | # # |    | # # |         P4        | # $
	$ # -------- # # ------ # # --------------------- # $
	$ #   PG1    # #   PG2  # #           PG3         # $
	$ ############ ########## ######################### $
	$                       S1                          $
	$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$
```

| Task | getpid | gettid | gettgid | getpgid | getsid |
| :--: | :----: | :----: | :-----: | :-----: | :----: |
|  P1  | P1.pid | P1.pid | P1.pid  | P1.pid  | P1.pid |
|  P2  | P2.pid | P2.pid | P2.pid  | P2.pid  | P1.pid |
|  P3  | P3.pid | P3.pid | P3.pid  | P2.pid  | P1.pid |
|  P4  | P4.pid | P4.pid | P4.pid  | P4.pid  | P1.pid |
|  T1  | P4.pid | T1.pid | P4.pid  | P4.pid  | P1.pid |
|  T2  | P4.pid | T2.pid | P4.pid  | P4.pid  | P1.pid |
|  T3  | P4.pid | T3.pid | P4.pid  | P4.pid  | P1.pid |

	Distinguish Process and Thread:
	    Process - pid == tgid
	    Thread  - pid != tgid

## Process

	A process is a program (object stored on some media) in the midst of execution

	Process resources:

> * Executing program code (text section)
> * Open files
> * Pending signals
> * Internal kernel data
> * Processor state
> * Memory address space with one or more memory mappings
> * Data section containing global variable
> * Thread(s) of exectuion

### Threads of exectuion

	Thread resource:

> * Program counter
> * Process stack
> * Set of processor registers

# OSv Sched

	OSv is different from Linux, there is only thread in OSv

## Schedule Policy

	Requirements:

> * global fairness
> * Cheap to compute

---

	Decaying average:

```
	R(t + dt) = (1 - k * dt)R(t) + p(t)r(t) * k * dt

		R - runtime recevied in the recent past
		p - priority
		r - runtime history, 1 when the thread is running, 0 otherwise
		k - a constant
```

---

	Update R only when scheduler is invoked, or priorities change:

```
	R(t2) = e^k(t1 - t2)R(t1) + 1 / k * p(t2)r(t2)(1 - e^k(t1 - t2))
```

---

	Only update running thread

```
	R'(t) = c(t)R(t)
	c(t2) = e^-k(t1 - t2) * c(t1)
	R'(t2) = R'(t1) + 1 / k * p(t2)r(t2)(c(t2) - c(t1))
	For non-runnint threads, r(t2) = 0
		R'(t2) = R'(t1)
```

	Renormalize R' periodically to avoid overflow of `c` and `R'`:

> * Dividing it for all threads by `c`
> * Set `c` to 1 


	Migrate:

> * Normalize in current cpu
> * Unnormalize in destinate cpu

---

	Achieve hysteresis to avoid immediate preemtion

> * Reduce the running thread's R by a constant `t_gran` when starting 
> * Increase it back by the same amount when stopping

---

	Compute `ts` for the lowest runnable thread `q`, which will replace the running thread `r`

```
	Rq(ts) = e^k(t0 - ts)Rq(t0)
	Rr(ts) = e^k(t0 - ts)Rr(t0) + 1 / k * pr * (1 - e^k(t0 - ts))

	Set Rq(ts) = Rr(ts), and solve for ts:
		ts - t0 = 1 / k * ln(1 + k / p / c(t0) * (R'q(t0) - R'r(t0)))

```

---

	Simplify

```
	a = 1 / k (units is time)
	R" = R' / a

	c(t2) = e^((t2 - t1)/a)c(t1)
	R"(t2) - R"(t1) = p(t2)(c(t2) - c(t1))
	ts - t0 = a * ln(1 + 1 / p / c(t0) * (R"q(t0) - R"r(t0)))
```

	Replace `e^((t2 - t1)/a)` with `O(x^2)` when `t2 - t1 < a / 1000`:

```
	x = (t2 - t1) / a
	c(t2) = (1 + x)c(t1)
```

---

	hysteresis called `ran_for`

> *	Set `t2 - t1 = -tH`, update `R'` and `c`
> * Then  Set `t2 - t1 = tH`, update `R'` and `c`

	It can be proved that `ran_for(d1 and then d2) = ran_for(d1 + d2)`

## Files

> * [include/osv/sched.hh](include/osv/sched.hh) - class definition
> * [core/sched.cc](core/sched.cc) - class implementation

## cpu_set

	Represent cpu set by `_mask`, each bit represent a aviable cpu

---

```
	void set(unsigned c)
```

	Set cpu in index `c`

---

```
	void clear(unsigned c)
```

	Clear cpu in index `c`


## timer_base

	Just represent a time point by `_time`, owned by a timer_base::client

	One client has one or more timer_bases

----

```
	void timer_base::set(osv::clock::uptime::time_point time)
```

	Set `_state` and `_time`, push it to client's `_active_timers`
	Then try to insert it into `cpu::current()->timers._list` and do `rearm()`

---

```
	void timer_base::reset(osv::clock::uptime::time_point time)
```

	Reset `_state` and `_time`, then do something like `set()`

---

```
	void timer_base::expire()
```

	Set `_state` `state::expired`, remove it from client's `_active_timers`, then do `_t.timer_fired()`

---

```
	void timer_base::cancel()
```

	Remove it from 	client's `_active_timers` and `cpu::current()->timers._list`


## timer

	Just use `thread` as timer_base::client


## wait_object<timer>

	Just a wrapper of `timer`

## thread_runtime

	Maintain the scheduler's view of the thread's priority

	Important properties:

> * `_priority` - p
> * `_Rtt` - R"

---

```
	void export_runtime();
```

	Unnormalize local runtime for migration

----

```
	void update_after_sleep();
```

	Update local runtime by renomarlizing (after sleeping) or normalizing (for migrating)

---

```
	void ran_for(duration time);
```

	Increase runtime (logically for hystersis)

---

```
	void hysteresis_run_start();
	void hysteresis_run_stop();
```

	Do hystersis by `ran_for`

---

```
	void add_context_switch_penalty();
```

---

```
	duration time_until(runtime_t target_local_runtime) const;
```

	Calculate avialable time to arive `targe_local_time`


## thread

	Represent a thread which can only be created on heap

	A thread has stack, app_runtime

## thread_handle

	Just a wrapper of thread::detached_state

## timer_list

	Hold a timer set

## cpu
	
	Hold some queues and times