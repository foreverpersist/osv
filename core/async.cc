/*
 * Copyright (C) 2014 Cloudius Systems, Ltd.
 *
 * This work is open source software, licensed under the terms of the
 * BSD license as described in the LICENSE file in the top-level directory.
 */

#include <osv/async.hh>
#include <osv/percpu.hh>
#include <osv/sched.hh>
#include <osv/trace.hh>
#include <osv/printf.hh>

#include <osv/irqlock.hh>
#include <osv/preempt-lock.hh>
#include <osv/migration-lock.hh>
#include <lockfree/unordered-queue-mpsc.hh>
#include <boost/intrusive/set.hpp>
#include <boost/intrusive/parent_from_member.hpp>
#include <osv/timer-set.hh>
#include <osv/aligned_new.hh>

namespace async {

TRACEPOINT(trace_async_timer_task_create, "timer=%x", timer_task*);
TRACEPOINT(trace_async_timer_task_destroy, "timer=%x", timer_task*);
TRACEPOINT(trace_async_timer_task_reschedule, "timer=%x, worker=%x, delay=%d", timer_task*, async_worker*, u64);
TRACEPOINT(trace_async_timer_task_cancel, "timer=%x, task=%x", timer_task*, percpu_timer_task*);
TRACEPOINT(trace_async_timer_task_shutdown, "timer=%x", timer_task*);
TRACEPOINT(trace_async_timer_task_fire, "timer=%x, task=%x", timer_task*, percpu_timer_task*);
TRACEPOINT(trace_async_timer_task_misfire, "timer=%x, task=%x", timer_task*, percpu_timer_task*);
TRACEPOINT(trace_async_timer_task_insert, "worker=%x, task=%x", async_worker*, percpu_timer_task*);
TRACEPOINT(trace_async_timer_task_remove, "worker=%x, task=%x", async_worker*, percpu_timer_task*);

TRACEPOINT(trace_async_worker_started, "worker=%x", async_worker*);
TRACEPOINT(trace_async_worker_timer_fire, "worker=%x, percpu=%x, delay=%u", async_worker*, percpu_timer_task*, u64);
TRACEPOINT(trace_async_worker_timer_fire_ret, "");

/*
 * The design behind timer_task
 *
 * timer_task was design for making cancel() and reschedule() scale well
 * with the number of threads and CPUs in the system. These methods may
 * be called frequently and from different CPUs. A task scheduled on one
 * CPU may be rescheduled later from another CPU. To avoid expensive
 * coordination between CPUs a lockfree per-CPU worker was implemented.
 *
 * Every CPU has a worker (async_worker) which has task registry and a
 * thread to execute them. Most of the worker's state may only be changed
 * from the CPU on which it runs.
 *
 * When timer_task is rescheduled it registers its percpu part in current
 * CPU's worker. When it is then rescheduled from another CPU, the
 * previous registration is marked as not valid and new percpu part is
 * registered. When percpu task fires it checks if it is the last
 * registration - only then it can fire.
 *
 * Because timer_task's state is scattered across CPUs some extra
 * housekeeping needs to be done before it can be destroyed.  We need to
 * make sure that no percpu task will try to access timer_task object
 * after it is destroyed. To ensure that we walk the list of
 * registrations of given timer_task and atomically flip their state from
 * ACTIVE to RELEASED. If that succeeds it means the task is now revoked
 * and worker will not try to execute it. If that fails it means the task
 * is in the middle of firing and we need to wait for it to finish. When
 * the per-CPU task is moved to RELEASED state it is appended to worker's
 * queue of released percpu tasks using lockfree mpsc queue. These
 * objects may be later reused for registrations.
 */

struct one_shot_task {
public:
    one_shot_task(callback_t&& callback)
        : _callback(std::move(callback))
    {
    }

    bi::slist_member_hook<> _hook;
    callback_t _callback;
};

TRACEPOINT(trace_async_worker_fire, "worker=%x, task=%x", async_worker*, one_shot_task*);
TRACEPOINT(trace_async_worker_fire_ret, "");

/**
 * CPU-local worker which executes deferred work. It is not SMP-safe by design.
 *
 * Unless otherwise documented its methods should be called with migration_lock held.
 * Holding migration lock is necessary to ensure that the CPU on which a reference to
 * the worker was obtained is the same CPU on which its methods will be called. The
 * same thing is guaranteed by preemption lock, however it cannot be used in all cases
 * because some of the operations call memory allocator which may sleep.
 */
class async_worker {
public:
    async_worker(sched::cpu* cpu)
        : _thread(sched::thread::make(std::bind(&async_worker::run, this),
            sched::thread::attr().pin(cpu).name(osv::sprintf("async_worker%d", cpu->id))))
        , _timer(*_thread)
        , _cpu(cpu)
    {
        _thread->start();
    }

    void insert(percpu_timer_task& task)
    {
        WITH_LOCK(preempt_lock) {
            trace_async_timer_task_insert(this, &task);

            assert(!task.queued);

            if (_timer_tasks.insert(task)) {
                /* 当前task的timestamp比_timer_tasks原先时间戳更靠前
                   重置_timer时间戳
                 */
                rearm(task.get_timeout());
            }

            task.queued = true;
        }
    }

    // May be called from any CPU
    void free(percpu_timer_task& task)
    {
        /* 将task放入released_timer_tasks
         */
        released_timer_tasks.push(&task);
    }

    percpu_timer_task& borrow_task()
    {
        WITH_LOCK(preempt_lock) {
            /* 从released_timer_task取出一个task
             */
            auto task = released_timer_tasks.pop();
            if (task) {
                /* 从_timer_tasks中移除
                   task可以同时存在于released_timer_tasks与_timer_tasks吗?
                   难道是已完成的任务重新加入当前CPU中,不会清除released_timer_tasks?
                 */
                if (task->queued) {
                    remove_locked(*task);
                }
                return *task;
            }
        }

        return *new percpu_timer_task(*this);
    }

    void fire_once(callback_t&& callback)
    {
        /* 新建一个one_shot_task加入_queue,
           加入前_queue为空,则唤醒_thread
         */
        auto task = new one_shot_task(std::move(callback));

        WITH_LOCK(preempt_lock) {
            if (_queue.empty()) {
                _thread->wake();
            }
            _queue.push_back(*task);
        }
    }

    void run()
    {
        trace_async_worker_started(this);

        for (;;) {
            /* 等待_timer设定的时间到达或_queue非空
             */
            sched::thread::wait_until([&] {
                assert(!sched::preemptable());
                return _timer.expired() || !_queue.empty();
            });

            WITH_LOCK(preempt_lock) {
                _timer.cancel();

                /* 让_timer_task中now之前的tasks过期
                   对于每一个非RELEASED状态的task,执行fire
                 */
                auto now = clock::now();
                _timer_tasks.expire(now);
                percpu_timer_task* task;
                while ((task = _timer_tasks.pop_expired())) {
                    mark_removed(*task);

                    /* 此处会出现RELEASED状态的task吗?
                     */
                    if (task->_state.load(std::memory_order_relaxed) !=
                            percpu_timer_task::state::RELEASED)
                    {
                        trace_async_worker_timer_fire(this, task, (now - task->get_timeout()).count());
                        fire(*task);
                        trace_async_worker_timer_fire_ret();
                    }
                }

                /* 重新设置_timer
                 */
                rearm(_timer_tasks.get_next_timeout());

                /* 逐一处理_queue中的one_shot_task
                   调用_callback后直接删除task
                 */
                while (!_queue.empty()) {
                    auto& task = *_queue.begin();
                    _queue.pop_front();
                    DROP_LOCK(preempt_lock) {
                        trace_async_worker_fire(this, &task);
                        task._callback();
                        delete &task;
                        trace_async_worker_fire_ret();
                    }
                }
            }
        }
    }

private:
    void rearm(clock::time_point time_point) {
        assert(sched::cpu::current() == _cpu);
        _timer.reset(time_point);
    }

    void mark_removed(percpu_timer_task& task)
    {
        assert(task.queued);
        trace_async_timer_task_remove(this, &task);
        task.queued = false;
    }

    void remove_locked(percpu_timer_task& task)
    {
        mark_removed(task);
        _timer_tasks.remove(task);
    }

    void fire(percpu_timer_task& task)
    {
        /* 设置task状态位FIRING,并让task内部的timer_task执行真实的fire
         */
        auto old = percpu_timer_task::state::ACTIVE;
        if (!task._state.compare_exchange_strong(
            old, percpu_timer_task::state::FIRING, std::memory_order_relaxed))
        {
            assert(old == percpu_timer_task::state::RELEASED);
            return;
        }

        auto& master = *task.master;
        DROP_LOCK(preempt_lock) {
            master.fire(task);
        }
    }

private:
    timer_set<percpu_timer_task, &percpu_timer_task::hook, clock> _timer_tasks;

    bi::slist<one_shot_task,
        bi::cache_last<true>,
        bi::member_hook<one_shot_task,
            bi::slist_member_hook<>,
            &one_shot_task::_hook>> _queue;

    lockfree::unordered_queue_mpsc<percpu_timer_task> released_timer_tasks;

    std::unique_ptr<sched::thread> _thread;
    sched::timer _timer;
    sched::cpu* _cpu;
};

static PERCPU(async_worker*, _percpu_worker);

static sched::cpu::notifier _notifier([] () {
    *_percpu_worker = aligned_new<async_worker>(sched::cpu::current());
});

static inline async_worker& get_worker()
{
    return **_percpu_worker;
}

timer_task::timer_task(mutex& lock, callback_t&& callback)
    : _active_task(nullptr)
    , _mutex(lock)
    , _callback(std::move(callback))
    , _terminating(false)
{
    trace_async_timer_task_create(this);
}

timer_task::~timer_task() {
    assert(_mutex.owned());
    trace_async_timer_task_destroy(this);

    assert(!_terminating);
    _terminating = true;
    _active_task = nullptr;

    _registrations.remove_and_dispose_if(
        [] (const percpu_timer_task& task) {
            auto old = percpu_timer_task::state::ACTIVE;
            return ((percpu_timer_task&) task)._state.compare_exchange_strong(old,
                percpu_timer_task::state::RELEASED, std::memory_order_relaxed);
        },
        [] (percpu_timer_task* task) {
            task->_worker.free(*task);
        });

    while (!_registrations.empty()) {
        _registrations_drained.wait(_mutex);
    }
}

bool timer_task::reschedule(clock::duration delay)
{
    return reschedule(clock::now() + delay);
}

bool timer_task::reschedule(clock::time_point time_point)
{
    assert(_mutex.owned());
    assert(!_terminating);

    bool was_pending = cancel();

    WITH_LOCK(migration_lock) {
        auto& _worker = get_worker();

        trace_async_timer_task_reschedule(this, &_worker, time_point.time_since_epoch().count());

        /* 从当前CPU的worker中取出一个空闲的percpu_timer_task,绑定this
         */
        auto& task = _worker.borrow_task();
        task.fire_at = time_point;
        task.master = this;
        task._state.store(percpu_timer_task::state::ACTIVE, std::memory_order_relaxed);

        /* 重置_active_task, 将percpu_timer_task加入_registrations,同时加入当前CPU的worker
         */
        _active_task = &task;
        _registrations.push_front(task);
        _worker.insert(task);
    }

    return was_pending;
}

void timer_task::free_registration(percpu_timer_task& task)
{
    /* 从_registration和task绑定的CPU worker上移除task
       _registrations为空时,唤醒_registration_drained
     */
    _registrations.erase(_registrations.iterator_to(task));
    if (_registrations.empty()) {
        _registrations_drained.wake_all(_mutex);
    }

    task._worker.free(task);
}

bool timer_task::cancel()
{
    assert(_mutex.owned());
    trace_async_timer_task_cancel(this, _active_task);
    assert(!_terminating);

    if (_active_task == nullptr) {
        return false;
    }

    /* 清除_active_task对应的task及其本身
     */
    auto old = percpu_timer_task::state::ACTIVE;
    if (_active_task->_state.compare_exchange_strong(old,
        percpu_timer_task::state::RELEASED, std::memory_order_relaxed))
    {
        free_registration(*_active_task);
    }

    _active_task = nullptr;
    return true;
}

void timer_task::fire(percpu_timer_task& task)
{
    WITH_LOCK(_mutex) {
        if (_active_task != &task) {
            /* _active_task与task不一致应该是一种罕见的异常情况(Error)
             */
            trace_async_timer_task_misfire(this, &task);
        } else {
            trace_async_timer_task_fire(this, &task);
            /* 清空_active_task,执行_callback
             */
            _active_task = nullptr;
            DROP_LOCK(_mutex) {
                _callback();
            }
        }

        /* 置task状态为RELEASED,清除task
         */
        task._state.store(percpu_timer_task::state::RELEASED, std::memory_order_relaxed);
        free_registration(task);
    }
}

bool timer_task::is_pending()
{
    assert(_mutex.owned());
    return _active_task != nullptr;
}

serial_timer_task::serial_timer_task(mutex& lock, callback_t&& callback)
    : _active(false)
    , _n_scheduled(0)
    , _lock(lock)
    , _task(lock, std::bind(std::move(callback), std::ref(*this)))
{
}

serial_timer_task::~serial_timer_task()
{
    assert(_n_scheduled == 0);
}

void serial_timer_task::reschedule(clock::duration delay)
{
    assert(_lock.owned());

    if (_task.reschedule(delay)) {
        _n_scheduled--;
    }

    _n_scheduled++;
    _active = true;
}

void serial_timer_task::cancel()
{
    assert(_lock.owned());

    _active = false;
    if (_task.cancel()) {
        _n_scheduled--;
    }
}

void serial_timer_task::cancel_sync()
{
    assert(_lock.owned());

    cancel();

    if (_n_scheduled) {
        _all_done.wait(_lock);
    }

    assert(_n_scheduled == 0);
}

bool serial_timer_task::is_active()
{
    assert(_lock.owned());
    return _active;
}

bool serial_timer_task::can_fire()
{
    assert(_lock.owned());
    return !_task.is_pending() && _active;
}

bool serial_timer_task::try_fire()
{
    assert(_lock.owned());

    if (--_n_scheduled == 0) {
        _all_done.wake_all(_lock);
    }

    if (!can_fire()) {
        return false;
    }

    _active = false;
    return true;
}

/* 加入一个one_shot_task到当前CPU的worker中
 */
void run_later(callback_t&& callback)
{
    WITH_LOCK(migration_lock) {
        get_worker().fire_once(std::move(callback));
    }
}

}
