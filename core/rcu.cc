/*
 * Copyright (C) 2013 Cloudius Systems, Ltd.
 *
 * This work is open source software, licensed under the terms of the
 * BSD license as described in the LICENSE file in the top-level directory.
 */

#include <osv/rcu.hh>
#include <osv/mutex.h>
#include <osv/semaphore.hh>
#include <vector>
#include <boost/algorithm/cxx11/all_of.hpp>
#include <osv/debug.hh>
#include <osv/percpu.hh>
#include <osv/preempt-lock.hh>
#include <osv/migration-lock.hh>
#include <osv/wait_record.hh>
#include <osv/mempool.hh>

namespace osv {

rcu_lock_type rcu_read_lock;
preempt_lock_in_rcu_type preempt_lock_in_rcu;
rcu_lock_in_preempt_type rcu_read_lock_in_preempt_disabled;

namespace rcu {

mutex mtx;

/* 使用array[2]作交换区,buf指示有效部分,每次使用后交换有效区和无效区
 */
struct rcu_defer_queue {
    int buf; // double-buffer: 0 or 1
    std::array<std::function<void ()>, 2000> callbacks[2];
    unsigned int ncallbacks[2];
};
static PERCPU(rcu_defer_queue, percpu_callbacks);

class cpu_quiescent_state_thread {
public:
    cpu_quiescent_state_thread(sched::cpu* cpu);
    void request(uint64_t generation);
    bool check(uint64_t generation);
private:
    void do_work();
    void work();
    void set_generation(uint64_t generation);
private:
    static std::atomic<uint64_t> next_generation;
    std::unique_ptr<sched::thread> _t;
    std::atomic<uint64_t> _generation = { 0 };
    std::atomic<uint64_t> _request = { 0 };
    std::atomic<bool> _requested { false };
};

std::atomic<uint64_t> cpu_quiescent_state_thread::next_generation { 0 };

std::vector<cpu_quiescent_state_thread*> cpu_quiescent_state_threads;
static PERCPU(sched::thread_handle, percpu_quiescent_state_thread);
static PERCPU(wait_record*, percpu_waiting_defers);

/* 在何处使用?
 */
// FIXME: hot-remove cpus
// FIXME: locking for the vector
sched::cpu::notifier cpu_notifier([] {
        cpu_quiescent_state_threads.push_back(new cpu_quiescent_state_thread(sched::cpu::current()));
});

cpu_quiescent_state_thread::cpu_quiescent_state_thread(sched::cpu* cpu)
    : _t(sched::thread::make([=] { work(); }, sched::thread::attr().pin(cpu).name(osv::sprintf("rcu%d", cpu->id))))
{
    (*percpu_quiescent_state_thread).reset(*_t);
    _t->start();
}

void cpu_quiescent_state_thread::request(uint64_t generation)
{
    auto r = _request.load(std::memory_order_relaxed);
    while (generation > r && !_request.compare_exchange_weak(r, generation, std::memory_order_relaxed)) {
        // nothing to do
    }
    _t->wake();
}

bool cpu_quiescent_state_thread::check(uint64_t generation)
{
    return _generation.load(std::memory_order_relaxed) >= generation;
}

void cpu_quiescent_state_thread::set_generation(uint64_t generation)
{
    _generation.store(generation, std::memory_order_relaxed);
    // Wake the quiescent threads who might be interested in my _generation.
    for (auto cqst : cpu_quiescent_state_threads) {
        if (cqst != this &&
                cqst->_requested.load(std::memory_order_relaxed)) {
            cqst->_t->wake();
        }
    }
}

bool all_at_generation(decltype(cpu_quiescent_state_threads)& cqsts,
                       uint64_t generation)
{
    for (auto cqst : cqsts) {
        if (!cqst->check(generation)) {
            return false;
        }
    }
    return true;
}

void cpu_quiescent_state_thread::work()
{
    WITH_LOCK(memory::reclaimer_lock) {
        do_work();
    }
}

void cpu_quiescent_state_thread::do_work()
{
    while (true) {
        bool toclean = false;
        WITH_LOCK(preempt_lock) {
            /* 将当前CPU上的percpu_callbacks->ncallbacks反转0 <-> 1
             */
            auto p = &*percpu_callbacks;
            if (p->ncallbacks[p->buf]) {
                toclean = true;
                p->buf = !p->buf;
            }
            /* 唤醒当前CPU上的所有wait records,并清空percpu_waiting_defers
             */
            // If an rcu_defer() is waiting for buffer room, let it know.
            auto q = *percpu_waiting_defers;
            while (q) {
                auto next = q->next;
                q->wake();
                q = next;
            }
            *percpu_waiting_defers = nullptr;
        }
        if (toclean) {
            /* fetch_add返回旧值,即g = next_generation + 1
             */
            auto g = next_generation.fetch_add(1, std::memory_order_relaxed) + 1;
            _requested.store(true, std::memory_order_relaxed);
            // copy cpu_quiescent_state_threads to prevent a hotplugged cpu
            // from changing the number of cpus we request a new generation on,
            // and the number of cpus we wait on
            // FIXME: better locking
            auto cqsts = cpu_quiescent_state_threads;
            /* 除当前线程外所有线程均request下一个generation
             */
            for (auto cqst : cqsts) {
                if (cqst != this) {
                    cqst->request(g);
                }
            }
            /* 直接设置当前线程generation,唤醒其他线程
             */
            set_generation(g);
            // Wait until desired generation g is reached, but while waiting
            // also service generation requests from other cpus' threads.
            while (true) {
                sched::thread::wait_until([&cqsts, &g, this] {
                    return ( (_generation.load(std::memory_order_relaxed) <
                                _request.load(std::memory_order_relaxed))
                             || all_at_generation(cqsts, g)); });
                auto r = _request.load(std::memory_order_relaxed);
                /* 可能其他线程又更新了generation,需要再次设置
                 */
                if (_generation.load(std::memory_order_relaxed) < r) {
                    set_generation(r);
                } else {
                    break;
                }
            }
            // Finally all_at_generation(cqsts, g), so can clean up
            _requested.store(false, std::memory_order_relaxed);
            auto p = &*percpu_callbacks;
            auto b = !p->buf;
            auto &callbacks = p->callbacks[b];
            auto ncallbacks = p->ncallbacks[b];
            p->ncallbacks[b] = 0;
            for (unsigned i = 0; i < ncallbacks; i++) {
                (callbacks[i])();
                callbacks[i] = nullptr;
            }
        } else {
            // Wait until we have a generation request from another CPU who
            // wants to clean up, or we are woken to clean up our callbacks
            sched::thread::wait_until([=] {
                return (_generation.load(std::memory_order_relaxed) <
                        _request.load(std::memory_order_relaxed)) ||
                        percpu_callbacks->ncallbacks[percpu_callbacks->buf]; });
            auto r = _request.load(std::memory_order_relaxed);
            if (_generation.load(std::memory_order_relaxed) < r) {
                set_generation(r);
            }
        }
    }
}

}

using namespace rcu;

void rcu_defer(std::function<void ()>&& func)
{
    WITH_LOCK(preempt_lock) {
        auto p = &*percpu_callbacks;
        while (p->ncallbacks[p->buf] == p->callbacks[p->buf].size()) {
            // We're out of room. Wait for the cleanup on this CPU to switch
            // buffers. Make sure to re-awake on the same CPU.
            // FIXME: We have a starvation possibility: another thread looping
            // on rcu_defer() can cause us to always find a full queue.
            wait_record wr(sched::thread::current());
            wr.next = *percpu_waiting_defers;
            *percpu_waiting_defers = &wr;
            WITH_LOCK(migration_lock) {
                DROP_LOCK(preempt_lock) {
                    (*percpu_quiescent_state_thread).wake();
                    wr.wait();
                }
            }
            assert (p == &*percpu_callbacks);
        }
        auto b = p->buf;
        p->callbacks[b][p->ncallbacks[b]++] = std::move(func);
    }
}

/* 通过等待信号量增加来等待generation同步完成
   rcu_flush同理
 */
void rcu_synchronize()
{
    semaphore s{0};
    WITH_LOCK(migration_lock) {
        rcu_defer([](semaphore* s) { s->post(); }, &s);
        // rcu_defer() might not wake the cleanup thread until enough deferred
        // callbacks have accumulated, so wake it up now.
        (*percpu_quiescent_state_thread).wake();
    }
    s.wait();
}

/// Ensure that all queued rcu callbacks are executed.
/// This function provides a barrier that ensures that all callbacks previously enqueued
/// with rcu_defer() have completed execution.  This is useful if some data that they
/// depend on is going away.
/// Use this only as a last resort -- usually a reference count on the object that can
/// go away is preferable.
void rcu_flush()
{
    semaphore s{0};
    for (auto c : sched::cpus) {
        std::unique_ptr<sched::thread> t(sched::thread::make([&] {
            rcu_defer([&] { s.post(); });
            // rcu_defer() might not wake the cleanup thread until enough deferred
            // callbacks have accumulated, so wake it up now.
            percpu_quiescent_state_thread->wake();
        }, sched::thread::attr().pin(c)));
        t->start();
        t->join();
    }
    s.wait(sched::cpus.size());
}

}
