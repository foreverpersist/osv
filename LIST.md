# Overview

Description Labels:

> * [E]mpty
> * [S]imple
> * [N]ormal
> * [K]ernel


|       Name      |      Dependencise      | Description |
| :-------------- | :--------------------- | :---------- |
| printf          |                        | [E] Use `<<` |
| version         |                        | [E] Return a constant string `VERSION` |
| per-cpu-counter | sched,percpu,debug     | [S] ...      |
| math            |                        | [S] Use `std::isxxx` |
| spinlock        | sched                  | [S] Use `__sync_lock_test_and_test` |
| osv_c_wrappers  | sched,app,debug        | [S] Return all tids of specific app (0 - current)|
| run             | app                    | [S] Invoke `run_and_join` |
| trace_count     | per-cpu-counter,trace  | [S] ...     |
| libaio          |                        | [S] Do nothing, umimplemented |
| kprintf         |                        | [S] Use stdio with fd=1 |
| power           | debug                  | [S] Invoke arch |
| chart           | sched,debug            | [S] Print boot event(str,stamp) |
| mmio            | mmu                    | [S] Do linear map, directly get/set at specific addr |
| shutdown        | sched,power,dhcp,debug | [S] Release dhcp, stop threads, umount fs, poweroff |
| semaphore       | sched                  | [S] ...     |
| percpu          | sched                  | [S] ...     |
| waitqueue       | sched                  | [S] ...     |
| demangle        | elf                    | [S] ...     |
| newpoll         | sched                  | [S] ...     |
| net_trace       | trace                  | [S] ...     |
| sampler         | sched,percpu,trace,debug         | [N]         | 
| percpu-worker   | sched,percpu,trace,debug,condvar | [N]         |
| alloctracker    |                                  | [S]         |
| rwlock          | sched,condvar,waitqueue          | [N]         |
| callstack       | percpu,trace                     | [N]         |
| net_channel     | sched,rcu,net_trace,debug        | [N]         |
| xen_intr        | sched,percpu,trace,debug         | [N]         |
| select          | poll,debug                       | [N]         |
| condvar         | sched,trace                      | [N]         |
| debug           | sched,printf                     | [N]         |
| osv_execve      | run,condvar,osv_execve,debug     | [N]         |
| rcu             | mempool,percpu,semaphore,debug   | [N]         |
| poll            | epoll,trace                      | [I]         |
| epoll           | pool,trace,debug                 | [I]         |
| lfmutex         | sched,trace                      | [I]         |
| async           | sched,percpu,condvar,waitqueue,trace,printf                  | [I]         |
| command         | power,debug                                                  | [I]         |
| app             | sched,elf,run,power,trace                                    | [I]         |
| pagecache       | mmu,mempool,trace                                            | [I]         |
| trace           | sched,percpu,semaphore,elf,rcu,debug                         | [I]         |
| elf             | sched,mmu,trace,version,demangle,app,debug                   | [I]         |
| mempool         | sched,mmu,percpu,condvar,semaphore,percpu-worker,trace,debug | [I]         |
| sched           | percpu,elf,math,app,rcu,rwlock,trace,debug                   | [I]         |
| mmu             | mempool,rcu,rwlock,trace,debug                               | [I]         |


# percpu per-cpu-counter trace-count

使用了定于在sched.cc中的全局域percpu_base - 表示当前CPU的percpu_base

使用了定义在percpu.cc中的文件域buffer - 一个percpu类型(多CPU副本)

percpu<T>(每个CPU会自动持有一个副本)
	对数据的操作均重定义到percpu_base + offset
	* percpu_base属于当前CPU或指定CPU
	* offset为属性的地址,而非属性的值

dynamic_percpu<T>
	对数据的操作同上
	* offset为buffer中满足align, size要求的一段空闲区间的位置(动态分配和释放)

per_cpu_counter 
	持有dynamic_percpu<ulong>属性
	* 对当前CPU动态分配的某个区间数据加1(禁止CPU抢占)
	* 读取所有CPU副本相同位置的数据求和

trace_counter
	持有per_cpu_counter和tracepoint_base&属性
	* trace_counter与tracepont_base是多对一的映射关系
	* 使用per_cpu_counter计数


# semaphore
	持有usigned, mutex, wait_record list属性
	* trywait尝试取出足够的信号值
	* wait先try,然后等待信号值足够或超时,超时则会移除等待者
	* post尝试按FIFO唤醒并移除等待者


# waitqueue

waiter
	持有一个thread*属性

wait_record
	在waiter基础上持有wait_record*属性(用于寻找下一个wait_record)
	* wake_lock使用外部传入的互斥锁

wait_queue
	持有一个_waiters_fifo属性(两个wait_record* - oldest, newest)
	* wait等待外部传入的互斥锁
	* wake_one, wait_all通知对应的thread在获取外部传入的互斥锁后醒来(未必立即醒来)

wait_object<waitqueue>
	持有wait_queue&, mutex&, wait_record属性
	* wait_record持有创建时的当前thread
	* poll查看wait_record是否被唤醒
	* arm将wait_record加入wait_queue
	* disarm将wait_record移除wait_queue(如wait_record未被唤醒)


# demangle

调用`__gcclibcxx_demangle_callback`或`abi::__cxa_demangle`执行真正的还原工作

面向过程
	* demangle还原完成后,在给定位置或新分配位置拷贝符号名称
	* demangler多次执行会重用同一块内存拷贝名称
	* lookup在当前program(app)中搜索


# newpoll

OSV自己额外实现的poll, [poller + pollable]类似[epoll + fd], 但一个pollable只能由一个线程等待

pollable
	持有thread*和std::atomic<bool>属性
	* wake设置bool属性true,唤醒对应thread
	* poll读取bool属性
	* read将bool属性与false原子交换返回旧值

poller
	持有forward_list<pollable*>和timer属性
	* timer与创建时当前线程关联
	* add添加一个与当前线程关联的pollable*
	* del删除一个poolable*
	* set_timer重新设置timer时间
	* expired在timer过期时取消timer
	* wait循环等待一个pollable状态为true或者timer超时
	* process循环检查pollable能否成功read继而执行on_wake回调


# net_trace

面向过程的网络收发和处理包时的log操作(in, out, handling) - 仅调用`trace_net_xxx`

mbuf_iterator
	持有mbuf*和size_t属性
	* size_t属性相对于整个mbuf链而言,若超出当前mbuf*范围,则mbuf*会向后定位
	* 计算mbuf_iterator的distance也是基于size_t属性而言的,可能会跨越多个mbuf
