# Overview

Description Labels:

> * [E]mpty
> * [S]imple
> * [N]ormal
> * [I]mportant


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
| sampler         | sched,percpu,trace,debug         | [N] ...     |
| percpu-worker   | sched,percpu,trace,debug,condvar | [N] ...     |
| alloctracker    |                                  | [S] ...     |
| rwlock          | sched,condvar,waitqueue          | [N] ...     |
| callstack       | percpu,trace                     | [N] ...     |
| net_channel     | sched,rcu,net_trace,debug        | [N] ...     |
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


# sampler

用作测试,文件域属性_active_cpus, _started_, _n_cpus, _config, _controller, control_lock, _sampler
	* _controller关联运行开始时当前线程(thread_handle)
	* 使用了定义于migration-lock.hh中的全局域migration_lock

cpu_sampler
	基于timer_base::client,持有timer_base和bool属性
	* 自身作为timer_base关联的client
	* start设置timer_base,置bool属性为true
	* stop取消timer_base,置bool属性为false

start_sampler
	* _active_cpus必须为0
	* start并发送CPU间中断
	* start之后等待至CPU全部用满触发_controller

stop_sampler
	* 发送CPU间中断并stop
	* stop之后等待至CPU全部空闲_controller


# worker_item workman

使用定义于percpu-worker.cc中的全局域
	(PERCPU) workman::_duty, workman::_ready, workman::_work_sheriff
	(extern) _percpu_workers_start, _percpu_workers_end
	workman::_cpu_notifier, workman_instance

worker_item
	持有bool[max_cpus]和function<void()>属性
	* signal进行trace,置位相应bool值为true,通知workman_instance向对应CPU发信号
	* have_work检查相应bool标志
	* set_finished仅有trace,无实质操作
	* clear_work置位相应bool值为false
	* 实际工作由function<void>在回调时执行

workman
	无任何属性,几乎全是静态方法,还是单例形式(class只是一具空壳)
	* signal检查当前CPU的_ready,置位指定CPU上的_duty,唤醒其上_work_sheriff
	* call_of_duty每个CPU执行的_work_sheriff线程路径:
		** 置位当前CPU的_ready为true
		** 死循环内逐一检查,清理,回调存在于_percpu_workers_xxx中的worker_item
	* pcpu_init每个CPU上启动_work_sheriff线程

work_item.signal(),_percpu_workers_xxx应当由外部操控,来间接控制workerman(唤醒,增删工作)
	* 具体如何操作,并未看到应用场景


# alloctracker

记录内存分配的调用路径,用于分析内存泄漏

使用定义于alloctracker.cc中全局域alloc_tracker::in_tracker

alloc_info
	仅一个struct
	* seq分配的序号,用于表示时间先后
	* (addr, size)描述内存
	* (nbacktrace, backtrace)描述调用栈
	* next用于构建逻辑链表(用数组配合索引实现)

alloc_tracker
	持有alloc_info*, mutex, int * 2, usigned long属性
	* alloc_info*链表逻辑上分为两部分:已用,空闲
	* 两个int分别执行最新使用和空闲位置索引
	* usigned long用作分配计数,表时间先后
	* remember找到一个空闲节点写入(必要时扩展大小*2),调用太深则尽可能保存上层信息
	* 在已用部分从新到旧查找并释放节点


# rwlock
	持有mutex, usigned * 2(_readers, _wrecurse), waitqueue * 2, void*属性
	* _wowner表示持有写锁的线程,_wrecurse表同一线程递归持有写锁次数
	* rlock等待可读锁,_readers加1
	* try_rlock尝试rlock
	* runlock将_readers减1,若为最后一个reader则唤醒一个write waiter
	* try_upgrade在当前唯一reader且write waiters为空时,清零_readers,设置_wowner为当前线程
	* wlock等待可写锁,设置_wowner,出现递归则对_wrecurse加1
	* try_wlock尝试wlock
	* wunlock调整_wrecurse或_wowner,唤醒一个write waiter或所有read waiters(写优先)
	* downgrade通过wunlock释放写锁,然后调用rlock(unlock可能会唤醒write waiters,引起rlock阻塞)
	* wowned检查当前线程是否持有写锁
	* read_lockable无线程持有写锁,且无wait writers为true
	* write_lockable当前线程持有写锁,或无线程持有写锁且无readers
	* reader_wait_lockable循环检查read_lockable
	* writer_wait_lockable循环检查write_lockable
	* has_readers检查_readers是否非0
	* rwlock_xxx为了提供C面向对象的API对class实例进行了操作,相当于一个代理


# callstack

用于检测tracepoint以收集调用栈信息

trace
	持有void* []和usigned * 2(hits, len)

histogram_compare
	一个空壳,含有一个()操作用于比较trace: 先比较hits,在比较地址

backtrace_hash
	持有一个usigned属性
	* ()定义了hash值的计算(一个循环,初始r=0)
	    ** 将r按位分割成(N-7 | 7)两部分,并交换左右位置(7 | N-7)
	    ** r ^= std_hash(bt[i])

callstack_collector
	持有属性:
	    atomic<bool> * 2(_running, _overflow), size_t, unsigned *2(_skip_frames, nr_frames), 
	    void*, vector<bucket>, (PERCPU)hash_table, atomiv<void*>, vector<tracepoint_base*>
	* attach添加一个tracepoint到对应vector
	* trace_objects_size返回trace类型大小 + _nr_frames个指针大小
	* start让所有tracepoints添加对此对象的探测,置_running为true
	* stop置_running为false,让所有tracepoints删除对此对象的探测,并将PERCPU的hash table都整合到CPU0
	* hit增加当前backtrace_safe获取的backtrace的hits计数或分配一个新的backtrace
	* histogram从所有PERCPU的hash table中返回包含至多n个trace的集合(丢弃最不频繁的)
	* dump使用给定function遍历histrogram返回的集合


# net_channel

net_channel
	持有属性
	    function<void (mbuf*)>, ring_spsc, thread_handle, 
	    rcu_ptr<vector>, rcu_hashtable<epoll_ptr>
	* push将mbuf*添加到ring_spsc
	* wake通知thread_handle唤醒,然后遍历polls和epolls进行各自唤醒操作
	* process_queue从ring_spsc逐一调用function处理
	* add_poller/del_poller增删pollreq(会引起RCU相关的操作)
	* add_epoll/del_epoll增删epoll_ptr

wait_object<net_channel>
	持有net_channel&属性
	* poll检查_queue是否非空
	* arm设置_waiting_thread为当前线程
	* disarm清除_waiting_thread

ipv4_tcp_conn_id
	持有in_addr * 2(src_addr, dst_addr), in_port_t * 2(src_port, dst_port)属性
	* hash四个属性做&运算
	* ==比较四个属性

classifier

维护了ipv4_tcp_conn_id -> net_channel的映射关系(仅TCP)

	持有mutex, rcu_hashtable属性
	* add加入一组映射
	* remove清除一组映射
	* post_packet解析ipv4_tcp_conn_id,放入对应net_channel并唤醒
