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
| xen_intr        | sched,percpu,trace,debug         | [N] ...     |
| select          | poll,debug                       | [N] ...     |
| condvar         | sched,trace                      | [N] ...     |
| debug           | sched,printf                     | [N] ...     |
| osv_execve      | run,condvar,osv_execve,debug     | [N] ...     |
| rcu             | mempool,percpu,semaphore,debug   | [N] ...     |
| poll            | epoll,trace                      | [I] ...     |
| epoll           | pool,trace,debug                 | [I] ...     |
| lfmutex         | sched,trace                      | [I] ...     |
| async           | sched,percpu,condvar,waitqueue,trace,printf                  | [I] ...     |
| commands        | power,debug                                                  | [I] ...     |
| app             | sched,elf,run,power,trace                                    | [I] ...     |
| pagecache       | mmu,mempool,trace                                            | [I] ...     |
| dhcp            | sched,mutex,debug                                            | [I] ...     |
| trace           | sched,percpu,semaphore,elf,rcu,debug                         | [I] ...     |
| elf             | sched,mmu,trace,version,demangle,app,debug                   | [I]         |
| mempool         | sched,mmu,percpu,condvar,semaphore,percpu-worker,trace,debug | [I]         |
| sched           | percpu,elf,math,app,rcu,rwlock,trace,debug                   | [I]         |
| mmu             | mempool,rcu,rwlock,trace,debug                               | [I]         |


# percpu per-cpu-counter trace-count

使用了定义于sched.cc中的全局域percpu_base - 表示当前CPU的percpu_base

使用了定义于percpu.cc中的文件域buffer - 一个percpu类型(多CPU副本)

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

使用了定义于percpu-worker.cc的全局域
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

使用了定义于alloctracker.cc的全局域alloc_tracker::in_tracker

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


# xen_intr

处理xen中断,定义了文件域单例xen_irq_handlers以提供面向过程API

使用了定义于xen.hh的全局域hypercall_page, xen_features, xen_start_info, 
                          HYPERVISOR_shared_info, xen_shared_info
使用了定义于xen_intr.cc的全局域xen_irq::_thread和文件域xen_allocated_irqs, xen_irq_handlers

xen_irq
	持有interrupt, cpu::notifier, (PERCPU)(static)thread*属性
	* register_irq/unregister_irq设置/取消xen_allocated_irqs指定项
	* wake唤醒PERCPU中断线程
	* 中断线程等待标志位,然后逐一检查端口并回调,然后重置端口位
	* interrupt属性似乎完全没啥用


# select

select
	借助poll实现select语义

pselect
	转换了timeout,在select前后做了sigprocmask处理


# condvar

非常类似waitqueue(不像POSIX标准, 并无signal改变条件操作)

	持有_waiters_fifo(两个wait_record* - oldest, newest), mutex_t, mutex_t*属性
	* mutex_t*记录最后wait使用的mutex
	* wait为当前线程新建wait record等待超时或被wake_one/wake_all唤醒(并无signal操作,很玄学)
	* wake_one选择oldest wait record通知send_lock
	* wake_all遍历wait records通知send_lock


# debug

输出调试信息(severity, tag, fmt)

使用了定义于debug.cc的全局域logger::_instance, debug_buffer, debug_buffer_idx, debug_buffer_full, verbose

使用logger单例模式提供面向过程API

logger
	持有map<string, logger_severity>, mutex, (static)logger*属性
	* instance实例化单例_instance
	* wrt调用vkprintf或debug输出

debug使用一个buffer,执行flush时通过console输出(貌似buffer满时无自动输出操作,可能会丢失信息?)

debug_early通过console::arch_early_console输出


# osv_execve

在新的ELF namespace执行program
(ELF namespace是什么? 为何可以调用std::thread?它又怎样执行?)

使用了定义于osv_execve.cc的文件域exited_threads, exec_mutex, cond

osv_execve
	创建std::thread执行thread_run_app_in_namespace
		设置thread_id为当前线程tid
		调用osv::application::run_and_join
		记录返回码
		唤醒原线程
		通过写入1回调notification_fd
	让原线程wait触发CPU schedule
	返回错误码

osv_waittid
	在exec_mutex, cond下从exited_threads无限循环查找指定tid,返回status


# rcu

使用了定义于rcu.cc的全局域rcu_read_lock, peempt_lock_in_rcu, rcu_read_lock_in_peempt_disabled, cpu_notifier
和文件域(PERCPU)percpu_callbacks, cpu_quiescent_state_threads, cpu_quiescent_state_thread::next_generation
        (PERCPU)percpu_quiescent_state_thread, (PERCPU)percpu_waiting_defers

rcu_ptr
	持有atomic<T*>属性
	* read/read_by_owner原子读取
	* assign原子写入
	* 析构时销毁T*

cpu_quiescent_state_thread
	持有thread, uint64_t * 2(_generation, _request), bool, (static)uint64_t属性
	* thread线程执行work
		唤醒percpu_waiting_defers上的wait records
		设置CPU的generation,同步来自其他CPU的request
	* request设置_request为指定的更高generation
	* check检查_generation是否不低于指定generation

rcu_defer加入一个callback到percpu_callbacks

rcu_synchronize通过在当前CPU加入一个信号量增加计数的回调,等待generation同步完成

rcu_flush通过在每个CPU加入一个信号量增加计数的回调,等待所有generation同步完成


# poll

一次poll形成一个pollreq,包含多个(fp, events),pollreq会被内部每个fp关联以便从任意fp唤醒

poll_file
	持有fileref, int * 2(events, last_poll_wake_count), short属性

pollreq
	持有vector<poll_file>, nfds_t, bool, thread_handle属性

poll_wake唤醒epoll和所有相关的pollreq

poll尝试立即返回,若失败则等待poll_wake的唤醒或超时


# epoll

通过传入class实例实现面向过程API

epoll_key
	持有int, file*属性

epoll_ptr
	持有epoll_file*, epoll_key属性

epoll_file
	持有map, mutex, set, waitqueue, queue, bool, thread_handle属性
	* add向map添加(key, event),向f_epools添加(this, key),如有可能直接wake(key)
	* mod修改(key, event),尝试向f_epools添加(this, key),如有可能直接wake(key)
	* del从map删除(key, event),从f_epools删除(this, key)
	* wait等待_waiter唤醒,超时或出现待处理activity,然后处理
		flush_activity_ring将待处理activity移动到set
		process_activity检查events,移除f_epolls无效内容或重新添加内容
	* wake/wake_in_rcu添加key到queue,唤醒wait所在阻塞线程

epoll_create创建一个epoll_file (会分配一个fd,这个fd是否是临时的?何时失效?)

epoll_ctl/epoll_wait/epoll_file_closed/epoll_wake_in_rcu在epoll_file上操作


# lfmutex

基于lock-free的多生产者单消费者队列(Multi-Producer Single-Consumer)实现的lock-free互斥锁

核心是原子操作

通过传入class实例实现面向过程API

queue_mpsc
	持有atomic<LT*> (pushlist)和LT* (poplist)属性
	* push使用循环配合compare_exchange_weak修改pushlist头指针
	* pop从poplist取出,若poplist为空,则通过exchange取出pushlist并反转加入poplist
	* iterator持有pushlist, poplist,优先选择pushlist操作

mutex
	持有atomic<int>, int, thread*, queue_mpsc<wait_record>, atomic<unsigned int>, unsigned int属性
	* lock尝试加锁或递归加锁,失败则加入等待队列,尝试执行handoff(handoff选中自己时直接加锁,否则线程等待)
		handoff
		* 在一个线程unlock时激活,只能被一个线程执行
		* 选择waitqueu里一个线程唤醒
	* send_lock无竞争时唤醒指定wait record,否则将其加入等待队列,尝试执行handoff
	* send_lock_unless_already_waiting由加锁线程执行,将不存在的wait record加入等待队列
	* receive_lock由send_lock唤醒的线程使用,直接加锁
	* try_lock尝试加锁,递归加锁,或通过handoff加锁(此处并不之心handoff,而只是利用此条件直接加锁)
	* unlock解一层递归锁或解锁,解锁后若有等待线程,则唤醒等待队列一个线程,
                若等待线程尚未进入队列,则激活handoff,由自己或其他线程执行handoff(使用了循环确保handoff执行)


# async

使用了定义于async.cc的文件域_percpu_worker, _notifier

aysnc_worker代表一个CPU上的worker,负责处理此CPU上注册的tasks
	持有属性
	    timer_set (_timer_tasks), slist (_queue), unordered_queue_mpsc (released_timer_tasks), 
	    thread, timer, cpu*
	* timers_set用于存放普通未过期的task(task.queue=true)
	* slist用于存放one_shot_tasks
	* unordered_queue_mpsc用于存放已完成的tasks以便重用
	* thread线程执行run(死循环)
		* 等待timer或_queue非空
		* 以now为界,逐一取出_timer_tasks过期任务,对非RELEASED状态任务执行fire
		* 重置timer以便下一次唤醒
		* 逐一处理_queue中one_shot_tasks任务,调用其注册的_callback
	* insert将task加入_timer_tasks,置task.queue为true
	* free将task加入released_timer_tasks
	* borrow_task从released_timer_tasks中取出一个task,若有必要,从_timer_tasks移除此task,
	             取出失败时,返回一个空白task
	* fire_once新建一个one_shot_task加入_queue


percup_timer_task代表一个任务路径,可以随意设置任务内容和执行时间点
	持有属性
	    async_worker&, list_member_hook<> * 2 (hook, registrations_hook), percpu_timer_task*, 
	    state, timer_task*, time_point, bool

timer_task
	持有属性
	    list, percpu_timer_task*, mutex&, callback_t, bool
	* reschedule首先cancel,然后从当前CPU worker里获得一个可重用/新建task绑定this,
	            重置_active_task,将task加入worker和_registrations
	* cancel清除_active_task对应的task(影响worker和_registrations)及其本身
	* fire清除_active_task,执行_callback,置task为RELEASED,清除task(影响worker和_registrations)

serial_timer_task对timer_task做了一些修饰,所有操作都需要持有锁,用于辅助实现timer_task的特殊需求
	持有bool, int, mutex&, timer_task, waitqueue属性
	* reschedule调用_task.rescedule
	* cancel调用_task.cancel

run_later加入一个one_shot_task到当前CPU的worker中


# commands

使用了定义于commands.hh的全局域__loader_argc, __loader_argv, __app_cmdline和文件域max_cmdline

使用了定义于commands.cc的全局域osv_cmdline和文件域parsed_cmdline

command
commands
	利用boost::spirit::qi::grammar定义了词法分析器
	* command规则
		string除' ', ';', '&'外字符组成的串
		quoted_string以'"'开始和结尾, 中间不包含'"'的串
		start由string或quoted_string被空格分割,去除末尾';', '&!', '&', eoi得到的集合(?)
	* commands规则
		start有command被空格分割得到的集合(?)

parse_command_line解析app命令,可能包含多个子命令,对于runscript <file>格式的子命令,读取<file>内容进行替换处理

getcmdline返回osv_cmdline

loader_parse_cmdline解析loader命令
	* 输入: str = "[option_value] <app> [arg]"
	* 输出: argc = len(argv), argv = "[option_value]", app_cmdline = "<app> [arg]"

parse_cmdline将传入的字符串复制osv_cmdline,然后通过loader_parse_cmdline解析到
             __loader_argc, __loader_argv, __app_cmdline

save_cmdline将(来自app的)newcmd写入`/dev/vblk0`文件512字节处(用于调试?),然后通过parse_cmdline解析


# app

使用了定义于app.cc的全局域overide_current_app, optind, __lib_stack_end, application::apps

使用了定义于api/unistd.h的全局域environ

使用了定义于elf.hh的全局域program_base = 0x 1000 0000 0000 UL

launch_error
invalid_elf_error
multiple_join_error
	基本等同于std::runtime_error

app_registry
	持有list<share_app_t>和mutex属性
	* join遍历list,逐一对app调用join等待其退出
	* remove将app从list移除,若app存在
	* push将app加入list


application_runtime
	持有application&属性
	* ~application_runtime设置app._terminated为true,唤醒app._joiner

application代表一个可执行的program,拥有独立的ELF namespace(一段8G地址区域)
	持有属性
	    pthread_t, elf::program, vector<std::string>, std::string, int, 
	    bool * 2(_termination_requested, _terminated), mutex, void (_entry_point*)(), 
	    elf::object * 3 (_lib, _libenviron, _libvdso), main_func_t*, char* [], char [], 
	    list<function<void()>>, application_runtime, thread*, function<void()>, 
	    (static)app_registry
	* join通过pthread_join等待app主线程完成
	* request_termination将_termination_requested置为true,在当前线程或std::thread新建线程执行callbacks
	* (static)get_current返回当前线程所属的runtime/app
	* (static)run创建一个新的app,通过start启动,并加入registry
		start通过pthread_create创建新的线程执行main
	* (static)join_all让registry执行join,等待所有app退出
	* (static)run_and_join创建一个新的app,通过start_and_join在当前线程执行,不加入registry
		start_and_join在当前线程执行main,执行前后替换和恢复当前线程的(runtime, name)
	* (static)on_termination_request向当前app加入callback,若_termiation_requested已置为false,则直接执行
	* (static)unsafe_stop_and_abandon_other_threads遍历所有threads,以unsafe_stop停止与当前线程归属同一
                                                       app的其他线程

with_all_app_threads遍历所有线程,对与指定线程runtime相同的线程(包括自身)执行指定funtion

on_termination_request即application::on_termination_request


# pagecache

使用了定义于pagecache.cc的文件域lru_max_length, lru_free_count, zero_page, 
cached_page_arc::arc_cache_map, read_cache, write_cache, write_lru, arc_lock, write_lock
和全局域max_lru_free_count

hashkey持有dev_t, ino_t, off_t属性

arc_hashkey持有unit64_t[]属性

cached_page
	持有hashkey, void*, ptep_list属性
	* map向ptep_list加入ptep
	* unmap从ptep_list移除ptep
	* flush对ptep_list逐一执行clear_pte
	* clear_accessed对ptep_list逐一执行clear_accessed
	* clear_dirty对ptep_list逐一执行clear_dirty

cached_page_write以cached_page为基础
	持有vnode*, bool属性
	* writeback通过VOP_WRITE将_page写回
	* release将_page持有页变为匿名页,_page置为空
	* mark_dirty标记dirty
	* flush_check_dirty对ptep_list逐一执行clear_pte,并检查是否有pte为dirty

cached_page_arc以cached_page为基础(几乎只有static方法)
	持有arc_buf_t*, bool, (static)arc_map(cached_page_arc::arc_cache_map)属性
		arc_cache_map是允许重复键的特殊哈希表unordered_multimap
		可能存在多个cache_page_arc实例具有相同的arc_buf_t*
	* (static)ref向arc_cache_map加入(arc_buf_t*, cached_page_arc*)
	* (static)unref从arc_cache_map移除(arc_buf_t*, cached_page_arc*)
	* (static)unmap_arc_buf遍历所有arc_buf_t*对应的cache_page_arc
		从read_cache中移除所有cache_page_arc*,移除前对每个内部的ptep_list逐一执行clear_pte
		从arc_cache_map移除所有(arc_buf_t*, cache_page_arc*)
		若至少处理了一个pte,则mmu::flush_tlb_all

get新增(cache, ptep, pte)联系
	* 写共享时,内容只存在于write_cache和write_lru
	* 写私有时,新建一份匿名内存拷贝内容,只在write_cache和write_lru可能存在副本(不计入ptep)
	* 读可利用写时,私有读标记COW
	* 读不可利用写时,在无写更新前提下,标记已有的或新建的读为COW

release从write_cache或read_cache中移除ptep,必要时标记dirty或移除cached_page_arc

sync检查write_cache相关的项,清除dirty,并执行writeback

map_arc_buf新建cached_page_arc加入arc_cached_map和read_cache,并执行arc_share_buf

unmap_arc_buf从read_cache移除所有相关的项,并清理ptep_list,必要时执行mmu::flush_tlb_all

access_scanner
	持有属性double, thread, (static)double * 2(_max_cpu, _min_cpu), unsigned
	* run周期性的扫描arc_cache_map,找出accessed项,并通过arc_buf_accessed清除,周期
	     由上次扫描的accessed占比动态调整,但限制在一个范围内


# dhcp

使用了定义于dhcp.cc的全局域(单例)net_dhcp_worker, requested_options, ipv4_zero

使用了定义于未知的全局域V_ifnet

dhcp_mbuf关于packet的封包和解包操作
	持有属性
	    bool, mbuf*, dhcp_message_type, 
	    addres_v4 * 5 (_router_ip, _dhcp_server_ip, _subnet_mask, _broadcast_ip, _your_ip), 
	    vector<address>, u32 * 3 (_lease_time_sec, _renewal_time_sec, _rebind_time_sec), 
	    u16, string
	* compose_xxx封包
	* decode解包

dhcp_socket
	持有ifnet*属性
	* dhcp_send直接通过_ifp->if_output传输

dhcp_interface_state状态机
	持有state, ifnet*, dhcp_socket*, address_v4 * 2(_client_addr, _server_addr), u32属性
	* discover置状态为DHCP_DISCOVER,发送DISCOVER消息
	* release置状态为DHCP_INIT,发送RELEASE消息,清空IP, routes, DNS
	* renew置状态为DHCP_REQUEST,发送RENEW消息
	* process_packet解包,进行状态转换
		DHCP_DISCOVER --state_discover--> DHCP_REQEUST
		DHCP_REQUEST  --state_request---> DHCP_ACKNOWLEDGE/DHCP_INIT
	* state_discover置状态为DHCP_REQUEST,发送REQUEST消息
	* state_request收到ACK消息,置状态为DHCP_ACKNOWLEDGE,设置IP, route, DNS
	               收到NAK消息,置状态为DHCP_INIT,重新discover

dhcp_worker以单例模式提供面向过程API
	持有thread* * 2 (_dhcp_thread, _waiter), mutex, list, map, bool属性
	* init为V_ifnet中每个有效项新建一个dhcp_interface_state,加入map,启动_dhcp_thread执行dhcp_worker_fn
		等待list非空
		取出一个包通过process_packet处理
		获取一个IP后,置bool为true,唤醒等待bool的线程
	* start每个dhcp_interface_state发送DISCOVER消息,等待bool为true
	* release每个dhcp_interface_state发送RELEASE消息,清除bool
	* renew每个dhcp_interface_state发送RENEW消息,等待bool为true
	* queue_packet将数据包放入list,唤醒_dhcp_thread

dhcp_hook_rx通过单例net_dhcp_worker执行queue_packet

dhcp_start通过单例net_dhcp_worker执行init, start

dhcp_release通过单例net_dhcp_worker执行release

dhcp_renew通过单例net_dhcp_worker执行renew


# trace

使用了定义于trace.cc全局域trace_buf::invalid_trace_point, (PERCPU)percpu_trace_buffer, trace_enabled, 
enabled_tracepoint_regexs, tracepoint_base::tp_list
和文件域global_backtrace_enabled, trace_control_lock, func_trace_nesting, symbol_functions, 
symbol_func_mutex, symbol_ids

trace_record
	持有tracepoint_base*, thread*, array<char>, u64, unsigned, bool, u8|long属性

trace_buf
	持有ptr<char[]>, size_t * 2(_last, _size), (static)tracepoint_base属性
	* allocate_trace_record从自己持有的内存区域分配一个trace_record

tracepoint_base::probe虽然声明为class,基本是个空壳,仅有hit方法

tracepoint_base
	持有tracepoint_id, char* 3(name, format, sig), tp_list_link_type,  
	    bool * 3(_backtrace, _logging, active), rcu_ptr<vector>, mutex, 
	    (static)list, (static)size_t属性
	* add_probe向vector添加一个probe,并通知更新
	* del_probe从vector移除一个probe,并通知更新
	* run_probe每个probe执行其唯一方法hit
	* do_log_backtrace通过backtrace_safe获取调用信息，写入buffer

__cyg_profile_func_enter执行trace_function_entry(嵌套调用仅执行一次)

__cyg_profile_func_exit执行trace_function_exit(嵌套调用仅执行一次)

trace::add_symbol_callback向symbol_functions加入function(允许重复function)

trace::remove_symbol_callback从symbol_functions移除function

trace::create_trace_dump将版本信心，ELF program信息，symbol_funcations, trace records写入文件

