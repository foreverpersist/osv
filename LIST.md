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
| elf             | sched,mmu,trace,version,demangle,app,debug                   | [I] ...     |
| mempool         | sched,mmu,percpu,condvar,semaphore,percpu-worker,trace,debug | [I] ...     |
| mmu             | mempool,rcu,rwlock,trace,debug                               | [I] ..      |
| sched           | percpu,elf,math,app,rcu,rwlock,trace,debug                   | [I]         |


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


# elf

使用了定义于elf.hh全局域prgram_base = 0x 1000 0000 0000 UL

使用了定义于elf.cc全局域_static_tls_alloc, s_program

使用了定义于arch/x64/arch.hh全局域ELF_IMAGE_START(OSV_KERNEL_BASE)

symbol_module
	持有Elf64_Sym*和object*属性

object代表一个ELF文件
	持有属性	    program&, string, Elf64_Ehdr, vector<Elf64_phdr>, void* * 3(_base, _end, _tls_segment), 
	    ulong * 3(tls_init_size, tls_uninit_size, _module_index), 
	    bool * 2(_static_tls, _is_executable), ptrdiff_t, (static)atomic<ptrdiff_t>, 
	    char[] * 2(_initial_tls, _section_names_cache), vector<ptrdiff_t>, Elf64_Dyn*, 
	    vector<object>, unordered_set<object>, mutex, atomic<void*>
	* Elf64_Ehdr描述ELF Header
	* vector<Elf64_phdr>描述Program Header Table
	* void*和ulong描述TLS
	* Elf64_Dyn*描述Dynamic Table
	* vector<object>和unordered_set<object>描述其他依赖
	* load_needed通过program::load_object加载依赖
	* unload_needed清空依赖依赖,并未立即卸载依赖(会在引用失效时触发program::remove_object)
	* relocate对DT_RELA和DT_JMPREL表项逐一重定位(改写对应内存位置的地址值)
	* lookup_symbol使用GNU Hash Table或Hash Table配合String Table快速查找Symbol Table中的symbol
	* load_segments处理Program Headers
		PT_LOAD    - 映射到内存
		PT_DYNAMIC - 设置_dynamic_table
		PT_INTERP  - 标记_is_executable
		PT_NOTE    - 仅支持自定OSv注释,未直接使用注释
		PT_TLS     - 设置TLS(_tls_segment, _tls_init_size, _tls_uninit_size)
		<OTHERS>   - 忽略或非法
	* unload_segments处理PT_LOAD类Program Headers,解除内存映射
	* fix_permissions将非PT_GUN_RELRO的Program Headers被映射的内存设置mprotect(perm_read)
	* resolve_pltgot对DT_JMPREL指定项symbol进行重定位,若symbol不属于此object,则加入
	               _used_by_resolve_plt_got
	* lookup通过lookup_symbol寻找symbol的重定位地址
	* lookup_addr寻找地址的符号(OBJECT|FUNC)相关信息
	* tls_addr返回当前线程对应_module_index的TLS地址,必要时在当前线程空间新建
	* init_static_tls统计自身及依赖的static TLS大小,在此object上分配空间让自身及依赖写入TLS内容

modules_list
	持有vector<object*>, int * 2(adds, subs)属性

program代表一个正在运行的程序(单例?)
	持有属性
	    (static)core_module_index, mutex * 2(_mutex, _modules_delete_mutex), void*, object, 
	    map<string, object>, vector<object*>, rcu_ptr<vector<string>>,rcu_ptr<modules_list>, 
	    int, vector<object*>, stack<vector<object>>, (static)vector<object*>, (static)mutex
	* 每个实例持有一个特殊object(memory_image),其base皆为ELF_IMAGE_BASE,表示内核
	* get_library通过load_object确保库及其依赖加载,并将新加载的所有库记入_loaded_object_statck
		之前未加载,则新建object执行load_segments, load_needed(递归), relocate, fix_permission
	* init_library取出_loaded_object_stack最后一组,反序执行init functions,执行前后取消和重设private
	* lookup_function遍历所有object寻找function
	* lookup_addr遍历所有object寻找地址的符号(OBJECT|FUNC)相关信息
	* tls_object从当前app的program或s_program中获取对应的object

create_main_program使用program_base作为base创建s_program

get_program返回当前app的program或s_program

init_dyn_tabs
	持有Elf_Sym*(symtab), Elf64_Word*(hashtab), char*(strtab)属性
	* lookup与object::lookup_symbol_old基本相同

init_table
	持有void (**)(), unsigned, tls_data, init_dyn_tabs属性

get_init读取ELF信息
		PT_LOAD    - base(用于设置Rela, Jmp重定位地址)
		PT_DYNAMIC - Init Array, Symbol Table, Hash Table, String Table, Rela, Jmp
		PT_TLS     - TLS


# mempool

使用了定义于mempool.hh全局域page_size = 4096

使用了定义于mempool.cc全局域smp_allocator_cnt, smp_allocator, osv_reclaimer_thread, 
phys_mem_size, tracker, malloc_pools, free_page_ranges_lock, 
s_mark_smp_allocator_initialized, mergency_alloc_level, reclaimer_thread, free_page_ranges, 
(PERCPU)percpu_l1, global_l2
和文件域garbage_collector, percpu_free_list, total_memory, free_memory, watermark_lo, 
current_jvm_heap_memory, reclaimer_lock, min_mergency_pool_size

free_object
	持有free_object*属性(即唯一指针属性)

garbage_sink垃圾回收槽(每个CPU持有N个garbage_sink)
	持有(static)int, unordered_queue_mpsc<free_object>, int属性
	* free向queue加入free_object,数量达到阈值时会唤醒对应CPU执行garbage_collector工作
	* pop从queue取出free_object

page_header
	持有pool*, unsigned * 2(cpu_id, nalloc), list_member_hook<>, free_object*属性

pool管理小对象(大小不超过page_size/4)
	持有属性unsigned, (PERCPU)free_list_type, size_t * 2(max_object_size, min_object_size)
	* alloc从list头部取出一个page_header,从中分配一个free_object,必要时从l1或free_page_ranges
	       补充page
	* free根据当前CPU和object源CPU,选择free_same_cpu或free_different_cpu
		free_same_cpu      - 释放object,视情况调整page_header位置或释放page
		free_different_cpu - 加入到对应的sink,达到阈值会唤醒对应CPU执行free_same_cpu

malloc_pool与pool基本无差别,新增了(static)compute_object_size(用于创建malloc_pools)

page_range每个实例的地址是从phys_mem开始的真实线性地址
	持有size_t, set_memeber_hook<>, list_member_hook<>属性

page_range_allocator管理pages(伙伴系统)
	持有multiset, list, bitset, dynamic_bitset, page_range*属性
	* alloc从_free_huge或_free取出order合适(优先size向上取整的可用order)的page_range,剩余部分
	       重新加入_free
	* alloc_aligned从大到小遍历order取出合适的page_range,并确保offset位置对齐,将头尾剩余部分
	       重新加入_free
	* free尝试与线性地址相邻的前后page_range合并后再加入_free_huge或_free
	* initial_add尝试与线性地址相邻的前一个page_range合并后在加入_free_huge或_free,将
	             _deferred_free持有的page_range通过free释放掉

shrinker每个实例都会被reclaimer_thread._shrinkers记录
	持有string, int属性
	* requeset_memory是其唯一有效方法,在子类中有多种实现(bsd, arc, jvm)

reclaimer_waiters
	持有list属性
	* wake_waiters从大到小遍历free_page_ranges的page_range,尝试唤醒尽可能多的waiters
	* wait将当前线程加入waiters,唤醒reclaimer_thread,等待被wake_waiters唤醒

reclaimer
	持有reclaimer_waiters, condvar, thread, vector<shrinker*>, mutex, int属性
	* _thread执行_do_reclaim(无限循环)
		等待condvar唤醒,回收目标是达到NORMAL
		尝试非hard模式回收(从JVM ballon回收)
		尝试hard模式回收(失效则OOM,成功则可能会重新调整JVM ballon)
	* 内存的实际回收是通过shrinkers实现的
	* wake执行condvar的wake_one唤醒_thread
	* wait_for_memory执行reclaimer_waiter的wait

l1每个CPU独立的page一级缓冲区
	持有属性
	    (static)size_t * 3(max, watermark_lo, watermark_hi), size_t, thread, void*[]
	* _fill_thread在pages低于watermark_lo或高于watermark_hi时通过refill或unfill调整
		refill - 从global_l2取一个page_batch尝试加入_pages
		unfill - 从_pages取出多个pages构成page_batch释放到global_l2
	* alloc_page通过循环配合直接的refill确保alloc_page_local最终成功
		pages低于watermark_lo唤醒_fill_thread
		尝试取出一个page
	* free_page通过循环配合直接的unfill确保free_page_local最终成功
		pages高于watermark_hi唤醒_fill_thread
		尝试加入一个page

l2全局的page二级缓冲区
	持有属性
	    size_t * 3*(max, watermark_lo, watermark_hi), atomic<size_t>, stack, thread
	* _fill_thread在batches低于watermark_lo或高于watermark_hi时通过refill或unfill调整
		refill - 从free_page_ranges分配多个pages形成page_batch尝试加入_stack
		unfill - 从_stack取出一个batch释放到free_page_ranges
	* alloc_page_batch通过循环配合直接的refill确保try_alloc_page_batch最终成功
		batchers低于watermark_lo唤醒_fill_thread
		尝试取出一个batch
	* free_page_batch通过循环配合直接的refill确保try_free_page_batch最终成功
		batchers高于watermark_hi唤醒_fill_thread
		尝试加入一个batch

malloc_large通过free_page_ranges分配有offset的page_range
	offset范围: [sizeof(page_range), <= page_size]
free_large通过free_page_ranges释放page_range
	page_range地址: (obj - 1)以page_size向下对齐

alloc_page通过l1或free_page_ranges分配一个page
free_page通过l1或free_page_ranges释放一个page

alloc_huge_page通过free_page_ranges分配无offset的page_range
free_huge_page通过free_page_ranges释放手动设置大小的page_range


malloc使用std_malloc或dbg::malloc
	std_malloc  - 从malloc_pools或l1或free_page_ranges分配,
	              并对于小于等于page_size的对象保持偏移移动线性地址区域
	dbg::malloc - 从debug_base单调递增分配线性地址,通过vpopulate分配并写入调试字符串

calloc通过malloc分配后,使用memeset置0

free通过header或dbg:free释放
	header    - 寻找page_header或page_range释放到malloc_pools或l1或free_page_ranges
	dbg::free - 通过vdepopulate和vcleanup释放

realloc通过malloc分配后,使用memcpy进行内存拷贝,再使用free释放原内存

alloc_phys_contiguous_aligned直接使用malloc_large
free_phys_contiguous_aligned直接使用free_large

phys_contiguous_memory通过mmu::virt_to_phys在初始化时获得物理地址
	持有void*, phys, size_t属性

make_phys_ptr通过alloc_phys_contiguous_aligned分配内存,
             并初始化会在引用失效时使用free_phys_contiguous_aligned的对象
make_phys_array基本同上,初始化的是数组

memory::virt_to_phys返回线性地址相对于phys_mem的偏移


# mmu

使用了定义于mmu-def.hh全局域page_size = 4096, page_size_shift = 12, pte_per_page = 512, 
pte_per_page_shift = 9, huge_page_size = page_size * pte_per_page, identity_mapped_areas, 
mem_area_size = 1 << 44, main_mem_area_base = 0x ffff 8000 0000 0000, 
phys_mem = main_mem_area_base, debug_mem_area_base = 0x ffff b000 0000 0000, 
debug_base = debug_mem_area_base

使用了定义于x64/arch-mmu.hh全局域rsvd_bits_used = 1, max_phys_bits = 51, mattr_default

使用了定义于arch/x64/mmu.cc文件域phys_bits = max_phys_bits, virt_bits =52, page_table_root

使用了定义于loader.cc全局域elf_start, elf_size

使用了定义于arch/x64/load.ld(?)全局域text_start, text_end

使用了定于于mmu.cc全局域vma_list, vma_list_mutex, page_table_mutex, nr_page_sizes, 
page_allocator_noinit, page_allocator_init, page_allocator_noinitp, page_allocator_initp

pt_element
	持有u64属性
	* 第50-0位表示物理地址
		第7-0位有些是标志位
		第12位表示large(非标志位)
	* 第63位表示!executable
	* addr取第50-0位,设置large标志时第12位置0
	* pfn取第50-12位
	* next_pt_addr/next_pt_pfn等同于未设置large标志时的addr/pfn

make_empty_pte新建一个空白pt_element(内部值为0)

make_pte新建一个pt_element,设置相应的标志位

hw_ptep
	持有atomic<pt_element>*/pt_element*属性
	* read
		level = 0,1   - 读atmoic<pt_element>*内容
		level = K     - 读pt_element*内容
	* write 写atomic<pt_element>*内容
	* exchange/compare_exchange操作atomic<pt_elemnt>*
	* at以pt_element*加上偏移新建hw_ptep(用于array?)
	* release返回pt_element*(用于之后不再使用时)
	* (static)以指定pt_element*新建hw_ptep*(外部新建实例的入口)

addr_range
	持有属性
	    unintptr_t * 2(_start, _end), unsigned * 2(_perm, _flags), bool, 
	    page_allocator*, set_member_hook<>

page_table_operation仅仅是一个接口
	* page访问page或huge_page时调用
	* intermediate_page_pre访问二级页表之前调用
	* intermediate_page_post访问二级页表之后调用
	* sub_page访问huge_page的子集时调用

map_level
	持有uninptr_t * 3(vma_start, vcur, vend), size_t, PageOp&, int属性
	* map_level降低一级ParentLevel访问某个范围
	* operator()使用PageOp访问parent开始的一个区域(很复杂?意思应该是递归遍历)

linear_page_mapper(PageOp)
	持有phys * 2(start, end), mattr属性
	* page使用物理地址(start + offset)新建pt_element替换ptep内容

vma_operation(PageOp)非线性映射的父类,未实现PageOp任何方法
	持有ulong属性
	* tlb_flush_needed返回TLB是否需要刷新
	* finalize最后的回调,用于清理工作
	* account在允许增加计数时,增加ulong计数

populate(VMA PageOp)代理page_allocator执行map
	持有page_allocator*, unsigned, bool * 2(_write, _map_dirty)属性
	* page未设置_write或pte已设置可写位时跳过,否则新建空白pt_element根据
	      _write和_map_dirty设置dirty位,使用page_allocator.map并增加计数

populate_small(VMA PageOp)限制了nr_page_sizes为1且N = 1的populate

splithugepages检查是否满足N != 1(N = 0)
	* page检查是否满足N != 1(N = 0)

tlb_gather即将被释放的线性空间的pages缓冲区
	持有size_t, tlb_page[]属性
	* push在pages已满时触发flush,将(addr, size)加入pages,返回是否已触发flush
	* flush执行flush_tlb_all,释放pages中所有page/huge_page表示的线性空间,
	  返回是否真正释放了page/huge_page(即pages非空)

unpopulate(VMA PageOp)代理page_allocator执行unmap
	持有tlb_gather, page_allocator*, bool属性
	* page将ptep内物理地址转线性地址,使用page_allocator.unmap且在成功时push
	      到tlb_gather,并增加计数,若未触发tlb_gather.flush则标记do_flush
	* intermediate_page_post等待RCU同步以释放ptep映射的线性空间page,
	                        然后将ptep置为空白
	* tlb_flush_needed触发tlb_gather.flush,在触发失败且do_flush被标记时返回true

protection(VMA PageOp)改变标志位
	持有unsigned, bool属性
	* page改变ptep的标志位,发生实际改变时标记do_flush
	* tlb_flush_needed直接返回do_flush

dirty_page_sync
	持有file*, f_offset, uint64_t, stack<elm>属性
	* operator()将(virt, len, off)信息加入stack
	* finalize通过file::write清理stack每一项

dirty_cleaner(VMA PageOp)文件内容同步
	持有bool, T属性 - T一般是dirty_page_sync
	* page清除pte的dirty位,标记do_flush,并通过handler()执行真正的清理工作
	* tlb_flush_needed直接返回do_flush
	* finalize执行handler.finalize

virt_to_phys_map(PageOp)计算物理地址?
	持有uintptr_t, phys, (static)phys属性
	* page/sub_page组合ptep的物理地址和v的低位以设置result
	* addr直接返回result

cleanup_intermediate_pages(PageOp)清理全空的二级pt_element
	持有unsigned, bool属性
	* page在N != 1时增加live_ptes计数
	* intermediate_pre重置live_ptes为0
	* intermediate_post在live_ptes为0时,确保每个item为空,将ptep内容置为空白,
	                   并等待RCU同步以释放原来用于存放items的线性地址page
	* tlb_flush_needed直接返回do_flush

virt_to_pte_map_rcu(PageOp)仅仅是一个代理
	持有virt_pte_visitor属性
	* page|sub_page通过virt_pte_visitor.pte处理ptep

operate_range通过map_range使用PageOp逐级处理pte,处理PageOp的TLB刷新标志,
             执行PageOp的finalize清理工作,返回PageOp的计数

map_range从最高level(4)开始使用PageOp处理pte,并递归处理下级

virt_to_phys_pt直接使用map_range配合virt_to_phys_map计算物理地址

virt_visit_pte_rcu直接使用map_range配合virt_pte_visitor浏览pte

protect设置对应VMA的权限,并通过map_range配合protection改变已映射pte权限

evacuate通过map_range配合unpopulate执行page_allocator::unmap,并移除对应VMA,
        必要时更新JVM heap内存计数

unmap进行size对齐的evacuate

sync对应的每个VMA执行自己的sync

page_allocator仅仅是一个接口,处理page/huge_page映射与解除(N = 0|1)
	* map映射page/huge_page
	* unmap解除映射page/huge_page

uninitialized_anonymous_page_provider(PageAlloc)
	* map分配线性空间page/huge_page,以此设置新pte替换空白ptep内容
	* unmap将ptep置为空白

initialized_anonymous_provider(Uninitialized PageAlloc)
	* map分配线性空间后并通过memset置0

map_file_page_read(Uninitialized PageAlloc)不使用pagecache
	持有file*, f_offset属性
	* map分配线性空间并通过file::read和memset填充

map_file_page_mmap(PageAlloc)表示一个使用pagecache的文件映射
	持有file*, off_t, bool属性
	* map使用pagecache::map_page
	* unmap使用pagecache::put_page

allocate寻找合适的VMA区域或通过evacuate强制释放以分配VMA加入vma_list

vpopulate通过operate_range配合populate和initialized_anonymous_page_provider
         映射内存区域

vdepopulate通过operate_range配合unpopulate和initialized_anonymous_page_provider
           解除内存区域映射


vcleanup通过operate_range配合cleanup_intermediate_pages清理空白的二级pte

depopulate对应的每个VMA使用自己的page_allocator构建unpopulate以执行自己的operate_range

nohugepage对应的每个VMA使用splithugepages执行自己的operate_range

advise执行depopulate或nohugepage(应当作用于已映射区域)

populate_vma指定的VMA使用自己的page_allocator构建populate以执行自己的operate_range

map_anon使用page_allocator_noinitp/page_allocator_initp构建anon_vma,
        通过allocate分配VMA,再通过populate_vma映射内存

map_file使用map_file_page_read/map_file_page_mmap构建file_vma,通过allocate分配VMA,
        再通过populate_vma映射内存

vm_fault分析错误原因,产生SIGSEGV信号,或由VMA执行自己的fault处理

vma
	持有属性
	    addr_range, unsigned * 2(_perm, _flags), bool, page_allocator*, 
	    set_member_hook<>
	* fault使用populate_vma映射,若对应JVM heap则更新计数
               (在VMA状态正常,但映射尚未建立时被vm_fault调用)

anon_vma(VMA)
	* split分离出一个新的anon_vma加入vma_list并调整当前_range._end

file_vma(VMA)
	持有fileref, f_offset属性
	* fault先检查是否发生文件访问越界,越界则产生SIGBUS信号,然后使用populate_vma映射
	* split分离出一个新的file_vma(类似map_file)加入vma_list并调整当前_range._end
	* sync对于不使用pagecache的文件,通过operate_range配合dirty_cleaner直接写文件
	      对于使用pagecache的文件,直接使用file::sync

jvm_ballon_vma(VMA)
	持有属性
	    ballon_ptr, unsigned char*, unsigned char*, uintptr_t, anon_vma, size_t, 
	    unsigned * 2(_real_perm, _real_flags), uintptr_t real_size
	* split[不允许]
	* fault
	* add_partial
	* ~jvm_ballon_vma

map_jvm

shm_file代表内存文件
	持有size_t, unordered_map属性
	* shm_file使用map_file_mmap新建一个file_vma
	* page从_pages中寻找或分配一个线性空间huge_page
	* map_page使用_pages对应huge_page的物理地址设置pte替换ptep内容
	* put_page直接返回false
	* close释放_pages中所有线性空间huge_pages

linear_map通过map_range配合linear_page_mapper直接映射(直接写pte)

free_initial_memory_range直接使用memory::free_initial_memory_range新增线性空间内存

mprotect对已映射内存使用protect

munmap对已映射内存使用sync和unmap

msync对已映射内存使用sync

mincore检查指定范围内每个page第一个字节是否可读

procfs_maps输出vma_list每一项的信息


# sched

使用了定义于arch/x64/loader.ld(?)全局域_percpu_start, _percpu_end

使用了定义于sched.hh全局域max_cpus = sizeof(unsigned long) * 8, tau, thyst, 
context_switch_penalty

使用了定义于sched.cc全局域percpu_base, cpus, 
s_current, current_cpu, preempt_counter, need_reschedule, tls, wakeup_ipi, cmax, 
cinitial, cpu::notifier::_mtx, cpu::notifier::_notifiers, cputime_shift, 
thread_map, tid_max, thread::_s_idgen, thread::_s_reaper, hysteresis_mul_exp_tau, 
hysteresis_div_exp_tau, penalty_exp_tau
和文件域inf, thread_map_mutex, total_app_time_exited, exit_notifiers, 
exit_notifiers_lock

cpu_set
	持有atomic<unsigned long>属性 - 每一位表示一个CPU
	* set设置某一位
	* clear清除某一位
	* fetch_clear清空_mask并返回旧值

cpu_set::iterator表示cpu_set中第_idx个CPU
	持有cpu_set&, unsigned属性

timer_base绑定一个client,但client可以关联多个timer_bases
	持有client&, state, time_point属性
	* set向绑定的client的_active_timers中加入,并尝试向当前CPU的timers中加入,触发rearm
	* cancel尝试从绑定的client的_active_timers和当前CPU的timers中移除
	* reset从当前CPU的timers中移除旧值或向绑定的client的_active_timers中加入新值,
	        尝试向当前CPU的timers中加入新值,触发rearm
	* expire从绑定的client的_active_timers中移除,并执行client的timer_fired
		client = cpu    - [Do nothing]
		client = thread - 执行wake唤醒此线程

timer_base::client
	持有bool, client_list_t(list<timer_base>)属性
	* timer_fired接口方法
	* suspend_timers执行当前CPU的timers的suspend,移除_active_timers
	* resume_timers执行当前CPU的timers的resume,尝试加入_active_timers,触发rearm

timer基本等同于timer_base

timer_list
	持有time_point, timer_set, (static)callback_dispatch属性
	* suspend从_list移除timer_bases
	* resume尝试向_list加入timer_bases,至少加入则触发rearm
	* rearm尝试为clock_event设置更早的触发时间

cpu(timer_base::client)
	持有属性
	    unsigned, struct arch_cpu, 
	    thread* * 3(bingup_thread, idle_thread, terminating_thread), 
	    runqueue_type, timer_list, timer_base, 
	    atomic<bool> * 3(idle_pool, lazy_flush_tlb, app_thread), cpu_set, 
	    incoming_wakeup_queue*, time_point, char*, runtime_t, int
	* idle_thread执行idle
	* handle_incoming_wakeups处理incoming_wakups内的线程,填充runqueue
	* idle执行一次schedule,启动thread_map中的线程,然后循环do_idle, schedule
		do_idle - 多次尝试handle_incoming_wakeups
	* send_wakeup_ipi向此CPU发送CPU间中断
	* load_balance从runqueue里选出_migrationt_lock_counter为0的线程迁移到
	              runqueue最小的CPU上
	* (static)schedule在当前CPU上重新调度

cpu::notifier每个notifier实例都会加入到cpu::notifier::_notifiers_
	持有function<void()>, (static)mutex, (static)list<notifier*>属性
	* fire执行_notifiers中每个notifier的回调_cpu_up


wait_object<timer>基本都是空方法
	持有timer&属性
	* poll返回timer::expired

thread_runtime表示线程的优先级,运行时间,时间归一化次数等信息
	持有runtime_t * 2(_priority, _Rtt), int属性
	* export_runtime将局部运行时间转换为全局运行时间
	* update_after_sleep调整睡眠结束线程的运行时间
		迁移而睡眠 - 全局运行时间转换为局部运行时间
		本地睡眠   - 处理落后的标准化(一次标准化或直接置0)
	* ran_for(假定)线程以当前优先级运行一定时间,更新其运行时间
	* hysteresis_run_start线程被调度前增加ran_for(-thyst)运行时间,避免立即被抢占
	* hysteresis_run_stop线程被调度后增加ran_for(-thyst)运行时间,恢复正常运行时间
	* add_context_switch_penalty增加线程切换惩罚的运行时间,避免频繁切换

thread::attr
	持有stack_info, cpu*, bool, array<char, 16>属性
	* stack_info
	  	持有void*, size_t属性

detached_state
	持有thread*, cpu*, bool, atomic<status>属性

thread(timer_base::client)
	持有属性
	    atomic<detach_state>, function<void()> * 2(_func, _cleanup), thread_state, 
	    thread_control_block*, thread_runtime, detached_state, attr, int, 
	    bool * 2(_pinned, _app), arch_thread, unsigned int, 
	    atomic<bool>, vector<char*>, application_runtime, atomic<thread*>, 
	    set_member_hook<>, lockless_queue_link<thread>, 
	    (static)float * 3(priority_idle, priority_default, priority_infinity), 
	    (static)unsigned long, (static)reaper, 
	    stat_counter * 3(stat_swtiches, stat_preemptions, stat_migrations), 
	    thread_runtime::duration, atomic<u64>
	*

thread::reaper
	持有mutex, list<thread*>, thread属性
	* _thread执行reap
		等待list非空
		遍历list中每个thread,逐一调用join和_cleanup
	* add_zombie将thread加入list,唤醒_thread

thread_handle
	持有thread::detached_state属性
	*

wait_guard

interruptible

noninterruptible
