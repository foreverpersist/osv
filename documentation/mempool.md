# Mempool

	Memory pool (allocate, reclaim)

## Files

> * [include/osv/contiguous_alloc.hh](inclue/osv/contiguous_alloc.hh) - function definitions
> * [include/osv/mempool.hh](include/osv/mempool.hh) - class definitions
> * [core/mempool.cc](core/mempool.cc) - class implementations

## Detail

## garbage_sink

	Represent a free object list of one cpu

	Each cpu owns N sinks pointed at all cpus

```
	void free(unsigned obj_cpu, free_object* obj)
```

	Push object, signal `obj_cpu` when threshod is met 

---

```
	free_object* pop()
```

	Pop object

---

## pool

	One pool manages objects with the same size by maintaining a list of free pages percpu

```
	Free List       Page Layout
	----------  ->   --------------
	| header | /     |   owner    |
	---------- \     --------------
	|        |  \    |   cpuid    |
	----------   \    --------------
	|  ...   |    \  |   nalloc   |     
	----------       --------------    
	                 | free_link  |
	                 -------------- 
	                 | local_free | ---
	                 -------------- <-|
	                 |            |
	                 |  obj(next) | ---
	                 |            |   |
	                 -------------- <--
	                 |            |
	                 |  obj(next) | ---
	                 |            |   |
	                 -------------- <--
	                 |            |
	                 |  obj(next) |
	                 |            |
	                 --------------

```
---

```
	void pool::collect_garbage()
```

	Free all sinks owned by current cpu, invoke `free_same_cpu`

---

```
	void* pool::alloc()
```

	Allocate a object, `add_page` if `_free` is empty

---

```
	void pool::add_page()
```

	Allocate a page by `untracked_alloc_page`, set up header, then add the header to tail

---

```
	void pool::free_same_cpu(free_object* obj, unsigned cpu_id)
```

	1) Only `obj` is allocated in current page & `_free` has full pages
	     - Remove the header, and free the page
	2) No free objs in current page
	  2.1) There are other allocated objs in current page
	         - Move the header to head
	  2.2) `obj` is the only `obj` in current page (big object)
	         - Move the header to tail
	     - Update `local_free` ot the header

---

```
	void pool::free_different_cpu(free_object* obj, unsigned obj_cpu, unsigned cur_cpu)
```

	Just invoke `sing->free(obj_cpu, obj)`

---

```
	void pool::free(void* object)
```

	Do 	`free_same_cpu` or `free_different_cpu`


## malloc_pool

```
	size_t malloc_pool::compute_object_size(unsigned pos)
```

	Return min(`max_object_size`, 1 << `pos`)


## reclaimer

	Just a upper interface for `reclaimer_waiters`

## page_range_allocator

	Partner algorithm

```
	  free lists
	--------------
	| [2^0, 2^1  |
	--------------    -----------------------
	| [2^1, 2^2) | -> | size |  size  | ... |
	--------------    -----------------------
	|    ...     |
	--------------
	| [2^N, max) |
	--------------
```

---

```
	page_range* page_range_allocator::alloc(size_t size)
```

	Search in `min (>= exact_order)` free order
	If `min = exact_order`, Loop it one by one


---

```
	page_range* page_range_allocator::alloc_aligned(size_t size, size_t offset,
                                                size_t alignment, bool fill)
```

	Foreach from `max_order`to minimum candidate order, Loop order one by one

```
	---------------------------------
	|        |   |       |          |
	---------------------------------
	             |<------size------>|
	             |<-off->|
	         |<--align-->|

```

---

```
	void page_range_allocator::free(page_range* pr)
```

	Free page range, and try to merge with adjacent pages (prev or next one)

---

```
	void page_range_allocator::initial_add(page_range* pr)
```

	Append extra page range, reset `_bitmap`


## reclaimer_waiters

```
	bool reclaimer_waiters::wake_waiters()
```

	Try to wake and remove waiters by looping free page ranges
	
---

```
	void reclaimer_waiters::wait(size_t bytes)
```

	Add waiters


## reclaimer

	Create a thread running `_do_reclaim`

---

```
	void reclaimer::_do_reclaim()
```

	Try to reclaim memory with `soft` mode or `hard` mode by `_shrinker_loop`
	    `soft` mode: reclaim memory from ballon
	    `hard` mode: reclaim memory from (z)fs cache?

## l1 l2

	L1-pool (Percpu page buffer pool)
	L2-pool (Global page buffer pool)

```
    -------                ------                --------------------
    | l1  | <=page batch=> |    |                |                  |
	-------                |    |                |                  |
	| l1  | <=page batch=> | l2 | <=page batch=> | free_page_ranges |
	-------                |    |                |                  |
	| ... |                |    |                |                  |
	-------                ------                --------------------
```

