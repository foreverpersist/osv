# MMU

	Memory Manage Unit

> * transfer: virtual addr -> physical addr
> * protect: read/write/execute permissions
> * cache control: (replacement algorithm)

```
	----------------------------------------------------------------------
	| Global(PGD) | Upper(PUD) | Middle(PMD) | Table(PTE) |    Offset    |
	----------------------------------------------------------------------
	                                                      |<-PAGE_SHIFT->|
	                                         |<--------PMD_SHIFT-------->|
	                           |<---------------PUD_SHIFT--------------->|
	              |<----------------------PGD_SHIFT--------------------->|

	|<-------------------PAGE_MASK----------------------->|<--PAGE_SIZE->|
	|<---------------PMD_MASK--------------->|<---------PMD_SIZE-------->|
	|<--------PUD_MASK-------->|<---------------PUD_SIZE---------------->|
	|<--PGD_MASK->|<----------------------PGD_SIZE---------------------->|


	                       Normal Translation

	   PGD          PUD          PMD          PTE         OFFSET
	    |            |            |            |            |  ---------
	    |            |            |            |            |  |       |
	    |            |            |            |            |  |       |
	    |            |            |            |  --------- |  |       |
	    |            |            |            |  | pte_t | |  |       |
	    |            |            |            |  --------- -> |       |
	    |            |            |  --------- |  |  ...  |    |       |
	    |            |            |  | pmd_t | |  ---------    |       |
	    |            |            |  --------- -> |       | -> ---------
	    |            |  --------- |  |  ...  |    ---------
	    |            |  | pud_t | |  ---------    |  ...  |
	    |            |  --------- -> |       | -> ---------
	    |  --------- |  |  ...  |    ---------
	    |  | pgd_t | |  ---------    |  ...  |
	    |  --------- -> |       | -> ---------
	    |  |  ...  |    ---------
	    |  ---------    |  ...  |
	    -> |       | -> ---------
	       ---------
	       |  ...  |
	CR3 -> ---------
	 |
	-----------------
	|mm_struct->pgd |
	-----------------


	                          TLB

	                   -----------------
	    -------------- |PGD|PUD|PMD|PTE|
	    |              -----------------
	    |  ---------------------------------------------
	    |  | TLB flags |      VPN      |      PPN      |
	    |  ---------------------------------------------
	    |  |    ...    |      ...      |      ...      |
	    |  ---------------------------------------------
	    -> |           |               |               |
	       ---------------------------------------------
	       |    ...    |      ...      |      ...      |
	CR3 -> ---------------------------------------------
	 |
	-----------------
	|mm_struct->pgd |
	-----------------
```

## Files

> * [include/osv/addr_range.hh](include/osv/addr_range.hh) - declaration & implementation of class addr_range
> * [include/osv/virt_to_phys.hh](include/osv/virt_to_phys.hh) - declaration of function `virt_to_phys`
> * [include/osv/mmu-defs.hh](include/osv/mmu-defs.hh) - declaration & implementation of class pt_*
> * [arch/x64/mmu.cc](arch/x64/mmu.cc) - arch related
> * [include/osv/mmu.hh](include/osv/mmu.hh) - class declaration
> * [core/mmu.cc](core/mmu.cc) - class implementation

## Detail

	OSv physical memory layout

```
	----------------- 0x 0000 0000 0000 0000
	|               |
	---kernel_base--- 0x 0000 0000 0200 0000
	|               |
	--lzkernel_base-- 0x 0000 0000 0180 0000
	|               |
	-----phy_mem----- 0x ffff 8000 0000 0000
	|   main area   |
	----------------- 0x ffff 9000 0000 0000
	|   page area   |
	----------------- 0x ffff a000 0000 0000
	|  mempool area |
	----------------- 0x ffff b000 0000 0000
	|   debug area  |
	----------------- ...
```

## basic

```
	phys pte_level_mask(unsigned level)
```
	Get pte mask

---

```
	void* phys_to_virt(phys pa)
```
	Translate physical address to virtual address:

| Type | phys |     virt      |
| :--- | :--: | :-----------: |
| ELF  |  pa  |      pa       |
| Other|  pa  | phys_mem + pa |

---

```
	phys virt_to_phys_pt(void *virt)
```

	Do `map_range`, then return mapped addr

---

```
	phys virt_to_phys(void *virt)
```
	Translate virtual address to physical address

| Type | virt |          phys         |
| :--- | :--: | :-------------------: |
| ELF  | virt |          virt         |
| Other| virt |    virt - phys_mem    |
| DEBUG| virt | virt_to_phys_pt(virt) |

---

```
	template<int N> void allocate_intermediate_level(hw_ptep<N> ptep, pt_element<N> org)
```

	Create a page table whose items' base addr is the same as org

---

```
	template<int N> void allocate_intermediate_level(hw_ptep<N> ptep)
```

	Create a page table whose items are empty pte

---

```
	template<> void split_large_page(hw_ptep<1> ptep)
```

	Split a large page pte to `pte_per_page` small page ptes

```
	-------    large page      -------                large page
	| pte | -> ----------      | pte | -> --------    ----------
	-------    |        |  =>  -------    | pte0 | -> | split0 |
	           |        |                 --------    ----------
	           |        |                 | ...  | -> |  ...   |
	           |        |                 --------    ----------
	           ----------                 | pteN | -> | splitN |
	                                     --------    ----------
``` 

## page_allocator

	map/unmap small pages or huge pages

## page_table_operation (page_mapper)

	page, intermediate_page_pre, intermediate_page_post, sub_page

## map_level

```
	template<int N>
    typename std::enable_if<N == level && N != 0>::type
    map_range(uintptr_t vcur, size_t size, PageOp& page_mapper, size_t slop, hw_ptep<N> ptep, uintptr_t base_virt)
```
	
	Just invoke operator `()`:

> * allocate intermediate pte if needed & possible
> * do `split_large_page` or `sub_page` for large pte
> * do `page` for level 0, travel children for high level if allowed


## linear_page_mapper

```
	bool page(hw_ptep<N> ptep, uintptr_t offset)
```

	Create leaf pte with `addr = start + offset`

## vma_operation

```
	bool tlb_flush_needed(void)
```

	Just return false

## polulate

```
	bool page(hw_ptep<N> ptep, uintptr_t offset)
```

	Create leaf pte tagged dirty, then map it

## populate_small

```
	bool page(hw_ptep<N> ptep, uintptr_t offset)
```

	Similar with `populate`

## splithugepages

```
	bool page(hw_ptep<N> ptep, uintptr_t offset)
```

	Just return true

## tlb_gather

	Max size is 20

---

```
	bool push(void *addr, size_t size)
```

	Store {addr, size}, do `flush` if tlb gather is full

---

```
	bool flush()
```

	Do `flush_tlb_all`, and free all pages (virt addr) in tlb gather


## unpopulate

```
	bool page(hw_ptep<N> ptep, uintptr_t offset)
```

	Unmap `addr`, and push it to tlb gather
	Set `do_flush` true if no tlb flush happened

	Write a empty intermediate pte in `intermediate_page_post`

---

```
	bool tlb_flush_needed(void)
```

	Do `_tlb_gather.flush()`
	Return true if gather is empty and `do_flush` is true

## protection

```
	bool page(hw_ptep<N> ptep, uintptr_t offset)
```

	Change permission, and set `do_flush` true


## dirty_cleaner

```
	bool page(hw_ptep<N> ptep, uintptr_t offset)
```

	Set pte's dirty flag false, invoke `()` of `handler`

## dirty_page_sync (handler)

```
	void operator()(phys addr, uintptr_t offset, size_t size)
```

	Keep {phys, len, off} in queue

---

```
	void finalize()
```

	Write data in queue to file system by `_file.write()`

## virt_to_phys_map

```
	bool page(hw_ptep<N> ptep, uintptr_t offset)
```

	Read phys in pte

## cleanup_intermediate_pages

```
	bool page(hw_ptep<N> ptep, uintptr_t offset)
```

	Accumulate `live_ptes`

	Free pages if `live_ptes` is 0 in `intermediate_page_post`

## virt_to_pte_map_rcu

```
	bool page(hw_ptep<N> ptep, uintptr_t offset)
```

	Do `_visitor.pte(pte)`

## addr_range

	Just a simple class consisting of two members: {_start, _end}

## pt_element_common

	Represents a PTE which points at a page frame (4K)

	Just use an u64 to record addr and bits

## basic II

```
	template<typename T> ulong operate_range(T mapper, void *vma_start, void *start, size_t size)
```

	Operate a virtual memory range with `mapper`
	Do `flush_tlb_all` if needed
	Do `mapper.finialize`

---

```
	void virt_visit_pte_rcu(uintptr_t virt, virt_pte_visitor& visitor)
```

	Just do map_range with mapper `visitor`

---

```
	static error protect(const void *addr, size_t size, unsigned int perm)
```

	Change permission by `operate_range`

---

```
	uintptr_t find_hole(uintptr_t start, uintptr_t size)
```

	Find hole between two vmas

---

```
	ulong evacuate(uintptr_t start, uintptr_t end)
```

	Unpopulate by `operate_range`, do `on_jvm_heap_free` if needed

---

```
	static void unmap(const void* addr, size_t size)
```

	Just invoke `evacuate`

---

```
	static error sync(const void* addr, size_t length, int flags)
```

	Do `vma->sync`

## uninitialized_anonymous_page_provider

```
	virtual bool map(uintptr_t offset, hw_ptep<0> ptep, pt_element<0> pte, bool write) override
```

	Write pte, free (huge) page if failed

---

```
	virtual bool unmap(void *addr, uintptr_t offset, hw_ptep<0> ptep) override
```

	Clear pte

## initialized_anonymous_page_provider

```
	virtual void* fill(void* addr, uint64_t offset, uintptr_t size) override
```

	Fill memory with 0 by `memset`

## map_file_page_read

```
	virtual void* fill(void* addr, uint64_t offset, uintptr_t size) override
```

	Fill memory with file content by `_file->read()` and 0 with `memset`

## map_file_page_mmap

```
	virtual bool map(uintptr_t offset, hw_ptep<0> ptep,  pt_element<0> pte, bool write) override
```

	Do 	`_file->map_page()`

---

```
	virtual bool unmap(void *addr, uintptr_t offset, hw_ptep<0> ptep) override
```

	Do `_file->put_page()`

## basic III

```
	uintptr_t allocate(vma *v, uintptr_t start, size_t size, bool search)
```

	Search a VM range for `v`, do `evacuate` if `search` is false

---

```
	void vpopulate(void* addr, size_t size)
```

	Populate by `operate_range`

---

```
	void vdepopulate(void* addr, size_t size)
```

	Unpopulate by `operate_range`

---

```
	void vcleanup(void* addr, size_t size)
```

	Cleanup by `operate_range`

---

```
	static void depopulate(void* addr, size_t length)
```

	Unpopulate vmas one by one by `operate_range`

---

```
	static void nohugepage(void* addr, size_t length)
```

	Split huge pages on vmas one by one by `operate_range`

---

```
	error advise(void* addr, size_t size, int advice)
```
	Deal adivice:
		advice_dontneed   - `depopulate`
		advise_nohugepage - `nohugepage`

---

```
	template<account_opt Account = account_opt::no> ulong populate_vma(vma *vma, void *v, size_t size, bool write = false)
```
	
	Populate vma by `operate_range`

---

```
	void* map_anon(const void* addr, size_t size, unsigned flags, unsigned perm)
```

	Create anon_vma, do `allocate`, and do `populate_vma` if needed

---

```
	static void vm_sigsegv(uintptr_t addr, exception_frame* ef)
```

	Just invoke `osv::handle_mmap_fault(addr, SIGSEGV, ef);`

---

```
	static void vm_sigbus(uintptr_t addr, exception_frame* ef)
```

	Just invoke `osv::handle_mmap_fault(addr, SIGBUS, ef);`

---

```
	void vm_fault(uintptr_t addr, exception_frame* ef)
```

	Check page fault reason, do `vm_sigsegv()` or `vma->fault()`

---

```
	ulong map_jvm(unsigned char* jvm_addr, size_t size, size_t align, balloon_ptr b)
```

	Create jvm_ballon_vma, do `evacuate` (complicated ...)

---

```
	void linear_map(void* _virt, phys addr, size_t size,
                size_t slop, mattr mem_attr)
```

	Do linear map with `map_range`

---

```
	void free_initial_memory_range(uintptr_t addr, size_t size)
```

	Just invoke `memory::free_initial_memory_range`

---

```
	error mprotect(const void *addr, size_t len, unsigned perm)
```

	Just check and invoke `protect`

---

```
	error munmap(const void *addr, size_t length)
```

	Just check and invoke `unmap`

---

```
	error msync(const void* addr, size_t length, int flags)
```

	Just check and invoke `sync`

---

```
	error mincore(const void *addr, size_t length, unsigned char *vec)
```

	Just check `is_linear_mapped` and `safe_load`

---

```
	std::string procfs_maps()
```

	Travel `vma_list`, read permissions and positions

## vma

	Virtual memory area/range with flags (permission, dirty, ...)

---

```
	template<typename T> ulong vma::operate_range(T mapper, void *addr, size_t size)
```

	Just do `mmu::operate_range`

---

```
	void vma::fault(uintptr_t addr, exception_frame *ef)
```

	Deal page fault by `populate_vma` set size with huge page size if possible
	If in JVM mapping, notify JVM by `memory::stats::on_jvm_heap_alloc`


## anon_vma

	Represent anonymous VMA

---

```
	void anon_vma::split(uintptr_t edge)
```

	Create a new VMA: (`edge`, `end`), set origin `end` to `edge`

---

```
	error anon_vma::sync(uintptr_t start, uintptr_t end)
```

	Do nothing

## file_vma

	Represent file VMA

---

```
	void file_vma::fault(uintptr_t addr, exception_frame *ef)
```

	Deal page fault by `populate_vma` set size with huge page size if possible

---

```
	void file_vma::split(uintptr_t edge)
```

	Map file (`edge`, `end`), set origin `end` to `edge` (how to map file?)

---

```
	error file_vma::sync(uintptr_t start, uintptr_t end)
```

	Only sync `mmap_shared` file
	Sync a range of file to filesystem by `operate_range` or `sync` (Use cache first?)

---

```
	int file_vma::validate_perm(unsigned perm)
```

	Validate permission (RWX)
	Fail at 1) non-R file; 2) tag W on shared and non-W file; 3) tag E on non-E file system

---

```
	f_offset file_vma::offset(uintptr_t addr)
```


## jvm_balloon_vma

	Represent JVM ballon for JVM GC

	JVM ballon hold a JAVA object to adjust JVM heap available size

---

```
	bool jvm_balloon_vma::add_partial(size_t partial, unsigned char *eff)
```

	Trace patial copying of JVM GC by `_effective_jvm_addr` and `_partial_copy`
	It seems that the function can only be invoked once

---

```
	void jvm_balloon_vma::split(uintptr_t edge)
```

	Not allowed

---

```
	error jvm_balloon_vma::sync(uintptr_t start, uintptr_t end)
```

	Do nothing

---

```
	void jvm_balloon_vma::fault(uintptr_t fault_addr, exception_frame *ef)
```

	Do normal page fault when in particial copying, otherwise do page fault by itself in `jvm_balloon_fault`

---

```
	jvm_balloon_vma::~jvm_balloon_vma()
```

	Map old vma as anoymous mapping (`map_anon`), and map new ballon ('map_jvm') when in particial copying (why?)


## shm_file

	Shared memory file

---

```
	std::unique_ptr<file_vma> shm_file::mmap(addr_range range, unsigned flags, unsigned perm, off_t offset)
```

	Create a `file_vma`

---

```
	void* shm_file::page(uintptr_t hp_off)
```

	Find a huge page in `_page`, allocate a new one (`alloc_huge_page`) and set 0 if it not exist

---

```
	bool shm_file::map_page(uintptr_t offset, hw_ptep<0> ptep, pt_element<0> pte, bool write, bool shared)
```

	`write_pte`

---

```
	bool shm_file::put_page(void *addr, uintptr_t offset, hw_ptep<0> ptep) {return false;}
```

	Just return false

---

```
	int shm_file::stat(struct stat* buf)
```

	Get `_size`

---

```
	int shm_file::close()
```

	Free huge pages (`free_huge_page`)


## virt_pte_visitor

	Visit pte



## arch

```
	void page_fault(exception_frame *ef)
```

	Do `mmu::vm_fault`

---

```
	void flush_tlb_local()
```

	Write CR3 with old value in CR3 (CR3 didn't changed?)

---

```
	void flush_tlb_all()
```

	Notify all CPUs to flush tlb

---

```
	pt_element<4> *get_root_pt(uintptr_t virt __attribute__((unused)))
```

	Return page_table_root

---

```
	void switch_to_runtime_page_tables()
```

	Write CR3 with `page_table_root.next_pt_addr()`

---

```
	bool fast_sigsegv_check(uintptr_t addr, exception_frame* ef)
```

	Check permission (protect, cow)