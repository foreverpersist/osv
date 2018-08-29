# ELF

	ELF file

```
	        ELF
	------------------------
	| ELF Header           | - {ident, type, machine, entry, phoff, phentsize, phnum, shentsize, shnum, ...}
	------------------------
	| Program Header Table | - [Program Header{type, offset, vaddr, paddr, filesz, memsz, flag, align}, ...]
	------------------------
	| Segment 1            | - [Section, ...]
	------------------------
	| ...                  |
	------------------------
	| Segment N            |
	------------------------
	| Section Header Table | - [Section Header{name, type, flag, addr, offset, size, link, info, ...}, ...]
	------------------------
```


## Files

> * [include/osv/elf.hh](include/osv/elf.hh) - class declaration
> * [core/elf.cc](core/elf.cc) - class implementation

## Details

	Manage ELF (library) files - map, unmap, lookup

### object

	Represent an ELF file or memory image - a super class


### file

	Represent an ELF file

---

	public

---

```
	void file::load_elf_header()
```

	Read ELF header

---

```
	void file::load_program_headers()
```

	Read program headers

---

	protected

---

```
	void file::load_segment(const Elf64_Phdr& phdr)
```

	Map part of file with align

```
	void file::unload_segment(const Elf64_Phdr& phdr)
```

	Unmap part of file

---


### memory_image

	Represent an ELF memory image (used for core libraries, such as libc)


### program

	Singleton
	Represent a running program in dynamic linker's view, consist of many files

	Kernel will automatically supply some libraries

> *	libresolv.so.2
> *	libc.so.6
> * libm.so.6
> * ld-linux-x86-64.so.2 (x64)
> * libboost_system.so.1.55.0 (x64)
> * libboost_program_options.so.1.55.0 (x64)
> * libpthread.so.0
> * libdl.so.2
> * librt.so.1
> * libstdc++.so.6
> * libaio.so.1
> * libxenstore.so.3.0
> * libcrypt.so.1

---

	public

---

```
	std::shared_ptr<object> program::get_library(std::string name, std::vector<std::string> extra_path, bool delay_init)
```

	Load object, then do init job

---

	private

---

```
	std::shared_ptr<elf::object> program::load_object(std::string name, std::vector<std::string> extra_path,
        std::vector<std::shared_ptr<object>> &loaded_objects)
```

	Load object from kernel or file in search path