/*
 * Copyright (C) 2013 Cloudius Systems, Ltd.
 *
 * This work is open source software, licensed under the terms of the
 * BSD license as described in the LICENSE file in the top-level directory.
 */

#include <osv/elf.hh>
#include <osv/app.hh>
#include <osv/mmu.hh>
#include <boost/format.hpp>
#include <exception>
#include <memory>
#include <string.h>
#include <osv/align.hh>
#include <osv/debug.hh>
#include <stdlib.h>
#include <unistd.h>
#include <boost/algorithm/string.hpp>
#include <boost/range/algorithm/find.hpp>
#include <functional>
#include <iterator>
#include <osv/sched.hh>
#include <osv/trace.hh>
#include <osv/version.hh>
#include <osv/stubbing.hh>
#include <sys/utsname.h>
#include <osv/demangle.hh>

#include "arch.hh"

TRACEPOINT(trace_elf_load, "%s", const char *);
TRACEPOINT(trace_elf_unload, "%s", const char *);
TRACEPOINT(trace_elf_lookup, "%s", const char *);
TRACEPOINT(trace_elf_lookup_addr, "%p", const void *);

using namespace boost::range;

namespace {
    typedef boost::format fmt;
}

namespace elf {

const ulong program::core_module_index = 0;

namespace {

/* st_info使用一个char保存类型信息和绑定信息
   | binding |   type  |
   7         3         0
 */
unsigned symbol_type(Elf64_Sym& sym)
{
    return sym.st_info & 15;
}

unsigned symbol_binding(Elf64_Sym& sym)
{
    return sym.st_info >> 4;
}

}

symbol_module::symbol_module()
    : symbol()
    , obj()
{
}

symbol_module::symbol_module(Elf64_Sym* _sym, object* _obj)
    : symbol(_sym)
    , obj(_obj)
{
}

/* 依据实际符号类型,解析重定位地址
 */
void* symbol_module::relocated_addr() const
{
    void* base = obj->base();
    if (symbol->st_shndx == SHN_UNDEF || symbol->st_shndx == SHN_ABS) {
        base = 0;
    }
    switch (symbol_type(*symbol)) {
    case STT_NOTYPE:
        return reinterpret_cast<void*>(symbol->st_value);
        break;
    case STT_OBJECT:
    case STT_FUNC:
        return base + symbol->st_value;
        break;
    case STT_IFUNC:
        return reinterpret_cast<void *(*)()>(base + symbol->st_value)();
    default:
        abort("Unknown symbol type %d\n", symbol_type(*symbol));
    }
}

u64 symbol_module::size() const
{
    return symbol->st_size;
}

std::atomic<ptrdiff_t> object::_static_tls_alloc;

object::object(program& prog, std::string pathname)
    : _prog(prog)
    , _pathname(pathname)
    , _tls_segment()
    , _tls_init_size()
    , _tls_uninit_size()
    , _static_tls(false)
    , _static_tls_offset(0)
    , _initial_tls_size(0)
    , _dynamic_table(nullptr)
    , _module_index(_prog.register_dtv(this))
    , _is_executable(false)
    , _visibility(nullptr)
{
}

object::~object()
{
    _prog.free_dtv(this);
}

/* _module_index为当前object在关联的program中的注册索引
 */
ulong object::module_index() const
{
    return _module_index;
}

/* _visibility指向某个thread,或者null
       指向thread - 私有,仅对此thread可见
       指向null   - 共享
 */
bool object::visible(void) const
{
    auto v = _visibility.load(std::memory_order_acquire);
    return (v == nullptr) || (v == sched::thread::current());
}

void object::setprivate(bool priv)
{
     _visibility.store(priv ? sched::thread::current() : nullptr,
             std::memory_order_release);
}


/* 通过lookup_symbol寻找
 */
template <>
void* object::lookup(const char* symbol)
{
    symbol_module sm{lookup_symbol(symbol), this};
    if (!sm.symbol || sm.symbol->st_shndx == SHN_UNDEF) {
        return nullptr;
    }
    return sm.relocated_addr();
}

/* 根据ELF Header中Section Table信息,直接从文件中读取Section Table
   多次调用是否会出现缓存到内存拷贝,甚至磁盘到内存拷贝,影响性能?
 */
std::vector<Elf64_Shdr> object::sections()
{
    size_t bytes = size_t(_ehdr.e_shentsize) * _ehdr.e_shnum;
    std::unique_ptr<char[]> tmp(new char[bytes]);
    read(_ehdr.e_shoff, tmp.get(), bytes);
    auto p = tmp.get();
    std::vector<Elf64_Shdr> ret;
    for (unsigned i = 0; i < _ehdr.e_shnum; ++i, p += _ehdr.e_shentsize) {
        ret.push_back(*reinterpret_cast<Elf64_Shdr*>(p));
    }
    return ret;
}

/* 取出String Table Section,拷贝至_section_names_cache
   从_section_names_cache中读取节名称
 */
std::string object::section_name(const Elf64_Shdr& shdr)
{
    if (_ehdr.e_shstrndx == SHN_UNDEF) {
        return {};
    }
    if (!_section_names_cache) {
        auto s = sections().at(_ehdr.e_shstrndx);
        std::unique_ptr<char[]> p(new char[s.sh_size]);
        read(s.sh_offset, p.get(), s.sh_size);
        _section_names_cache = std::move(p);
    }
    return _section_names_cache.get() + shdr.sh_name;
}

/* 通过systab_len读取_dynamic_table信息
 */
std::vector<Elf64_Sym> object::symbols() {
    auto symtab = dynamic_ptr<Elf64_Sym>(DT_SYMTAB);
    auto len = symtab_len();
    return std::vector<Elf64_Sym>(symtab, symtab + len);
}

/* 从字符串表读取符号名称
 */
const char * object::symbol_name(const Elf64_Sym * sym) {
    auto strtab = dynamic_ptr<char>(DT_STRTAB);
    return strtab + sym->st_name;
}

/* 返回ELF Header中的e_entry
 */
void* object::entry_point() const {
    if (!_is_executable) {
        return nullptr;
    }
    return _base + _ehdr.e_entry;
}

/* 指定fileref作为ELF文件
 */
file::file(program& prog, ::fileref f, std::string pathname)
    : object(prog, pathname)
    , _f(f)
{
    load_elf_header();
    load_program_headers();
}

file::~file()
{
}

/* memory_image指定内存位置作为ELF的起点
   似乎只有内核会使用?
 */
memory_image::memory_image(program& prog, void* base)
    : object(prog, "")
{
    _ehdr = *static_cast<Elf64_Ehdr*>(base);
    auto p = static_cast<Elf64_Phdr*>(base + _ehdr.e_phoff);
    assert(_ehdr.e_phentsize == sizeof(*p));
    _phdrs.assign(p, p + _ehdr.e_phnum);
    set_base(base);
}

void memory_image::load_segment(const Elf64_Phdr& phdr)
{
}

void memory_image::unload_segment(const Elf64_Phdr& phdr)
{
}

void memory_image::read(Elf64_Off offset, void* data, size_t size)
{
    throw std::runtime_error("cannot load from Elf memory image");
}

/* 读取ELF Header
   对ELF Header有严格限制
       e_ident[EI_MAG0, EI_MAG3] = \x7fELF
       e_ident[EI_CLASS]         = ELFCLASS64      (仅64位)
       e_ident[EI_DATA]          = ELFDATA2LSB     (仅小端对齐)
       e_ident[EI_VERSION]       = EV_CURRENT
       e_ident[EI_OSABI]         = ELFOSABI_LINUX  (仅Linux架构)
       e_type                    = ET_DYN          (仅共享文件)

   为支持可执行文件,需要放宽
       e_type = ET_DYN | ET_EXEC
 */
void file::load_elf_header()
{
    try {
        read(0, &_ehdr, sizeof(_ehdr));
    } catch(error &e) {
        throw osv::invalid_elf_error(
                std::string("can't read elf header: ") + strerror(e.get()));
    }
    if (!(_ehdr.e_ident[EI_MAG0] == '\x7f'
          && _ehdr.e_ident[EI_MAG1] == 'E'
          && _ehdr.e_ident[EI_MAG2] == 'L'
          && _ehdr.e_ident[EI_MAG3] == 'F')) {
        throw osv::invalid_elf_error("bad elf header");
    }
    if (!(_ehdr.e_ident[EI_CLASS] == ELFCLASS64)) {
        throw osv::invalid_elf_error("bad elf class");
    }
    if (!(_ehdr.e_ident[EI_DATA] == ELFDATA2LSB)) {
        throw osv::invalid_elf_error("bad elf endianness");
    }
    if (!(_ehdr.e_ident[EI_VERSION] == EV_CURRENT)) {
        throw osv::invalid_elf_error("bad elf version");
    }
    if (!(_ehdr.e_ident[EI_OSABI] == ELFOSABI_LINUX
          || _ehdr.e_ident[EI_OSABI] == 0)) {
        throw osv::invalid_elf_error("bad os abi");
    }
    // We currently only support running ET_DYN objects (shared library or
    // position-independent executable). In the future we can add support for
    // ET_EXEC (ordinary, position-dependent executables) but it will require
    // loading them at their specified address and moving the kernel out of
    // their way.
    if (_ehdr.e_type != ET_DYN) {
        throw osv::invalid_elf_error(
                "bad executable type (only shared-object or PIE supported)");
    }
}

/* 检查文件大小后,直接通过文件接口read读取
 */
void file::read(Elf64_Off offset, void* data, size_t size)
{
    // read(fileref, ...) is void, and crashes with assertion failure if the
    // file is not long enough. So we need to check first.
    if (::size(_f) < offset + size) {
        throw osv::invalid_elf_error("executable too short");
    }
    ::read(_f, data, offset, size);
}

namespace {

void* align(void* addr, ulong align, ulong offset)
{
    return align_up(addr - offset, align) + offset;
}

}

/* 设置_base, _end
   考虑了Program Headers对齐
 */
void object::set_base(void* base)
{
    auto p = std::min_element(_phdrs.begin(), _phdrs.end(),
                              [](Elf64_Phdr a, Elf64_Phdr b)
                                  { return a.p_type == PT_LOAD
                                        && a.p_vaddr < b.p_vaddr; });
    _base = align(base, p->p_align, p->p_vaddr & (p->p_align - 1)) - p->p_vaddr;
    auto q = std::min_element(_phdrs.begin(), _phdrs.end(),
                              [](Elf64_Phdr a, Elf64_Phdr b)
                                  { return a.p_type == PT_LOAD
                                        && a.p_vaddr > b.p_vaddr; });
    _end = _base + q->p_vaddr + q->p_memsz;
}

void* object::base() const
{
    return _base;
}

void* object::end() const
{
    return _end;
}

/* 读取Program Header Table
 */
void file::load_program_headers()
{
    _phdrs.resize(_ehdr.e_phnum);
    for (unsigned i = 0; i < _ehdr.e_phnum; ++i) {
        read(_ehdr.e_phoff + i * _ehdr.e_phentsize,
            &_phdrs[i],
            _ehdr.e_phentsize);
    }
}

/* 将文件一部分映射到内存,必要时填充0进行补齐,也可能映射一些空的匿名页
 */
void file::load_segment(const Elf64_Phdr& phdr)
{
    ulong vstart = align_down(phdr.p_vaddr, mmu::page_size);
    ulong filesz_unaligned = phdr.p_vaddr + phdr.p_filesz - vstart;
    ulong filesz = align_up(filesz_unaligned, mmu::page_size);
    ulong memsz = align_up(phdr.p_vaddr + phdr.p_memsz, mmu::page_size) - vstart;

    unsigned perm = 0;
    if (phdr.p_flags & PF_X)
        perm |= mmu::perm_exec;
    if (phdr.p_flags & PF_W)
        perm |= mmu::perm_write;
    if (phdr.p_flags & PF_R)
        perm |= mmu::perm_read;

    auto flag = mmu::mmap_fixed | (mlocked() ? mmu::mmap_populate : 0);
    mmu::map_file(_base + vstart, filesz, flag, perm, _f, align_down(phdr.p_offset, mmu::page_size));
    if (phdr.p_filesz != phdr.p_memsz) {
        assert(perm & mmu::perm_write);
        memset(_base + vstart + filesz_unaligned, 0, filesz - filesz_unaligned);
        if (memsz != filesz) {
            mmu::map_anon(_base + vstart + filesz, memsz - filesz, flag, perm);
        }
    }
}

/* 只要存在.note.osv-mlock节就需要mlocked
 */
bool object::mlocked()
{
    for (auto&& s : sections()) {
        if (section_name(s) == ".note.osv-mlock") {
            return true;
        }
    }
    return false;
}

/* 读取Elf64_Note并解析name, descriptor域
   原始Elf64_Note
       namesz
       descsz
       type
       <str>: | name | descriptor |
              0    namesz    namesz+descsz
   解析后Elf64_Note
       n_owner  = name
       n_value  = descriptor
       n_type   = type
 */
Elf64_Note::Elf64_Note(void *_base, char *str)
{
    Elf64_Word *base = reinterpret_cast<Elf64_Word *>(_base);
    n_type = base[2];

    n_owner.reserve(base[0]);
    n_value.reserve(base[1]);

    // The note section strings will include the trailing 0. std::string
    // doesn't like that very much, and comparisons against a string that is
    // constructed from this string will fail. Therefore the - 1 at the end
    if (base[0] > 0) {
        n_owner.assign(str, base[0] -1);
    }
    str = align_up(str + base[0], 4);
    if (base[1] > 0) {
        n_value.assign(str, base[1] - 1);
    }
}

/* 加载Program Headers
       PT_LOAD    - 通过load_segment映射到内存
       PT_DYNAMIC - 设置_dynamic_table地址
       PT_INTERP  - 标记为可执行
       PT_NOTE    - 仅支持OSv定义的注释
       PT_TLS     - 设置_tls_segment, _tls_init_size, _tls_uninit_size
       <OTHERS>   - 忽略或报非法错误

    不支持使用TLS,编译时使用-pie的执行程序
    实质是initial-exec/local-exec TLS model相关的bug,(OpenMP库libgomp即是一个例子)
 */
void object::load_segments()
{
    for (unsigned i = 0; i < _ehdr.e_phnum; ++i) {
        auto &phdr = _phdrs[i];
        switch (phdr.p_type) {
        case PT_NULL:
            break;
        case PT_LOAD:
            load_segment(phdr);
            break;
        case PT_DYNAMIC:
            _dynamic_table = reinterpret_cast<Elf64_Dyn*>(_base + phdr.p_vaddr);
            break;
        case PT_INTERP:
            _is_executable = true;
            break;
        case PT_NOTE: {
            if (phdr.p_memsz < 16) {
                /* we have the PT_NOTE segment in the linker scripts,
                 * but if we have no note sections we will end up with
                 * a zero length segment. Handle this case by validating
                 * the phdr length.
                 */
                break;
            }
            void *start = _base + phdr.p_vaddr;
            char *str = align_up((char *)start + 3 * sizeof(Elf64_Word), 4);
            struct Elf64_Note header(start, str);

            if (header.n_type != NT_VERSION) {
                break;
            }

            if (header.n_owner != "OSv") {
                break;
            }

            // FIXME: In the future, we should probably prevent loading of libosv.so in this
            // situation.
            if (header.n_value != osv::version()) {
                printf("WARNING: libosv.so version mismatch. Kernel is %s, lib is %s\n",
                        osv::version().c_str(), header.n_value.c_str());
            }
            break;
        }
        case PT_PHDR:
        case PT_GNU_STACK:
        case PT_GNU_RELRO:
        case PT_GNU_EH_FRAME:
        case PT_PAX_FLAGS:
            break;
        case PT_TLS:
            _tls_segment = _base + phdr.p_vaddr;
            _tls_init_size = phdr.p_filesz;
            _tls_uninit_size = phdr.p_memsz - phdr.p_filesz;
            break;
        default:
            abort();
            throw osv::invalid_elf_error("bad p_type");
        }
    }
    // As explained in issue #352, we currently don't correctly support TLS
    // used in PIEs.
    if (_is_executable && _tls_segment) {
        std::cout << "WARNING: " << pathname() << " is a PIE using TLS. This "
                  << "is currently unsupported (see issue #352). Link with "
                  << "'-shared' instead of '-pie'.\n";
    }
}

/* 解除内存映射
 */
void file::unload_segment(const Elf64_Phdr& phdr)
{
    ulong vstart = align_down(phdr.p_vaddr, mmu::page_size);
    ulong filesz_unaligned = phdr.p_vaddr + phdr.p_filesz - vstart;
    ulong filesz = align_up(filesz_unaligned, mmu::page_size);
    ulong memsz = align_up(phdr.p_vaddr + phdr.p_memsz, mmu::page_size) - vstart;
    mmu::munmap(_base + vstart, filesz);
    mmu::munmap(_base + vstart + filesz, memsz - filesz);
}

/* 只处理PT_LOAD类型的Program Headers - 解除内存映射
 */
void object::unload_segments()
{
    for (unsigned i = 0; i < _ehdr.e_phnum; ++i) {
        auto &phdr = _phdrs[i];
        switch (phdr.p_type) {
        case PT_LOAD:
            unload_segment(phdr);
            break;
        default:
            break;
        }
     }
}

/* 将非PT_GUN_RELRO类型的Program Headers设置mprotect(perm_read)
   只有实际被映射的Program Headers有效 - 即被映射的类型为PT_LOAD的Program Headers
 */
void object::fix_permissions()
{
    for (auto&& phdr : _phdrs) {
        if (phdr.p_type != PT_GNU_RELRO)
            continue;

        ulong vstart = align_down(phdr.p_vaddr, mmu::page_size);
        ulong memsz = align_up(phdr.p_vaddr + phdr.p_memsz, mmu::page_size) - vstart;

        assert((phdr.p_flags & (PF_R | PF_W | PF_X)) == PF_R);
        mmu::mprotect(_base + vstart, memsz, mmu::perm_read);
    }
}

template <typename T>
T* object::dynamic_ptr(unsigned tag)
{
    return static_cast<T*>(_base + dynamic_tag(tag).d_un.d_ptr);
}

Elf64_Xword object::dynamic_val(unsigned tag)
{
    return dynamic_tag(tag).d_un.d_val;
}

const char* object::dynamic_str(unsigned tag)
{
    return dynamic_ptr<const char>(DT_STRTAB) + dynamic_val(tag);
}

bool object::dynamic_exists(unsigned tag)
{
    return _dynamic_tag(tag);
}

/* 在_dynamic_table中寻找
   _dynamic_tab可能有重复的tag,如string array
 */
Elf64_Dyn* object::_dynamic_tag(unsigned tag)
{
    if (!_dynamic_table) {
        return nullptr;
    }
    for (auto p = _dynamic_table; p->d_tag != DT_NULL; ++p) {
        if (p->d_tag == tag) {
            return p;
        }
    }
    return nullptr;
}

Elf64_Dyn& object::dynamic_tag(unsigned tag)
{
    auto r = _dynamic_tag(tag);
    if (!r) {
        throw osv::invalid_elf_error("missing tag");
    }
    return *r;
}

/* 在_dynamic_table寻找String Table
   然后在_dynamic_table寻找string array的各项索引,配合String Table形成字符串
 */
std::vector<const char *>
object::dynamic_str_array(unsigned tag)
{
    auto strtab = dynamic_ptr<const char>(DT_STRTAB);
    std::vector<const char *> r;
    for (auto p = _dynamic_table; p->d_tag != DT_NULL; ++p) {
        if (p->d_tag == tag) {
            r.push_back(strtab + p->d_un.d_val);
        }
    }
    return r;
}

/* 还原一个函数?
   何时需要还原?怎样(通过libc)还原?
 */
static std::string demangle(const char *name) {
    auto demangled = osv::demangle(name);
    std::string ret(name);
    if (demangled) {
        ret += " (";
        ret += demangled.get();
        ret += ")";
    }
    return ret;
}

/* 先从Symbol Table中寻找symbol,然后通过_prog.lookup寻找更有效更详细的symbol取代之
   仅有STB_WEAK绑定类型的symbol允许_prog找不到,其他都应当找到
 */
symbol_module object::symbol(unsigned idx)
{
    auto symtab = dynamic_ptr<Elf64_Sym>(DT_SYMTAB);
    assert(dynamic_val(DT_SYMENT) == sizeof(Elf64_Sym));
    auto sym = &symtab[idx];
    auto nameidx = sym->st_name;
    auto name = dynamic_ptr<const char>(DT_STRTAB) + nameidx;
    auto ret = _prog.lookup(name);
    auto binding = symbol_binding(*sym);
    if (!ret.symbol && binding == STB_WEAK) {
        return symbol_module(sym, this);
    }
    if (!ret.symbol) {
        abort("%s: failed looking up symbol %s\n",
                pathname().c_str(), demangle(name).c_str());
    }
    return ret;
}

/* 从绑定到相同的program的其他object中寻找
   应当必定找到
 */
// symbol_other(idx) is similar to symbol(idx), except that the symbol is not
// looked up in the object itself, just in the other objects.
symbol_module object::symbol_other(unsigned idx)
{
    auto symtab = dynamic_ptr<Elf64_Sym>(DT_SYMTAB);
    assert(dynamic_val(DT_SYMENT) == sizeof(Elf64_Sym));
    auto sym = &symtab[idx];
    auto nameidx = sym->st_name;
    auto name = dynamic_ptr<const char>(DT_STRTAB) + nameidx;
    symbol_module ret(nullptr,nullptr);
    _prog.with_modules([&](const elf::program::modules_list &ml) {
        for (auto module : ml.objects) {
            if (module == this)
                continue; // do not match this module
            if (auto sym = module->lookup_symbol(name)) {
                ret = symbol_module(sym, module);
                break;
            }
        }
    });
    if (!ret.symbol) {
        abort("%s: failed looking up symbol %s in other objects\n",
                pathname().c_str(), demangle(name).c_str());
    }
    return ret;
}

/* 从_dynamic_table取出DT_RELA表
   解析每一项(type, sym, addr, addend),通过arch_relocate_rela处理(改写addr所指内存的内容)
 */
void object::relocate_rela()
{
    auto rela = dynamic_ptr<Elf64_Rela>(DT_RELA);
    assert(dynamic_val(DT_RELAENT) == sizeof(Elf64_Rela));
    unsigned nb = dynamic_val(DT_RELASZ) / sizeof(Elf64_Rela);
    for (auto p = rela; p < rela + nb; ++p) {
        auto info = p->r_info;
        u32 sym = info >> 32;
        u32 type = info & 0xffffffff;
        void *addr = _base + p->r_offset;
        auto addend = p->r_addend;

        if (!arch_relocate_rela(type, sym, addr, addend)) {
            debug_early_u64("relocate_rela(): unknown relocation type ", type);
            abort();
        }
    }
}

extern "C" { void __elf_resolve_pltgot(void); }

/* 从_dynamic_table去除DT_JMPREL表
   解析每一项(sym, addr, addend),
       通过arch_relocate_jump_slot设置addr内容
       或使用original_plt设置addr内容
       或使用_base设置addr内容
   PLT, Original PLT, PLTGOT是什么?预连接是怎样的操作?
 */
void object::relocate_pltgot()
{
    auto pltgot = dynamic_ptr<void*>(DT_PLTGOT);
    void *original_plt = nullptr;
    if (pltgot[1]) {
        // The library was prelinked before being copied to OSV, so the
        // .GOT.PLT entries point not to the .PLT but to a prelinked address
        // of the actual function. We'll need to return the link to the .PLT.
        // The prelinker saved us in pltgot[1] the address of .plt + 0x16.
#ifdef AARCH64_PORT_STUB
        assert(0);
#endif /* AARCH64_PORT_STUB */
        original_plt = static_cast<void*>(_base + (u64)pltgot[1]);
    }
    bool bind_now = dynamic_exists(DT_BIND_NOW) || mlocked() ||
        (dynamic_exists(DT_FLAGS) && (dynamic_val(DT_FLAGS) & DF_BIND_NOW)) ||
        (dynamic_exists(DT_FLAGS_1) && (dynamic_val(DT_FLAGS_1) & DF_1_NOW));

    auto rel = dynamic_ptr<Elf64_Rela>(DT_JMPREL);
    auto nrel = dynamic_val(DT_PLTRELSZ) / sizeof(*rel);
    for (auto p = rel; p < rel + nrel; ++p) {
        auto info = p->r_info;
        u32 type = info & 0xffffffff;
        assert(type == ARCH_JUMP_SLOT);
        void *addr = _base + p->r_offset;
        if (bind_now) {
            // If on-load binding is requested (instead of the default lazy
            // binding), resolve all the PLT entries now.
            u32 sym = info >> 32;
            if (!arch_relocate_jump_slot(sym, addr, p->r_addend)) {
                debug_early("relocate_pltgot(): failed jump slot relocation\n");
                abort();
            }
        } else if (original_plt) {
            // Restore the link to the original plt.
            // We know the JUMP_SLOT entries are in plt order, and that
            // each plt entry is 16 bytes.
            *static_cast<void**>(addr) = original_plt + (p-rel)*16;
        } else {
            // The JUMP_SLOT entry already points back to the PLT, just
            // make sure it is relocated relative to the object base.
            *static_cast<u64*>(addr) += reinterpret_cast<u64>(_base);
        }
    }

    // PLTGOT resolution has a special calling convention,
    // for x64 the symbol index and some word is pushed on the stack,
    // for AArch64 &pltgot[n] and LR are pushed on the stack,
    // so we need an assembly stub to convert it back to the
    // standard calling convention.
    pltgot[1] = this;
    pltgot[2] = reinterpret_cast<void*>(__elf_resolve_pltgot);
}

/* 从DT_JMPREL表读取重定位信息,寻找对应symbol
   symbol属于其他object则将object加入_used_by_resolve_plt_got(记录依赖?)
   通过arch_relocate_jump_slot设置addr内容
 */
void* object::resolve_pltgot(unsigned index)
{
    assert(sched::preemptable());
    auto rel = dynamic_ptr<Elf64_Rela>(DT_JMPREL);
    auto slot = rel[index];
    auto info = slot.r_info;
    u32 sym = info >> 32;
    u32 type = info & 0xffffffff;
    assert(type == ARCH_JUMP_SLOT);
    void *addr = _base + slot.r_offset;
    auto sm = symbol(sym);

    if (sm.obj != this) {
        WITH_LOCK(_used_by_resolve_plt_got_mutex) {
            _used_by_resolve_plt_got.insert(sm.obj->shared_from_this());
        }
    }

    if (!arch_relocate_jump_slot(sym, addr, slot.r_addend)) {
        debug_early("resolve_pltgot(): failed jump slot relocation\n");
        abort();
    }

    return *static_cast<void**>(addr);
}

/* 对DT_RELA和DT_JMPREL表逐项重定位
 */
void object::relocate()
{
    assert(!dynamic_exists(DT_REL));
    if (dynamic_exists(DT_RELA)) {
        relocate_rela();
    }
    if (dynamic_exists(DT_JMPREL)) {
        relocate_pltgot();
    }
}

/* 字符串的hash算法
 */
unsigned long
elf64_hash(const char *name)
{
    unsigned long h = 0, g;
    while (*name) {
        h = (h << 4) + (unsigned char)(*name++);
        if ((g = h & 0xf0000000)) {
            h ^= g >> 24;
        }
        h  &=  0x0fffffff;
    }
    return h;
}

/* 通过Hash Symbol Table快速查找Symbol Table中对应名称的symbol
       Hash Symbol Table?
           | count |  - info
           ---------
           | ....  |  - data
           ---------
           | ...   |  - rehash link
 */
Elf64_Sym* object::lookup_symbol_old(const char* name)
{
    auto symtab = dynamic_ptr<Elf64_Sym>(DT_SYMTAB);
    auto strtab = dynamic_ptr<char>(DT_STRTAB);
    auto hashtab = dynamic_ptr<Elf64_Word>(DT_HASH);
    auto nbucket = hashtab[0];
    auto buckets = hashtab + 2;
    auto chain = buckets + nbucket;
    for (auto ent = buckets[elf64_hash(name) % nbucket];
            ent != STN_UNDEF;
            ent = chain[ent]) {
        auto &sym = symtab[ent];
        if (strcmp(name, &strtab[sym.st_name]) == 0) {
            return &sym;
        }
    }
    return nullptr;
}

/* 另一种字符串的hash算法
 */
uint_fast32_t
dl_new_hash(const char *s)
{
    uint_fast32_t h = 5381;
    for (unsigned char c = *s; c != '\0'; c = *++s) {
        h = h * 33 + c;
    }
    return h & 0xffffffff;
}

/* 通过GNU Hash Symbol Table快速查找Symbol Table中对应的symbol
       GNU Hash Symbol Table?
           | count  |  - (just reference)
           | symndx |  - info
           | mask   |
           | shift  |
           ----------
           |  ...   |  - data
           ----------
           |        |  - (overlap?)
           ----------
           |  ...   |  - rehash link
 */
Elf64_Sym* object::lookup_symbol_gnu(const char* name)
{
    auto symtab = dynamic_ptr<Elf64_Sym>(DT_SYMTAB);
    auto strtab = dynamic_ptr<char>(DT_STRTAB);
    auto hashtab = dynamic_ptr<Elf64_Word>(DT_GNU_HASH);
    auto nbucket = hashtab[0];
    auto symndx = hashtab[1];
    auto maskwords = hashtab[2];
    auto shift2 = hashtab[3];
    auto bloom = reinterpret_cast<const Elf64_Xword*>(hashtab + 4);
    auto C = sizeof(*bloom) * 8;
    auto hashval = dl_new_hash(name);
    auto bword = bloom[(hashval / C) % maskwords];
    auto hashbit1 = hashval % C;
    auto hashbit2 = (hashval >> shift2) % C;
    if ((bword >> hashbit1) == 0 || (bword >> hashbit2) == 0) {
        return nullptr;
    }
    auto buckets = reinterpret_cast<const Elf64_Word*>(bloom + maskwords);
    auto chains = buckets + nbucket - symndx;
    auto idx = buckets[hashval % nbucket];
    if (idx == 0) {
        return nullptr;
    }
    do {
        if ((chains[idx] & ~1) != (hashval & ~1)) {
            continue;
        }
        if (strcmp(&strtab[symtab[idx].st_name], name) == 0) {
            return &symtab[idx];
        }
    } while ((chains[idx++] & 1) == 0);
    return nullptr;
}

/* 根据是否含有DT_GUN_HASH表选择lookup_symbol_gun或lookup_symbol_old查找
   二者hash表组织的方式略有差异,使用的hash算法不同
 */
Elf64_Sym* object::lookup_symbol(const char* name)
{
    if (!visible()) {
        return nullptr;
    }
    Elf64_Sym* sym;
    if (dynamic_exists(DT_GNU_HASH)) {
        sym = lookup_symbol_gnu(name);
    } else {
        sym = lookup_symbol_old(name);
    }
    if (sym && sym->st_shndx == SHN_UNDEF) {
        sym = nullptr;
    }
    return sym;
}

/* 返回Hash Table或GUN Hash Table有效项数目
 */
unsigned object::symtab_len()
{
    if (dynamic_exists(DT_HASH)) {
        auto hashtab = dynamic_ptr<Elf64_Word>(DT_HASH);
        return hashtab[1];
    }
    auto hashtab = dynamic_ptr<Elf64_Word>(DT_GNU_HASH);
    auto nbucket = hashtab[0];
    auto symndx = hashtab[1];
    auto maskwords = hashtab[2];
    auto bloom = reinterpret_cast<const Elf64_Xword*>(hashtab + 4);
    auto buckets = reinterpret_cast<const Elf64_Word*>(bloom + maskwords);
    auto chains = buckets + nbucket - symndx;
    unsigned len = 0;
    for (unsigned b = 0; b < nbucket; ++b) {
        auto idx = buckets[b];
        if (idx == 0) {
            continue;
        }
        do {
            ++len;
        } while ((chains[idx++] & 1) == 0);
    }
    return len;
}

/* 寻找指定地址处的符号(OBJECT|FUNC),地址位于符号起止区间内
 */
dladdr_info object::lookup_addr(const void* addr)
{
    dladdr_info ret;
    if (addr < _base || addr >= _end) {
        return ret;
    }
    ret.fname = _pathname.c_str();
    ret.base = _base;
    auto strtab = dynamic_ptr<char>(DT_STRTAB);
    auto symtab = dynamic_ptr<Elf64_Sym>(DT_SYMTAB);
    auto len = symtab_len();
    symbol_module best;
    for (unsigned i = 1; i < len; ++i) {
        auto& sym = symtab[i];
        auto type = sym.st_info & 15;
        if (type != STT_OBJECT && type != STT_FUNC) {
            continue;
        }
        auto bind = symbol_binding(sym);
        if (bind != STB_GLOBAL && bind != STB_WEAK) {
            continue;
        }
        symbol_module sm{&sym, this};
        auto s_addr = sm.relocated_addr();
        if (s_addr > addr) {
            continue;
        }
        if (!best.symbol || sm.relocated_addr() > best.relocated_addr()) {
            best = sm;
        }
    }
    if (!best.symbol || addr > best.relocated_addr() + best.size()) {
        return ret;
    }
    ret.sym = strtab + best.symbol->st_name;
    ret.addr = best.relocated_addr();
    return ret;
}

bool object::contains_addr(const void* addr)
{
    return addr >= _base && addr < _end;
}

static std::string dirname(std::string path)
{
    auto pos = path.rfind('/');
    if (pos == path.npos) {
        return "/";
    }
    return path.substr(0, pos);
}

/* 通过_prog.load_object从DT_RPATH指定路径中加载依赖,并将成功加载的依赖记入_needed
 */
void object::load_needed(std::vector<std::shared_ptr<object>>& loaded_objects)
{
    std::vector<std::string> rpath;
    if (dynamic_exists(DT_RPATH)) {
        std::string rpath_str = dynamic_str(DT_RPATH);
        boost::replace_all(rpath_str, "$ORIGIN", dirname(_pathname));
        boost::split(rpath, rpath_str, boost::is_any_of(":"));
    }
    auto needed = dynamic_str_array(DT_NEEDED);
    for (auto lib : needed) {
        auto obj = _prog.load_object(lib, rpath, loaded_objects);
        if (obj) {
            // Keep a reference to the needed object, so it won't be
            // unloaded until this object is unloaded.
            _needed.push_back(std::move(obj));
        } else {
            debug("could not load %s\n", lib);
        }
    }
}

/* 清空_needed, _used_by_resolve_plt_got
 */
void object::unload_needed()
{
    _needed.clear();
    _used_by_resolve_plt_got.clear();
}

ulong object::get_tls_size()
{
    return _tls_init_size + _tls_uninit_size;
}

/* 把当前对象加入ds,对不存在于ds中的_needed项递归处理
   即从上至下,递归地将所有依赖记入ds
 */
void object::collect_dependencies(std::unordered_set<elf::object*>& ds)
{
    ds.insert(this);
    for (auto&& d : _needed) {
        if (!ds.count(d.get())) {
            d->collect_dependencies(ds);
        }
    }
}

std::string object::soname()
{
    return dynamic_exists(DT_SONAME) ? dynamic_str(DT_SONAME) : std::string();
}

const std::vector<Elf64_Phdr> *object::phdrs()
{
    return &_phdrs;
}

std::string object::pathname()
{
    return _pathname;
}

/* 调用DT_INIT, DT_INIT_ARRAY描述的所有初始functions,原型为void (*)(int, char**)
 */
// Run the object's static constructors or similar initialization
void object::run_init_funcs(int argc, char** argv)
{
    // Invoke any init functions if present and pass in argc and argv
    // The reason why we pass argv and argc is explained in issue #795
    if (dynamic_exists(DT_INIT)) {
        auto func = dynamic_ptr<void>(DT_INIT);
        if (func) {
            reinterpret_cast<void(*)(int, char**)>(func)(argc, argv);
        }
    }
    if (dynamic_exists(DT_INIT_ARRAY)) {
        auto funcs = dynamic_ptr<void(*)(int, char**)>(DT_INIT_ARRAY);
        auto nr = dynamic_val(DT_INIT_ARRAYSZ) / sizeof(*funcs);
        for (auto i = 0u; i < nr; ++i) {
            funcs[i](argc, argv);
        }
    }
}

/* 调用DT_FINI_ARRAY, DT_FINI描述的所有终止functions,原型为void (*)()
 */
// Run the object's static destructors or similar finalization
void object::run_fini_funcs()
{
    if (dynamic_exists(DT_FINI_ARRAY)) {
        auto funcs = dynamic_ptr<void (*)()>(DT_FINI_ARRAY);
        auto nr = dynamic_val(DT_FINI_ARRAYSZ) / sizeof(*funcs);
        // According to the standard, call functions in reverse order.
        for (int i = nr - 1; i >= 0; --i) {
            funcs[i]();
        }
    }
    if (dynamic_exists(DT_FINI)) {
        auto func = dynamic_ptr<void>(DT_FINI);
        if (func) {
            reinterpret_cast<void(*)()>(func)();
        }
    }
}

/* 返回当前线程拥有的_tls[_module_index],必要时在当前线程空间新建_tls[_module_index]
   每个线程都有一份相同的_tls[]?
 */
void* object::tls_addr()
{
    auto t = sched::thread::current();
    auto r = t->get_tls(_module_index);
    if (!r) {
        r = t->setup_tls(_module_index, _tls_segment, _tls_init_size, _tls_uninit_size);
    }
    return r;
}

/* 直接分配(_static_tls_alloc, _static_tls_alloc + tls_size)
   更新_static_tls_alloc记录已分配的空间
   不对应真实内存地址,object及其依赖使用同一块内存
 */
void object::alloc_static_tls()
{
    auto tls_size = get_tls_size();
    if (!_static_tls && tls_size) {
        _static_tls = true;
        _static_tls_offset = _static_tls_alloc.fetch_add(tls_size, std::memory_order_relaxed);
    }
}

bool object::is_core()
{
    return _prog._core.get() == this;
}

/* 统计自身及所有依赖最大的static_tls_end,对齐后作为_initial_tls_size
   重置_initial_tls大小,让自身及所有依赖在_initial_t上prepare_initial_tls(写入_tls_segment及0)
 */
void object::init_static_tls()
{
    std::unordered_set<object*> deps;
    collect_dependencies(deps);
    bool static_tls = false;
    for (auto&& obj : deps) {
        if (obj->is_core()) {
            continue;
        }
        static_tls |= obj->_static_tls;
        _initial_tls_size = std::max(_initial_tls_size, obj->static_tls_end());
	// Align initial_tls_size to 64 bytes, to not break the 64-byte
	// alignment of the TLS segment defined in loader.ld.
	_initial_tls_size = align_up(_initial_tls_size, (size_t)64);
    }
    if (!static_tls) {
        _initial_tls_size = 0;
        return;
    }
    assert(_initial_tls_size);
    _initial_tls.reset(new char[_initial_tls_size]);
    for (auto&& obj : deps) {
        if (obj->is_core()) {
            continue;
        }
        obj->prepare_initial_tls(_initial_tls.get(), _initial_tls_size,
                                 _initial_tls_offsets);
    }
}

program* s_program;

void create_main_program()
{
    assert(!s_program);
    s_program = new elf::program();
}

/* 新建地址为ELF_IMAGE_START(OSV_KERNEL_BASE)的memory_image设置为_core - 表示内核本身?
   每个program都会持有自己独立的_core实例,但实际指向相同的内存区间
   _core内包含了一系列预定义的动态库
 */
program::program(void* addr)
    : _next_alloc(addr)
{
    _core = std::make_shared<memory_image>(*this, (void*)ELF_IMAGE_START);
    assert(_core->module_index() == core_module_index);
    _core->load_segments();
    set_search_path({"/", "/usr/lib"});
    /* 设置_files中预定义动态库对应的object都为_core
       向_modules_rcu加入一个仅包含_core的modules_list
     */
    // Our kernel already supplies the features of a bunch of traditional
    // shared libraries:
    static const auto supplied_modules = {
          "libresolv.so.2",
          "libc.so.6",
          "libm.so.6",
#ifdef __x86_64__
          "ld-linux-x86-64.so.2",
          "libboost_system.so.1.55.0",
          "libboost_program_options.so.1.55.0",
#endif /* __x86_64__ */
#ifdef __aarch64__
          "ld-linux-aarch64.so.1",
          "libboost_system-mt.so.1.55.0",
          "libboost_program_options-mt.so.1.55.0",
#endif /* __aarch64__ */
          "libpthread.so.0",
          "libdl.so.2",
          "librt.so.1",
          "libstdc++.so.6",
          "libaio.so.1",
          "libxenstore.so.3.0",
          "libcrypt.so.1",
    };
    auto ml = new modules_list();
    ml->objects.push_back(_core.get());
    for (auto name : supplied_modules) {
        _files[name] = _core;
    }
    _modules_rcu.assign(ml);
}

void program::set_search_path(std::initializer_list<std::string> path)
{
    _search_path = path;
}

static std::string getcwd()
{
    auto r = ::getcwd(NULL, 0);
    std::string rs = r;
    free(r);
    return rs;
}

static std::string canonicalize(std::string p)
{
    auto r = realpath(p.c_str(), NULL);
    if (r) {
        std::string rs = r;
        free(r);
        return rs;
    } else {
        return p;
    }
}

/* 确保加载指定库
      已加载 - <Do nothing>
      未加载 - 新建object记入_modules_rcu, _files,
              加载Program Headers,加载依赖(递归操作),重定位,处理mprotect
 */
// This is the part of program::get_library() which loads an object and all
// its dependencies, but doesn't yet run the objects' init functions. We can
// only do this after loading all the dependent objects, as we need to run the
// init functions of the deepest needed object first, yet it may use symbols
// from the shalower objects (as those are first in the search path).
// So while loading the objects, we just collect a list of them, and
// get_library() will run the init functions later.
std::shared_ptr<elf::object>
program::load_object(std::string name, std::vector<std::string> extra_path,
        std::vector<std::shared_ptr<object>> &loaded_objects)
{
    fileref f;
    /* _files存在有效的object,直接返回
     */
    if (_files.count(name)) {
        auto obj = _files[name].lock();
        if (obj) {
            return obj;
        }
    }
    /* 仅有文件名,在extra_path和_search_path下搜索
       含有目录,使用绝对路径查找
     */
    if (name.find('/') == name.npos) {
        std::vector<std::string> search_path;
        search_path.insert(search_path.end(), extra_path.begin(), extra_path.end());
        search_path.insert(search_path.end(), _search_path.begin(), _search_path.end());
        for (auto dir : search_path) {
            auto dname = canonicalize(dir + "/" + name);
            f = fileref_from_fname(dname);
            if (f) {
                name = dname;
                break;
            }
        }
    } else {
        if (name[0] != '/') {
            name = getcwd() + "/" + name;
        }
        name = canonicalize(name);
        f = fileref_from_fname(name);
    }

    /* 查找过程中,被其他线程成功加载,直接返回
     */
    if (_files.count(name)) {
        auto obj = _files[name].lock();
        if (obj) {
            return obj;
        }
    }
    if (f) {
        trace_elf_load(name.c_str());
        auto ef = std::shared_ptr<object>(new file(*this, f, name),
                [=](object *obj) { remove_object(obj); });
        ef->set_base(_next_alloc);
        ef->setprivate(true);
        /* 将ef加入到modules_rcu倒数第二位置(kernel之前), 也同时加入到loaded_objects以返回
           通过load_needed递归加载其依赖,并记入loaded_objects
           将ef记入_files
         */
        // We need to push the object at the end of the list (so that the main
        // shared object gets searched before the shared libraries it uses),
        // with one exception: the kernel needs to remain at the end of the
        // list - We want it to behave like a library, not the main program.
        auto old_modules = _modules_rcu.read_by_owner();
        std::unique_ptr<modules_list> new_modules (
                new modules_list(*old_modules));
        new_modules->objects.insert(
                std::prev(new_modules->objects.end()), ef.get());
        new_modules->adds++;
        _modules_rcu.assign(new_modules.release());
        osv::rcu_dispose(old_modules);
        ef->load_segments();
        _next_alloc = ef->end();
        add_debugger_obj(ef.get());
        loaded_objects.push_back(ef);
        ef->load_needed(loaded_objects);
        ef->relocate();
        ef->fix_permissions();
        _files[name] = ef;
        _files[ef->soname()] = ef;
        return ef;
    } else {
        return std::shared_ptr<object>();
    }
}

/* 通过load_object确保库加载,将新加载的库记入_loaded_objects_stack
   尝试初始化static TLS
   可能会执行初始functions
 */
std::shared_ptr<object>
program::get_library(std::string name, std::vector<std::string> extra_path, bool delay_init)
{
    SCOPE_LOCK(_mutex);
    //
    // Shared library needs to be initialized before any of its symbols (function or variable)
    // is accessed. The initialization involves invoking so called init functions and is handled by
    // the init_library() method below. The parameter delay_init determines whether init_library is
    // called right away or at some arbitrary time later.
    //
    // Because init_library() needs to access the library object itself and it's dependencies possibly
    // later we push the loaded objects list on a _loaded_objects_stack member variable of the program.
    //
    // Since a library can load another one like java.so does in OSv, we want a stack
    // structure so each init_library call gets it's corresponding list of objects to operate on.
    //
    std::vector<std::shared_ptr<object>> loaded_objects;
    auto ret = load_object(name, extra_path, loaded_objects);
    _loaded_objects_stack.push(loaded_objects);

    if (ret) {
        ret->init_static_tls();
    }

    if (!delay_init) {
        init_library();
    }

    return ret;
}

/* 取出_loaded_objects_stack最新的loaded_objects
   按相反顺序逐一执行object的初始functions,执行前后先取消private再重新设置private为当前线程
   最终的private是否可能与加载时关联的线程不同?
 */
void program::init_library(int argc, char** argv)
{
    // Get the list of pointers to shared objects from stack before iterating on them
    if(!_loaded_objects_stack.empty()) {
        std::vector<std::shared_ptr<object>> loaded_objects =
                _loaded_objects_stack.top();
        //
        // After loading the object and all its needed objects, run these objects'
        // init functions in reverse order (so those of deepest needed object runs
        // first) and finally make the loaded objects visible in search order.
        auto size = loaded_objects.size();
        for (unsigned i = 0; i < size; i++) {
            loaded_objects[i]->setprivate(true);
        }
        for (int i = size - 1; i >= 0; i--) {
            loaded_objects[i]->run_init_funcs(argc, argv);
        }
        for (unsigned i = 0; i < size; i++) {
            loaded_objects[i]->setprivate(false);
        }
        _loaded_objects_stack.pop();
    }
}

/* 执行中止functions,从_files, modules_rcu中移除,中间确保CPU RCU同步
   清空依赖
   加入到_modules_to_delete,通过module_delete_enable解除Program Headers内存映射
 */
void program::remove_object(object *ef)
{
    SCOPE_LOCK(_mutex);
    trace_elf_unload(ef->pathname().c_str());

    // ensure that any module rcu callbacks are completed before static destructors
    osv::rcu_flush();

    ef->run_fini_funcs();

    // ensure that any module rcu callbacks launched by static destructors
    // are completed before we delete the module
    osv::rcu_flush();

    del_debugger_obj(ef);
    // Note that if we race with get_library() of the same library, we may
    // find in _files a new copy of the same library, and mustn't remove it.
    if (_files[ef->pathname()].expired())
        _files.erase(ef->pathname());
    if (_files[ef->soname()].expired())
        _files.erase(ef->soname());
    auto old_modules = _modules_rcu.read_by_owner();
    std::unique_ptr<modules_list> new_modules (
            new modules_list(*old_modules));
    new_modules->objects.erase(std::find(
            new_modules->objects.begin(), new_modules->objects.end(), ef));
    new_modules->subs++;
    _modules_rcu.assign(new_modules.release());
    osv::rcu_dispose(old_modules);

    ef->unload_needed();

    // We want to unload and delete ef, but need to delay that until no
    // concurrent dl_iterate_phdr() is still using the modules it got from
    // modules_get().
    module_delete_disable();
    WITH_LOCK(_modules_delete_mutex) {
        _modules_to_delete.push_back(ef);
    }
    module_delete_enable();
}

std::vector<object*> program::s_objs;
mutex program::s_objs_mutex;

void program::add_debugger_obj(object* obj)
{
    SCOPE_LOCK(s_objs_mutex);
    s_objs.push_back(obj);
}

void program::del_debugger_obj(object* obj)
{
    SCOPE_LOCK(s_objs_mutex);
    auto it = std::find(s_objs.begin(), s_objs.end(), obj);
    if (it != s_objs.end()) {
        s_objs.erase(it);
    }
}

/* 从所有的库中寻找symbol
 */
symbol_module program::lookup(const char* name)
{
    trace_elf_lookup(name);
    symbol_module ret(nullptr,nullptr);
    with_modules([&](const elf::program::modules_list &ml)
    {
        for (auto module : ml.objects) {
            if (auto sym = module->lookup_symbol(name)) {
                ret = symbol_module(sym, module);
                return;
            }
        }
    });
    return ret;
}

/* 在所有库中寻找function
 */
void* program::do_lookup_function(const char* name)
{
    auto sym = lookup(name);
    if (!sym.symbol) {
        throw std::runtime_error("symbol not found " + demangle(name));
    }
    if ((sym.symbol->st_info & 15) != STT_FUNC) {
        throw std::runtime_error("symbol is not a function " + demangle(name));
    }
    return sym.relocated_addr();
}

/* 在所有库中寻找symbol(OBJECT|FUNC)
 */
dladdr_info program::lookup_addr(const void* addr)
{
    trace_elf_lookup_addr(addr);
    dladdr_info ret;
    with_modules([&](const elf::program::modules_list &ml)
    {
        for (auto module : ml.objects) {
            ret = module->lookup_addr(addr);
            if (ret.fname) {
                return;
            }
        }
        ret = {};
    });
    return ret;
}

/* 在所有库中寻找addr所属的object
 */
object *program::object_containing_addr(const void *addr)
{
    object *ret = nullptr;
    module_delete_disable();
    WITH_LOCK(osv::rcu_read_lock) {
         const auto &modules = _modules_rcu.read()->objects;
         for (object *module : modules) {
             if (module->contains_addr(addr)) {
                 ret = module;
                 break;
             }
         }
    }
    module_delete_enable();
    return ret;
}

/* 返回当前app的program或单例s_program
   app的progam可能是一个独立的program实例?
 */
program* get_program()
{
    auto app = sched::thread::current_app();

    if (app && app->program()) {
        return app->program();
    }

    return s_program;
}

/* 与object::lookup_symbol_old基本相同
 */
const Elf64_Sym *init_dyn_tabs::lookup(u32 sym)
{
    auto nbucket = this->hashtab[0];
    auto buckets = hashtab + 2;
    auto chain = buckets + nbucket;
    auto name = strtab + symtab[sym].st_name;

    for (auto ent = buckets[elf64_hash(name) % nbucket];
         ent != STN_UNDEF;
         ent = chain[ent]) {

        auto &sym = symtab[ent];
        if (strcmp(name, &strtab[sym.st_name]) == 0) {
            return &sym;
        }
    }

    return nullptr;
};

/* 读取ELF信息
       DYNAMIC - Init Array, Symbol Table, Hash Table, String Table, Rela
       TLS
 */
init_table get_init(Elf64_Ehdr* header)
{
    void* pbase = static_cast<void*>(header);
    void* base = pbase;
    auto phdr = static_cast<Elf64_Phdr*>(pbase + header->e_phoff);
    auto n = header->e_phnum;
    bool base_adjusted = false;
    init_table ret = { 0 };
    for (auto i = 0; i < n; ++i, ++phdr) {
        if (!base_adjusted && phdr->p_type == PT_LOAD) {
            base_adjusted = true;
            base -= phdr->p_vaddr;
        }
        if (phdr->p_type == PT_DYNAMIC) {
            auto dyn = reinterpret_cast<Elf64_Dyn*>(phdr->p_vaddr);
            unsigned ndyn = phdr->p_memsz / sizeof(*dyn);
            ret.dyn_tabs = {
                .symtab = nullptr, .hashtab = nullptr, .strtab = nullptr,
            };
            const Elf64_Rela* rela = nullptr;
            const Elf64_Rela* jmp = nullptr;
            unsigned nrela = 0;
            unsigned njmp = 0;

            for (auto d = dyn; d < dyn + ndyn; ++d) {
                switch (d->d_tag) {
                case DT_INIT_ARRAY:
                    ret.start = reinterpret_cast<void (**)()>(d->d_un.d_ptr);
                    break;
                case DT_INIT_ARRAYSZ:
                    ret.count = d->d_un.d_val / sizeof(ret.start);
                    break;
                case DT_RELA:
                    rela = reinterpret_cast<const Elf64_Rela*>(d->d_un.d_ptr);
                    break;
                case DT_RELASZ:
                    nrela = d->d_un.d_val / sizeof(*rela);
                    break;
                case DT_SYMTAB:
                    ret.dyn_tabs.symtab = reinterpret_cast<const Elf64_Sym*>(d->d_un.d_ptr);
                    break;
                case DT_HASH:
                    ret.dyn_tabs.hashtab = reinterpret_cast<const Elf64_Word*>(d->d_un.d_ptr);
                    break;
                case DT_STRTAB:
                    ret.dyn_tabs.strtab = reinterpret_cast<const char*>(d->d_un.d_ptr);
                    break;
                case DT_JMPREL:
                    jmp = reinterpret_cast<const Elf64_Rela*>(d->d_un.d_ptr);
                    break;
                case DT_PLTRELSZ:
                    njmp = d->d_un.d_val / sizeof(*jmp);
                    break;
                }
            }
            auto relocate_table = [=](struct init_table *t,
                                      const Elf64_Rela *rtab, unsigned n) {
                if (!rtab) {
                    return;
                }
                for (auto r = rtab; r < rtab + n; ++r) {
                    auto info = r->r_info;
                    u32 sym = info >> 32;
                    u32 type = info & 0xffffffff;
                    void *addr = base + r->r_offset;
                    auto addend = r->r_addend;

                    if (!arch_init_reloc_dyn(t, type, sym,
                                             addr, base, addend)) {
                        debug_early_u64("Unsupported relocation type=", type);
                        abort();
                    }
                }
            };
            relocate_table(&ret, rela, nrela);
            relocate_table(&ret, jmp, njmp);
        } else if (phdr->p_type == PT_TLS) {
            ret.tls.start = reinterpret_cast<void*>(phdr->p_vaddr);
            ret.tls.filesize = phdr->p_filesz;
            ret.tls.size = phdr->p_memsz;
        }
    }
    return ret;
}

/* 将obj加入_module_index_list_rcu第一个空白位置,返回位置
 */
ulong program::register_dtv(object* obj)
{
    SCOPE_LOCK(_module_index_list_mutex);
    auto list = _module_index_list_rcu.read_by_owner();
    if (!list) {
        _module_index_list_rcu.assign(new std::vector<object*>({obj}));
        return 0;
    }
    auto i = find(*list, nullptr);
    if (i != list->end()) {
        *i = obj;
        return i - list->begin();
    } else {
        auto newlist = new std::vector<object*>(*list);
        newlist->push_back(obj);
        _module_index_list_rcu.assign(newlist);
        osv::rcu_dispose(list);
        return newlist->size() - 1;
    }
}

/* 将_module_index_list_rcu对应位置置为nullptr
 */
void program::free_dtv(object* obj)
{
    SCOPE_LOCK(_module_index_list_mutex);
    auto list = _module_index_list_rcu.read_by_owner();
    auto i = find(*list, obj);
    assert(i != list->end());
    *i = nullptr;
}

/* 返回_modules_rcu的副本
 */
// Used in implementation of program::with_modules. We cannot keep the RCU
// read lock (which disables preemption) while a user function is running,
// so we use this function to make a copy the current list of modules.
program::modules_list program::modules_get() const
{
    modules_list ret;
    WITH_LOCK(osv::rcu_read_lock) {
        auto modules = _modules_rcu.read();
        auto needed = modules->objects.size();
        while (ret.objects.capacity() < needed) {
            // tmp isn't large enough to copy the list without allocations,
            // which are not allowed in rcu critical section.
            DROP_LOCK(osv::rcu_read_lock) {
                ret.objects.reserve(needed);
            }
            // After re-entering rcu critical section, need to reread
            modules = _modules_rcu.read();
            needed = modules->objects.size();
        }
        ret.objects.assign(modules->objects.begin(), modules->objects.end());
        ret.adds = modules->adds;
        ret.subs = modules->subs;
    }
    return ret;
}

// Prevent actual freeing of modules by remove_object() until the
// matching modules_delete_enable(). We need this so the user can iterate on
// the output of dl_iterate_phdr() without fearing that concurrently some
// of the modules are freed (they can be removed from the search path,
// but not actually freed).
void program::module_delete_disable()
{
    WITH_LOCK(_modules_delete_mutex) {
        _module_delete_disable++;
    }
}

void program::module_delete_enable()
{
    std::vector<object*> to_delete;
    WITH_LOCK(_modules_delete_mutex) {
        assert(_module_delete_disable >= 0);
        if (--_module_delete_disable || _modules_to_delete.empty()) {
            return;
        }
        to_delete = _modules_to_delete;
        _modules_to_delete.clear();
    }

    for (auto ef : to_delete) {
        ef->unload_segments();
        delete ef;
    }
}

}

using namespace elf;

extern "C" { void* elf_resolve_pltgot(unsigned long index, elf::object* obj); }

void* elf_resolve_pltgot(unsigned long index, elf::object* obj)
{
    // symbol resolution of a variable can happen with a dirty fpu
    sched::fpu_lock fpu;
    WITH_LOCK(fpu) {
        return obj->resolve_pltgot(index);
    }
}

struct module_and_offset {
    ulong module;
    ulong offset;
};

/* 在当前线程空间设置TLS
 */
char *object::setup_tls()
{
    return (char *) sched::thread::current()->setup_tls(
            _module_index, _tls_segment, _tls_init_size, _tls_uninit_size);
}

/* 返回TLS地址,必要时在当前线程空间设置TLS
 */
extern "C"
void* __tls_get_addr(module_and_offset* mao)
{
#ifdef AARCH64_PORT_STUB
    abort();
#endif /* AARCH64_PORT_STUB */

    auto tls = sched::thread::current()->get_tls(mao->module);
    if (tls) {
        return tls + mao->offset;
    } else {
        // This module's TLS block hasn't yet been allocated for this thread:
        object *obj = get_program()->tls_object(mao->module);
        assert(mao->module == obj->module_index());
        return obj->setup_tls() + mao->offset;
    }
}


// We can just call uname, because that will copy the strings to a temporary
// buffer, that won't be alive after this function return. We could of course
// have a static area and copy only once. But since our uname implementation
// also uses a static area for uname, we can just return that.
extern utsname utsname;

/* 返回type对应的值(常量)
 */
extern "C"
unsigned long getauxval(unsigned long type)
{
    switch (type) {
    // Implemented, and really 0
    case AT_EUID:
    case AT_EGID:
    case AT_UID:
        return 0;

    // Implemented, with real value
    case AT_BASE:
        return program_base;
    case AT_PLATFORM:
        return reinterpret_cast<long>(utsname.machine);
    case AT_PAGESZ:
        return sysconf(_SC_PAGESIZE);
    case AT_CLKTCK:
        return sysconf(_SC_CLK_TCK);

    // Unimplemented, man page says we should return 0
    case AT_PHDR:
    case AT_PHENT:
    case AT_PHNUM:
    case AT_DCACHEBSIZE:
    case AT_ENTRY:
    case AT_EXECFD:
    case AT_EXECFN:
    case AT_HWCAP:
    case AT_ICACHEBSIZE:
    case AT_RANDOM:
    case AT_SECURE:
    case AT_UCACHEBSIZE:
        WARN_STUBBED();
        return 0;
    default:
        return 0;
    }
}
