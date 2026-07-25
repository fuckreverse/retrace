#include "io/code_table.h"
#include "common/platform_mmap.h"
#include <cstring>
#include <cstdint>

namespace tenet {

// ─── Mach-O constants (minimal, no <mach-o/loader.h> to stay portable) ──────
static constexpr uint32_t MH_MAGIC_64 = 0xFEEDFACFu;
static constexpr uint32_t LC_SEGMENT_64 = 0x19u;
static constexpr uint32_t VM_PROT_EXECUTE = 0x04u;  // VM_PROT_READ=1, WRITE=2, EXECUTE=4

// ─── ELF constants (for x86_64/linux targets) ───────────────────────────────
static constexpr uint32_t ELFMAG = 0x464C457Fu;  // "\x7FELF" little-endian
static constexpr uint8_t  ELFCLASS64 = 2;

#pragma pack(push, 1)
struct MachHeader64 {
    uint32_t magic;
    uint32_t cputype;
    uint32_t cpusubtype;
    uint32_t filetype;
    uint32_t ncmds;
    uint32_t sizeofcmds;
    uint32_t flags;
    uint32_t reserved;
};
struct SegmentCommand64 {
    uint32_t cmd;
    uint32_t cmdsize;
    char     segname[16];
    uint64_t vmaddr;
    uint64_t vmsize;
    uint64_t fileoff;
    uint64_t filesize;
    uint32_t maxprot;
    uint32_t initprot;
    uint32_t nsects;
    uint32_t flags;
};
struct Elf64Ehdr {
    uint8_t  e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
};
struct Elf64Phdr {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
};
#pragma pack(pop)

static constexpr uint32_t ELF_PT_LOAD = 1;
static constexpr uint32_t ELF_PF_X = 1;

// ─── Move support — MappedFile transfers mapping ownership ─────────────────

ImageFallback::ImageFallback(ImageFallback&& other) noexcept
    : mapped_file_(std::move(other.mapped_file_)),
      segments_(std::move(other.segments_)) {}

ImageFallback& ImageFallback::operator=(ImageFallback&& other) noexcept {
    if (this != &other) {
        mapped_file_ = std::move(other.mapped_file_);
        segments_ = std::move(other.segments_);
    }
    return *this;
}

bool ImageFallback::load(const std::string& path, uint64_t module_base) {
    // Release any previously loaded image before loading a new one.
    mapped_file_.reset();
    segments_.clear();

    std::string map_error;
    mapped_file_ = platform::MappedFile::open(path, &map_error);
    if (!mapped_file_.valid() || mapped_file_.size() == 0) {
        mapped_file_.reset();
        return false;
    }
    mapped_file_.advise(platform::AccessHint::Random);

    const uint8_t* data = mapped_file_.data();
    const uint64_t size = mapped_file_.size();

    // Parse executable segments. We need the ASLR slide to map preferred
    // vmaddrs to runtime PCs. module_base is the runtime base of the image's
    // preferred load address (the lowest vmaddr among loaded segments). The
    // slide is therefore: slide = module_base - min_vmaddr.
    const auto* p = data;
    if (size < 4) return false;
    uint32_t magic;
    std::memcpy(&magic, p, 4);

    if (magic == MH_MAGIC_64) {
        if (size < sizeof(MachHeader64)) return false;
        const auto* hdr = reinterpret_cast<const MachHeader64*>(p);
        uint32_t ncmds = hdr->ncmds;
        const uint8_t* cmd = p + sizeof(MachHeader64);
        // First pass: find min vmaddr among executable segments to compute slide.
        uint64_t min_vmaddr = UINT64_MAX;
        for (uint32_t i = 0; i < ncmds; ++i) {
            if ((size_t)(cmd - p) + sizeof(SegmentCommand64) > size) break;
            const auto* seg = reinterpret_cast<const SegmentCommand64*>(cmd);
            if (seg->cmd == LC_SEGMENT_64 && (seg->initprot & VM_PROT_EXECUTE) &&
                seg->vmsize > 0 && seg->vmaddr < min_vmaddr) {
                min_vmaddr = seg->vmaddr;
            }
            cmd += seg->cmdsize;
        }
        if (min_vmaddr == UINT64_MAX) return false;  // no executable segment
        uint64_t slide = module_base - min_vmaddr;
        // Second pass: record executable segments.
        cmd = p + sizeof(MachHeader64);
        for (uint32_t i = 0; i < ncmds; ++i) {
            if ((size_t)(cmd - p) + sizeof(SegmentCommand64) > size) break;
            const auto* seg = reinterpret_cast<const SegmentCommand64*>(cmd);
            if (seg->cmd == LC_SEGMENT_64 && (seg->initprot & VM_PROT_EXECUTE) &&
                seg->vmsize > 0) {
                Segment s;
                s.runtime_start = seg->vmaddr + slide;
                s.runtime_end = s.runtime_start + seg->vmsize;
                s.file_offset = seg->fileoff;
                segments_.push_back(s);
            }
            cmd += seg->cmdsize;
        }
    } else if (magic == ELFMAG) {
        // ELF64 only (the tracer's x86_64 path).
        if (size < sizeof(Elf64Ehdr)) return false;
        const auto* hdr = reinterpret_cast<const Elf64Ehdr*>(p);
        if (hdr->e_ident[4] != ELFCLASS64) return false;
        uint64_t phoff = hdr->e_phoff;
        uint16_t phnum = hdr->e_phnum;
        uint16_t phentsize = hdr->e_phentsize;
        // Find min p_vaddr among executable PT_LOAD to compute slide.
        uint64_t min_vaddr = UINT64_MAX;
        for (uint16_t i = 0; i < phnum; ++i) {
            uint64_t off = phoff + (uint64_t)i * phentsize;
            if (off + sizeof(Elf64Phdr) > size) break;
            const auto* ph = reinterpret_cast<const Elf64Phdr*>(p + off);
            if (ph->p_type == ELF_PT_LOAD && (ph->p_flags & ELF_PF_X) &&
                ph->p_memsz > 0 && ph->p_vaddr < min_vaddr) {
                min_vaddr = ph->p_vaddr;
            }
        }
        if (min_vaddr == UINT64_MAX) return false;
        uint64_t slide = module_base - min_vaddr;
        for (uint16_t i = 0; i < phnum; ++i) {
            uint64_t off = phoff + (uint64_t)i * phentsize;
            if (off + sizeof(Elf64Phdr) > size) break;
            const auto* ph = reinterpret_cast<const Elf64Phdr*>(p + off);
            if (ph->p_type == ELF_PT_LOAD && (ph->p_flags & ELF_PF_X) && ph->p_memsz > 0) {
                Segment s;
                s.runtime_start = ph->p_vaddr + slide;
                s.runtime_end = s.runtime_start + ph->p_memsz;
                s.file_offset = ph->p_offset;
                segments_.push_back(s);
            }
        }
    } else {
        // Unknown format — release the mapping.
        mapped_file_.reset();
        return false;
    }

    std::sort(segments_.begin(), segments_.end(),
              [](const Segment& a, const Segment& b) { return a.runtime_start < b.runtime_start; });
    return !segments_.empty();
}

std::optional<uint32_t> ImageFallback::opcode_at(uint64_t runtime_pc) const {
    const uint8_t* data = mapped_file_.data();
    const uint64_t size = mapped_file_.size();
    if (segments_.empty() || data == nullptr) return std::nullopt;
    // Binary search for the segment covering runtime_pc.
    size_t lo = 0, hi = segments_.size();
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (runtime_pc < segments_[mid].runtime_start) {
            hi = mid;
        } else if (runtime_pc >= segments_[mid].runtime_end) {
            lo = mid + 1;
        } else {
            // Found. Map to file offset and read 4 bytes.
            uint64_t file_off = segments_[mid].file_offset + (runtime_pc - segments_[mid].runtime_start);
            if (file_off + 4 > size) return std::nullopt;
            uint32_t op;
            std::memcpy(&op, data + file_off, 4);
            return op;
        }
    }
    return std::nullopt;
}

size_t ImageFallback::read_bytes_at(uint64_t runtime_addr, size_t len, uint8_t* out) const {
    const uint8_t* data = mapped_file_.data();
    const uint64_t size = mapped_file_.size();
    if (segments_.empty() || data == nullptr || len == 0) return 0;
    // Binary search for the segment covering runtime_addr.
    size_t lo = 0, hi = segments_.size();
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (runtime_addr < segments_[mid].runtime_start) {
            hi = mid;
        } else if (runtime_addr >= segments_[mid].runtime_end) {
            lo = mid + 1;
        } else {
            // Found. Map to file offset and read as many bytes as available.
            uint64_t seg_off = runtime_addr - segments_[mid].runtime_start;
            uint64_t file_off = segments_[mid].file_offset + seg_off;
            // Don't read past the segment's runtime end.
            uint64_t avail_in_seg = segments_[mid].runtime_end - runtime_addr;
            size_t to_read = static_cast<size_t>(
                std::min<uint64_t>({len, avail_in_seg, size - file_off}));
            if (to_read == 0) return 0;
            std::memcpy(out, data + file_off, to_read);
            return to_read;
        }
    }
    return 0;
}

}  // namespace tenet
