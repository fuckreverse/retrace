#pragma once

#include "common/types.h"

#include <cstdint>
#include <iosfwd>

namespace tenet {

class TraceReader;

enum class DumpFormat {
    Text,
    Jsonl,
};

struct DumpOptions {
    DumpFormat format = DumpFormat::Text;
    uint64_t limit = 0;        // 0 = unlimited INST records
    bool include_regs = true;
    bool include_mem = true;
};

struct DumpStats {
    uint64_t records = 0;
    uint64_t inst_records = 0;
};

Result<DumpStats> dump_trace(TraceReader& reader,
                             const DumpOptions& options,
                             std::ostream& out);

}  // namespace tenet
