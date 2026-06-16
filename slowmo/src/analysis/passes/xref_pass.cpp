#include "analysis/passes/xref_pass.h"
#include "analysis/trace_collector.h"
#include "io/trace_reader.h"
#include "io/index_builder.h"

#include <fmt/core.h>

namespace tenet {

PassResult XrefPass::run(PassContext& ctx) {
    auto& reader = ctx.reader();
    auto& index = ctx.index();
    const auto& range = ctx.range();

    uint64_t start = range.start_inst_id;
    uint64_t end = std::min(range.end_inst_id, index.inst_count());
    if (end == 0) end = index.inst_count();

    XrefCollector collector;
    TraceScanEngine engine(reader, index.inst_count());
    engine.add_collector(&collector);
    engine.set_progress([&ctx, total = end - start](uint64_t processed, uint64_t /*total_arg*/) {
        ctx.progress(static_cast<float>(processed) / static_cast<float>(total));
    });
    engine.set_cancel_check([&ctx]() { return ctx.cancelled(); });
    engine.run(start, end);

    ctx.progress(1.0f, fmt::format("Xref: {} unique PCs, {} instructions",
                                    collector.result.unique_pc_count, collector.result.total_indexed));
    return PassResult::success(std::move(collector.result));
}

}  // namespace tenet
