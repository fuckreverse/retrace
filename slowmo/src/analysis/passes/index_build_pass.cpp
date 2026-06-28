#include "analysis/passes/index_build_pass.h"
#include "io/trace_reader.h"
#include "io/index_builder.h"

#include <fmt/core.h>

namespace tenet {

PassResult IndexBuildPass::run(PassContext& ctx) {
    // The index is already open and locked by the PassManager (opened in
    // main.cpp before any pass runs).  Calling TraceIndex::open_or_build()
    // here would attempt to open a *second* RocksDB handle to the same
    // directory, which fails with "lock hold by current process".
    //
    // In the run_all pipeline the index is always already built, so we
    // simply report its stats.  A forced rebuild (which closes the DB,
    // deletes it, and rebuilds from scratch) is only available via the
    // CLI --rebuild-index flag, not from within the pass pipeline.
    auto& index = ctx.index();
    ctx.progress(1.0f, fmt::format(
        "Index: {} instructions, {} anchors (already built)",
        index.inst_count(), index.stats().anchor_count));
    return PassResult::success(index.stats());
}

}  // namespace tenet
