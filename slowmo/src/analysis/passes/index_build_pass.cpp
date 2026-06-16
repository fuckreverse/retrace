#include "analysis/passes/index_build_pass.h"
#include "io/trace_reader.h"
#include "io/index_builder.h"

namespace tenet {

PassResult IndexBuildPass::run(PassContext& ctx) {
    auto& reader = ctx.reader();

    // Build (or reopen cached) index via public API
    auto result = TraceIndex::open_or_build(reader);
    if (!result) {
        return PassResult::failed(result.error().message);
    }

    // Report progress
    ctx.progress(1.0f, "Index built successfully");

    return PassResult::success(result->stats());
}

}  // namespace tenet
