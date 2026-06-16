#pragma once

#include "analysis/pass_manager.h"
#include <string>

namespace tenet {

/// Pass that builds the sparse index (RocksDB) from a raw trace file.
/// This is typically the first pass to run; it produces the TraceIndex
/// that other passes depend on via ctx.index().
///
/// Result type: std::string (path to the index DB directory)
class IndexBuildPass final : public AnalysisPass {
public:
    /// @param db_path  Path to store the RocksDB index.
    ///                 If empty, defaults to "<trace_path>.idx/"
    explicit IndexBuildPass(std::string db_path = "")
        : db_path_(std::move(db_path)) {}

    std::string_view name() const override { return "index_build"; }
    std::string_view description() const override {
        return "Build sparse offset/anchor index from raw trace";
    }

    std::vector<std::string_view> dependencies() const override {
        return {};  // No dependencies — first pass
    }

    PassResult run(PassContext& ctx) override;

    float estimated_cost() const override { return 10.0f; }

private:
    std::string db_path_;
};

}  // namespace tenet
