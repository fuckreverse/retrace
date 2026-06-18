#include "analysis/passes/entropy_pass.h"
#include "io/trace_reader.h"
#include "io/index_builder.h"
#include "core/memory_model.h"

#include <cmath>
#include <cstring>
#include <algorithm>

namespace tenet {

// ─── Shannon entropy calculation ──────────────────────────────────────────

float EntropyPass::compute_entropy(const uint8_t* data, size_t len) {
    if (len == 0) return 0.0f;

    uint32_t freq[256] = {};
    for (size_t i = 0; i < len; i++) {
        freq[data[i]]++;
    }

    float entropy = 0.0f;
    for (int i = 0; i < 256; i++) {
        if (freq[i] == 0) continue;
        float p = static_cast<float>(freq[i]) / len;
        entropy -= p * std::log2(p);
    }
    return entropy;
}

// ─── Batch memory read (16 bytes at a time) ───────────────────────────────
//
// Optimization: Instead of calling byte_at() once per byte (each call creates
// a new RocksDB Iterator + seek), we use memory.read(addr, 16, at_inst_id)
// which reads 16 bytes in one RocksDB seek.
//
// For a 4096-byte region: 4096 seeks → 256 seeks (16× fewer).
// For the timeline (cfg_.size × sample_points): reduction is multiplicative.

static void batch_read_region(MemoryModel& memory, uint64_t base_addr, uint32_t size,
                              uint64_t at_inst_id,
                              std::vector<uint8_t>& out_data,
                              std::vector<bool>& out_known,
                              uint32_t& known_count) {
    out_data.resize(size, 0);
    out_known.resize(size, false);
    known_count = 0;

    // Read in 16-byte chunks using memory.read()
    for (uint32_t offset = 0; offset < size; offset += 16) {
        uint8_t chunk_size = static_cast<uint8_t>(std::min(uint32_t(16), size - offset));
        auto result = memory.read(base_addr + offset, chunk_size, at_inst_id);

        for (uint8_t i = 0; i < chunk_size; i++) {
            if (result.known[i]) {
                out_data[offset + i] = result.data[i];
                out_known[offset + i] = true;
                known_count++;
            }
        }
    }
}

// ─── Main pass execution ──────────────────────────────────────────────────

PassResult EntropyPass::run(PassContext& ctx) {
    if (cfg_.addr == 0 && cfg_.size == 0) {
        return PassResult::failed("Entropy analysis requires addr and size");
    }

    auto& memory = ctx.memory();
    auto& index = ctx.index();

    const uint64_t at_id = (cfg_.at_inst_id > 0)
        ? cfg_.at_inst_id : index.inst_count();

    EntropyResult result;
    result.addr = cfg_.addr;
    result.region_size = cfg_.size;

    ctx.progress(0.0f, "Entropy: reading memory region (batch 16B)...");

    // ── Batch-read the region (16× fewer RocksDB seeks than byte_at()) ──
    std::vector<uint8_t> region_data;
    std::vector<bool> region_known;
    uint32_t known_count = 0;

    batch_read_region(memory, cfg_.addr, cfg_.size, at_id,
                      region_data, region_known, known_count);

    result.known_bytes = known_count;

    if (known_count == 0) {
        result.overall_entropy = 0.0f;
        result.classification = EntropyResult::Unknown;
        return PassResult::success(std::move(result));
    }

    ctx.progress(0.3f, "Entropy: computing per-block entropy...");

    // Compute per-block entropy
    for (uint32_t offset = 0; offset < cfg_.size; offset += cfg_.block_size) {
        uint32_t block_len = std::min(cfg_.block_size, cfg_.size - offset);

        // Collect known bytes in this block
        std::vector<uint8_t> block_bytes;
        block_bytes.reserve(block_len);
        bool all_known = true;
        for (uint32_t i = 0; i < block_len; i++) {
            if (region_known[offset + i]) {
                block_bytes.push_back(region_data[offset + i]);
            } else {
                all_known = false;
            }
        }

        EntropyBlock block;
        block.offset = offset;
        block.size = block_len;
        block.is_known = all_known;
        block.entropy = block_bytes.empty() ? 0.0f
            : compute_entropy(block_bytes.data(), block_bytes.size());
        result.blocks.push_back(block);
    }

    // Compute overall entropy (only known bytes)
    std::vector<uint8_t> known_bytes_vec;
    known_bytes_vec.reserve(known_count);
    for (uint32_t i = 0; i < cfg_.size; i++) {
        if (region_known[i]) known_bytes_vec.push_back(region_data[i]);
    }
    result.overall_entropy = compute_entropy(known_bytes_vec.data(), known_bytes_vec.size());

    // Classify
    if (known_count < 8) {
        result.classification = EntropyResult::Unknown;
    } else if (result.overall_entropy > 7.5f) {
        result.classification = EntropyResult::Encrypted;
    } else if (result.overall_entropy > 6.0f) {
        result.classification = EntropyResult::Compressed;
    } else if (result.overall_entropy < 4.0f) {
        result.classification = EntropyResult::Plaintext;
    } else if (cfg_.size <= 64) {
        result.classification = EntropyResult::KeyMaterial;
    } else {
        result.classification = EntropyResult::Compressed;
    }

    ctx.progress(0.6f, "Entropy: detecting transitions...");

    // Compute entropy timeline if requested
    if (cfg_.compute_timeline) {
        auto write_history = memory.write_history(cfg_.addr, static_cast<uint8_t>(std::min(cfg_.size, 8u)));

        uint32_t sample_count = 0;
        float prev_entropy = 0.0f;

        for (uint64_t writer_id : write_history) {
            if (++sample_count % cfg_.timeline_interval != 0) continue;

            // ── Batch-read region at this snapshot point ──
            std::vector<uint8_t> sample_data;
            std::vector<bool> sample_known;
            uint32_t sample_known_count = 0;

            batch_read_region(memory, cfg_.addr, cfg_.size, writer_id,
                              sample_data, sample_known, sample_known_count);

            // Collect only known bytes for entropy calculation
            std::vector<uint8_t> known_sample;
            known_sample.reserve(sample_known_count);
            for (uint32_t i = 0; i < cfg_.size; i++) {
                if (sample_known[i]) known_sample.push_back(sample_data[i]);
            }

            float ent = known_sample.empty() ? 0.0f
                : compute_entropy(known_sample.data(), known_sample.size());

            EntropyTimelineEntry te;
            te.inst_id = writer_id;
            te.overall_entropy = ent;
            te.known_bytes = sample_known_count;
            result.timeline.push_back(te);

            // Detect transitions
            float delta = ent - prev_entropy;
            if (std::abs(delta) > 2.0f && prev_entropy > 0.01f) {
                result.transitions.push_back({writer_id, prev_entropy, ent, delta});
            }
            prev_entropy = ent;
        }
    }

    ctx.progress(1.0f, "Entropy: complete");
    return PassResult::success(std::move(result));
}

}  // namespace tenet
