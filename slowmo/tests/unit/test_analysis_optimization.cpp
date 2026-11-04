#include <catch2/catch_test_macros.hpp>
#include <catch2/catch_approx.hpp>
#include "fixtures/trace_fixture.h"
#include "common/chunked_vector.h"
#include "common/external_sort.h"
#include "common/entropy.h"
#include "io/reverse_trace_window.h"
#include "analysis/passes/structure/xref_pass.h"
#include "analysis/passes/taint/taint_pass.h"
#include "analysis/passes/taint/backward_taint_pass.h"
#include "analysis/passes/memory/entropy_pass.h"
#include "analysis/passes/profile/dataflow_graph_pass.h"
#include "infra/scan_orchestrator.h"
using namespace tenet;
using namespace tenet::test;

TEST_CASE("Chunked result storage spills nontrivial objects and preserves random access", "[unit][optimization]") {
    ChunkedVector<std::string, 4096> values; values.set_resident_budget(0);
    for (int i = 1000; i > 0; --i) values.push_back(std::to_string(i));
    REQUIRE(values.spilled_bytes() > 0); REQUIRE(values.resident_capacity_bytes() == 0);
    std::sort(values.begin(), values.end());
    REQUIRE(values.front() == "1"); REQUIRE(values.back() == "999");
    auto copy = values;
    auto moved = std::move(values); values.push_back("reused");
    REQUIRE(values.front() == "reused"); REQUIRE(copy.size() == moved.size());
    moved.erase(moved.begin() + 2, moved.begin() + 7);
    REQUIRE(moved.size() == 995); REQUIRE(copy.size() == 1000);
}
TEST_CASE("External sort performs bounded multi-level merge without losing duplicates", "[unit][optimization]") {
    ExternalSorter<uint64_t> sort(64);
    for (uint64_t i = 3000; i > 0; --i) sort.add(i % 73);
    uint64_t last = 0, n = 0, total = 0;
    sort.finish([&](uint64_t v) { REQUIRE(v >= last); last = v; ++n; total += v; });
    REQUIRE(n == 3000); REQUIRE(sort.runs_written() > 32);
    uint64_t expected = 0; for (uint64_t i = 1; i <= 3000; ++i) expected += i % 73;
    REQUIRE(total == expected);
}
TEST_CASE("Reverse windows match indexed v5 reads with bounded buffering", "[unit][optimization]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.write_header_v5(); MachineState ms;
        for (int i = 0; i < 400; ++i) tw.emit_v5(ms, 0x1000 + (i % 8)*4, enc::add_imm(0, 0, 1), {{0,uint64_t(i+1)}}, {});
    }, "reverse_window"); REQUIRE(env != nullptr);
    ReverseTraceWindow window(*env->reader, *env->index, 17, 65536);
    for (uint64_t i = 400; i-- > 0;) {
        auto off = env->index->offset_of_with_pc(i, *env->reader);
        const auto expected = env->reader->record_at(off.offset, off.seed_pc).as_inst();
        const auto actual = window.at(i).as_inst();
        REQUIRE(expected.pc == 0x5000 + (i % 8)*4);
        REQUIRE(actual.pc == expected.pc); REQUIRE(actual.reg_diff(0).value == expected.reg_diff(0).value);
    }
    auto first = env->index->offset_of_with_pc(0, *env->reader);
    auto iter = TraceReader::Iterator(env->reader.get(), first.offset, first.seed_pc);
    REQUIRE((*iter).as_inst().pc == 0x5000);
    REQUIRE((*iter).as_inst().pc == 0x5000);
    ++iter; ++iter;
    // A CODE record separates the first two instructions.
    REQUIRE((*iter).as_inst().pc == 0x5004);
    REQUIRE(window.window_loads() < 30); REQUIRE(window.buffered_bytes() <= 65536);
}
TEST_CASE("External xref agrees with in-memory counts and bitmaps", "[unit][optimization]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.write_header(); MachineState ms;
        for (int i = 0; i < 5000; ++i) tw.emit(ms, 0x1000 + (i % 13)*4, enc::nop(), {{33,tw.rt(0x1000 + ((i+1)%13)*4)}}, {});
    }, "external_xref"); REQUIRE(env != nullptr);
    AnalysisRange range; range.end_inst_id = 4999; // isolate the comparison from persistence
    auto a = make_pm(*env); a->set_range(range); a->register_pass(std::make_unique<XrefPass>());
    const auto& baseline = a->require("xref").get<XrefResult>();
    auto b = make_pm(*env); b->set_range(range); b->set_analysis_memory_budget(8192);
    b->register_pass(std::make_unique<XrefPass>());
    const auto& actual = b->require("xref").get<XrefResult>();
    REQUIRE(actual.lazy_loader != nullptr); REQUIRE(actual.total_indexed == baseline.total_indexed);
    for (const auto& [pc, count] : baseline.pc_exec_count) {
        REQUIRE(actual.execution_count(pc) == count); REQUIRE(actual.inst_ids_at(pc) == baseline.inst_ids_at(pc));
    }
    REQUIRE(actual.pc_transitions.size() == baseline.pc_transitions.size());
}

static std::unique_ptr<TraceEnv> threaded_chain() {
    return make_env([](TraceWriter& tw) {
        tw.write_header(); MachineState a, b;
        tw.emit_thread(100); tw.emit_anchor(a);
        tw.emit(a, 0x1000, enc::add_imm(1,0,1), {{1,1},{33,tw.rt(0x1004)}}, {});
        tw.emit(a, 0x1004, enc::str_imm(1,2,0), {{33,tw.rt(0x1008)}}, {{2,8,0x9000,1}});
        tw.emit_thread(200); tw.emit_anchor(b);
        tw.emit(b, 0x2000, enc::add_imm(3,0,1), {{3,1},{33,tw.rt(0x2004)}}, {});
        tw.emit(b, 0x2004, enc::ldr_imm(4,2,0), {{4,1},{33,tw.rt(0x2008)}}, {{1,8,0x9000,1}});
        tw.emit_thread(100); tw.emit_anchor(a);
        tw.emit(a, 0x1008, enc::add_imm(5,1,1), {{5,2},{33,tw.rt(0x100c)}}, {});
    }, "threaded_taint_chain");
}
TEST_CASE("Threaded forward and backward taint isolate registers and share memory", "[unit][optimization]") {
    auto env = threaded_chain(); REQUIRE(env != nullptr);
    auto pm = make_pm(*env);
    TaintConfig f; f.add_source_reg(0); f.use_xref_acceleration = false;
    pm->register_pass(std::make_unique<TaintPass>(f));
    const auto& forward = pm->require("taint").get<TaintResult>();
    REQUIRE((forward.thread_taint.at(100).gpr & (1ULL << 5)) != 0);
    REQUIRE((forward.thread_taint.at(200).gpr & (1ULL << 3)) == 0);
    REQUIRE((forward.thread_taint.at(200).gpr & (1ULL << 4)) != 0);
    REQUIRE_FALSE(forward.quality.thread_context_not_isolated);
    BackwardTaintConfig b; b.sink_inst_id = 4; b.add_sink_reg(4);
    pm->register_pass(std::make_unique<BackwardTaintPass>(b));
    const auto& backward = pm->require("backward_taint").get<BackwardTaintResult>();
    REQUIRE(backward.is_contributing(3)); REQUIRE(backward.is_contributing(1)); REQUIRE(backward.is_contributing(0));
    REQUIRE_FALSE(backward.is_contributing(2)); REQUIRE_FALSE(backward.quality.thread_context_not_isolated);
}
TEST_CASE("Whole-vector taint crosses scalar aliases and memory in both directions", "[unit][optimization]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.write_header(); MachineState ms;
        tw.emit(ms,0x1000,0x9e670020u,{{33,tw.rt(0x1004)}},{}); // fmov d0, x1
        tw.emit(ms,0x1004,0x4e284860u,{{33,tw.rt(0x1008)}},{}); // aese v0, v3
        tw.emit(ms,0x1008,0x4e083c04u,{{4,7},{33,tw.rt(0x100c)}},{}); // umov x4, v0.d[0]
    }, "vector_taint_chain"); REQUIRE(env != nullptr);
    auto pm = make_pm(*env);
    TaintConfig f; f.add_source_reg(1); f.include_simd = true; f.use_xref_acceleration = false;
    pm->register_pass(std::make_unique<TaintPass>(f));
    const auto& forward = pm->require("taint").get<TaintResult>();
    REQUIRE(forward.is_tainted(34)); REQUIRE(forward.is_tainted(4)); REQUIRE_FALSE(forward.quality.has_gaps());
    BackwardTaintConfig b; b.sink_inst_id=3; b.add_sink_reg(4); b.include_simd=true;
    pm->register_pass(std::make_unique<BackwardTaintPass>(b));
    const auto& backward = pm->require("backward_taint").get<BackwardTaintResult>();
    REQUIRE(backward.is_contributing(0)); REQUIRE(backward.is_contributing(1)); REQUIRE(backward.is_contributing(2));
    REQUIRE((backward.all_involved_simd & 1) != 0);
}

TEST_CASE("Incremental entropy matches historical memory across the entire region", "[unit][optimization]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.write_header(); MachineState ms;
        for (int i=0;i<40;++i) tw.emit(ms,0x1000+(i%4)*4,enc::str_imm(0,1,0),{{33,tw.rt(0x1004)}},{{2,8,0x9000+uint64_t((i%4)*8),uint64_t(i)*0x0101010101010101ULL}});
    }, "incremental_entropy"); REQUIRE(env != nullptr);
    auto pm = make_pm(*env); EntropyConfig cfg; cfg.addr=0x9000; cfg.size=32; cfg.compute_timeline=true; cfg.timeline_interval=1;
    pm->register_pass(std::make_unique<EntropyPass>(cfg));
    const auto& r = pm->require("entropy").get<EntropyResult>();
    REQUIRE(r.timeline.size() == 40);
    for (const auto& sample : r.timeline) {
        auto snap = env->memory->read_region(cfg.addr,cfg.size,sample.inst_id);
        std::vector<uint8_t> known; for(size_t i=0;i<snap.data.size();++i) if(snap.known[i]) known.push_back(snap.data[i]);
        REQUIRE(sample.known_bytes == known.size());
        REQUIRE(sample.overall_entropy == Catch::Approx(shannon_entropy(known.data(), known.size())).margin(1e-5));
    }
}

TEST_CASE("Control taint includes branch guards and stops at known joins", "[unit][optimization]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.write_header(); MachineState ms;
        for (bool taken : {false, true}) {
            tw.emit(ms,0x1000,enc::cmp_imm(0,0),{{33,tw.rt(0x1004)}},{});
            tw.emit(ms,0x1004,enc::b_eq(12),{{33,tw.rt(taken?0x1010:0x1008)}},{});
            if (taken) tw.emit(ms,0x1010,enc::movz(1,9),{{1,9},{33,tw.rt(0x1014)}},{});
            else {
                tw.emit(ms,0x1008,enc::movz(1,7),{{1,7},{33,tw.rt(0x100c)}},{});
                tw.emit(ms,0x100c,enc::b(8),{{33,tw.rt(0x1014)}},{});
            }
            tw.emit(ms,0x1014,enc::movz(2,5),{{2,5},{33,tw.rt(0x1000)}},{});
        }
    }, "control_taint_join"); REQUIRE(env != nullptr);
    auto pm = make_pm(*env); TaintConfig f; f.add_source_reg(0); f.include_control=true; f.use_xref_acceleration=false;
    pm->register_pass(std::make_unique<TaintPass>(f));
    const auto& forward = pm->require("taint").get<TaintResult>();
    REQUIRE(forward.is_tainted(1)); REQUIRE_FALSE(forward.is_tainted(2));
    BackwardTaintConfig b; b.sink_inst_id=4; b.add_sink_reg(1); b.include_control=true;
    pm->register_pass(std::make_unique<BackwardTaintPass>(b));
    const auto& backward = pm->require("backward_taint").get<BackwardTaintResult>();
    REQUIRE(backward.is_contributing(2)); REQUIRE(backward.is_contributing(1)); REQUIRE(backward.is_contributing(0));
    bool control_edge=false;
    for (const auto& e : backward.dataflow_edges) if(e.via_reg==0xff && e.from_inst_id==1 && e.to_inst_id==2) control_edge=true;
    REQUIRE(control_edge);
}
namespace {
class BudgetPass : public AnalysisPass {
public:
    struct Collector : TraceCollector {
        size_t bytes=0; bool aborted=false;
        std::string_view name() const override { return "budget probe"; }
        void on_inst(uint64_t,const InstView&) override { bytes+=64; }
        size_t resident_bytes() const override { return bytes; }
        void abort() noexcept override { bytes=0; aborted=true; }
    } collector;
    bool ran=false;
    std::string_view name() const override { return "budget_probe"; }
    std::string_view description() const override { return "budget regression"; }
    bool has_scan() const override { return true; }
    std::vector<std::string_view> dependencies() const override { return {}; }
    void declare_scan(ScanOrchestrator& s,PassContext&) override { s.declare({name(),&collector,false}); }
    PassResult run(PassContext&) override { ran=true; return PassResult::success(1); }
};
}
TEST_CASE("Unified scan rejects over-budget collectors without caching partial success", "[unit][optimization]") {
    auto env=make_env([](TraceWriter& tw){ tw.write_header();MachineState ms;
        for(int i=0;i<3000;++i) tw.emit(ms,0x1000,enc::nop(),{},{});
    },"collector_budget"); REQUIRE(env!=nullptr);
    auto pm=make_pm(*env);pm->set_analysis_memory_budget(512);
    auto pass=std::make_unique<BudgetPass>();auto* probe=pass.get();pm->register_pass(std::move(pass));
    pm->run_all(2);
    const auto& result=pm->require("budget_probe");
    REQUIRE_FALSE(result.ok()); REQUIRE(result.error_message.find("budget")!=std::string::npos);
    REQUIRE_FALSE(probe->ran); REQUIRE(probe->collector.aborted);
}
TEST_CASE("Large dataflow graphs use paged CSR queries", "[unit][optimization]") {
    DataflowGraphResult r; r.nodes.set_resident_budget(0); r.edges.set_resident_budget(0);
    for(uint64_t i=0;i<66000;++i){ DataflowNode n;n.inst_id=i;n.pc=0x1000+i*4;r.nodes.push_back(std::move(n));
        if(i)r.edges.emplace_back(i-1,i,0,0);
    }
    r.build_adjacency(); REQUIRE(r.compact_adjacency); REQUIRE(r.nodes.spilled_bytes()>0);
    const auto incoming=r.producers_of(50000); const auto outgoing=r.consumers_of(50000);
    REQUIRE(incoming.size()==1); REQUIRE(incoming[0].from_inst_id==49999);
    REQUIRE(outgoing.size()==1); REQUIRE(outgoing[0].to_inst_id==50001);
}

TEST_CASE("Entropy combines aligned pages and preserves historical snapshots", "[unit][optimization]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.write_header(); MachineState ms;
        for (uint64_t i=0; i<1024; ++i)
            tw.emit(ms,0x1000,enc::str_imm(0,2,0),{},{{2,8,0x10000+i*8,i<512?0ULL:UINT64_MAX}});
    }, "entropy_aligned_pages"); REQUIRE(env != nullptr);
    EntropyConfig c; c.addr=0x10000;c.size=8192;c.block_size=4096;
    auto pm=make_pm(*env);pm->register_pass(std::make_unique<EntropyPass>(c));
    const auto& r=pm->require("entropy").get<EntropyResult>();
    REQUIRE(r.overall_entropy == Catch::Approx(1.f));
    REQUIRE(r.blocks[0].entropy == Catch::Approx(0.f));
    REQUIRE(r.blocks[1].entropy == Catch::Approx(0.f));
    c.at_inst_id=512;
    pm=make_pm(*env);
    pm->register_pass(std::make_unique<EntropyPass>(c));
    const auto& h=pm->require("entropy").get<EntropyResult>();
    REQUIRE(h.overall_entropy == Catch::Approx(0.f)); REQUIRE(h.known_bytes == 4096);
    c.compute_timeline=true;c.timeline_interval=0;
    pm=make_pm(*env);
    pm->register_pass(std::make_unique<EntropyPass>(c));REQUIRE_FALSE(pm->require("entropy").ok());
}

TEST_CASE("Spill storage shares backing descriptors across thousands of chunks", "[unit][optimization]") {
    ChunkedVector<uint64_t,64> values;values.set_resident_budget(0);
    for(uint64_t i=0;i<40000;++i) values.push_back(i*3);
    for(size_t i=0;i<values.size();++i) {values.cool_before(i);REQUIRE(values[i]==i*3);}
    auto moved=std::move(values); values.push_back(7);
    REQUIRE(values[0]==7);REQUIRE(moved.back()==119997);
}
