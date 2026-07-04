/*
 * test_pass_call_graph.cpp — Unit tests for tenet::CallGraphPass
 *
 * Verifies: call graph node/edge construction, caller→callee relationships,
 * call counts, edge_between queries, and has_call_path reachability.
 */
#include <catch2/catch_test_macros.hpp>

#include "fixtures/trace_fixture.h"
#include "analysis/passes/structure/function_pass.h"
#include "analysis/passes/structure/call_graph_pass.h"

using namespace tenet;
using namespace tenet::test;

// Helper: 3-level call chain main → foo → bar
static void gen_call_chain(TraceWriter& tw) {
    tw.anchor_interval = 256;
    tw.write_header();
    MachineState ms; ms.sp() = 0x16F000000ULL; ms.fp() = ms.sp();

    // main @ 0x1000: bl foo @ 0x2000
    tw.emit(ms, 0x1000, enc::bl(0x2000 - 0x1000), {{30, tw.rt(0x1004)}, {33, tw.rt(0x2000)}}, {});
    // foo @ 0x2000: bl bar @ 0x3000
    tw.emit(ms, 0x2000, enc::bl(0x3000 - 0x2000), {{30, tw.rt(0x2004)}, {33, tw.rt(0x3000)}}, {});
    // bar @ 0x3000: ret
    tw.emit(ms, 0x3000, enc::ret(), {{33, tw.rt(0x2004)}}, {});
    // foo @ 0x2004: ret
    tw.emit(ms, 0x2004, enc::ret(), {{33, tw.rt(0x1004)}}, {});
    // main @ 0x1004: ret
    tw.emit(ms, 0x1004, enc::ret(), {{33, 0ULL}}, {});
    tw.emit_anchor(ms);
}

TEST_CASE("CallGraphPass builds nodes for each function", "[unit][pass][call_graph]") {
    auto env = make_env(gen_call_chain, "callgraph_nodes");

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<FunctionPass>());
    pm->register_pass(std::make_unique<CallGraphPass>());

    auto& result_raw = pm->require("call_graph");
    REQUIRE(result_raw.ok());
    auto& cg = result_raw.get<CallGraphResult>();

    SECTION("all functions are nodes") {
        // main is the trace's entry point, so it is never itself the target
        // of a recorded CallEvent — CallGraphPass has no way to know who
        // "calls" it, and represents that unknown outer caller as a
        // synthetic root pseudo-node keyed by the *call-site* PC of main's
        // "bl foo" (0x1000), tagged via call_graph_root_call_site's inverse
        // (see call_graph_is_root_key() in call_graph_pass.h). Only foo and
        // bar are ever the *target* of a call, so exactly 3 nodes are
        // expected: <root>, foo, bar. This is documented, verified
        // behavior, not a "might be" guess.
        REQUIRE(cg.nodes.size() == 3);
        const uint64_t root_key = kCallGraphRootTagBit | rt_pc(0x1000);
        auto* root = cg.node_at(root_key);
        REQUIRE(root != nullptr);
        REQUIRE(root->is_root);
        REQUIRE(call_graph_is_root_key(root->entry_pc));
        REQUIRE(call_graph_root_call_site(root->entry_pc) == rt_pc(0x1000));
    }

    SECTION("node_at returns function info") {
        // foo (0x2000) is a real call target and must be a fully-populated node.
        auto* node = cg.node_at(rt_pc(0x2000));
        REQUIRE(node != nullptr);
        REQUIRE(node->entry_pc == rt_pc(0x2000));
    }
}

TEST_CASE("CallGraphPass builds caller→callee edges", "[unit][pass][call_graph]") {
    auto env = make_env(gen_call_chain, "callgraph_edges");

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<FunctionPass>());
    pm->register_pass(std::make_unique<CallGraphPass>());

    auto& cg = pm->require("call_graph").get<CallGraphResult>();

    const uint64_t root_key = kCallGraphRootTagBit | rt_pc(0x1000);

    SECTION("edge from <root> to main's first callee (foo) exists") {
        // main@0x1000 is the trace entry point and was never itself called,
        // so it has no CallEvent / no entry in FunctionResult::functions —
        // CallGraphPass cannot know main's own entry_pc and instead attributes
        // the "bl foo" call site to a synthetic root pseudo-caller keyed by
        // that call site's own PC (0x1000), tagged so it can never collide
        // with a real function entry. The edge is therefore
        // (root_key(0x1000), foo), NOT (main=0x1000, foo). See
        // CallGraphPass::run(): caller_entry_pc is taken from the *call
        // stack*, which is empty for the very first call.
        auto* e1 = cg.edge_between(root_key, rt_pc(0x2000));
        REQUIRE(e1 != nullptr);
        REQUIRE(e1->call_count == 1);
    }

    SECTION("edge from foo to bar exists (foo is a real node, unlike main)") {
        // Unlike main, foo@0x2000 *is* the target of a recorded call (from
        // <root>), so it gets a real entry_pc and becomes the caller for its
        // own "bl bar" — this is the case that actually exercises
        // caller-resolution via the simulated call stack.
        auto* e2 = cg.edge_between(rt_pc(0x2000), rt_pc(0x3000));
        REQUIRE(e2 != nullptr);
        REQUIRE(e2->call_count == 1);
    }

    SECTION("callees_of(<root>) returns foo") {
        auto callees = cg.callees_of(root_key);
        bool found_foo = false;
        for (auto* c : callees) {
            if (c->entry_pc == rt_pc(0x2000)) found_foo = true;
        }
        REQUIRE(found_foo);
    }

    SECTION("callers_of(foo) returns <root>") {
        auto callers = cg.callers_of(rt_pc(0x2000));
        bool found_root = false;
        for (auto* c : callers) {
            if (c->entry_pc == root_key) found_root = true;
        }
        REQUIRE(found_root);
    }

    SECTION("callees_of(foo) returns bar") {
        auto callees = cg.callees_of(rt_pc(0x2000));
        bool found_bar = false;
        for (auto* c : callees) {
            if (c->entry_pc == rt_pc(0x3000)) found_bar = true;
        }
        REQUIRE(found_bar);
    }

    SECTION("callers_of(bar) returns foo") {
        auto callers = cg.callers_of(rt_pc(0x3000));
        bool found_foo = false;
        for (auto* c : callers) {
            if (c->entry_pc == rt_pc(0x2000)) found_foo = true;
        }
        REQUIRE(found_foo);
    }
}

TEST_CASE("CallGraphPass has_call_path reachability", "[unit][pass][call_graph]") {
    auto env = make_env(gen_call_chain, "callgraph_path");

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<FunctionPass>());
    pm->register_pass(std::make_unique<CallGraphPass>());

    auto& cg = pm->require("call_graph").get<CallGraphResult>();

    const uint64_t root_key = kCallGraphRootTagBit | rt_pc(0x1000);

    SECTION("path from <root> to bar exists (transitively: root -> foo -> bar)") {
        REQUIRE(cg.has_call_path(root_key, rt_pc(0x3000)));
    }

    SECTION("no path from bar back to <root> (call graph is a DAG here)") {
        // bar never calls back into foo/root in this fixture, so the
        // reverse direction must NOT be reachable — a real negative case,
        // not just an "API doesn't crash" smoke test.
        REQUIRE_FALSE(cg.has_call_path(rt_pc(0x3000), root_key));
    }

    SECTION("path from a function to itself is true (base case)") {
        auto* foo = cg.node_at(rt_pc(0x2000));
        REQUIRE(foo != nullptr);
        REQUIRE(cg.has_call_path(rt_pc(0x2000), rt_pc(0x2000)));
    }
}

TEST_CASE("CallGraphPass tracks call counts", "[unit][pass][call_graph]") {
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        // Call foo 3 times
        for (int i = 0; i < 3; i++) {
            uint64_t call_pc = 0x1000 + i * 8;
            tw.emit(ms, call_pc, enc::bl(0x2000 - call_pc),
                    {{30, tw.rt(call_pc + 4)}, {33, tw.rt(0x2000)}}, {});
            tw.emit(ms, 0x2000, enc::nop(), {{33, tw.rt(0x2004)}}, {});
            tw.emit(ms, 0x2004, enc::ret(), {{33, tw.rt(call_pc + 4)}}, {});
        }
        tw.emit_anchor(ms);
    }, "callgraph_counts");

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<FunctionPass>());
    pm->register_pass(std::make_unique<CallGraphPass>());

    auto& cg = pm->require("call_graph").get<CallGraphResult>();

    SECTION("foo receives 3 calls") {
        auto* foo = cg.node_at(rt_pc(0x2000));
        REQUIRE(foo != nullptr);
        REQUIRE(foo->total_calls_received == 3);
    }

    SECTION("total call events counted") {
        REQUIRE(cg.total_call_events >= 3);
    }
}

// Helper: recursive function `fact` calling itself once per invocation
// before returning (2-level self-recursion), called from `main`.
static void gen_recursive_call(TraceWriter& tw) {
    tw.anchor_interval = 256;
    tw.write_header();
    MachineState ms; ms.sp() = 0x16F000000ULL; ms.fp() = ms.sp();

    // main @ 0x1000: bl fact @ 0x2000
    tw.emit(ms, 0x1000, enc::bl(0x2000 - 0x1000), {{30, tw.rt(0x1004)}, {33, tw.rt(0x2000)}}, {});
    // fact @ 0x2000 (outer call): bl fact @ 0x2000 (self-recursive call)
    tw.emit(ms, 0x2000, enc::bl(0), {{30, tw.rt(0x2004)}, {33, tw.rt(0x2000)}}, {});
    // fact @ 0x2000 (inner/base-case call): ret straight back to the outer frame
    tw.emit(ms, 0x2000, enc::ret(), {{33, tw.rt(0x2004)}}, {});
    // fact @ 0x2004 (outer frame resumes): ret back to main
    tw.emit(ms, 0x2004, enc::ret(), {{33, tw.rt(0x1004)}}, {});
    // main @ 0x1004: ret
    tw.emit(ms, 0x1004, enc::ret(), {{33, 0ULL}}, {});
    tw.emit_anchor(ms);
}

TEST_CASE("CallGraphPass detects recursive functions", "[unit][pass][call_graph]") {
    auto env = make_env(gen_recursive_call, "callgraph_recursive");

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<FunctionPass>());
    pm->register_pass(std::make_unique<CallGraphPass>());

    auto& cg = pm->require("call_graph").get<CallGraphResult>();

    SECTION("fact has a self-edge and is reported as recursive") {
        REQUIRE(cg.has_call_path(rt_pc(0x2000), rt_pc(0x2000)));
        auto recursive = cg.recursive_functions();
        bool found_fact = false;
        for (uint64_t pc : recursive) {
            if (pc == rt_pc(0x2000)) found_fact = true;
        }
        REQUIRE(found_fact);
    }

    SECTION("main is not recursive") {
        auto recursive = cg.recursive_functions();
        for (uint64_t pc : recursive) {
            REQUIRE(pc != rt_pc(0x1000));
        }
    }
}

TEST_CASE("CallGraphPass ranking helpers order by call count", "[unit][pass][call_graph]") {
    // driver (a REAL function, called once from the trace entry point so it
    // stays on the call stack throughout) calls foo 5 times and bar 1 time;
    // foo never calls anything. Because `driver` itself is never popped off
    // the stack between the inner calls, all 6 inner calls share the same
    // *real* caller entry — unlike a naive "main calls foo/bar directly and
    // returns to empty stack each time" fixture, this doesn't accidentally
    // exercise the <root> per-call-site fan-out (see the "two independent
    // roots" / "collapses repeated calls" tests above for that behavior).
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL; ms.fp() = ms.sp();

        // Trace entry: bl driver @ 0x2000 (single outermost call -> single root)
        tw.emit(ms, 0x1000, enc::bl(0x2000 - 0x1000), {{30, tw.rt(0x1004)}, {33, tw.rt(0x2000)}}, {});

        uint64_t pc = 0x2000;
        for (int i = 0; i < 5; i++) {
            tw.emit(ms, pc, enc::bl(0x3000 - pc), {{30, tw.rt(pc + 4)}, {33, tw.rt(0x3000)}}, {});
            tw.emit(ms, 0x3000, enc::nop(), {{33, tw.rt(0x3004)}}, {});
            tw.emit(ms, 0x3004, enc::ret(), {{33, tw.rt(pc + 4)}}, {});
            pc += 8;
        }
        tw.emit(ms, pc, enc::bl(0x4000 - pc), {{30, tw.rt(pc + 4)}, {33, tw.rt(0x4000)}}, {});
        tw.emit(ms, 0x4000, enc::nop(), {{33, tw.rt(0x4004)}}, {});
        tw.emit(ms, 0x4004, enc::ret(), {{33, tw.rt(pc + 4)}}, {});
        // driver returns to trace entry, which then returns (end of trace).
        tw.emit(ms, pc + 4, enc::ret(), {{33, tw.rt(0x1004)}}, {});
        tw.emit(ms, 0x1004, enc::ret(), {{33, 0ULL}}, {});
        tw.emit_anchor(ms);
    }, "callgraph_ranking");

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<FunctionPass>());
    pm->register_pass(std::make_unique<CallGraphPass>());

    auto& cg = pm->require("call_graph").get<CallGraphResult>();

    SECTION("hottest_callees ranks the 5x-called function first") {
        auto hottest = cg.hottest_callees(1);
        REQUIRE(hottest.size() == 1);
        REQUIRE(hottest[0].first == rt_pc(0x3000));
        REQUIRE(hottest[0].second == 5);
    }

    SECTION("most_active_callers ranks driver first (6 outgoing calls)") {
        // driver@0x2000 is a real node (it was itself called from the
        // trace's single root) and stays on the call stack across all 6 of
        // its own outgoing calls, so it — not <root> — is correctly
        // reported as the most active caller.
        auto active = cg.most_active_callers(1);
        REQUIRE(active.size() == 1);
        REQUIRE(active[0].first == rt_pc(0x2000));
        REQUIRE(active[0].second == 6);
    }
}

// Helper: two *independent* outermost invocations from two different call
// sites, each starting with an empty call stack (e.g. as if a hooked
// function were entered twice from two different callers, and the tracer's
// call-stack simulation has no way to see anything above either entry).
//   Call site 0x1000 -> foo @ 0x2000 -> ret
//   Call site 0x5000 -> baz @ 0x6000 -> ret
// These must NOT be merged into a single <root> node/edge set: they are
// genuinely distinct top-level callers and a shared <root> would make
// callees_of(<root>) / edge call-counts meaningless (see kCallGraphRootTagBit
// docs in call_graph_pass.h for the historical bug this guards against).
static void gen_two_independent_roots(TraceWriter& tw) {
    tw.anchor_interval = 256;
    tw.write_header();
    MachineState ms; ms.sp() = 0x16F000000ULL; ms.fp() = ms.sp();

    // First outermost call: call site 0x1000 -> foo @ 0x2000
    tw.emit(ms, 0x1000, enc::bl(0x2000 - 0x1000), {{30, tw.rt(0x1004)}, {33, tw.rt(0x2000)}}, {});
    tw.emit(ms, 0x2000, enc::ret(), {{33, tw.rt(0x1004)}}, {});
    tw.emit(ms, 0x1004, enc::ret(), {{33, 0ULL}}, {});

    // Stack is now empty again (both calls above returned). Second,
    // independent outermost call from a *different* call site: 0x5000 -> baz @ 0x6000.
    tw.emit(ms, 0x5000, enc::bl(0x6000 - 0x5000), {{30, tw.rt(0x5004)}, {33, tw.rt(0x6000)}}, {});
    tw.emit(ms, 0x6000, enc::ret(), {{33, tw.rt(0x5004)}}, {});
    tw.emit(ms, 0x5004, enc::ret(), {{33, 0ULL}}, {});

    tw.emit_anchor(ms);
}

TEST_CASE("CallGraphPass keeps distinct outermost call sites as separate root nodes",
          "[unit][pass][call_graph]") {
    auto env = make_env(gen_two_independent_roots, "callgraph_two_roots");

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<FunctionPass>());
    pm->register_pass(std::make_unique<CallGraphPass>());

    auto& cg = pm->require("call_graph").get<CallGraphResult>();

    const uint64_t root_key_1000 = kCallGraphRootTagBit | rt_pc(0x1000);
    const uint64_t root_key_5000 = kCallGraphRootTagBit | rt_pc(0x5000);

    SECTION("two distinct root nodes exist, not one shared <root>") {
        REQUIRE(root_key_1000 != root_key_5000);
        auto* root1 = cg.node_at(root_key_1000);
        auto* root2 = cg.node_at(root_key_5000);
        REQUIRE(root1 != nullptr);
        REQUIRE(root2 != nullptr);
        REQUIRE(root1->is_root);
        REQUIRE(root2->is_root);
        // 4 nodes total: root@0x1000, foo, root@0x5000, baz.
        REQUIRE(cg.nodes.size() == 4);
    }

    SECTION("root@0x1000 only calls foo, not baz") {
        auto callees = cg.callees_of(root_key_1000);
        REQUIRE(callees.size() == 1);
        REQUIRE(callees[0]->entry_pc == rt_pc(0x2000));
    }

    SECTION("root@0x5000 only calls baz, not foo") {
        auto callees = cg.callees_of(root_key_5000);
        REQUIRE(callees.size() == 1);
        REQUIRE(callees[0]->entry_pc == rt_pc(0x6000));
    }

    SECTION("each root's outgoing call count is 1, not merged into 2") {
        auto* e1 = cg.edge_between(root_key_1000, rt_pc(0x2000));
        auto* e2 = cg.edge_between(root_key_5000, rt_pc(0x6000));
        REQUIRE(e1 != nullptr);
        REQUIRE(e2 != nullptr);
        REQUIRE(e1->call_count == 1);
        REQUIRE(e2->call_count == 1);
    }

    SECTION("foo has no edge to/from root@0x5000 (no cross-contamination)") {
        REQUIRE(cg.edge_between(root_key_5000, rt_pc(0x2000)) == nullptr);
        REQUIRE(cg.edge_between(root_key_1000, rt_pc(0x6000)) == nullptr);
    }
}

TEST_CASE("CallGraphPass collapses repeated calls from the same outermost call site",
          "[unit][pass][call_graph]") {
    // Same call site (0x1000) invoked 3 times back-to-back, each time with
    // an empty call stack (fully returns before the next call). This must
    // still collapse into a *single* root node/edge with call_count == 3 —
    // only genuinely distinct call sites should get distinct root nodes,
    // not repeated invocations of the same one.
    auto env = make_env([](TraceWriter& tw) {
        tw.anchor_interval = 256;
        tw.write_header();
        MachineState ms; ms.sp() = 0x16F000000ULL;
        for (int i = 0; i < 3; i++) {
            tw.emit(ms, 0x1000, enc::bl(0x2000 - 0x1000), {{30, tw.rt(0x1004)}, {33, tw.rt(0x2000)}}, {});
            tw.emit(ms, 0x2000, enc::ret(), {{33, tw.rt(0x1004)}}, {});
            tw.emit(ms, 0x1004, enc::ret(), {{33, 0ULL}}, {});
        }
        tw.emit_anchor(ms);
    }, "callgraph_repeated_root");

    auto pm = make_pm(*env);
    pm->register_pass(std::make_unique<FunctionPass>());
    pm->register_pass(std::make_unique<CallGraphPass>());

    auto& cg = pm->require("call_graph").get<CallGraphResult>();
    const uint64_t root_key = kCallGraphRootTagBit | rt_pc(0x1000);

    SECTION("only one root node exists") {
        // 2 nodes total: root@0x1000, foo. Not 4 (one root per invocation).
        REQUIRE(cg.nodes.size() == 2);
        REQUIRE(cg.node_at(root_key) != nullptr);
    }

    SECTION("the edge's call_count reflects all 3 invocations") {
        auto* e = cg.edge_between(root_key, rt_pc(0x2000));
        REQUIRE(e != nullptr);
        REQUIRE(e->call_count == 3);
    }
}
