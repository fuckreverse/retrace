/*
 * test_graph_grid_layout.cpp — Unit tests for tenet::GraphGridLayout
 *
 * GraphGridLayout is the core hierarchical/grid graph layout algorithm
 * ported from Cutter (rizinorg/cutter). It underlies CFGLayoutPass (see
 * test_pass_cfg_layout.cpp for pass-level integration tests) but has never
 * had direct algorithm-level test coverage.
 *
 * These tests construct small Graph topologies directly (no trace/CFG
 * needed — GraphGridLayout operates purely on the public Graph/GraphBlock/
 * GraphEdge types) and verify:
 *   - basic layout invariants (parent above children, non-overlapping
 *     blocks, positive canvas dimensions) for common topologies (single
 *     node, linear chain, diamond branch, self-loop, back-edge loop,
 *     disconnected/unreachable subgraph, dense fan-out)
 *   - boundary conditions that exercise the defensive fallbacks added
 *     around the ported algorithm's internal invariants (entry not in the
 *     graph, single isolated node, all three LayoutType variants)
 *   - that calculateLayout() never crashes / hangs on any of the above,
 *     with and without the optimizeLayout() linear-program pass enabled
 */
#include <catch2/catch_test_macros.hpp>

#include "analysis/passes/GraphGridLayout.h"

// Note: GraphGridLayout/Graph/GraphBlock/GraphEdge/Vec2f live in the global
// namespace (see GraphGridLayout.h) — no `tenet::` qualification needed.

namespace {

/// Build a simple block with a fixed size, ready to be inserted into a Graph.
GraphBlock make_block(uint64_t entry, int width = 200, int height = 40) {
    GraphBlock b;
    b.entry = entry;
    b.width = width;
    b.height = height;
    return b;
}

/// True if no two blocks in `graph` overlap in pixel space (post-layout).
bool blocks_non_overlapping(const Graph& graph) {
    std::vector<const GraphBlock*> blocks;
    blocks.reserve(graph.size());
    for (const auto& [id, b] : graph) blocks.push_back(&b);

    for (size_t i = 0; i < blocks.size(); ++i) {
        const auto& a = *blocks[i];
        for (size_t j = i + 1; j < blocks.size(); ++j) {
            const auto& b = *blocks[j];
            bool disjoint = (a.x + a.width <= b.x) || (b.x + b.width <= a.x) ||
                            (a.y + a.height <= b.y) || (b.y + b.height <= a.y);
            if (!disjoint) return false;
        }
    }
    return true;
}

/// Run calculateLayout() for all three LayoutType presets and assert the
/// common invariants hold for each. Returns the Medium-layout canvas size
/// via out params for callers that want to inspect it further.
void run_all_layout_types(Graph graph, uint64_t entry, int& out_w, int& out_h) {
    for (auto type : {GraphGridLayout::LayoutType::Narrow,
                       GraphGridLayout::LayoutType::Medium,
                       GraphGridLayout::LayoutType::Wide}) {
        Graph g = graph;  // fresh copy: calculateLayout() mutates x/y/edges in place
        GraphGridLayout layout(type);
        int w = 0, h = 0;
        layout.calculateLayout(g, entry, w, h);

        REQUIRE(w > 0);
        REQUIRE(h > 0);
        REQUIRE(blocks_non_overlapping(g));

        if (type == GraphGridLayout::LayoutType::Medium) {
            out_w = w;
            out_h = h;
        }
    }
}

}  // namespace

TEST_CASE("GraphGridLayout on an empty graph does not crash", "[unit][gui][graph_grid_layout]") {
    Graph graph;
    GraphGridLayout layout;
    int w = 0, h = 0;
    // calculateLayout() must early-return cleanly (see: `if (blocks.empty())
    // return;`), leaving width/height at their caller-supplied defaults.
    layout.calculateLayout(graph, /*entry=*/0, w, h);
    REQUIRE(w == 0);
    REQUIRE(h == 0);
}

TEST_CASE("GraphGridLayout on a single isolated node produces a positive-size canvas",
          "[unit][gui][graph_grid_layout]") {
    Graph graph;
    graph[1] = make_block(1);

    int w = 0, h = 0;
    run_all_layout_types(graph, /*entry=*/1, w, h);
    REQUIRE(w > 0);
    REQUIRE(h > 0);
}

TEST_CASE("GraphGridLayout falls back to an arbitrary entry when the given entry is missing",
          "[unit][gui][graph_grid_layout]") {
    // calculateLayout() explicitly handles `blocks.find(entry) == blocks.end()`
    // by substituting blocks.begin()->first. Verify this doesn't crash and
    // still produces a valid layout.
    Graph graph;
    graph[1] = make_block(1);
    graph[1].edges.emplace_back(GraphEdge(2));
    graph[2] = make_block(2);

    GraphGridLayout layout;
    int w = 0, h = 0;
    layout.calculateLayout(graph, /*entry=*/0xDEADBEEF, w, h);

    REQUIRE(w > 0);
    REQUIRE(h > 0);
    REQUIRE(blocks_non_overlapping(graph));
}

TEST_CASE("GraphGridLayout places a linear chain with parent above child",
          "[unit][gui][graph_grid_layout]") {
    // 1 -> 2 -> 3 (straight-line fallthrough chain)
    Graph graph;
    graph[1] = make_block(1);
    graph[1].edges.emplace_back(GraphEdge(2));
    graph[2] = make_block(2);
    graph[2].edges.emplace_back(GraphEdge(3));
    graph[3] = make_block(3);

    int w = 0, h = 0;
    run_all_layout_types(graph, /*entry=*/1, w, h);

    Graph g = graph;
    GraphGridLayout layout;
    layout.calculateLayout(g, 1, w, h);

    REQUIRE(g[1].y < g[2].y);
    REQUIRE(g[2].y < g[3].y);
}

TEST_CASE("GraphGridLayout places a diamond (if/else) branch with both children below parent "
          "and the merge block below both",
          "[unit][gui][graph_grid_layout]") {
    //      1
    //     / \
    //    2   3
    //     \ /
    //      4
    Graph graph;
    graph[1] = make_block(1);
    graph[1].edges.emplace_back(GraphEdge(2));
    graph[1].edges.emplace_back(GraphEdge(3));
    graph[2] = make_block(2);
    graph[2].edges.emplace_back(GraphEdge(4));
    graph[3] = make_block(3);
    graph[3].edges.emplace_back(GraphEdge(4));
    graph[4] = make_block(4);

    int w = 0, h = 0;
    run_all_layout_types(graph, /*entry=*/1, w, h);

    Graph g = graph;
    GraphGridLayout layout;
    layout.calculateLayout(g, 1, w, h);

    REQUIRE(g[1].y < g[2].y);
    REQUIRE(g[1].y < g[3].y);
    REQUIRE(g[2].y < g[4].y);
    REQUIRE(g[3].y < g[4].y);
    // The two branches should not be placed at the same column (otherwise
    // they'd visually overlap on the horizontal axis).
    REQUIRE(g[2].x != g[3].x);
}

TEST_CASE("GraphGridLayout handles a self-loop block (edge back to itself)",
          "[unit][gui][graph_grid_layout]") {
    // A block whose only outgoing edge targets itself — the degenerate case
    // that most directly exercises calculateEdgeMainColumn()'s "no empty
    // column found on either side" defensive fallback, since the loop edge
    // and the block occupy the same column.
    Graph graph;
    graph[1] = make_block(1);
    graph[1].edges.emplace_back(GraphEdge(1));

    int w = 0, h = 0;
    run_all_layout_types(graph, /*entry=*/1, w, h);
}

TEST_CASE("GraphGridLayout handles a loop with a back-edge to an ancestor",
          "[unit][gui][graph_grid_layout]") {
    // 1 -> 2 -> 3 -> 2 (back-edge), 3 -> 4 (exit)
    Graph graph;
    graph[1] = make_block(1);
    graph[1].edges.emplace_back(GraphEdge(2));
    graph[2] = make_block(2);
    graph[2].edges.emplace_back(GraphEdge(3));
    graph[3] = make_block(3);
    graph[3].edges.emplace_back(GraphEdge(2));  // back-edge (loop)
    graph[3].edges.emplace_back(GraphEdge(4));  // exit
    graph[4] = make_block(4);

    int w = 0, h = 0;
    run_all_layout_types(graph, /*entry=*/1, w, h);

    Graph g = graph;
    GraphGridLayout layout;
    layout.calculateLayout(g, 1, w, h);

    // Forward structure should still hold despite the back-edge.
    REQUIRE(g[1].y < g[2].y);
    REQUIRE(g[2].y < g[3].y);
}

TEST_CASE("GraphGridLayout handles a disconnected subgraph unreachable from entry",
          "[unit][gui][graph_grid_layout]") {
    // Entry component: 1 -> 2. Separate unreachable component: 3 -> 4.
    // topoSort() explicitly handles this via its second loop that DFS-visits
    // any block not reached from `entry`.
    Graph graph;
    graph[1] = make_block(1);
    graph[1].edges.emplace_back(GraphEdge(2));
    graph[2] = make_block(2);
    graph[3] = make_block(3);
    graph[3].edges.emplace_back(GraphEdge(4));
    graph[4] = make_block(4);

    int w = 0, h = 0;
    run_all_layout_types(graph, /*entry=*/1, w, h);

    Graph g = graph;
    GraphGridLayout layout;
    layout.calculateLayout(g, 1, w, h);

    // All 4 blocks must still get a valid (non-overlapping) placement even
    // though blocks 3/4 are unreachable from the chosen entry.
    REQUIRE(blocks_non_overlapping(g));
}

TEST_CASE("GraphGridLayout handles a dense fan-out (switch-like) block",
          "[unit][gui][graph_grid_layout]") {
    // One block branching to many targets — stresses calculateEdgeMainColumn's
    // column-finding sweep line with many simultaneous edges competing for
    // columns, and roughRouting's per-block edge spacing logic.
    constexpr int kFanOut = 24;
    Graph graph;
    graph[0] = make_block(0);
    for (int i = 1; i <= kFanOut; i++) {
        graph[0].edges.emplace_back(GraphEdge(static_cast<uint64_t>(i)));
        graph[static_cast<uint64_t>(i)] = make_block(static_cast<uint64_t>(i));
    }

    int w = 0, h = 0;
    run_all_layout_types(graph, /*entry=*/0, w, h);
}

TEST_CASE("GraphGridLayout produces routed polylines with at least a start and end point",
          "[unit][gui][graph_grid_layout]") {
    // Regression guard for connectEdgeEnds(): every edge with a non-empty
    // polyline must have its first/last point's y-coordinate rewritten to
    // connect exactly to the source block's bottom / target block's top.
    // (An edge with an unexpectedly empty polyline is defensively skipped
    // rather than crashing; this test pins down the *expected*, non-empty
    // case still working correctly.)
    Graph graph;
    graph[1] = make_block(1);
    graph[1].edges.emplace_back(GraphEdge(2));
    graph[2] = make_block(2);

    GraphGridLayout layout;
    int w = 0, h = 0;
    layout.calculateLayout(graph, 1, w, h);

    REQUIRE(graph[1].edges.size() == 1);
    const auto& edge = graph[1].edges[0];
    REQUIRE_FALSE(edge.polyline.empty());
    // First point connects to the bottom of the source block.
    REQUIRE(edge.polyline.front().y == static_cast<float>(graph[1].y + graph[1].height));
    // Last point connects to the top of the target block.
    REQUIRE(edge.polyline.back().y == static_cast<float>(graph[2].y));
}

TEST_CASE("GraphGridLayout respects cancellation callback", "[unit][gui][graph_grid_layout]") {
    // A cancel_check_ that returns true immediately should cause
    // calculateLayout() to bail out early at its very first check, without
    // crashing (many internal loops re-check cancelled() on each iteration).
    Graph graph;
    graph[1] = make_block(1);
    graph[1].edges.emplace_back(GraphEdge(2));
    graph[2] = make_block(2);

    GraphGridLayout layout;
    layout.setCancelCheck([]() { return true; });

    int w = 0, h = 0;
    layout.calculateLayout(graph, 1, w, h);
    // No crash is the primary assertion; width/height may be left at 0 or
    // partially computed depending on how early cancellation was observed.
    SUCCEED("calculateLayout() returned without crashing under cancellation");
}

TEST_CASE("GraphGridLayout handles a large linear chain without crashing (LARGE_CFG-scale)",
          "[unit][gui][graph_grid_layout]") {
    // CFGLayoutPass switches to Narrow layout + disables optimizeLayout()
    // above LARGE_CFG_THRESHOLD (2000 blocks). Exercise that exact
    // configuration directly against GraphGridLayout (bypassing trace
    // generation, which would make this test prohibitively slow) to confirm
    // the ported algorithm itself scales to that size without hitting any
    // of the internal invariants defensively guarded against in this patch
    // (negative column index, no-empty-column-found, mismatched side counts).
    constexpr int kNumBlocks = 2500;
    Graph graph;
    for (int i = 0; i < kNumBlocks; i++) {
        graph[static_cast<uint64_t>(i)] = make_block(static_cast<uint64_t>(i));
        if (i > 0) {
            graph[static_cast<uint64_t>(i - 1)].edges.emplace_back(
                GraphEdge(static_cast<uint64_t>(i)));
        }
    }

    GraphGridLayout layout(GraphGridLayout::LayoutType::Narrow);
    layout.setLayoutOptimization(false);
    int w = 0, h = 0;
    layout.calculateLayout(graph, 0, w, h);

    REQUIRE(w > 0);
    REQUIRE(h > 0);
    REQUIRE(static_cast<int>(graph.size()) == kNumBlocks);
}
