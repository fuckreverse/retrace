#pragma once

// Ported from Cutter (rizinorg/cutter) - LGPL-3.0 License
// Original: src/widgets/GraphGridLayout.h
//
// Modifications:
//   - Removed Qt dependency (QPolygonF -> std::vector<Vec2f>, QPointF -> Vec2f)
//   - Removed rizin dependency (ut64 -> uint64_t, ut8 -> uint8_t)
//   - Self-contained, no external framework required

#include "common/LinkedListPool.h"

#include <cstdint>
#include <unordered_map>
#include <vector>

// ─── Minimal 2D point type (replaces QPointF) ────────────────────────────────

struct Vec2f {
    float x = 0.0f;
    float y = 0.0f;

    Vec2f() = default;
    Vec2f(float x, float y) : x(x), y(y) {}

    Vec2f& operator-=(const Vec2f& o) { x -= o.x; y -= o.y; return *this; }
    float rx() const { return x; }
    float ry() const { return y; }
    float& rx() { return x; }
    float& ry() { return y; }
    void setX(float v) { x = v; }
    void setY(float v) { y = v; }
};

// ─── Graph data structures ───────────────────────────────────────────────────

struct GraphEdge {
    uint64_t target;
    std::vector<Vec2f> polyline;    // replaces QPolygonF
    enum ArrowDirection : uint8_t { Down, Left, Up, Right, None };
    ArrowDirection arrow = ArrowDirection::Down;

    explicit GraphEdge(uint64_t target) : target(target) {}
};

struct GraphBlock {
    int x = 0;
    int y = 0;
    int width = 0;
    int height = 0;
    uint64_t entry;
    std::vector<GraphEdge> edges;
};

using Graph = std::unordered_map<uint64_t, GraphBlock>;

struct LayoutConfig {
    int blockVerticalSpacing   = 40;
    int blockHorizontalSpacing = 20;
    int edgeVerticalSpacing    = 10;
    int edgeHorizontalSpacing  = 10;
};

// ─── GraphGridLayout ─────────────────────────────────────────────────────────

/**
 * @brief Graph layout algorithm on layered graph layout approach.
 *
 * Ported from Cutter's GraphGridLayout. Computes pixel-space (x, y) coordinates
 * for each block and edge polyline. Does NOT require Qt or rizin.
 *
 * Usage:
 *   GraphGridLayout layout(GraphGridLayout::LayoutType::Medium);
 *   int w, h;
 *   layout.calculateLayout(graph, entry_id, w, h);
 *   // graph[id].x / .y / .edges[i].polyline are now filled
 */
class GraphGridLayout {
public:
    enum class LayoutType : uint8_t {
        Medium,
        Wide,
        Narrow,
    };

    explicit GraphGridLayout(LayoutType layoutType = LayoutType::Medium);

    void calculateLayout(Graph &blocks, uint64_t entry, int &width, int &height) const;

    void setLayoutConfig(const LayoutConfig &config) { layoutConfig = config; }
    void setTightSubtreePlacement(bool enabled) { tightSubtreePlacement = enabled; }
    void setParentBetweenDirectChild(bool enabled) { parentBetweenDirectChild = enabled; }
    void setVerticalBlockAlignmentMiddle(bool enabled) { verticalBlockAlignmentMiddle = enabled; }
    void setLayoutOptimization(bool enabled) { useLayoutOptimization = enabled; }

private:
    LayoutConfig layoutConfig;
    bool tightSubtreePlacement       = false;
    bool parentBetweenDirectChild    = false;
    bool verticalBlockAlignmentMiddle = false;
    bool useLayoutOptimization       = true;

    struct GridBlock {
        uint64_t id;
        std::vector<uint64_t> treeEdge;
        std::vector<uint64_t> dagEdge;
        std::size_t hasParent = false;
        int inputCount  = 0;
        int outputCount = 0;
        int rowCount    = 0;
        int col         = 0;
        int row         = 0;
        uint64_t mergeBlock = 0;
        int lastRowLeft   = 0;
        int lastRowRight  = 0;
        int leftPosition  = 0;
        int rightPosition = 0;
        LinkedListPool<int>::List leftSideShape;
        LinkedListPool<int>::List rightSideShape;
    };

    struct Point {
        int row;
        int col;
        int offset;
        int16_t kind;
        int16_t spacingOverride;
    };

    struct GridEdge {
        uint64_t dest;
        int mainColumn = -1;
        std::vector<Point> points;
        int secondaryPriority;

        void addPoint(int row, int col, int16_t kind = 0)
        {
            this->points.push_back({ row, col, 0, kind, 0 });
        }
    };

    struct LayoutState {
        std::unordered_map<uint64_t, GridBlock>              gridBlocks;
        std::unordered_map<uint64_t, GraphBlock>            *blocks = nullptr;
        std::unordered_map<uint64_t, std::vector<GridEdge>>  edge;
        size_t rows    = static_cast<size_t>(-1);
        size_t columns = static_cast<size_t>(-1);
        std::vector<int> columnWidth;
        std::vector<int> rowHeight;
        std::vector<int> edgeColumnWidth;
        std::vector<int> edgeRowHeight;
        std::vector<int> columnOffset;
        std::vector<int> rowOffset;
        std::vector<int> edgeColumnOffset;
        std::vector<int> edgeRowOffset;
    };

    using GridBlockMap = std::unordered_map<uint64_t, GridBlock>;

    void findMergePoints(LayoutState &state) const;
    void computeAllBlockPlacement(const std::vector<uint64_t> &blockOrder,
                                  LayoutState &layoutState) const;
    static std::vector<uint64_t> topoSort(LayoutState &state, uint64_t entry);
    static void assignRows(LayoutState &state, const std::vector<uint64_t> &blockOrder);
    static void selectTree(LayoutState &state);

    void routeEdges(LayoutState &state) const;
    void calculateEdgeMainColumn(LayoutState &state) const;
    void roughRouting(LayoutState &state) const;
    void elaborateEdgePlacement(LayoutState &state) const;
    void adjustColumnWidths(LayoutState &state) const;
    static int calculateColumnOffsets(const std::vector<int> &columnWidth,
                                      std::vector<int> &edgeColumnWidth,
                                      std::vector<int> &columnOffset,
                                      std::vector<int> &edgeColumnOffset);
    void convertToPixelCoordinates(LayoutState &state, int &width, int &height) const;
    void cropToContent(Graph &graph, int &width, int &height) const;
    void connectEdgeEnds(Graph &graph) const;
    void optimizeLayout(LayoutState &state) const;
};
