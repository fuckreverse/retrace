# UI Layer 详细设计 (v2)

## 设计原则

1. **UI 是消费者，不是逻辑承载者**：所有数据来自 Core + Pass Pipeline，UI 只负责展示和交互路由。
2. **后端无关**：通过 `ViewPort` 抽象隔离渲染后端（FTXUI / ImGui / IDA Plugin）。
3. **响应式**：用户操作 → 更新 SessionState → 通知各视图重绘。长耗时分析异步执行。

## 架构

```
┌─────────────────────────────────────────────────────────────┐
│                     UI Shell (Event Loop)                     │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐      │
│  │InstView  │ │RegView   │ │MemView   │ │CFGView   │ ...  │
│  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘      │
│       └──────┬──────┴──────┬─────┴──────┬─────┘            │
│              ▼             ▼            ▼                    │
│         ┌─────────────────────────────────┐                 │
│         │        SessionState             │                 │
│         │  (current_inst_id, selection,   │                 │
│         │   taint state, cfg state, ...)  │                 │
│         └────────────────┬────────────────┘                 │
│                          │                                   │
│                   ┌──────┴──────┐                           │
│                   │  Commander  │  (异步命令执行)             │
│                   └──────┬──────┘                           │
└──────────────────────────┼───────────────────────────────────┘
                           ▼
              ┌─────────────────────────┐
              │  Core + Pass Pipeline   │
              └─────────────────────────┘
```

## SessionState

```cpp
class SessionState {
public:
    // 当前焦点
    uint64_t current_inst_id = 0;
    uint64_t current_thread_id = 0;

    // 选中项
    struct Selection {
        enum Type { None, Register, Memory, Instruction } type = None;
        uint8_t reg_index = 0;
        uint64_t mem_addr = 0;
        uint16_t mem_size = 0;
    };
    Selection selection;

    // 活跃的分析结果
    std::optional<TaintResult> active_taint;
    std::optional<CFGResult::FunctionCFG> active_cfg;

    // 导航历史
    void goto_inst(uint64_t id);
    void step_forward();
    void step_backward();
    void history_back();
    void history_forward();

    // 观察者
    using Listener = std::function<void(const std::string& event)>;
    void subscribe(Listener listener);
    void notify(const std::string& event);

private:
    std::vector<uint64_t> history_;
    size_t history_pos_ = 0;
    std::vector<Listener> listeners_;
};
```

## Commander — 异步命令

长耗时操作（污点追踪、CFG 构建）通过 Commander 异步执行，避免阻塞 UI。

```cpp
class Commander {
public:
    using Callback = std::function<void(PassResult&&)>;

    // 提交异步任务
    void submit(std::string description,
                std::function<PassResult()> task,
                Callback on_complete);

    // 取消当前任务
    void cancel();

    // 轮询完成状态（UI event loop 中调用）
    void poll();

    // 当前状态
    bool busy() const;
    float progress() const;
    std::string_view current_task() const;

private:
    std::thread worker_;
    std::atomic<bool> cancelled_{false};
    std::atomic<float> progress_{0.0f};
    // ...
};
```

## 视图接口

每个视图实现 `View` 接口：

```cpp
class View {
public:
    virtual ~View() = default;
    virtual std::string_view name() const = 0;

    // 当 SessionState 变化时被调用
    virtual void on_state_changed(const SessionState& state,
                                  const std::string& event) = 0;

    // FTXUI: 返回 Element 组件
    virtual ftxui::Element render(const SessionState& state) = 0;

    // 处理用户输入（返回 true 表示已处理）
    virtual bool handle_event(ftxui::Event event, SessionState& state) = 0;
};
```

## 视图清单

| 视图 | 功能 | 快捷键 |
|------|------|--------|
| **InstructionView** | 汇编列表 + 寄存器变化标注 | `1` |
| **RegisterView** | 当前 inst_id 的完整寄存器状态 | `2` |
| **MemoryView** | Hex dump + 时间维度 | `3` |
| **XRefView** | Use-Def/Def-Use 树形展示 | `4` |
| **CFGView** | CFG 文本/图形展示 | `5` |
| **TaintView** | 污点传播结果列表 + 高亮 | `6` |
| **StringView** | 字符串列表 + 搜索 | `7` |
| **StatusBar** | 进度、当前 inst_id、trace 信息 | — |

各视图的详细交互在 v1 文档中已充分描述（键绑定、显示格式等），此处不重复。
核心变化是：所有数据获取通过 `PassManager::require()` 而非直接调用 Core 接口，
UI 层不再直接持有分析引擎的引用。

## FTXUI 布局

```cpp
auto ui = ftxui::Container::Vertical({
    ftxui::Container::Horizontal({
        instruction_view,   // 左主面板
        ftxui::Container::Vertical({
            register_view,  // 右上
            memory_view,    // 右下
        }),
    }),
    status_bar,            // 底部状态栏
});
```

支持 Tab 切换焦点面板，支持面板大小拖拽（FTXUI ResizableSplit）。

## CLI 模式（非交互）

tenet 同时支持 CLI 批处理模式，不启动 TUI：

```bash
# 导出 CFG
tenet --export-cfg 0x750bd5400 --format dot -o func.dot trace.bin

# 批量污点追踪
tenet --taint '{"source": {"reg": "x0", "inst_id": 162718}, "direction": "forward"}' trace.bin

# 字符串扫描
tenet --strings --min-length 8 trace.bin
```

CLI 模式直接调用 PassManager，输出 JSON/DOT/文本到 stdout 或文件。
