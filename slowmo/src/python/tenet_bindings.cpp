/**
 * tenet Python bindings via pybind11
 *
 * Exposes the core tenet analysis API to Python:
 *   - TraceReader  : open + iterate trace records
 *   - RegisterFile : state_before / state_after
 *   - MemoryModel  : read_region
 *   - TraceIndex   : inst_count, offset_of, stats
 *   - PassManager  : run passes, get results
 *   - Basic result types: RegState, MemRegion, TaintResult, XrefResult
 *
 * Usage (Python):
 *   import tenet._core as _c
 *   reader = _c.TraceReader.open("trace.bin")
 *   index  = _c.TraceIndex.open_or_build(reader)
 *   regfile = _c.RegisterFile(reader, index)
 *   state = regfile.state_before(100)
 *   print(hex(state.pc))
 *
 * Note: the high-level tenet/__init__.py wrapper uses subprocess/RPC and is
 *   the recommended API. This _core module is available for power users who
 *   need zero-overhead direct access from Python scripts.
 */

#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <pybind11/functional.h>

#include "io/trace_reader.h"
#include "io/index_builder.h"
#include "io/code_table.h"
#include "core/register_file.h"
#include "core/memory_model.h"
#include "core/instruction_decoder.h"
#include "common/types.h"

#include <stdexcept>
#include <sstream>
#include <iomanip>

namespace py = pybind11;
using namespace tenet;

// ─── Helpers ────────────────────────────────────────────────────────────────

static const char* kRegNames[] = {
    "x0","x1","x2","x3","x4","x5","x6","x7",
    "x8","x9","x10","x11","x12","x13","x14","x15",
    "x16","x17","x18","x19","x20","x21","x22","x23",
    "x24","x25","x26","x27","x28","fp","lr","sp","nzcv","pc"
};

// ─── Module definition ───────────────────────────────────────────────────────

PYBIND11_MODULE(_core, m) {
    m.doc() = "tenet trace analysis engine — Python bindings";

    // ── TraceError ─────────────────────────────────────────────────────────
    py::register_exception<std::runtime_error>(m, "TraceError");

    // ── FileHeader ─────────────────────────────────────────────────────────
    py::class_<FileHeader>(m, "FileHeader")
        .def_readonly("magic",       &FileHeader::magic)
        .def_readonly("version",     &FileHeader::version)
        .def_readonly("num_gpr",     &FileHeader::num_gpr)
        .def_readonly("module_base", &FileHeader::module_base)
        .def_readonly("module_slide",&FileHeader::module_slide)
        .def_readonly("module_name", &FileHeader::module_name)
        .def_readonly("flags",       &FileHeader::flags)
        .def("has_mem",       &FileHeader::has_mem)
        .def("has_code",      &FileHeader::has_code)
        .def("reg_diff",      &FileHeader::reg_diff)
        .def("has_old_value", &FileHeader::has_old_value)
        .def("__repr__", [](const FileHeader& h) {
            std::ostringstream ss;
            ss << "<FileHeader module='" << h.module_name
               << "' base=0x" << std::hex << h.module_base
               << " slide=0x" << h.module_slide << ">";
            return ss.str();
        });

    // ── TraceReader ────────────────────────────────────────────────────────
    py::class_<TraceReader>(m, "TraceReader")
        .def_static("open", [](const std::string& path) {
            auto result = TraceReader::open(path);
            if (!result) {
                throw std::runtime_error("Failed to open trace: " + result.error().message);
            }
            return std::move(*result);
        }, py::arg("path"), "Open a .bin trace file")
        .def("header",    &TraceReader::header,    py::return_value_policy::reference_internal)
        .def("file_size", &TraceReader::file_size)
        .def("path",      [](const TraceReader& r) { return r.path().string(); })
        .def("__repr__", [](const TraceReader& r) {
            return "<TraceReader path='" + r.path().string() + "'>";
        });

    // ── IndexStats ────────────────────────────────────────────────────────
    py::class_<IndexStats>(m, "IndexStats")
        .def_readonly("inst_count",    &IndexStats::inst_count)
        .def_readonly("anchor_count",  &IndexStats::anchor_count)
        .def_readonly("code_count",    &IndexStats::code_count)
        .def_readonly("event_count",   &IndexStats::event_count)
        .def_readonly("total_records", &IndexStats::total_records)
        .def_readonly("build_seconds", &IndexStats::build_seconds)
        .def("__repr__", [](const IndexStats& s) {
            return "<IndexStats inst_count=" + std::to_string(s.inst_count) + ">";
        });

    // ── TraceIndex ────────────────────────────────────────────────────────
    py::class_<TraceIndex>(m, "TraceIndex")
        .def_static("open_or_build",
            [](const TraceReader& reader) {
                auto result = TraceIndex::open_or_build(reader);
                if (!result) {
                    throw std::runtime_error("TraceIndex failed: " + result.error().message);
                }
                return std::move(*result);
            },
            py::arg("reader"),
            "Open or build the RocksDB index for a trace")
        .def("inst_count", &TraceIndex::inst_count)
        .def("stats",      &TraceIndex::stats)
        .def("__repr__", [](const TraceIndex& idx) {
            return "<TraceIndex insts=" + std::to_string(idx.inst_count()) + ">";
        });

    // ── RegState ──────────────────────────────────────────────────────────
    py::class_<RegState>(m, "RegState")
        .def_property_readonly("pc",   [](const RegState& s) { return s.pc(); })
        .def_property_readonly("sp",   [](const RegState& s) { return s.sp(); })
        .def_property_readonly("lr",   [](const RegState& s) { return s.lr(); })
        .def_property_readonly("fp",   [](const RegState& s) { return s.fp(); })
        .def_property_readonly("nzcv", [](const RegState& s) { return s.nzcv(); })
        .def("__getitem__", [](const RegState& s, const std::string& name) -> uint64_t {
            for (int i = 0; i < 34; i++) {
                if (name == kRegNames[i]) return s.gpr[i];
            }
            if (name == "x29") return s.gpr[29];
            if (name == "x30") return s.gpr[30];
            throw py::key_error("Unknown register: " + name);
        })
        .def("as_dict", [](const RegState& s) {
            py::dict d;
            for (int i = 0; i < 34; i++) {
                d[kRegNames[i]] = s.gpr[i];
            }
            return d;
        })
        .def("__repr__", [](const RegState& s) {
            std::ostringstream ss;
            ss << "<RegState pc=0x" << std::hex << s.pc()
               << " sp=0x" << s.sp()
               << " x0=0x" << s.gpr[0] << ">";
            return ss.str();
        });

    // ── RegisterFile ──────────────────────────────────────────────────────
    py::class_<RegisterFile>(m, "RegisterFile")
        .def(py::init<const TraceReader&, const TraceIndex&>(),
             py::arg("reader"), py::arg("index"))
        .def("state_before", &RegisterFile::state_before, py::arg("inst_id"),
             "Get register state BEFORE instruction inst_id")
        .def("state_after",  &RegisterFile::state_after,  py::arg("inst_id"),
             "Get register state AFTER instruction inst_id")
        .def("build_checkpoints", &RegisterFile::build_checkpoints,
             py::arg("stride") = 0,
             "Build dense checkpoint array for O(K) random-access queries. "
             "Must be called before state_before()/state_after() return meaningful results.")
        .def("has_checkpoints", &RegisterFile::has_checkpoints,
             "Check if the checkpoint array is built.")
        .def("cache_stats", [](const RegisterFile& rf) {
            auto s = rf.cache_stats();
            py::dict d;
            d["ckpt_queries"]   = s.ckpt_queries;
            d["ckpt_fallbacks"] = s.ckpt_fallbacks;
            return d;
        });

    // ── MemRegion ─────────────────────────────────────────────────────────
    py::class_<MemoryModel::RegionReadResult>(m, "MemRegion")
        .def_readonly("data",        &MemoryModel::RegionReadResult::data)
        .def_readonly("known",       &MemoryModel::RegionReadResult::known)
        .def_readonly("known_count", &MemoryModel::RegionReadResult::known_count)
        .def("hex", [](const MemoryModel::RegionReadResult& r) {
            std::ostringstream ss;
            for (size_t i = 0; i < r.data.size(); i++) {
                ss << std::hex << std::setw(2) << std::setfill('0')
                   << static_cast<int>(r.data[i]);
            }
            return ss.str();
        })
        .def("__repr__", [](const MemoryModel::RegionReadResult& r) {
            return "<MemRegion size=" + std::to_string(r.data.size())
                   + " known=" + std::to_string(r.known_count) + ">";
        });

    // ── MemoryModel ───────────────────────────────────────────────────────
    py::class_<MemoryModel>(m, "MemoryModel")
        .def(py::init<const TraceReader&, const TraceIndex&>(),
             py::arg("reader"), py::arg("index"))
        .def("read_region",
            [](MemoryModel& mm, uint64_t addr, size_t size, uint64_t at_inst_id) {
                return mm.read_region(addr, size, at_inst_id);
            },
            py::arg("addr"), py::arg("size"), py::arg("at_inst_id") = UINT64_MAX,
            "Read memory region at a given trace time")
        .def("active_pages", &MemoryModel::active_pages,
             "Return a list of all pages that were written during the trace")
        .def("__repr__", [](const MemoryModel&) {
            return "<MemoryModel>";
        });

    // ── PageActivity ──────────────────────────────────────────────────────
    py::class_<MemoryModel::PageActivity>(m, "PageActivity")
        .def_readonly("page_addr",    &MemoryModel::PageActivity::page_addr)
        .def_readonly("write_count",  &MemoryModel::PageActivity::write_count)
        .def_readonly("read_count",   &MemoryModel::PageActivity::read_count)
        .def_readonly("first_inst_id",&MemoryModel::PageActivity::first_inst_id)
        .def_readonly("last_inst_id", &MemoryModel::PageActivity::last_inst_id)
        .def("__repr__", [](const MemoryModel::PageActivity& p) {
            std::ostringstream ss;
            ss << "<PageActivity addr=0x" << std::hex << p.page_addr
               << " writes=" << std::dec << p.write_count << ">";
            return ss.str();
        });

    // ── Convenience: open_trace() factory ────────────────────────────────
    m.def("open_trace", [](const std::string& path) {
        auto reader_result = TraceReader::open(path);
        if (!reader_result) {
            throw std::runtime_error("Failed to open: " + reader_result.error().message);
        }
        return std::move(*reader_result);
    }, py::arg("path"), "Open a .bin trace file and return a TraceReader");
}
