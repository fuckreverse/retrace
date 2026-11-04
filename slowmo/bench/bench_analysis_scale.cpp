#include "common/logger.h"
#include "common/external_sort.h"
#include "fixtures/trace_writer.h"
#include "io/trace_reader.h"
#include "io/index_builder.h"
#include "io/code_table.h"
#include "core/register_file.h"
#include "core/memory_model.h"
#include "core/instruction_decoder.h"
#include "analysis/pass_manager.h"
#include "analysis/passes/structure/xref_pass.h"
#include "analysis/passes/structure/cfg_pass.h"
#include "analysis/passes/structure/loop_pass.h"
#include "analysis/passes/structure/function_pass.h"
#include "analysis/passes/taint/backward_taint_pass.h"
#include "analysis/passes/memory/entropy_pass.h"
#include <nlohmann/json.hpp>
#include <zstd.h>
#include <chrono>
#include <atomic>
#include <fstream>
#include <thread>
#include <iostream>
#include <map>
using namespace tenet;
using namespace tenet::test;
namespace fs=std::filesystem;
using Clock=std::chrono::steady_clock;
static double ms(Clock::time_point t){return std::chrono::duration<double,std::milli>(Clock::now()-t).count();}
static uint64_t bytes(const fs::path& dir){uint64_t n=0;std::error_code ec;
 for(auto i=fs::recursive_directory_iterator(dir,ec);!ec&&i!=fs::recursive_directory_iterator();i.increment(ec))
  if(i->is_regular_file(ec))n+=i->file_size(ec);return n;
}
static void block_compress(const fs::path& input,const fs::path& output){
 std::ifstream in(input,std::ios::binary);qbditrace::qbditrace_file_header_t h{};
 in.read(reinterpret_cast<char*>(&h),sizeof(h));h.flags|=qbditrace::QBDITRACE_HF_BLOCK_COMPRESSED;
 std::ofstream out(output,std::ios::binary);out.write(reinterpret_cast<char*>(&h),sizeof(h));
 std::vector<char> plain(256*1024), encoded(ZSTD_compressBound(plain.size()));
 std::vector<qbditrace::qbditrace_block_entry_t> entries;uint64_t offset=0;
 while(in){in.read(plain.data(),plain.size());const size_t n=in.gcount();if(!n)break;
  const auto z=ZSTD_compress(encoded.data(),encoded.size(),plain.data(),n,1);
  if(ZSTD_isError(z))throw std::runtime_error("zstd failed");
  qbditrace::qbditrace_block_entry_t e{};e.original_offset=offset;e.original_size=n;e.compressed_offset=out.tellp();e.compressed_size=z;
  entries.push_back(e);out.write(encoded.data(),z);offset+=n;
 }
 qbditrace::qbditrace_block_footer_t f{};f.index_offset=out.tellp();f.block_count=entries.size();f.magic=QBDITRACE_BLOCK_INDEX_MAGIC;
 out.write(reinterpret_cast<const char*>(entries.data()),entries.size()*sizeof(entries[0]));out.write(reinterpret_cast<const char*>(&f),sizeof(f));
 if(!out)throw std::runtime_error("compressed trace write failed");
}
int main(int argc,char** argv){try{
 std::map<std::string,std::string> args;
 for(int i=1;i<argc;i+=2){if(i+1>=argc)throw std::runtime_error("Expected --key value");args[argv[i]]=argv[i+1];}
 auto get=[&](const std::string& k,const std::string& d){auto i=args.find(k);return i==args.end()?d:i->second;};
 if(args.count("--generate")){
  const auto n=std::stoull(args.at("--generate"));const auto threads=std::stoul(get("--threads","1"));
  if(!threads||threads>64)throw std::runtime_error("threads must be 1..64");
  fs::path path=args.at("--output");const auto format=get("--format","v4");auto raw=path;if(format=="block")raw+=".raw";
  TraceWriter w;if(!w.open(raw.string().c_str()))throw std::runtime_error("Cannot create trace");
  if(format=="v5")w.write_header_v5();else w.write_header();
  std::vector<MachineState> states(threads);
  for (unsigned t=0;t<threads;++t) states[t].x(2)=0x9000+t*8;
  uint64_t active=UINT64_MAX;
  for(uint64_t i=0;i<n;++i){auto tid=(i/4096)%threads;auto& s=states[tid];
   if(tid!=active){if(threads>1)w.emit_thread(tid+100);w.emit_anchor(s);active=tid;}
   const auto slot=i%16;const auto pc=0x1000+4*slot;std::vector<TraceWriter::RegDiff> regs;std::vector<TraceWriter::MemAcc> mem;
   uint32_t op;
   if(slot==0){op=enc::str_imm(0,2,0);mem.push_back({2,8,0x9000+tid*8,s.x(0)});}
   else if(slot==1){op=enc::ldr_imm(1,2,0);mem.push_back({1,8,0x9000+tid*8,s.x(0)});regs.push_back({1,s.x(0)});}
   else if(slot==15)op=enc::b(-60);
   else{op=enc::add_imm(0,0,1);regs.push_back({0,s.x(0)+1});}
   regs.push_back({33,w.rt(slot==15?0x1000:pc+4)});
   if(format=="v5")w.emit_v5(s,pc,op,std::move(regs),std::move(mem));else w.emit(s,pc,op,std::move(regs),std::move(mem));
  }
  w.close();if(format=="block"){block_compress(raw,path);fs::remove(raw);}
  std::cout<<nlohmann::json{{"instructions",n},{"trace_bytes",fs::file_size(path)},{"format",format},{"threads",threads}}.dump()<<"\n";return 0;
 }
 const fs::path trace=args.at("--trace");const auto mode=get("--mode","xref");auto start=Clock::now();
 auto opened=TraceReader::open(trace);if(!opened)throw std::runtime_error(opened.error().message);auto reader=std::move(*opened);
 auto built=TraceIndex::open_or_build(reader,nullptr);if(!built)throw std::runtime_error(built.error().message);auto index=std::move(*built);
 const auto index_ms=ms(start);CodeTable code;index.load_code_table(code);InstructionDecoder decoder;decoder.init();RegisterFile regs(reader,index);
 MemoryModel memory(reader,index,index.raw_db(),index.mem_write_cf(),index.mem_read_cf());
 PassManager pm;pm.set_reader(&reader);pm.set_index(&index);pm.set_code_table(&code);pm.set_decoder(&decoder);pm.set_regfile(&regs);pm.set_memory(&memory);
 pm.set_analysis_memory_budget(std::stoull(get("--budget-mb","8"))<<20);
 if(get("--reference","false")=="true")pm.set_analysis_memory_budget(0);
 if(get("--cache","cold")=="cold")index.delete_all_pass_blobs();
 start=Clock::now();pm.init_infra();const auto init_ms=ms(start);
 std::string pass=mode;
 if(mode=="xref")pm.register_pass(std::make_unique<XrefPass>());
 else if(mode=="backward"){
  BackwardTaintConfig c;c.sink_inst_id=index.inst_count();c.add_sink_reg(0);c.max_tainted_insts=0;
  pm.register_pass(std::make_unique<BackwardTaintPass>(c));pass="backward_taint";
 }else if(mode=="entropy"){
  EntropyConfig c;c.addr=0x9000;c.size=512;c.compute_timeline=true;c.timeline_interval=100;
  pm.register_pass(std::make_unique<EntropyPass>(c));
 }else if(mode=="pipeline"){
  pm.register_pass(std::make_unique<XrefPass>());pm.register_pass(std::make_unique<CFGPass>());pm.register_pass(std::make_unique<LoopPass>());pm.register_pass(std::make_unique<FunctionPass>());
 }else throw std::runtime_error("Unknown benchmark mode");
 std::atomic<bool> done{false};std::atomic<double> peak{log::rss_mb()};std::atomic<double> requested{-1};
 start=Clock::now();const auto cancel_ms=std::stoull(get("--cancel-ms","0"));
 std::thread monitor([&]{while(!done.load()){
  peak.store(std::max(peak.load(),log::rss_mb()));
  if(cancel_ms && requested.load()<0 && ms(start)>=cancel_ms){requested.store(ms(start));pm.cancel_all();}
  std::this_thread::sleep_for(std::chrono::milliseconds(2));
 }});
 nlohmann::json extra;bool success;
 if(mode=="pipeline"){pm.run_all(1);success=pm.state("loop")==PassManager::PassState::Completed;}
 else{
  const auto& r=pm.require(pass);success=r.ok();if(!success)extra["error"]=r.error_message;
  if(r.ok()&&mode=="backward"){const auto& b=r.get<BackwardTaintResult>();extra["contributing"]=b.events.size();extra["spill_bytes"]=b.events.spilled_bytes()+b.dataflow_edges.spilled_bytes();extra["quality"]=b.quality.to_json();}
  if(r.ok()&&mode=="xref"){const auto& x=r.get<XrefResult>();extra["indexed"]=x.total_indexed;extra["unique_pc"]=x.unique_pc_count;extra["lazy"]=bool(x.lazy_loader);}
  if(r.ok()&&mode=="entropy"){const auto& e=r.get<EntropyResult>();extra["samples"]=e.timeline.size();extra["entropy"]=e.overall_entropy;}
 }
 const auto pass_ms=ms(start);done.store(true);monitor.join();
 nlohmann::json result={{"mode",mode},{"trace",trace.string()},{"instructions",index.inst_count()},{"trace_bytes",fs::file_size(trace)},
  {"index_ms",index_ms},{"init_ms",init_ms},{"pass_ms",pass_ms},{"peak_rss_mb",peak.load()},
  {"index_bytes",bytes(index.db_path())},{"success",success},{"cache",get("--cache","cold")},
  {"cancel_requested_ms",requested.load()},{"cancel_latency_ms",requested.load()<0?0:pass_ms-requested.load()},
  {"reference",get("--reference","false")=="true"},{"budget_mb",get("--budget-mb","8")},{"detail",extra}};
 std::cout<<result.dump()<<"\n";memory.invalidate_thread_iterators();return success||requested.load()>=0?0:1;
}catch(const std::exception& e){std::cerr<<e.what()<<"\n";return 1;}}
