
// ══════════════════════════════════════════════════════════════════════════=
// run_batch_analysis — the entire "register + run + format" pipeline
// ══════════════════════════════════════════════════════════════════════════=

int tenet::run_batch_analysis(const CliOptions& opts,
                              TraceReader& reader,
                              TraceIndex& index,
                              CodeTable& code_table,
                              InstructionDecoder& decoder,
                              RegisterFile& regfile,
                              MemoryModel& memory) {
    const auto& hdr = reader.header();

