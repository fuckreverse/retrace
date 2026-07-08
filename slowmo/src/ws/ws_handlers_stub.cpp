// tools/tenet/src/ws/ws_handlers_stub.cpp
// Stub implementations — replaced by real handlers in Tasks 4-6
#include "ws/tenet_ws_service.h"

namespace tenet {

void TenetWSService::handle_navigate(void* ws, uint32_t msg_id, const uint8_t*, size_t) {
    send_error(ws, msg_id, 4, "not implemented: Navigate");
}

void TenetWSService::handle_nav_back(void* ws, uint32_t msg_id) {
    send_error(ws, msg_id, 4, "not implemented: NavBack");
}

void TenetWSService::handle_nav_forward(void* ws, uint32_t msg_id) {
    send_error(ws, msg_id, 4, "not implemented: NavForward");
}

void TenetWSService::handle_toggle_bookmark(void* ws, uint32_t msg_id, const uint8_t*, size_t) {
    send_error(ws, msg_id, 4, "not implemented: ToggleBookmark");
}

void TenetWSService::handle_get_bookmarks(void* ws, uint32_t msg_id) {
    send_error(ws, msg_id, 4, "not implemented: GetBookmarks");
}

void TenetWSService::handle_get_trace_info(void* ws, uint32_t msg_id) {
    send_error(ws, msg_id, 4, "not implemented: GetTraceInfo");
}

void TenetWSService::handle_search_forward(void* ws, uint32_t msg_id, const uint8_t*, size_t) {
    send_error(ws, msg_id, 4, "not implemented: SearchForward");
}

void TenetWSService::handle_search_clear(void* ws, uint32_t msg_id) {
    send_error(ws, msg_id, 4, "not implemented: SearchClear");
}

void TenetWSService::handle_get_search_results(void* ws, uint32_t msg_id) {
    send_error(ws, msg_id, 4, "not implemented: GetSearchResults");
}

void TenetWSService::handle_run_pass(void* ws, uint32_t msg_id, const uint8_t*, size_t) {
    send_error(ws, msg_id, 4, "not implemented: RunPass");
}

void TenetWSService::handle_run_default_passes(void* ws, uint32_t msg_id) {
    send_error(ws, msg_id, 4, "not implemented: RunDefaultPasses");
}

void TenetWSService::handle_clear_analysis(void* ws, uint32_t msg_id) {
    send_error(ws, msg_id, 4, "not implemented: ClearAnalysis");
}

void TenetWSService::handle_get_pass_state(void* ws, uint32_t msg_id, const uint8_t*, size_t) {
    send_error(ws, msg_id, 4, "not implemented: GetPassState");
}

void TenetWSService::handle_get_pass_result(void* ws, uint32_t msg_id, const uint8_t*, size_t) {
    send_error(ws, msg_id, 4, "not implemented: GetPassResult");
}

void TenetWSService::handle_get_pass_catalog(void* ws, uint32_t msg_id) {
    send_error(ws, msg_id, 4, "not implemented: GetPassCatalog");
}

void TenetWSService::handle_get_call_stack(void* ws, uint32_t msg_id, const uint8_t*, size_t) {
    send_error(ws, msg_id, 4, "not implemented: GetCallStack");
}

void TenetWSService::handle_get_last_writer(void* ws, uint32_t msg_id, const uint8_t*, size_t) {
    send_error(ws, msg_id, 4, "not implemented: GetLastWriter");
}

void TenetWSService::handle_get_write_history(void* ws, uint32_t msg_id, const uint8_t*, size_t) {
    send_error(ws, msg_id, 4, "not implemented: GetWriteHistory");
}

void TenetWSService::handle_get_functions(void* ws, uint32_t msg_id) {
    send_error(ws, msg_id, 4, "not implemented: GetFunctions");
}

}  // namespace tenet
