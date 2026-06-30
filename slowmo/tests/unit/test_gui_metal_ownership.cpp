#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>

namespace {

std::string read_text(const std::filesystem::path& path) {
    std::ifstream in(path);
    REQUIRE(in.good());
    std::ostringstream buffer;
    buffer << in.rdbuf();
    return buffer.str();
}

std::filesystem::path tenet_source_root() {
    return std::filesystem::path(__FILE__).parent_path().parent_path().parent_path();
}

}  // namespace

TEST_CASE("GuiApp keeps Metal layer ownership explicit", "[unit][gui][metal]") {
    const auto root = tenet_source_root();
    const auto header_path = root / "src/gui/gui_app.h";
    const auto source_path = root / "src/gui/gui_app.mm";

    const std::string header = read_text(header_path);
    const std::string source = read_text(source_path);

    SECTION("stores SDL metal view instead of SDL renderer") {
        REQUIRE(header.find("SDL_MetalView metal_view_") != std::string::npos);
        REQUIRE(header.find("SDL_Renderer* renderer_") == std::string::npos);
    }

    SECTION("creates and destroys the SDL metal view directly") {
        REQUIRE(source.find("SDL_Metal_CreateView(window_)") != std::string::npos);
        REQUIRE(source.find("SDL_Metal_DestroyView(metal_view_)") != std::string::npos);
    }

    SECTION("uses the explicit metal view to fetch CAMetalLayer") {
        REQUIRE(source.find("SDL_Metal_GetLayer(metal_view_)") != std::string::npos);
        REQUIRE(source.find("SDL_GetRenderMetalLayer(") == std::string::npos);
    }

    SECTION("does not construct an SDL metal renderer") {
        REQUIRE(source.find("SDL_CreateRenderer(") == std::string::npos);
    }
}
