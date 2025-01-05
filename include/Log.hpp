#pragma once
#include <fmt/format.h>
#include <fmt/color.h>

#define DEBUG(format_string, ...) fmt::println("{}", fmt::format(fmt::fg(fmt::color::light_gray), format_string, __VA_ARGS__))
#define TRACE(format_string, ...) fmt::println("{}", fmt::format(fmt::fg(fmt::color::white), format_string, __VA_ARGS__))
#define WARN(format_string, ...) fmt::println("{}", fmt::format(fmt::fg(fmt::color::yellow), format_string, __VA_ARGS__))
#define ERR(format_string, ...) fmt::println("{}", fmt::format(fmt::fg(fmt::color::red), format_string, __VA_ARGS__))