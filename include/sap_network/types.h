#pragma once
#include <memory>
#include <span>
#include <string_view>
#include <vector>

namespace stl {
    using string_view = std::string_view;

    template <typename T, std::size_t Extent = std::dynamic_extent>
    using span = std::span<T, Extent>;

    template <typename T, typename Allocator = std::allocator<T>>
    using vector = std::vector<T, Allocator>;

    template <typename T, typename Deleter = std::default_delete<T>>
    using unique_ptr = std::unique_ptr<T, Deleter>;
    
    using std::make_unique;
} // namespace stl