#pragma once

#include <chrono>

namespace sap::network {
    // Reuse one deadline across header/payload transfers. max() means no limit.
    using Deadline = std::chrono::steady_clock::time_point;

    inline Deadline deadline_after(std::chrono::milliseconds timeout) {
        if (timeout.count() <= 0)
            return (Deadline::max)();
        const auto now = std::chrono::steady_clock::now();
        const auto available = std::chrono::duration_cast<std::chrono::milliseconds>((Deadline::max)() - now);
        return timeout >= available ? (Deadline::max)() : now + timeout;
    }
} // namespace sap::network
