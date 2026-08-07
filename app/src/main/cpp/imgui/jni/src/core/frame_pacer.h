#pragma once

#include <chrono>
#include <thread>

namespace aimgui {

// Drift-corrected frame pacer. SetTargetFps(0) means "use vsync" (Wait()
// becomes a no-op); any positive target installs a fixed-period deadline
// and sleep_until's the calling thread up to it.
class FramePacer {
public:
    void SetTargetFps(int fps) {
        if (fps == m_TargetFps) return;
        m_TargetFps = fps;
        m_Period    = fps > 0 ? std::chrono::nanoseconds(1'000'000'000LL / fps)
                              : std::chrono::nanoseconds::zero();
        m_NextDeadline = std::chrono::steady_clock::now();
    }
    void Wait() {
        if (m_TargetFps <= 0) return;
        auto now = std::chrono::steady_clock::now();
        m_NextDeadline += m_Period;
        if (m_NextDeadline < now) m_NextDeadline = now + m_Period;
        std::this_thread::sleep_until(m_NextDeadline);
    }
private:
    int m_TargetFps = 0;
    std::chrono::nanoseconds m_Period{};
    std::chrono::steady_clock::time_point m_NextDeadline{};
};

} // namespace aimgui
