#include "keyboard_input.h"

#include "imgui.h"

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <linux/input.h>
#include <mutex>
#include <thread>
#include <unistd.h>
#include <vector>

namespace aimgui::kbd_input {

namespace {

// ─── Linux KEY_* → ImGuiKey + ASCII mapping ───────────────────────────
struct KeyMapping {
    int      linux_code;
    ImGuiKey imgui_key;
    char     ascii;       // 0 if no plain ASCII character
    char     ascii_shift; // 0 if no shifted character
};

constexpr KeyMapping kMap[] = {
    {KEY_A, ImGuiKey_A, 'a', 'A'}, {KEY_B, ImGuiKey_B, 'b', 'B'},
    {KEY_C, ImGuiKey_C, 'c', 'C'}, {KEY_D, ImGuiKey_D, 'd', 'D'},
    {KEY_E, ImGuiKey_E, 'e', 'E'}, {KEY_F, ImGuiKey_F, 'f', 'F'},
    {KEY_G, ImGuiKey_G, 'g', 'G'}, {KEY_H, ImGuiKey_H, 'h', 'H'},
    {KEY_I, ImGuiKey_I, 'i', 'I'}, {KEY_J, ImGuiKey_J, 'j', 'J'},
    {KEY_K, ImGuiKey_K, 'k', 'K'}, {KEY_L, ImGuiKey_L, 'l', 'L'},
    {KEY_M, ImGuiKey_M, 'm', 'M'}, {KEY_N, ImGuiKey_N, 'n', 'N'},
    {KEY_O, ImGuiKey_O, 'o', 'O'}, {KEY_P, ImGuiKey_P, 'p', 'P'},
    {KEY_Q, ImGuiKey_Q, 'q', 'Q'}, {KEY_R, ImGuiKey_R, 'r', 'R'},
    {KEY_S, ImGuiKey_S, 's', 'S'}, {KEY_T, ImGuiKey_T, 't', 'T'},
    {KEY_U, ImGuiKey_U, 'u', 'U'}, {KEY_V, ImGuiKey_V, 'v', 'V'},
    {KEY_W, ImGuiKey_W, 'w', 'W'}, {KEY_X, ImGuiKey_X, 'x', 'X'},
    {KEY_Y, ImGuiKey_Y, 'y', 'Y'}, {KEY_Z, ImGuiKey_Z, 'z', 'Z'},

    {KEY_0, ImGuiKey_0, '0', ')'}, {KEY_1, ImGuiKey_1, '1', '!'},
    {KEY_2, ImGuiKey_2, '2', '@'}, {KEY_3, ImGuiKey_3, '3', '#'},
    {KEY_4, ImGuiKey_4, '4', '$'}, {KEY_5, ImGuiKey_5, '5', '%'},
    {KEY_6, ImGuiKey_6, '6', '^'}, {KEY_7, ImGuiKey_7, '7', '&'},
    {KEY_8, ImGuiKey_8, '8', '*'}, {KEY_9, ImGuiKey_9, '9', '('},

    {KEY_SPACE,     ImGuiKey_Space,        ' ',  ' '},
    {KEY_ENTER,     ImGuiKey_Enter,        0,    0  },
    {KEY_BACKSPACE, ImGuiKey_Backspace,    0,    0  },
    {KEY_TAB,       ImGuiKey_Tab,          '\t', '\t'},
    {KEY_ESC,       ImGuiKey_Escape,       0,    0  },
    {KEY_LEFT,      ImGuiKey_LeftArrow,    0,    0  },
    {KEY_RIGHT,     ImGuiKey_RightArrow,   0,    0  },
    {KEY_UP,        ImGuiKey_UpArrow,      0,    0  },
    {KEY_DOWN,      ImGuiKey_DownArrow,    0,    0  },
    {KEY_HOME,      ImGuiKey_Home,         0,    0  },
    {KEY_END,       ImGuiKey_End,          0,    0  },
    {KEY_DELETE,    ImGuiKey_Delete,       0,    0  },
    {KEY_INSERT,    ImGuiKey_Insert,       0,    0  },

    {KEY_MINUS,      ImGuiKey_Minus,         '-',  '_'},
    {KEY_EQUAL,      ImGuiKey_Equal,         '=',  '+'},
    {KEY_LEFTBRACE,  ImGuiKey_LeftBracket,   '[',  '{'},
    {KEY_RIGHTBRACE, ImGuiKey_RightBracket,  ']',  '}'},
    {KEY_BACKSLASH,  ImGuiKey_Backslash,     '\\', '|'},
    {KEY_SEMICOLON,  ImGuiKey_Semicolon,     ';',  ':'},
    {KEY_APOSTROPHE, ImGuiKey_Apostrophe,    '\'', '"'},
    {KEY_GRAVE,      ImGuiKey_GraveAccent,   '`',  '~'},
    {KEY_COMMA,      ImGuiKey_Comma,         ',',  '<'},
    {KEY_DOT,        ImGuiKey_Period,        '.',  '>'},
    {KEY_SLASH,      ImGuiKey_Slash,         '/',  '?'},
};

const KeyMapping* Lookup(int linux_code) {
    for (const auto& m : kMap)
        if (m.linux_code == linux_code) return &m;
    return nullptr;
}

// ─── Pending event queue ──────────────────────────────────────────────
struct PendingEvent {
    enum Kind { Char, Key } kind;
    union {
        unsigned int ch;
        struct { ImGuiKey key; bool down; } k;
    };
};

std::mutex                g_mtx;
std::vector<PendingEvent> g_queue;

std::atomic<bool>         g_running{false};
std::vector<int>          g_fds;
std::vector<std::thread>  g_threads;
std::atomic<int>          g_volume_presses{0};

// ─── Probe whether a /dev/input/eventX device looks like a keyboard ──
bool LooksLikeKeyboard(int fd) {
    uint8_t bits[(KEY_MAX / 8) + 1] = {};
    if (ioctl(fd, EVIOCGBIT(EV_KEY, sizeof(bits)), bits) < 0) return false;
    auto has = [&](int k) -> bool {
        return (bits[k / 8] & (1u << (k % 8))) != 0;
    };
    int letters = 0;
    for (int k = KEY_A; k <= KEY_Z; ++k) if (has(k)) ++letters;
    if (letters >= 20) return true;
    // Also accept the volume / power gpio-keys device — needed for the
    // volume-key UI-toggle shortcut.
    if (has(KEY_VOLUMEUP) || has(KEY_VOLUMEDOWN)) return true;
    return false;
}

// ─── Reader thread ────────────────────────────────────────────────────
void ReaderLoop(int fd) {
    bool shift = false;
    input_event ev[16];
    while (g_running.load(std::memory_order_relaxed)) {
        ssize_t n = ::read(fd, ev, sizeof(ev));
        if (n <= 0) {
            if (n < 0 && (errno == EAGAIN || errno == EINTR)) {
                usleep(5'000);
                continue;
            }
            break;
        }
        size_t count = (size_t)n / sizeof(input_event);

        std::lock_guard<std::mutex> lk(g_mtx);
        for (size_t i = 0; i < count; ++i) {
            if (ev[i].type != EV_KEY) continue;
            const bool down  = (ev[i].value != 0);
            const bool press = (ev[i].value == 1); // not repeat (=2)

            // Volume keys → UI-visibility toggle (don't queue as text input).
            if (press && (ev[i].code == KEY_VOLUMEUP ||
                          ev[i].code == KEY_VOLUMEDOWN)) {
                g_volume_presses.fetch_add(1, std::memory_order_relaxed);
                continue;
            }

            if (ev[i].code == KEY_LEFTSHIFT || ev[i].code == KEY_RIGHTSHIFT) {
                shift = down;
            }

            const KeyMapping* m = Lookup(ev[i].code);
            if (!m) continue;

            PendingEvent pe{};
            pe.kind  = PendingEvent::Key;
            pe.k.key = m->imgui_key;
            pe.k.down = down;
            g_queue.push_back(pe);

            if ((press || ev[i].value == 2) && (shift ? m->ascii_shift : m->ascii)) {
                PendingEvent ce{};
                ce.kind = PendingEvent::Char;
                ce.ch   = (unsigned int)(shift ? m->ascii_shift : m->ascii);
                g_queue.push_back(ce);
            }
        }
    }
}

} // namespace

void Init() {
    if (g_running.exchange(true)) return;

    DIR* dir = opendir("/dev/input");
    if (!dir) return;
    while (dirent* e = readdir(dir)) {
        if (std::strncmp(e->d_name, "event", 5) != 0) continue;
        char path[64];
        std::snprintf(path, sizeof(path), "/dev/input/%s", e->d_name);
        int fd = ::open(path, O_RDONLY | O_NONBLOCK);
        if (fd < 0) continue;
        if (!LooksLikeKeyboard(fd)) { ::close(fd); continue; }
        g_fds.push_back(fd);
        g_threads.emplace_back(ReaderLoop, fd);
    }
    closedir(dir);
}

void Shutdown() {
    g_running.store(false);
    for (int fd : g_fds) ::close(fd);
    for (auto& t : g_threads) if (t.joinable()) t.detach(); // read() may be blocked
    g_threads.clear();
    g_fds.clear();
    std::lock_guard<std::mutex> lk(g_mtx);
    g_queue.clear();
}

void Flush() {
    ImGuiIO& io = ImGui::GetIO();
    std::lock_guard<std::mutex> lk(g_mtx);
    for (const auto& ev : g_queue) {
        if (ev.kind == PendingEvent::Key) io.AddKeyEvent(ev.k.key, ev.k.down);
        else                              io.AddInputCharacter(ev.ch);
    }
    g_queue.clear();
}

int ConsumeVolumePresses() {
    return g_volume_presses.exchange(0, std::memory_order_relaxed);
}

} // namespace aimgui::kbd_input
