#pragma once

// Reads key events from any /dev/input/event* device that advertises a
// keyboard-class capability set (KEY_A..KEY_Z). Each detected device is
// pumped on its own reader thread; events are queued under a mutex and
// drained into ImGui's input queue from the main thread.
//
// Covers: USB OTG keyboards, Bluetooth keyboards, and software IMEs that
// emulate input via /dev/uinput (some Chinese gaming IMEs, GBoard hardware
// keyboard mode, "Mock Input"-style tools).
//
// Does NOT cover: Android system IMEs that deliver characters via
// InputConnection (the normal soft keyboard path). Such IMEs route
// characters through a JVM Binder interface that a native ELF without an
// Activity / WindowManagerService-registered window cannot receive.

namespace aimgui::kbd_input {

void Init();
void Shutdown();

// Drain pending events into ImGui::GetIO(). Call once per frame from the
// main thread, before ImGui::NewFrame().
void Flush();

// Returns and clears the count of volume-up / volume-down press edges
// captured since the last call. Used to toggle UI visibility from the
// device's physical buttons.
int ConsumeVolumePresses();

} // namespace aimgui::kbd_input
