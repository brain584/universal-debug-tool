// --- START OF FILE TouchHelperA.cpp ---
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <cmath>
#include <linux/input.h>
#include <linux/uinput.h>
#include <vector>
#include <thread>
#include <unordered_map>
#include "spinlock.h"

#include "imgui.h"
#include "TouchHelperA.h"
#include "Utils.h"

#define maxE 5
#define maxF 10
#define UNGRAB 0
#define GRAB 1

// 声明外部检测函数，该实现在 main.cpp 中提供
extern bool IsPointInImGuiWindow(float x, float y);

namespace Touch {
    static struct {
        input_event downEvent[2]{{{}, EV_KEY, BTN_TOUCH,       1}, {{}, EV_KEY, BTN_TOOL_FINGER, 1}};
        input_event event[512]{0};
    } input;

    static My_Vector2 touch_scale;
    static My_Vector2 screenSize;
    static std::vector<Device> devices;
    static int nowfd;
    static int orientation = 0;
    static bool initialized = false;
    static bool readOnly = false;
    static bool otherTouch = false;
    static std::function<void(std::vector<Device> *)> callback;
    static spinlock lock;

    void Upload() {
        static bool isFirstDown = true;
        int tmpCnt = 0;
        int active_fingers = 0;
        bool has_intercepted = false; 

        for (auto &device: devices) {
            for (auto &finger: device.Finger) {
                if (finger.isDown) {
                    if (finger.isIntercepted) {
                        has_intercepted = true; // 截断了，不上报坐标给安卓
                    } else {
                        // 正常上报给安卓的手指
                        if (active_fingers >= 20) {
                            goto finish;
                        }
                        input.event[tmpCnt].type = EV_ABS;
                        input.event[tmpCnt].code = ABS_X;
                        input.event[tmpCnt].value = (int) finger.pos.x;
                        tmpCnt++;

                        input.event[tmpCnt].type = EV_ABS;
                        input.event[tmpCnt].code = ABS_Y;
                        input.event[tmpCnt].value = (int) finger.pos.y;
                        tmpCnt++;

                        input.event[tmpCnt].type = EV_ABS;
                        input.event[tmpCnt].code = ABS_MT_POSITION_X;
                        input.event[tmpCnt].value = (int) finger.pos.x;
                        tmpCnt++;

                        input.event[tmpCnt].type = EV_ABS;
                        input.event[tmpCnt].code = ABS_MT_POSITION_Y;
                        input.event[tmpCnt].value = (int) finger.pos.y;
                        tmpCnt++;

                        input.event[tmpCnt].type = EV_ABS;
                        input.event[tmpCnt].code = ABS_MT_TRACKING_ID;
                        input.event[tmpCnt].value = finger.id;
                        tmpCnt++;

                        input.event[tmpCnt].type = EV_SYN;
                        input.event[tmpCnt].code = SYN_MT_REPORT;
                        input.event[tmpCnt].value = 0;
                        tmpCnt++;
                        
                        active_fingers++;
                    }
                }
            }
        }
        finish:
        
        // 如果当前没有任何手指(给安卓的)，就释放触摸按键
        if (active_fingers == 0) {
            input.event[tmpCnt].type = EV_SYN;
            input.event[tmpCnt].code = SYN_MT_REPORT;
            input.event[tmpCnt].value = 0;
            tmpCnt++;
            if (!isFirstDown) {
                isFirstDown = true;
                input.event[tmpCnt].type = EV_KEY;
                input.event[tmpCnt].code = BTN_TOUCH;
                input.event[tmpCnt].value = 0;
                tmpCnt++;
                input.event[tmpCnt].type = EV_KEY;
                input.event[tmpCnt].code = BTN_TOOL_FINGER;
                input.event[tmpCnt].value = 0;
                tmpCnt++;
            }
        }

        // --- 防息屏机制 ---
        static int wakeup_counter = 0;
        // 只要有手指被 ImGui 截断，说明用户在操作你的 UI，开始欺骗系统
        if (has_intercepted) {
            wakeup_counter++;
            if (wakeup_counter > 120) { // 按照 60Hz 采样，大约每 2 秒发一次唤醒指令
                input.event[tmpCnt].type = EV_KEY;
                input.event[tmpCnt].code = 240; // KEY_UNKNOWN (无副作用，但能重置息屏时间)
                input.event[tmpCnt].value = 1;
                tmpCnt++;
                input.event[tmpCnt].type = EV_SYN;
                input.event[tmpCnt].code = SYN_REPORT;
                input.event[tmpCnt].value = 0;
                tmpCnt++;
                
                input.event[tmpCnt].type = EV_KEY;
                input.event[tmpCnt].code = 240;
                input.event[tmpCnt].value = 0;
                tmpCnt++;
                wakeup_counter = 0;
            }
        } else {
            wakeup_counter = 0;
        }

        input.event[tmpCnt].type = EV_SYN;
        input.event[tmpCnt].code = SYN_REPORT;
        input.event[tmpCnt].value = 0;
        tmpCnt++;

        if (active_fingers > 0 && isFirstDown) {
            isFirstDown = false;
            // 注意：当 active_fingers > 0 且之前是全松开状态时，附加上 downEvent (按下指令) 一起发
            write(nowfd, &input, sizeof(struct input_event) * (tmpCnt + 2));
        } else {
            // 否则只发常规滑动坐标与防息屏按键
            write(nowfd, input.event, sizeof(struct input_event) * tmpCnt);
        }
    }

    static void *TypeA(void *arg) {
        int i = (int) (long) arg;
        Device &device = devices[i];

        int latest = 0;
        input_event inputEvent[64]{0};

        while (initialized) {
            auto readSize = (int32_t) read(device.fd, inputEvent, sizeof(inputEvent));
            if (readSize <= 0 || (readSize % sizeof(input_event)) != 0) {
                continue;
            }
            size_t count = size_t(readSize) / sizeof(input_event);

            lock.lock();
            for (size_t j = 0; j < count; j++) {
                input_event &ie = inputEvent[j];
                if (ie.type == EV_ABS) {
                    if (ie.code == ABS_MT_SLOT) {
                        latest = ie.value;
                        continue;
                    }
                    if (ie.code == ABS_MT_TRACKING_ID) {
                        if (ie.value == -1) {
                            device.Finger[latest].isDown = false;
                            device.Finger[latest].isIntercepted = false;
                            device.Finger[latest].needs_check = false;
                        } else {
                            device.Finger[latest].id = (i * 2 + 1) * maxF + latest;
                            device.Finger[latest].isDown = true;
                            device.Finger[latest].needs_check = true; // 标记：初始落下，需要被核对坐标归属权
                        }
                        continue;
                    }
                    if (ie.code == ABS_MT_POSITION_X) {
                        device.Finger[latest].id = (i * 2 + 1) * maxF + latest;
                        device.Finger[latest].pos.x = (float) ie.value * device.S2TX;
                        continue;
                    }
                    if (ie.code == ABS_MT_POSITION_Y) {
                        device.Finger[latest].id = (i * 2 + 1) * maxF + latest;
                        device.Finger[latest].pos.y = (float) ie.value * device.S2TY;
                        continue;
                    }
                }
                if (ie.code == SYN_REPORT) {
                    if (ImGui::GetCurrentContext() != nullptr) {
                        ImGuiIO &io = ImGui::GetIO();
                        bool any_down = false;

                        for (int k = 0; k < 10; k++) {
                            if (device.Finger[k].isDown) {
                                // 彻底解决图标拖断核心逻辑：仅在手指第一下按向屏幕时做判断，之后终身绑定该归属权
                                if (device.Finger[k].needs_check) {
                                    auto pos = Touch2Screen(device.Finger[k].pos);
                                    device.Finger[k].isIntercepted = ::IsPointInImGuiWindow(pos.x, pos.y);
                                    device.Finger[k].needs_check = false;
                                }
                                
                                // 如果该手指定调为拦截给 ImGui 用，那就只发给 ImGui
                                if (device.Finger[k].isIntercepted) {
                                    auto pos = Touch2Screen(device.Finger[k].pos);
                                    io.MousePos = ImVec2(pos.x, pos.y);
                                    any_down = true;
                                }
                            }
                        }
                        io.MouseDown[0] = any_down;
                    }

                    if (!readOnly) {
                        if (callback) {
                            callback(&devices);
                        } else {
                            Upload();
                        }
                    }
                    continue;
                }
            }
            lock.unlock();

        }
        return nullptr;
    }

    static bool checkDeviceIsTouch(int fd) {
        uint8_t *bits = NULL;
        ssize_t bits_size = 0;
        int res, j, k;
        bool itmp = false, itmp2 = false, itmp3 = false;
        struct input_absinfo abs{};
        while (true) {
            res = ioctl(fd, EVIOCGBIT(EV_ABS, bits_size), bits);
            if (res < bits_size)
                break;
            bits_size = res + 16;
            bits = (uint8_t *) realloc(bits, bits_size * 2);
        }
        for (j = 0; j < res; j++) {
            for (k = 0; k < 8; k++)
                if (bits[j] & 1 << k && ioctl(fd, EVIOCGABS(j * 8 + k), &abs) == 0) {
                    if (j * 8 + k == ABS_MT_SLOT) {
                        itmp = true;
                        continue;
                    }
                    if (j * 8 + k == ABS_MT_POSITION_X) {
                        itmp2 = true;
                        continue;
                    }
                    if (j * 8 + k == ABS_MT_POSITION_Y) {
                        itmp3 = true;
                        continue;
                    }
                }
        }
        free(bits);
        return itmp && itmp2 && itmp3;
    }

    bool Init(const My_Vector2 &s, bool p_readOnly) {
        Close();
        devices.clear();
        My_Vector2 size = s;
        readOnly = p_readOnly;
        if (size.x > size.y) {
            screenSize = size;
        } else {
            screenSize = {size.y, size.x};
        }
        DIR *dir = opendir("/dev/input/");
        if (!dir) {
            return false;
        }

        dirent *ptr = NULL;
        int eventCount = 0;
        while ((ptr = readdir(dir)) != NULL) {
            if (strstr(ptr->d_name, "event"))
                eventCount++;
        }

        char temp[128];
        for (int i = 0; i <= eventCount; i++) {
            sprintf(temp, "/dev/input/event%d", i);
            int fd = open(temp, O_RDWR);
            if (fd < 0) {
                continue;
            }
            if (checkDeviceIsTouch(fd)) {
                Device device{};
                if (ioctl(fd, EVIOCGABS(ABS_MT_POSITION_X), &device.absX) == 0
                    && ioctl(fd, EVIOCGABS(ABS_MT_POSITION_Y), &device.absY) == 0) {
                    device.fd = fd;
                    
                    if (!readOnly) {
                        ioctl(fd, EVIOCGRAB, GRAB);
                    }
                    devices.push_back(device);
                }
            } else {
                close(fd);
            }
        }

        if (devices.empty()) {
            return false;
        }

        int screenX = devices[0].absX.maximum;
        int screenY = devices[0].absY.maximum;

        if (!readOnly) {
            struct uinput_user_dev ui_dev;
            nowfd = open("/dev/uinput", O_WRONLY | O_NONBLOCK);
            if (nowfd <= 0) {
                return false;
            }

            int string_len = rand() % 10 + 5;
            char string[64]; // [修复] 完全兼容 C++ 标准，杜绝变长数组 VLA
            memset(&ui_dev, 0, sizeof(ui_dev));

            genRandomString(string, string_len);
            strncpy(ui_dev.name, string, UINPUT_MAX_NAME_SIZE);

            ui_dev.id.bustype = 0;
            ui_dev.id.vendor = rand() % 10 + 5;
            ui_dev.id.product = rand() % 10 + 5;
            ui_dev.id.version = rand() % 10 + 5;

            ioctl(nowfd, UI_SET_PROPBIT, INPUT_PROP_DIRECT);

            ioctl(nowfd, UI_SET_EVBIT, EV_ABS);
            ioctl(nowfd, UI_SET_ABSBIT, ABS_X);
            ioctl(nowfd, UI_SET_ABSBIT, ABS_Y);
            ioctl(nowfd, UI_SET_ABSBIT, ABS_MT_POSITION_X);
            ioctl(nowfd, UI_SET_ABSBIT, ABS_MT_POSITION_Y);
            ioctl(nowfd, UI_SET_ABSBIT, ABS_MT_TRACKING_ID);
            ioctl(nowfd, UI_SET_EVBIT, EV_SYN);
            ioctl(nowfd, UI_SET_EVBIT, EV_KEY);
            ioctl(nowfd, UI_SET_KEYBIT, BTN_TOOL_FINGER);
            ioctl(nowfd, UI_SET_KEYBIT, BTN_TOUCH);
            
            // [新增] 授予 uinput 虚拟设备使用 KEY_UNKNOWN 按键的权限，用于防息屏
            ioctl(nowfd, UI_SET_KEYBIT, 240); 

            genRandomString(string, string_len);
            ioctl(nowfd, UI_SET_PHYS, string);

            int fd = devices[0].fd;
            {
                struct input_id id{};
                if (ioctl(fd, EVIOCGID, &id) == 0) {
                    ui_dev.id.bustype = id.bustype;
                    ui_dev.id.vendor = id.vendor;
                    ui_dev.id.product = id.product;
                    ui_dev.id.version = id.version;
                }
                uint8_t *bits = NULL;
                ssize_t bits_size = 0;
                int res, j, k;
                while (1) {
                    res = ioctl(fd, EVIOCGBIT(EV_KEY, bits_size), bits);
                    if (res < bits_size)
                        break;
                    bits_size = res + 16;
                    bits = (uint8_t *) realloc(bits, bits_size * 2);
                }
                for (j = 0; j < res; j++) {
                    for (k = 0; k < 8; k++)
                        if (bits[j] & 1 << k) {
                            if (j * 8 + k == BTN_TOUCH || j * 8 + k == BTN_TOOL_FINGER)
                                continue;
                            ioctl(nowfd, UI_SET_KEYBIT, j * 8 + k);
                        }
                }
                free(bits);
            }
            ui_dev.absmin[ABS_MT_POSITION_X] = 0;
            ui_dev.absmax[ABS_MT_POSITION_X] = screenX;
            ui_dev.absmin[ABS_MT_POSITION_Y] = 0;
            ui_dev.absmax[ABS_MT_POSITION_Y] = screenY;
            ui_dev.absmin[ABS_X] = 0;
            ui_dev.absmax[ABS_X] = screenX;
            ui_dev.absmin[ABS_Y] = 0;
            ui_dev.absmax[ABS_Y] = screenY;
            ui_dev.absmin[ABS_MT_TRACKING_ID] = 0;
            ui_dev.absmax[ABS_MT_TRACKING_ID] = 65535;
            write(nowfd, &ui_dev, sizeof(ui_dev));

            if (ioctl(nowfd, UI_DEV_CREATE)) {
                return false;
            }
        }
        initialized = true;

        pthread_t t;
        for (int i = 0; i < devices.size(); i++) {
            devices[i].S2TX = (float) screenX / (float) devices[i].absX.maximum;
            devices[i].S2TY = (float) screenY / (float) devices[i].absY.maximum;
            pthread_create(&t, nullptr, TypeA, (void *) (long) i);
        }
        if (size.x > size.y) {
            std::swap(size.x, size.y);
        }
        if (otherTouch) {
            std::swap(size.x, size.y);
        }
        touch_scale.x = (float) screenX / size.x;
        touch_scale.y = (float) screenY / size.y;

        return true;
    }

    void Close() {
        if (initialized) {
            for (auto &device: devices) {
                if (!readOnly)
                    ioctl(device.fd, EVIOCGRAB, UNGRAB);
                close(device.fd);
                device.fd = 0;
            }
            if (nowfd > 0) {
                ioctl(nowfd, UI_DEV_DESTROY);
                close(nowfd);
                nowfd = 0;
            }
            memset(input.event, 0, sizeof(input.event));
            initialized = false;
            devices.clear();
        }
    }

    void Down(float x, float y) {
        lock.lock();
        touchObj &touch = devices[0].Finger[9];
        touch.id = 19;
        touch.pos = My_Vector2(x, y) * touch_scale;
        touch.isDown = true;
        Upload();
        lock.unlock();
    }

    void Move(touchObj *touch, float x, float y) {
        lock.lock();
        touch->pos = My_Vector2(x, y) * touch_scale;
        Upload();
        lock.unlock();
    }

    void Move(float x, float y) {
        Down(x, y);
    }

    void Up() {
        lock.lock();
        touchObj &touch = devices[0].Finger[9];
        touch.isDown = false;
        Upload();
        lock.unlock();
    }

    void SetCallBack(const std::function<void(std::vector<Device> *)> &cb) {
        callback = cb;
    }

    My_Vector2 Touch2Screen(const My_Vector2 &coord) {
        float x = coord.x, y = coord.y;
        float xt = x / touch_scale.x;
        float yt = y / touch_scale.y;

        if (otherTouch) {
            switch (orientation) {
                case 1:
                    x = xt;
                    y = yt;
                    break;
                case 2:
                    y = yt;
                    x = screenSize.y - xt;
                    break;
                case 3:
                    x = screenSize.y - xt;
                    y = screenSize.x - yt;
                    break;
                default:
                    y = xt;
                    x = screenSize.y - yt;
                    break;
            }
        } else {
            switch (orientation) {
                case 1:
                    x = yt;
                    y = screenSize.y - xt;
                    break;
                case 2:
                    x = screenSize.y - xt;
                    y = screenSize.x - yt;
                    break;
                case 3:
                    y = xt;
                    x = screenSize.x - yt;
                    break;
                default:
                    x = xt;
                    y = yt;
                    break;
            }
        }
        return {x, y};
    }

    My_Vector2 GetScale() {
        return touch_scale;
    }

    void setOrientation(int o) {
        orientation = o;
    }

    void setOtherTouch(bool p_otherTouch) {
        otherTouch = p_otherTouch;
    }
}