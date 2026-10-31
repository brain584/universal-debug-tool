# LSPlant static libs (vendored, prebuilt)

These `.a` are built **once** from LSPosed/LSPlant master + DexBuilder + parallel-hashmap,
using NDK 30 and CMake 3.31 with LSPosed's module-enabled libc++ prefab.
The app build itself does **not** need C++23 modules or network: it only links these archives.

Files:
- `liblsplant.a`      <- lsplant_static
- `libdex_builder.a`  <- dex_builder_static (LSPlant generates its hooker stub class at runtime)
- `libstd_modules.a`  <- _prefab_cxx_std23_ON (empty std-module BMI provider, needed at link time)
- `include/lsplant.hpp` <- public API header (plain C++, no modules needed by the consumer)

Toolchain used:
- NDK 30.0.16248370 (pinned in app/build.gradle.kts: ndkVersion)
- CMake 3.31.6 (SDK cmake; generator must be Ninja because of C++23 modules scan)
- org.lsposed.libcxx:libcxx:30.0.16248370 (prefab; `find_package(cxx CONFIG)`)

Reproduce (scratch tree outside this repo):
1. Copy `LSPlant/lsplant/src/main/jni` -> `src/lsplant`
2. `src/lsplant/external/dex_builder` <- DexBuilder master
3. `src/lsplant/external/dex_builder/external/parallel_hashmap` <- greg7mdp/parallel-hashmap master
4. cxx prefab: extract the AAR, write a small `cmake/cxxConfig.cmake` that defines
   imported `cxx::cxx` (libcxx.a + include) and `include(.../modules/cxx/include/prefab/cmake-config.cmake)`
5. Configure with:
   - CMAKE_TOOLCHAIN_FILE=<ndk>/build/cmake/android.toolchain.cmake
   - ANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-24 -DANDROID_STL=none
   - -DCMAKE_FIND_ROOT_PATH_MODE_PACKAGE=BOTH   (required: legacy toolchain sets ONLY)
   - -DCMAKE_PREFIX_PATH=<scratch>/cmake
   - -DLSPLANT_BUILD_SHARED=OFF -DLSPLANT_STANDALONE=ON -DDEX_BUILDER_BUILD_SHARED=OFF
   - -DANDROID_SUPPORT_FLEXIBLE_PAGE_SIZES=ON
6. Ninja build; take `liblsplant_static.a`, `dex_builder/libdex_builder_static.a`,
   `lib_prefab_cxx_std23_ON.a`.

Note: LSPlant is LGPL-3.0. Keep its license/notice when redistributing the APK.
