#pragma once
#include <stdlib.h>
#include <stdio.h>    
#include <string.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <vector>
#include <pthread.h>
#include <thread>
#include <time.h>
#include <ctype.h> 
#include <sys/mman.h> 
#include <signal.h> 
using namespace std;

//AlguiMemTool开源版本：3.0.24109
/*
 * MIT License
 *
 * 版权所有 (c) [2024] ByteCat
 *
 * 特此授予任何获得本项目及相关文档文件 副本的人，免费使用该软件的权利，包括但不限于使用、复制、修改、合并、出版、分发、再许可和/或出售该软件的副本，以及允许他人这样做，条件如下：
 *
 * 1. 上述版权声明和本许可声明应包含在所有副本或实质性部分中。
 * 2. 本软件是按“原样”提供的，不附有任何形式的明示或暗示的担保，包括但不限于对适销性、特定用途的适用性和不侵权的担保。
 * 3. 在任何情况下，作者或版权持有人对因使用本项目或与本项目的其他交易而引起的任何索赔、损害或其他责任不承担任何责任，无论是在合同、侵权或其他方面。
 * 4. 请注意，**禁止删除或修改本版权声明和作者信息**，以确保所有用户都能了解软件的来源和许可条款。
 * * **请勿删除下面的信息！**
 * 作者：ByteCat
 * 游戏逆向交流QQ群：931212209
 * 作者QQ：3353484607
 * 私人定制请联系我 => 接C/C++ Java 安卓开发 联系作者QQ：3353484607
 * 此项目对接到Java请联系我 联系作者QQ：3353484607
 */



 // 更新内容(只列出重要更新)：
 // 0. 新增完整的联合搜索 完全和GG修改器的联合搜索一样
 // 1. 所有修改内存数据操作 都会对当前进程进行内存保护🛡️ 防止GG模糊搜索
 // 注意：内存保护只对当前进程有效 意味着只有直装能够防模糊 Root修改外部进程时无法防模糊[可能需要附加调试器进行代码注入] 
 // 所以如果你开发的是Root插件辅助请使用简单粗暴的方式 直接调用killGG_Root();方法来杀掉GG修改器
 // 2. Ca内存已适配android11+ scudo内存分配器 修复了某些Ca内存数据搜不到
 // 3. 完全兼容了模拟器架构
 // 4. 内存搜索已支持范围搜索 例如：10~20
 // 5. 动静态基址修改 已兼容所有基址头 HEAD_XA，HEAD_CD，HEAD_CB
 // 6. 所有修改内存数据操作 新增冻结修改 例如：MemoryOffsetWrite("99999", TYPE_DWORD, 0, true); 将bool参数改为true则冻结 否则改为false则停止冻结
 // 7. 新增打印搜索结果列表到指定文件 和 打印冻结列表到指定文件的 调试方法
 // 8. 新增所有常用数据类型和常用内存范围
 // 9. 重写了所有内存筛选规则，对于内存筛选更加精准了
 // 10. 新增一些Root跨进程工具
 // 11. 很多逻辑都进行了原理注释 让新手更好学习
 // 
 // 2024-10-9 更新内容：
 // 0. 联合搜索增加了对范围联合搜索的支持 例：0.1F;3~6D;9 
 // 1. 新增内存改善 休眠进程 解冻进程 
 // 2. 偏移改善增加了对范围改善和联合改善的支持
 // 2. ~偏移联合改善 -适用于：某些副特征码会变化但是永远只会变为那几个固定值的情况 比如只会变化为22或15或27时可以使用偏移联合改善22;15;27
 // 2. ~偏移范围改善 -适用于：某些副特征码会变化但是只会在一个范围之内变化时 比如特征码始终为1或2或3时 可以使用偏移范围改善使用1~3即可
 // 3. 优化搜索速度
 // 4. 修复潜在溢出
 // 5. 修复一亿个bug

 //初始化ABI字符串
#if defined(__arm__) && !defined(__aarch64__) //针对 ARM 32 位架构 
#define ABI "ARM32"
#elif defined(__aarch64__) //针对 ARM 64 位架构 
#define ABI "ARM64"
#elif defined(__x86_64__) || defined(_M_X64) //针对 x64 架构 
#define ABI "x64"
#elif defined(__i386__) || defined(_M_IX86) //针对 x86 架构 
#define ABI "x86"
#else // 其他架构或未知架构
#define ABI "null"
#endif	
//内存区域
#define RANGE_ALL 0        // 所有内存区域  -  全部内存		
#define RANGE_JAVA_HEAP 2  // Java 虚拟机堆内存  -  jh内存	
#define RANGE_C_HEAP 1     // C++ 堆内存  -  ch内存			
#define RANGE_C_ALLOC 4    // C++ 分配的内存  -  ca内存	[已适配 android11+ scudo内存分配器]
#define RANGE_C_DATA 8    // C++ 的数据段  -  cd内存		
#define RANGE_C_BSS 16     // C++ 未初始化的数据  -  cb内存		
#define RANGE_ANONYMOUS 32  // 匿名内存区域  -  a内存			
#define RANGE_JAVA 65536	   // Java 虚拟机内存 - j内存
#define RANGE_STACK 64     // 栈内存区域  -  s内存			
#define RANGE_ASHMEM 524288    // Android 共享内存  -  as内存		
#define RANGE_VIDEO 1048576     // 视频内存区域  -  v内存			
#define RANGE_OTHER -2080896     // 其他内存区域  -  o内存	     
#define RANGE_B_BAD 131072      // 错误的内存区域  -  b内存
#define RANGE_CODE_APP 16384   // 应用程序代码区域  -  xa内存	
#define RANGE_CODE_SYSTEM 32768 // 系统代码区域  -  xs内存	
#define isSecureWrites false//是否进行安全写入(慢)

//安全写入(慢)
#if isSecureWrites
#if defined(__arm__) || defined(__aarch64__) //arm32和arm64架构
#define BCMAPSFLAG(mapLine, id) \
	(\
		(id) == RANGE_ALL ? true: \
		(id) == RANGE_JAVA_HEAP ? ((strstr(mapLine, "w-")!=NULL||strstr(mapLine, "wx")!=NULL) && strstr(mapLine, "dalvik-")!=NULL) : \
		(id) == RANGE_C_HEAP ? ((strstr(mapLine, "w-")!=NULL||strstr(mapLine, "wx")!=NULL) && strstr(mapLine, "[heap]")!=NULL) : \
		(id) == RANGE_C_ALLOC ? ((strstr(mapLine, "w-")!=NULL||strstr(mapLine, "wx")!=NULL) && (strstr(mapLine, "[anon:libc_malloc]")!=NULL || strstr(mapLine,"[anon:scudo")!=NULL)) : \
		(id) == RANGE_C_DATA ? (strstr(mapLine, "xp")==NULL && (strstr(mapLine, "/data/app/")!=NULL || strstr(mapLine, "/data/data/")!=NULL||strstr(mapLine, "/data/user/")!=NULL)) : \
		(id) == RANGE_C_BSS ? ((strstr(mapLine, "w-")!=NULL||strstr(mapLine, "wx")!=NULL) && strstr(mapLine, "[anon:.bss]")!=NULL) : \
		(id) == RANGE_ANONYMOUS ? ((strstr(mapLine, "w-")!=NULL||strstr(mapLine, "wx")!=NULL) && strchr(mapLine, '[') == NULL && strchr(mapLine, '/') == NULL) : \
		(id) == RANGE_JAVA ? ((strstr(mapLine, "w-")!=NULL||strstr(mapLine, "wx")!=NULL) && strstr(mapLine, "dalvik-")!=NULL) : \
		(id) == RANGE_STACK ? ((strstr(mapLine, "w-")!=NULL||strstr(mapLine, "wx")!=NULL) && strstr(mapLine, "[stack")!=NULL) : \
		(id) == RANGE_ASHMEM ? ((strstr(mapLine, "w-")!=NULL||strstr(mapLine, "wx")!=NULL) && strstr(mapLine, "xp")==NULL && strstr(mapLine, "/dev/ashmem/")!=NULL && strstr(mapLine,"dalvik")==NULL) : \
		(id) == RANGE_VIDEO ? ((strstr(mapLine, "w-")!=NULL||strstr(mapLine, "wx")!=NULL) && strstr(mapLine, "/dev/mali")!=NULL) : \
		(id) == RANGE_B_BAD ? ((strstr(mapLine, "kgsl-3d0")!=NULL||strstr(mapLine, ".ttf")!=NULL)) : \
		(id) == RANGE_CODE_APP ? (strstr(mapLine, "xp")!=NULL && (strstr(mapLine, "/data/app/")!=NULL || strstr(mapLine, "/data/data/")!=NULL || (strstr(mapLine, "/dev/ashmem/")!=NULL&& strstr(mapLine,"dalvik")!=NULL) ||strstr(mapLine, "/data/user/")!=NULL)) : \
		(id) == RANGE_CODE_SYSTEM ? (strstr(mapLine, "xp")!=NULL && (strstr(mapLine, "/system")!=NULL || strstr(mapLine, "/vendor") !=NULL || strstr(mapLine, "/apex") !=NULL || strstr(mapLine, "/memfd") !=NULL || strstr(mapLine, "[vdso")!=NULL)) : \
		(id) == RANGE_OTHER ? ((strstr(mapLine, "w-")!=NULL||strstr(mapLine, "wx")!=NULL)&& !(strstr(mapLine, "dalvik-")!=NULL||strstr(mapLine, "[heap]")!=NULL||strstr(mapLine, "[anon:libc_malloc]")!=NULL || strstr(mapLine,"[anon:scudo")!=NULL || strstr(mapLine, "/data/app/")!=NULL || strstr(mapLine, "/data/data/")!=NULL ||strstr(mapLine, "/data/user/")!=NULL|| strstr(mapLine, "[anon:.bss]")!=NULL || (strchr(mapLine, '[') == NULL && strchr(mapLine, '/') == NULL) ||strstr(mapLine, "[stack")!=NULL||strstr(mapLine, "/dev/ashmem/")!=NULL||strstr(mapLine, "/dev/mali")!=NULL||strstr(mapLine, "kgsl-3d0")!=NULL||strstr(mapLine, ".ttf")!=NULL||strstr(mapLine, "/system")!=NULL||strstr(mapLine, "/vendor")!=NULL||strstr(mapLine, "/apex")!=NULL||strstr(mapLine, "/memfd")!=NULL||strstr(mapLine, "[vdso")!=NULL)) : \
		true\
	)
#else //x86和x64架构 针对雷电9模拟器《已知bug：cd可能会多搜到一些xa的数据》
#define BCMAPSFLAG(mapLine, id) \
	(\
		(id) == RANGE_ALL ? true: \
		(id) == RANGE_JAVA_HEAP ? ((strstr(mapLine, "w-")!=NULL||strstr(mapLine, "wx")!=NULL) && strstr(mapLine, "dalvik-")!=NULL) : \
		(id) == RANGE_C_HEAP ? ((strstr(mapLine, "w-")!=NULL||strstr(mapLine, "wx")!=NULL) && strstr(mapLine, "[heap]")!=NULL) : \
		(id) == RANGE_C_ALLOC ? ((strstr(mapLine, "w-")!=NULL||strstr(mapLine, "wx")!=NULL) && (strstr(mapLine, "[anon:libc_malloc]")!=NULL || strstr(mapLine,"[anon:scudo")!=NULL)) : \
		(id) == RANGE_C_DATA ? ((strstr(mapLine, "w-")!=NULL||strstr(mapLine, "wx")!=NULL) && strstr(mapLine, "xp")==NULL && (strstr(mapLine, "/data/app/")!=NULL || strstr(mapLine, "/data/data/")!=NULL||strstr(mapLine, "/data/user/")!=NULL)) : \
		(id) == RANGE_C_BSS ? ((strstr(mapLine, "w-")!=NULL||strstr(mapLine, "wx")!=NULL) && strstr(mapLine, "[anon:.bss]")!=NULL) : \
		(id) == RANGE_ANONYMOUS ? ((strstr(mapLine, "w-")!=NULL||strstr(mapLine, "wx")!=NULL) && strchr(mapLine, '[') == NULL && strchr(mapLine, '/') == NULL) : \
		(id) == RANGE_JAVA ? ((strstr(mapLine, "w-")!=NULL||strstr(mapLine, "wx")!=NULL) && strstr(mapLine, "dalvik-")!=NULL) : \
		(id) == RANGE_STACK ? ((strstr(mapLine, "w-")!=NULL||strstr(mapLine, "wx")!=NULL) && strstr(mapLine, "[stack")!=NULL) : \
		(id) == RANGE_ASHMEM ? ((strstr(mapLine, "w-")!=NULL||strstr(mapLine, "wx")!=NULL) && strstr(mapLine, "xp")==NULL && strstr(mapLine, "/dev/ashmem/")!=NULL && strstr(mapLine,"dalvik")==NULL) : \
		(id) == RANGE_VIDEO ? ((strstr(mapLine, "w-")!=NULL||strstr(mapLine, "wx")!=NULL) && strstr(mapLine, "/dev/mali")!=NULL) : \
		(id) == RANGE_B_BAD ? ( (strstr(mapLine, "kgsl-3d0")!=NULL||strstr(mapLine, ".ttf")!=NULL)) : \
		(id) == RANGE_CODE_APP ? ( (strstr(mapLine, "xp")!=NULL||strstr(mapLine, "--p")!=NULL) && (strstr(mapLine, "/data/app/")!=NULL || strstr(mapLine, "/data/data/")!=NULL || (strstr(mapLine, "/dev/ashmem/")!=NULL&& strstr(mapLine,"dalvik")!=NULL) ||strstr(mapLine, "/data/user/")!=NULL)) : \
		(id) == RANGE_CODE_SYSTEM ? ( (strstr(mapLine, "xp")!=NULL||strstr(mapLine, "--p")!=NULL) && (strstr(mapLine, "/system")!=NULL || strstr(mapLine, "/vendor") !=NULL || strstr(mapLine, "/apex") !=NULL || strstr(mapLine, "/memfd") !=NULL || strstr(mapLine, "[vdso")!=NULL)) : \
		(id) == RANGE_OTHER ? ((strstr(mapLine, "w-")!=NULL||strstr(mapLine, "wx")!=NULL) != NULL && !(strstr(mapLine, "dalvik-") != NULL || strstr(mapLine, "[heap]") != NULL || strstr(mapLine, "[anon:libc_malloc]") != NULL || strstr(mapLine, "[anon:scudo") != NULL || strstr(mapLine, "/data/app/") != NULL || strstr(mapLine, "/data/data/") != NULL || strstr(mapLine, "/data/user/") != NULL || strstr(mapLine, "[anon:.bss]") != NULL || (strchr(mapLine, '[') == NULL && strchr(mapLine, '/') == NULL) || strstr(mapLine, "[stack") != NULL || strstr(mapLine, "/dev/ashmem/") != NULL || strstr(mapLine, "/dev/mali") != NULL || strstr(mapLine, "kgsl-3d0") != NULL || strstr(mapLine, ".ttf") != NULL || strstr(mapLine, "/system") != NULL || strstr(mapLine, "/vendor") != NULL || strstr(mapLine, "/apex") != NULL || strstr(mapLine, "/memfd") != NULL || strstr(mapLine, "[vdso") != NULL)) : \
		true\
	)
#endif
#else //普通
#if defined(__arm__) || defined(__aarch64__) //arm32和arm64架构
#define BCMAPSFLAG(mapLine, id) \
	(\
		(id) == RANGE_ALL ? true: \
		(id) == RANGE_JAVA_HEAP ? (strstr(mapLine, "rw")!=NULL && strstr(mapLine, "dalvik-")!=NULL) : \
		(id) == RANGE_C_HEAP ? (strstr(mapLine, "rw")!=NULL && strstr(mapLine, "[heap]")!=NULL) : \
		(id) == RANGE_C_ALLOC ? (strstr(mapLine, "rw")!=NULL && (strstr(mapLine, "[anon:libc_malloc]")!=NULL || strstr(mapLine,"[anon:scudo")!=NULL)) : \
		(id) == RANGE_C_DATA ? (strstr(mapLine, " r")!=NULL && strstr(mapLine, "xp")==NULL && (strstr(mapLine, "/data/app/")!=NULL || strstr(mapLine, "/data/data/")!=NULL||strstr(mapLine, "/data/user/")!=NULL)) : \
		(id) == RANGE_C_BSS ? (strstr(mapLine, "rw")!=NULL && strstr(mapLine, "[anon:.bss]")!=NULL) : \
		(id) == RANGE_ANONYMOUS ? (strstr(mapLine, "rw")!=NULL && strchr(mapLine, '[') == NULL && strchr(mapLine, '/') == NULL) : \
		(id) == RANGE_JAVA ? (strstr(mapLine, "rw")!=NULL && strstr(mapLine, "dalvik-")!=NULL) : \
		(id) == RANGE_STACK ? (strstr(mapLine, "rw")!=NULL && strstr(mapLine, "[stack")!=NULL) : \
		(id) == RANGE_ASHMEM ? (strstr(mapLine, "rw")!=NULL && strstr(mapLine, "xp")==NULL && strstr(mapLine, "/dev/ashmem/")!=NULL && strstr(mapLine,"dalvik")==NULL) : \
		(id) == RANGE_VIDEO ? (strstr(mapLine, "rw")!=NULL && strstr(mapLine, "/dev/mali")!=NULL) : \
		(id) == RANGE_B_BAD ? (strstr(mapLine, " r")!=NULL && (strstr(mapLine, "kgsl-3d0")!=NULL||strstr(mapLine, ".ttf")!=NULL)) : \
		(id) == RANGE_CODE_APP ? (strstr(mapLine, " r")!=NULL && strstr(mapLine, "xp")!=NULL && (strstr(mapLine, "/data/app/")!=NULL || strstr(mapLine, "/data/data/")!=NULL || (strstr(mapLine, "/dev/ashmem/")!=NULL&& strstr(mapLine,"dalvik")!=NULL) ||strstr(mapLine, "/data/user/")!=NULL)) : \
		(id) == RANGE_CODE_SYSTEM ? (strstr(mapLine, " r")!=NULL && strstr(mapLine, "xp")!=NULL && (strstr(mapLine, "/system")!=NULL || strstr(mapLine, "/vendor") !=NULL || strstr(mapLine, "/apex") !=NULL || strstr(mapLine, "/memfd") !=NULL || strstr(mapLine, "[vdso")!=NULL)) : \
		(id) == RANGE_OTHER ? (strstr(mapLine, "rw")!=NULL && !(strstr(mapLine, "dalvik-")!=NULL||strstr(mapLine, "[heap]")!=NULL||strstr(mapLine, "[anon:libc_malloc]")!=NULL || strstr(mapLine,"[anon:scudo")!=NULL || strstr(mapLine, "/data/app/")!=NULL || strstr(mapLine, "/data/data/")!=NULL ||strstr(mapLine, "/data/user/")!=NULL|| strstr(mapLine, "[anon:.bss]")!=NULL || (strchr(mapLine, '[') == NULL && strchr(mapLine, '/') == NULL) ||strstr(mapLine, "[stack")!=NULL||strstr(mapLine, "/dev/ashmem/")!=NULL||strstr(mapLine, "/dev/mali")!=NULL||strstr(mapLine, "kgsl-3d0")!=NULL||strstr(mapLine, ".ttf")!=NULL||strstr(mapLine, "/system")!=NULL||strstr(mapLine, "/vendor")!=NULL||strstr(mapLine, "/apex")!=NULL||strstr(mapLine, "/memfd")!=NULL||strstr(mapLine, "[vdso")!=NULL)) : \
		true\
	)
#else //x86和x64架构 针对雷电9模拟器《已知bug：cd可能会多搜到一些xa的数据》
#define BCMAPSFLAG(mapLine, id) \
	(\
		(id) == RANGE_ALL ? true: \
		(id) == RANGE_JAVA_HEAP ? (strstr(mapLine, "rw")!=NULL && strstr(mapLine, "dalvik-")!=NULL) : \
		(id) == RANGE_C_HEAP ? (strstr(mapLine, "rw")!=NULL && strstr(mapLine, "[heap]")!=NULL) : \
		(id) == RANGE_C_ALLOC ? (strstr(mapLine, "rw")!=NULL && (strstr(mapLine, "[anon:libc_malloc]")!=NULL || strstr(mapLine,"[anon:scudo")!=NULL)) : \
		(id) == RANGE_C_DATA ? (strstr(mapLine, "rw")!=NULL && strstr(mapLine, "xp")==NULL && (strstr(mapLine, "/data/app/")!=NULL || strstr(mapLine, "/data/data/")!=NULL||strstr(mapLine, "/data/user/")!=NULL)) : \
		(id) == RANGE_C_BSS ? (strstr(mapLine, "rw")!=NULL && strstr(mapLine, "[anon:.bss]")!=NULL) : \
		(id) == RANGE_ANONYMOUS ? (strstr(mapLine, "rw")!=NULL && strchr(mapLine, '[') == NULL && strchr(mapLine, '/') == NULL) : \
		(id) == RANGE_JAVA ? (strstr(mapLine, "rw")!=NULL && strstr(mapLine, "dalvik-")!=NULL) : \
		(id) == RANGE_STACK ? (strstr(mapLine, "rw")!=NULL && strstr(mapLine, "[stack")!=NULL) : \
		(id) == RANGE_ASHMEM ? (strstr(mapLine, "rw")!=NULL && strstr(mapLine, "xp")==NULL && strstr(mapLine, "/dev/ashmem/")!=NULL && strstr(mapLine,"dalvik")==NULL) : \
		(id) == RANGE_VIDEO ? (strstr(mapLine, "rw")!=NULL && strstr(mapLine, "/dev/mali")!=NULL) : \
		(id) == RANGE_B_BAD ? (strstr(mapLine, " r")!=NULL && (strstr(mapLine, "kgsl-3d0")!=NULL||strstr(mapLine, ".ttf")!=NULL)) : \
		(id) == RANGE_CODE_APP ? (strstr(mapLine, " r")!=NULL && (strstr(mapLine, "xp")!=NULL||strstr(mapLine, "--p")!=NULL) && (strstr(mapLine, "/data/app/")!=NULL || strstr(mapLine, "/data/data/")!=NULL || (strstr(mapLine, "/dev/ashmem/")!=NULL&& strstr(mapLine,"dalvik")!=NULL) ||strstr(mapLine, "/data/user/")!=NULL)) : \
		(id) == RANGE_CODE_SYSTEM ? (strstr(mapLine, " r")!=NULL && (strstr(mapLine, "xp")!=NULL||strstr(mapLine, "--p")!=NULL) && (strstr(mapLine, "/system")!=NULL || strstr(mapLine, "/vendor") !=NULL || strstr(mapLine, "/apex") !=NULL || strstr(mapLine, "/memfd") !=NULL || strstr(mapLine, "[vdso")!=NULL)) : \
		(id) == RANGE_OTHER ? (strstr(mapLine, "rw") != NULL && !(strstr(mapLine, "dalvik-") != NULL || strstr(mapLine, "[heap]") != NULL || strstr(mapLine, "[anon:libc_malloc]") != NULL || strstr(mapLine, "[anon:scudo") != NULL || strstr(mapLine, "/data/app/") != NULL || strstr(mapLine, "/data/data/") != NULL || strstr(mapLine, "/data/user/") != NULL || strstr(mapLine, "[anon:.bss]") != NULL || (strchr(mapLine, '[') == NULL && strchr(mapLine, '/') == NULL) || strstr(mapLine, "[stack") != NULL || strstr(mapLine, "/dev/ashmem/") != NULL || strstr(mapLine, "/dev/mali") != NULL || strstr(mapLine, "kgsl-3d0") != NULL || strstr(mapLine, ".ttf") != NULL || strstr(mapLine, "/system") != NULL || strstr(mapLine, "/vendor") != NULL || strstr(mapLine, "/apex") != NULL || strstr(mapLine, "/memfd") != NULL || strstr(mapLine, "[vdso") != NULL)) : \
		true\
	)
#endif
#endif
//(id) == RANGE_OTHER ? (strstr(mapLine, "rw") != NULL && strstr(mapLine, "[anon:mmv8]")!=NULL) : \

//基址头
#define HEAD_XA 0	//xa基址头
#define HEAD_CD 1	//cd基址头
#define HEAD_CB 2	//cb基址头 [bss]

//数据类型
#define TYPE_DWORD 4       // DWORD 类型  -  D类型
#define TYPE_FLOAT 16       // FLOAT 类型  -  F类型
#define TYPE_DOUBLE 64      // DOUBLE 类型  -  E类型
#define TYPE_WORD 2      // WORD 类型  -  W类型
#define TYPE_BYTE 1      // BYTE 类型  -  B类型
#define TYPE_QWORD 32      // QWORD 类型  -  Q类型

//映射数据类型别名 方便管理
#define DWORD int32_t      // 32 位有符号整数
#define FLOAT float        // 单精度浮点数
#define DOUBLE double      // 双精度浮点数
#define WORD signed short		   // 有符号短整型
#define BYTE signed char   // 有符号字符
#define QWORD int64_t      // 64 位有符号整数

//范围搜索格式
#define R_SEPARATE "~"   // 范围搜索符号

//联合搜索格式
#define U_DEFRANGE 512        // 默认搜索附近范围
#define U_SEPARATE ";"        // 数据分隔符
#define U_RANGESEPARATE ":"   // 数据范围符【存在两个此符号将视为按顺序搜索】
#define U_dword "d"      // 32 位有符号整数
#define U_float "f"      // 单精度浮点数
#define U_double "e"     // 双精度浮点数
#define U_word "w"       // 有符号短整型
#define U_byte "b"       // 有符号字符
#define U_qword "q"      // 64 位有符号整数
#define U_DWORD "D"      // 32 位有符号整数的大写
#define U_FLOAT "F"      // 单精度浮点数的大写
#define U_DOUBLE "E"     // 双精度浮点数的大写
#define U_WORD "W"       // 有符号短整型的大写
#define U_BYTE "B"       // 有符号字符的大写
#define U_QWORD "Q"      // 64 位有符号整数的大写

#define FLAG_FREE "FREE" //修改时只进行冻结的标志
//结构体声明：

struct Item;//内存数据项
struct Federated;//联合搜索项

//全局变量
bool isInit = false;//是否进行了初始化
bool isMapsMemArea = false;//是否为自定义内存区域
int pid = -1;//存储进程ID
char* packName;//存储进程包名
int memory = RANGE_ALL;//存储要搜索的内存区域【默认所有内存】
char* memoryMaps;//存储自定义要搜索的内存区域【maps内存段 使用自定义内存区域可以精准搜索并且提升100倍搜索速度】
char memPath[1024];//存储进程mem内存映射虚拟文件路径
char mapsPath[1024];//存储进程maps内存区域映射文件路径
uint32_t freezeDelay = 200;//冻结修改延迟（毫秒）默认200ms
static bool isFreeze;//是否正在冻结 确保只开一个冻结线程
vector < Item > FreezeList;//冻结修改项列表
vector < unsigned long >outcomeList;//最终搜索结果列表 - 存储最终筛选出的数据的内存地址列表
std::mutex lockMutex;//互斥锁 防止全局数据竞争

//函数声明：
//初始化
int getPID(const char* packageName);// 获取进程ID
int setPackageName(const char* packageName);// 设置目标包名 【注意：这是初始化函数，不调用此函数的话其它内存操作均失效】
void setIsSecureWrites(bool sw);// 设置安全写入启用状态


//模块[动/静]态基址偏移内存修改
unsigned long getModuleBaseAddr(const char* module_name, int headType);//获取模块起始地址(基址) 模块名内使用[1]来代表获取第几个模块的基址
unsigned long jump(unsigned long addr,int count);//跳转指针
unsigned long jump32(unsigned long addr);//跳转指针 [32位]
unsigned long jump64(unsigned long addr);//跳转指针 [64位]
int setMemoryAddrValue(const char* value, unsigned long addr, int type, bool isFree);//设置指定内存地址指向的值
char* getMemoryAddrData(unsigned long addr, int type);//获取指定内存地址的数据

//内存搜索
void setMemoryArea(int memoryArea);//设置要搜索的内存区域
void setMemoryArea(const char* memoryArea);//设置自定义搜索的内存区域 好处：能精准找到想要的数据，并且搜索速度直接提升100倍 坏处：需要自己去找数据所在的maps内存段 示例：setMemoryArea("/apex/com.android.tethering/lib64/libframework-connectivity-jni.so");
vector < unsigned long > MemorySearch(const char* value, int type);//内存搜索 【支持范围搜索 格式：最小值~最大值(同GG) 支持联合搜索 格式：值1;值2;值3;n个值:范围 示例：2D;3F;4E:50 或 2D;3F;4E没有范围则使用默认范围,两个范围符::代表按顺序搜索 (同GG)】
vector < unsigned long > MemorySearchRange(const char* value, int type);//范围内存搜索 【格式：最小值~最大值 (同GG)】
vector < unsigned long > MemorySearchUnited(const char* value, int type);//联合内存搜索 【格式：值1;值2;值3;n个值:附近范围 示例：2D;3F;4E:50 或 2D;3F;4E没有范围则使用默认范围,两个范围符::代表按顺序搜索 (同GG) 并且值也支持范围例如1~2;3:64】
vector < unsigned long > ImproveOffset(const char* value, int type, unsigned long offset);//偏移改善 [筛选偏移处特征值 支持联合改善，范围改善]
vector < unsigned long > ImproveOffsetRange(const char* value, int type, unsigned long offset);//偏移范围改善 [筛选偏移处只会在一个范围内变化的特征值] 【格式：最小值~最大值 (同GG)】
vector < unsigned long > ImproveOffsetUnited(const char* value, int type, unsigned long offset);//偏移联合改善 [筛选偏移处永远只会为某些值的特征值] 【格式：值1;值2;n个值; 示例：2D;3F;4E 或 2D;3~6F;9E 注：联合改善不支持附近范围和顺序改善】
vector < unsigned long > ImproveValue(const char* value, int type);//改善 [支持联合改善，范围改善]
int MemoryOffsetWrite(const char* value, int type, unsigned long offset, bool isFree);//结果偏移写入数据
int getResultCount();//获取最终搜索结果数量
vector < unsigned long > getResultList();//获取最终搜索结果列表
int printResultListToFile(const char* filePath);//打印最终搜索结果列表到指定文件
int clearResultList();//清空最终搜索结果列表

//冻结内存修改
vector < Item > getFreezeList();//获取冻结修改项列表
void setFreezeDelayMs(uint32_t delay);//设置冻结修改延迟【毫秒】
int getFreezeNum();//获取冻结修改项数量
int addFreezeItem(const char* value, unsigned long addr, int type);	// 添加一个冻结修改项
int removeFreezeItem(unsigned long addr);	// 移除一个冻结修改项
int removeAllFreezeItem();//移除所有冻结修改项
void* freezeThread(void* arg);		// 冻结循环修改线程
int startAllFreeze();				// 开始冻结所有修改项
int stopAllFreeze();				// 停止冻结所有修改项
int printFreezeListToFile(const char* filePath);//打印冻结列表到指定文件

//获取内存信息相关工具
char* getMemoryAddrMapLine(unsigned long address);//获取指定内存地址的Maps映射行
char* getMapLineMemoryAreaName(const char* mapLine);//获取Maps映射行所在内存区域名称
char* getMemoryAreaIdName(int memid);//获取指定内存id的内存名称
char* getMemoryAreaName();//获取当前内存名称
char* getDataTypeName(int typeId);//获取指定数据类型id的数据类型名称

//完全需要ROOT权限的操作 
//PS：告诉一下菜鸟，这些操作涉及到跨进程和系统操作，所以必须完全ROOT，直装也没用
//--kill--
int killProcess_Root(const char* packageName); // 杀掉指定包名的进程 (此方法对于执行者自身进程无需Root)
int stopProcess_Root(const char* packageName); // 暂停指定包名的进程 (此方法对于执行者自身进程无需Root)
int resumeProcess_Root(const char* packageName); // 恢复被暂停的指定包名的进程 (此方法对于执行者自身进程无需Root)
void killAllInotify_Root(); // 杀掉所有inotify监视器，防止游戏监视文件变化
int killGG_Root(); // 杀掉GG修改器
int killXscript_Root(); // 杀掉XS脚本
//--Other--
int rebootsystem_Root(); // 重启手机
int installapk_Root(const char* apkPackagePath); // 静默安装 指定路径的APK安装包
int uninstallapk_Root(const char* packageName); // 静默卸载 指定包名的APK软件
int Cmd(const char* command);//执行命令
int Cmd_Root(const char* command);//执行超级命令


//2025-2-9 艾琳更新
int getMemoryPage(unsigned long addr,unsigned long* start,int* length);//获取指定内存地址所在内存页
int setAddrVisitP(unsigned long addr,int p);//设置指定内存地址整页的访问权限




//-内部耗时操作
//void __MemorySearch__(const char* value, int type);//内存搜索
//void __MemorySearchRange__(const char* value, int type);//范围内存搜索
//void __MemorySearchUnited__(const char* value, int type);//联合内存搜索
//void __ImproveOffset__(const char* value, int type, unsigned long offset);//偏移改善
//void __ImproveOffsetRange__(const char* value, int type, unsigned long offset);//偏移范围改善
//void __ImproveOffsetUnited__(const char* value, int type, unsigned long offset);//偏移联合改善
//void __ImproveValue__(const char* value, int type);//改善

/// <summary>
/// 内存数据项
/// </summary>
struct Item {
	char* value;//值
	unsigned long addr;//地址
	int type; //类型
};

/// <summary>
/// 联合搜索项
/// </summary>
struct Federated {
	char* value;//搜索值
	int type;//类型
	bool isRange = false;//是否为范围值 例1~20
	char minValue[64 + 2];//最小值（范围值）
	char maxValue[64 + 2];//最大值（范围值）
	/// <summary>
	/// 构造
	/// </summary>
	/// <param name="v">搜索值</param>
	/// <param name="defType">默认类型：如果值没有+类型字母符则使用此默认类型</param>
	Federated(const char* v, int defType) {
		//初始化类型
		if (strstr(v, U_dword) != nullptr || strstr(v, U_DWORD) != nullptr) {
			type = TYPE_DWORD;
		}
		else if (strstr(v, U_float) != nullptr || strstr(v, U_FLOAT) != nullptr) {
			type = TYPE_FLOAT;
		}
		else if (strstr(v, U_double) != nullptr || strstr(v, U_DOUBLE) != nullptr) {
			type = TYPE_DOUBLE;
		}
		else if (strstr(v, U_word) != nullptr || strstr(v, U_WORD) != nullptr) {
			type = TYPE_WORD;
		}
		else if (strstr(v, U_byte) != nullptr || strstr(v, U_BYTE) != nullptr) {
			type = TYPE_BYTE;
		}
		else if (strstr(v, U_qword) != nullptr || strstr(v, U_QWORD) != nullptr) {
			type = TYPE_QWORD;
		}
		else {
			type = defType;
		}

		//初始化值
		value = strdup(v);

		//去除值中的类型字母符
		int j = 0; //用于跟踪新的字符串索引
		for (int i = 0; value[i] != '\0'; i++) {
			//检查当前字符是否为字母
			if (!isalpha(value[i])) {
				//如果不是字母，则将其放到前面
				value[j] = value[i];
				j++;
			}
		}
		value[j] = '\0'; //添加字符串结束符

		//如果是范围值 [这里不要使用strtok来获取 因为如果外部正在使用strtok来初始化时这将影响到外部strtok的分割]
		char* start = strstr(value, R_SEPARATE);
		if (start != NULL) {
			strncpy(minValue, value, start - value); //从开头到分隔符的部分为最小值
			minValue[start - value] = '\0'; //最小值最后的位置添加字符串结束符
			strcpy(maxValue, start + 1); //从分隔符后一个字符开始为最大值
			isRange = true;
		}
	}

};

    //获取指定地址所在内存页
    int getMemoryPage(unsigned long addr,unsigned long* start,size_t* length) {
        int i=-1;
		FILE* maps = fopen(mapsPath, "r");
        if (maps) {
            char mapLine[1024];
            unsigned long startBuff,endBuff;
            while (!feof(maps))
            {
                fgets(mapLine, sizeof(mapLine), maps);
                sscanf(mapLine, "%lx-%lx", &startBuff, &endBuff);
                if (addr >= startBuff && addr <= endBuff) {
                    *start=startBuff;
                    *length = endBuff - startBuff;
                    i=0;
                    break;
                }
            }
            fclose(maps);
        }
        return i;
	}

    //设置指定内存地址的访问权限
    int setAddrVisitP(unsigned long addr,int p){
        unsigned long start;
        size_t len;
        int i = getMemoryPage(addr,&start,&len);
        if(i!=-1){
            mprotect((void*)start, len, p);
            i=0;
        }
        return i;
    }
///// <summary>
///// 内存搜索
///// </summary>
///// <param name="value">搜索值</param>
///// <param name="type">搜索类型</param>
//void MemorySearch(const char* value, int type) {
//	std::thread t([=]() {
//		// 加锁，确保在访问 outcomeList 时是安全的
//		std::lock_guard<std::mutex> lock(lockMutex); //锁定互斥量
//		__MemorySearch__(value, type); // 假设 __MemorySearch__ 函数会操作 outcomeList
//		});
//	t.detach();
//}
//
///// <summary>
///// 内存搜索某个范围区域内的所有值
///// </summary>
///// <param name="value">范围值 格式：10~20</param>
///// <param name="type">搜索类型</param>
//void MemorySearchRange(const char* value, int type) {
//	std::thread t([=]() {
//		std::lock_guard<std::mutex> lock(lockMutex); //锁定互斥量
//		__MemorySearchRange__(value, type);
//		});
//	t.detach();
//}
//
///// <summary>
///// 联合内存搜索 [注意：附近范围某些情况可能会比GG多4~8个字节]
///// </summary>
///// <param name="value">联合搜索值 格式：值1;值2;值3;n个值:附近范围</param>
///// <param name="type">默认联合搜索类型</param>
//void MemorySearchUnited(const char* value, int type) {
//	std::thread t([=]() {
//		std::lock_guard<std::mutex> lock(lockMutex); //锁定互斥量
//		__MemorySearchUnited__(value, type);
//		});
//	t.detach();
//}
//
///// <summary>
///// 从当前搜索结果中 筛选结果附近指定偏移处具有指定特征值的结果
///// </summary>
///// <param name="value">数据附近特征值</param>
///// <param name="type">特征值数据类型</param>
///// <param name="offset">特征值相对主数据的偏移量</param>
//void ImproveOffset(const char* value, int type, unsigned long offset) {
//	std::thread t([=]() {
//		std::lock_guard<std::mutex> lock(lockMutex); //锁定互斥量
//		__ImproveOffset__(value, type, offset);
//		});
//	t.detach();
//}
//
///// <summary>
///// 从当前搜索结果中 筛选指定偏移处的值在这个范围内的结果
///// </summary>
///// <param name="value">范围值[格式：最小~最大]</param>
///// <param name="type">数据类型</param>
//void ImproveOffsetRange(const char* value, int type, unsigned long offset) {
//	std::thread t([=]() {
//		std::lock_guard<std::mutex> lock(lockMutex); //锁定互斥量
//		__ImproveOffsetRange__(value, type, offset);
//		});
//	t.detach();
//}
//
///// <summary>
///// 从当前搜索结果中 筛选指定偏移处的值为联合值中的某一个值的结果
///// </summary>
///// <param name="value">联合筛选值</param>
///// <param name="type">默认类型</param>
//void ImproveOffsetUnited(const char* value, int type, unsigned long offset) {
//	std::thread t([=]() {
//		std::lock_guard<std::mutex> lock(lockMutex); //锁定互斥量
//		__ImproveOffsetUnited__(value, type, offset);
//		});
//	t.detach();
//}
//
///// <summary>
///// 从当前搜索结果中 直接改善 [支持范围改善和联合改善]
///// </summary>
///// <param name="value">改善值</param>
///// <param name="type">默认类型</param>
//void ImproveValue(const char* value, int type) {
//	std::thread t([=]() {
//		std::lock_guard<std::mutex> lock(lockMutex); //锁定互斥量
//		__ImproveValue__(value, type);
//		});
//	t.detach();
//}

/// <summary>
///  通过包名获取进程ID
/// </summary>
/// <param name="packageName">进程APK包名</param>
/// <returns>进程ID</returns>
int getPID(const char* packageName)
{
	int id = -1;           // 进程ID，初始化为-1，表示未找到
	DIR* dir;              // 目录流指针
	FILE* fp;              // 文件指针
	char filename[64];     // 存储/proc/[pid]/cmdline路径
	char cmdline[64];      // 存储进程的命令行信息
	struct dirent* entry; // 目录项结构体，用于存储目录中的条目

	dir = opendir("/proc"); // 打开/proc目录
	if (dir != NULL) {
		while ((entry = readdir(dir)) != NULL) // 遍历/proc目录下的每一个条目
		{
			id = atoi(entry->d_name); // 将条目名转换为进程ID
			if (id >= 0)              // 过滤非进程ID的条目
			{
				sprintf(filename, "/proc/%d/cmdline", id); // 生成进程命令行文件路径
				fp = fopen(filename, "r"); // 打开命令行文件
				if (fp != NULL)
				{
					fgets(cmdline, sizeof(cmdline), fp); // 读取命令行信息
					fclose(fp); // 关闭文件
					if (strcmp(packageName, cmdline) == 0) // 比较包名与命令行信息
					{
						closedir(dir); // 关闭目录
						return id;//找到了
					}
				}
			}
		}
		closedir(dir); // 关闭目录
	}
	return -1;     // 未找到进程，返回-1
}

/// <summary>
/// 设置包名，函数内部将获取该包名的进程ID方便之后操作
/// </summary>
/// <param name="packageName">进程APK包名</param>
/// <returns>进程ID</returns>
int setPackageName(const char* packageName)
{
	pid = getPID(packageName);
	if (pid != -1) {
		sprintf(memPath, "/proc/%d/mem", pid);//初始化构造mem内存文件路径
		sprintf(mapsPath, "/proc/%d/maps", pid);//初始化构造maps内存文件路径
		isInit = true;//进行了初始化
		packName = strdup(packageName);//设置包名
		//outcomeList.reserve(100000000); // 预分配足够的内存
	}
	return pid;
}

/// <summary>
/// 设置安全写入的启用状态
/// </summary>
/// <param name="sw">状态</param>
void setIsSecureWrites(bool sw) {
	//isSecureWrites = sw;
}







/// <summary>
/// 获取动态共享库的基址(起始地址)
/// </summary>
/// <param name="module_name">动态共享库名称(后缀.so文件)</param>
/// <param name="headType">基址头类型</param>
/// <returns>基地址</returns>
unsigned long getModuleBaseAddr(const char* module_name, int headType)
{
	if (!isInit) {
		//未进行初始化
		return 0;
	}

	unsigned long start = 0;//存储获取到的模块的起始地址
    unsigned long end = 0;//存储获取到的模块的结束地址
	
	FILE* fp = fopen(mapsPath, "r");
	if (fp != NULL)
	{
        
    char line[1024];       //存储读取的行
    bool cd = false; //是否开始查询cd
    bool cb = false; //是否开始查询bss
	bool isFoundIt = false;//是否找到
    
    //存储模块名称
    char* mod_name = strdup(module_name);  //复制字符串
    if (mod_name == NULL) {
        perror("strdup failed");
        return 0;
    }
      int whatNumber = 1;//获取第几个模块？
      int index=1;//模块索引
    if (sscanf(mod_name, "%*[^[][%d]%*[^]]", &whatNumber) <=0) { whatNumber=1; }
      
    char *openBracket = strchr(mod_name, '[');
    char *closeBracket = strchr(mod_name, ']');

    if (openBracket && closeBracket && openBracket < closeBracket) {
      
        memmove(openBracket, closeBracket + 1, strlen(closeBracket));
    }

    //检测如果包含:bss则去除
    char* pos = strstr(mod_name, ":bss");
    if (pos != NULL) {
        //如果找到bss
        *pos = '\0';  //将:bss换成字符串中断符进行截断
	}
    
  
		//逐行读取文件
		while (fgets(line, sizeof(line), fp))
		{
			if (isMapsMemArea) {
				//对于自定义内存区域
				if (strstr(line, memoryMaps)) {
					//提取起始地址和结束地址
					sscanf(line, "%lx-%lx", &start, &end);
					break;
				}
			}
			else {
				switch (headType) {
				case HEAD_XA:
				{
					//查找行中是否包含模块名
					if (strstr(line, mod_name) && BCMAPSFLAG(line, RANGE_CODE_APP))
					{
                        if(index!=whatNumber){
                            index++;
                            break;
                        }
						//提取起始地址和结束地址
						sscanf(line, "%lx-%lx", &start, &end);

						//转换特殊地址
						if (start == 0x8000) {
							start = 0;
						}
						isFoundIt = true;//找到了
                        
					}
				}
				break;
				case HEAD_CD:
				{
                    //找到xa之后才开始查询cd
                    if (strstr(line, mod_name) && BCMAPSFLAG(line, RANGE_CODE_APP))
                    {
                        cd = true;
					}
                    if(cd){
                        if (strstr(line, mod_name) && BCMAPSFLAG(line, RANGE_C_DATA))
						{
                            if(index!=whatNumber){
                            index++;
                            break;
                        }
                        //提取起始地址和结束地址
                        sscanf(line, "%lx-%lx", &start, &end);
                        isFoundIt = true;//找到了
                        }
                    }
                 
                }
                break;
                case HEAD_CB:
				{
					//找到xa之后才开始查询bss
					if (strstr(line, mod_name) && BCMAPSFLAG(line, RANGE_CODE_APP))
					{
						cb = true;
					}
					if (cb)
					{
						if (BCMAPSFLAG(line, RANGE_C_BSS))
						{
                              if(index!=whatNumber){
                            index++;
                            break;
                        }
							//提取起始地址和结束地址
							sscanf(line, "%lx-%lx", &start, &end);
							
					        isFoundIt = true;//找到了
								
							
							
						}
					}
				}
				break;
				}
				//检查是否找到
				if (isFoundIt) {
					break;//跳出循环
				}
				
			}
		
		}
		//关闭文件
		fclose(fp);
        //释放模块字符串
	    free(mod_name);
	}
	
	// 返回模块的基地址
	return start;
}

/// <summary>
/// 跳转到指定内存地址的指针
/// </summary>
/// <param name="addr">内存地址</param>
//  <param name="count">要读取的字节数</param>
/// <returns>指针地址</returns>
unsigned long jump(unsigned long addr,int count)
{
	int fd = open(memPath, O_RDONLY);
	if (fd >= 0) {
		unsigned long pAddr=0;
		ssize_t r = pread64(fd, &pAddr, count, addr);
		if(r<0){
		    pAddr = 0;
		}
		close(fd);
		return pAddr;
	}
	return 0;
}
/// <summary>
/// 跳转到指定内存地址的指针【32位】
/// </summary>
/// <param name="addr">内存地址</param>
/// <returns>指针地址</returns>
unsigned long jump32(unsigned long addr)
{
	return jump(addr,4);//读取4字节
}
/// <summary>
/// 跳转到指定内存地址的指针【64位】
/// </summary>
/// <param name="addr">内存地址</param>
/// <returns>指针地址</returns>
unsigned long jump64(unsigned long addr)
{
	return jump(addr,8);//读取8字节
}


/// <summary>
/// 设置指定内存地址指向的值
/// </summary>
/// <param name="value">设置的值</param>
/// <param name="addr">内存地址</param>
/// <param name="type">数据类型</param>
/// <param name="isFree">是否冻结</param>
/// <returns>设置成功与否</returns>
int setMemoryAddrValue(const char* value, unsigned long addr, int type, bool isFree)
{
	if (!isInit) {
		//未进行初始化
		return -1;
	}
	if (isSecureWrites) {
       setAddrVisitP(addr,6);
    }   
	//是否冻结修改
	if (isFree) {
		addFreezeItem(value, addr, type);//添加一个冻结修改项目
		startAllFreeze();//开始冻结
		return 0;
	}
	else {
		int fd = open(memPath, O_RDWR | O_SYNC);
		//打开maps文件
		FILE* maps = fopen(mapsPath, "r");
		if (fd >= 0 && maps) {
            
			switch (type)
			{
			case TYPE_DWORD:
			{
				DWORD v = atoi(value);
				pwrite64(fd, &v, sizeof(DWORD), addr);
			}
			break;
			case TYPE_FLOAT:
			{
				FLOAT v = atof(value);
				pwrite64(fd, &v, sizeof(FLOAT), addr);
			}
			break;
			case TYPE_DOUBLE:
			{
				DOUBLE v = strtod(value, NULL);
				pwrite64(fd, &v, sizeof(DOUBLE), addr);
			}
			break;
			case TYPE_QWORD:
			{
				QWORD v = atoll(value);
				pwrite64(fd, &v, sizeof(QWORD), addr);
			}
			break;
			case TYPE_WORD:
			{
				WORD v = (WORD)atoi(value);
				pwrite64(fd, &v, sizeof(WORD), addr);
			}
			break;
			case TYPE_BYTE:
			{
				BYTE v = (BYTE)atoi(value);
				pwrite64(fd, &v, sizeof(BYTE), addr);
			}
			break;
			}
            
		}
		if (fd >= 0) {
			close(fd);
		}

		if (maps) {
			fclose(maps);
		}
		removeFreezeItem(addr);//移除这个冻结修改项目（如果存在）
		return 0;
	}


	return -1;
}

/// <summary>
/// 获取指定内存地址的数据
/// </summary>
/// <param name="addr">内存地址</param>
/// <param name="type">数据类型</param>
/// <returns>获取到的数据[指针记得用完调用free释放]</returns>
char* getMemoryAddrData(unsigned long addr, int type)
{
	if (!isInit) {
		//未进行初始化
		return "NULL";
	}

	int fd = open(memPath, O_RDONLY);
	if (fd >= 0) {
		int size = -1;
		void* buff;
		char* value = "NULL";

		switch (type)
		{
		case TYPE_DWORD:
		{
			size = sizeof(DWORD);//存储要读取的字节数
			buff = (void*)malloc(size);//分配一块内存来存储读取到的数据
			pread64(fd, buff, size, addr);//从mem文件指定内存地址读取数据到buff
			DWORD v = *(DWORD*)buff;//解析获取到的数据
			int len = snprintf(NULL, 0, "%d", v);//获取数据的字符长度
			value = (char*)malloc(len + 1);//字符串动态分配足够内存来存储数据 确保能足够存储数据的字符数量
			sprintf(value, "%d", v);//将数据格式化为字符串
		}
		break;
		case TYPE_FLOAT:
		{
			size = sizeof(FLOAT);
			buff = (void*)malloc(size);
			pread64(fd, buff, size, addr);
			FLOAT v = *(FLOAT*)buff;
			int len = snprintf(NULL, 0, "%f", v);
			value = (char*)malloc(len + 1);
			sprintf(value, "%f", v);
			//检测是否需要使用科学记数法来格式化
			bool isScience = true;
			for (int i = 0; i < len; i++) {
				if (value[i] == '.' || value[i] == '-') {
					continue;
				}
				if (value[i] != '0') {
					isScience = false;
				}
			}
			if (isScience) {
				sprintf(value, "%.8e", v);
			}
			if (strstr(value, "nan")) {
				value = "NaN";
			}
		}
		break;
		case TYPE_DOUBLE:
		{
			size = sizeof(DOUBLE);
			buff = (void*)malloc(size);
			pread64(fd, buff, size, addr);
			DOUBLE v = *(DOUBLE*)buff;
			int len = snprintf(NULL, 0, "%f", v);
			value = (char*)malloc(len + 1);
			sprintf(value, "%f", v);
			//检测是否需要使用科学记数法来格式化
			bool isScience = true;
			if (len < 20) {
				for (int i = 0; i < len; i++) {
					if (value[i] == '.' || value[i] == '-') {
						continue;
					}
					if (value[i] != '0') {
						isScience = false;
					}
				}
			}
			if (isScience) {
				sprintf(value, "%.8e", v);
			}
			if (strstr(value, "nan")) {
				value = "NaN";
			}
		}
		break;
		case TYPE_QWORD:
		{
			size = sizeof(QWORD);
			buff = (void*)malloc(size);
			pread64(fd, buff, size, addr);
			QWORD v = *(QWORD*)buff;
			int len = snprintf(NULL, 0, "%lld", v);
			value = (char*)malloc(len + 1);
			sprintf(value, "%lld", v);
		}
		break;
		case TYPE_WORD:
		{
			size = sizeof(WORD);
			buff = (void*)malloc(size);
			pread64(fd, buff, size, addr);
			WORD v = *(WORD*)buff;
			int len = snprintf(NULL, 0, "%d", v);
			value = (char*)malloc(len + 1);
			sprintf(value, "%d", v);
		}
		break;
		case TYPE_BYTE:
		{
			size = sizeof(BYTE);
			buff = (void*)malloc(size);
			pread64(fd, buff, size, addr);
			BYTE v = *(BYTE*)buff;
			int len = snprintf(NULL, 0, "%d", v);
			value = (char*)malloc(len + 1);
			sprintf(value, "%d", v);
		}
		break;
		}

		close(fd);
		if (buff != NULL) {
			free(buff);
		}
		return value;
	}
	return "NULL";
}


/// <summary>
/// 设置要搜索的内存区域，初始化内存区域方便之后内存搜索
/// </summary>
/// <param name="memoryArea">内存区域</param>
void setMemoryArea(int memoryArea)
{
	memory = memoryArea;
	isMapsMemArea = false;
}
/// <summary>
/// 设置自定义内存区域 好处：能精准找到想要的数据，并且搜索速度直接提升100倍 坏处：需要自己去找数据所在的maps内存段 示例：setMemoryArea("/apex/com.android.tethering/lib64/libframework-connectivity-jni.so");
/// </summary>
/// <param name="memoryArea">maps内存段</param>
void setMemoryArea(const char* memoryArea)
{
	memoryMaps = strdup(memoryArea);
	isMapsMemArea = true;
}
/// <summary>
/// 内存搜索
/// </summary>
/// <param name="value">搜索值</param>
/// <param name="type">搜索类型</param>
/// <returns>搜索结果列表</returns>
vector < unsigned long > MemorySearch(const char* value, int type)
{
	//如果包含分隔符则使用联合搜索
	if (strstr(value, U_SEPARATE)) {
		return MemorySearchUnited(value, type);
	}
	//如果包含范围则使用范围搜索
	if (strstr(value, R_SEPARATE) && !strstr(value, U_SEPARATE)) {
		return MemorySearchRange(value, type);
	}

	if (isInit) {
		//只读打开mem内存文件
		int mem = open(memPath, O_RDONLY);
		//只读打开maps内存映射文件
		FILE* maps = fopen(mapsPath, "r");
		if (mem >= 0 && maps)
		{

			//清空搜索结果列表
			//clearResultList();

			char mapLine[1024];  //用于存储每行读取到的信息
			unsigned long start; //存储内存起始地址
			unsigned long end;   //存储内存结束地址
			//逐行读取maps文件每行信息
			while (fgets(mapLine, sizeof(mapLine), maps))
			{
				//如果当前行匹配内存标志则进行搜索
				if (BCMAPSFLAG(mapLine, memory))
				{
					//从该行中解析出内存区域的起始和结束地址
					sscanf(mapLine, "%lx-%lx", &start, &end);
					int size = end - start; //计算内存区域的大小
					void* buf = (void*)malloc(size);//存储指向起始地址的指针
					int ret = pread64(mem, buf, size, start);//buf指向起始地址
					switch (type)
					{
					case TYPE_DWORD:
					{
						DWORD v = atoi(value);//存储要搜索的数值
						int increment = sizeof(DWORD);//偏移增量
						if (ret == size)
						{
							int index = 0;//存储偏移
							while (index < size)
							{
								//如果当前buf+偏移中的数据等于要查找的数据则将该地址加入搜索结果列表中
								if (*(DWORD*)((char*)buf + index) == v)
								{
									outcomeList.push_back(start + index);
								}
								index += increment;//偏移移动到下一个位置
							}
						}
					}
					break;
					case TYPE_FLOAT:
					{
						FLOAT v = atof(value);
						int increment = sizeof(FLOAT);//偏移增量
						if (ret == size)
						{
							int index = 0;//存储偏移
							while (index < size)
							{
								//如果当前buf+偏移中的数据等于要查找的数据则将该地址加入搜索结果列表中
								if (*(FLOAT*)((char*)buf + index) == v)
								{
									outcomeList.push_back(start + index);
								}
								index += increment;//偏移移动到下一个位置
							}
						}
					}
					break;
					case TYPE_DOUBLE:
					{
						DOUBLE v = strtod(value, NULL);
						//DOUBLE v = atof(value);
						int increment = sizeof(DOUBLE);//偏移增量
						if (ret == size)
						{
							int index = 0;//存储偏移
							while (index < size)
							{
								//如果当前buf+偏移中的数据等于要查找的数据则将该地址加入搜索结果列表中
								if (*(DOUBLE*)((char*)buf + index) == v)
								{
									outcomeList.push_back(start + index);
								}
								index += increment;//偏移移动到下一个位置
							}
						}
					}
					break;
					case TYPE_QWORD:
					{
						QWORD v = atoll(value);
						int increment = sizeof(QWORD);//偏移增量
						if (ret == size)
						{
							int index = 0;//存储偏移
							while (index < size)
							{
								//如果当前buf+偏移中的数据等于要查找的数据则将该地址加入搜索结果列表中
								if (*(QWORD*)((char*)buf + index) == v)
								{
									outcomeList.push_back(start + index);
								}
								index += increment;//偏移移动到下一个位置
							}
						}
					}
					break;
					case TYPE_WORD:
					{
						WORD v = (WORD)atoi(value);
						int increment = sizeof(WORD);//偏移增量
						if (ret == size)
						{
							int index = 0;//存储偏移
							while (index < size)
							{
								//如果当前buf+偏移中的数据等于要查找的数据则将该地址加入搜索结果列表中
								if (*(WORD*)((char*)buf + index) == v)
								{
									outcomeList.push_back(start + index);
								}
								index += increment;//偏移移动到下一个位置
							}
						}
					}
					break;
					case TYPE_BYTE:
					{
						BYTE v = (BYTE)atoi(value);
						int increment = sizeof(BYTE);//偏移增量
						if (ret == size)
						{
							int index = 0;//存储偏移
							while (index < size)
							{
								//如果当前buf+偏移中的数据等于要查找的数据则将该地址加入搜索结果列表中
								if (*(BYTE*)((char*)buf + index) == v)
								{
									outcomeList.push_back(start + index);
								}
								index += increment;//偏移移动到下一个位置
							}
						}
					}
					break;
					}
					if (buf != NULL) {
						free(buf);
					}
				}
			}
		}
		if (mem >= 0) {
			close(mem);
		}

		if (maps) {
			fclose(maps);
		}
	}
	return outcomeList;
}

/// <summary>
/// 内存搜索某个范围区域内的所有值
/// </summary>
/// <param name="value">范围值 格式：10~20</param>
/// <param name="type">搜索类型</param>
/// <returns>搜索结果列表</returns>
vector < unsigned long > MemorySearchRange(const char* value, int type)
{
	if (isInit) {
		//只读打开mem内存文件
		int mem = open(memPath, O_RDONLY);
		//只读打开maps内存映射文件
		FILE* maps = fopen(mapsPath, "r");
		if (mem >= 0 && maps)
		{
			//清空搜索结果列表
			//clearResultList();
			//outcomeList.reserve(100000000); // 预分配足够的内存
			char mapLine[1024];  //用于存储每行读取到的信息
			unsigned long start; //存储内存起始地址
			unsigned long end;   //存储内存结束地址
			char formatString[50]; //存储格式规则

			//逐行读取maps每一行
			while (fgets(mapLine, sizeof(mapLine), maps))
			{
				//如果当前行匹配内存标志则进行搜索
				if (BCMAPSFLAG(mapLine, memory))
				{
					//从该行中解析出内存区域的起始和结束地址
					sscanf(mapLine, "%lx-%lx", &start, &end);
					int size = end - start; //计算内存区域的大小
					void* buf = (void*)malloc(size);//存储指向起始地址的指针
					int ret = pread64(mem, buf, size, start);//buf指向起始地址
					switch (type)
					{
					case TYPE_DWORD:
					{
						DWORD minv, maxv;//存储最小值和最大值
						sprintf(formatString, "%s%s%s", "%d", R_SEPARATE, "%d");
						sscanf(value, formatString, &minv, &maxv);//解析范围值
						int increment = sizeof(DWORD);//偏移增量
						if (ret == size)
						{
							int index = 0;//存储偏移
							while (index < size)
							{
								DWORD v = *(DWORD*)((char*)buf + index);
								//如果这个数据大于等于最小值并且小于等于最大值的话就加入最终搜索结果列表
								if (v >= minv && v <= maxv) {
									outcomeList.push_back(start + index);//添加几千万以上大量数据时可能会影响性能
								}
								index += increment;//偏移移动到下一个位置
							}
						}
					}
					break;
					case TYPE_FLOAT:
					{
						FLOAT minv, maxv;//存储最小值和最大值
						sprintf(formatString, "%s%s%s", "%f", R_SEPARATE, "%f");
						sscanf(value, formatString, &minv, &maxv);//解析范围值
						int increment = sizeof(FLOAT);//偏移增量
						if (ret == size)
						{
							int index = 0;//存储偏移
							while (index < size)
							{
								FLOAT v = *(FLOAT*)((char*)buf + index);
								//如果这个数据大于等于最小值并且小于等于最大值的话就加入最终搜索结果列表
								if (v >= minv && v <= maxv) {
									outcomeList.push_back(start + index);
								}
								index += increment;//偏移移动到下一个位置
							}
						}
					}
					break;
					case TYPE_DOUBLE:
					{
						DOUBLE minv, maxv;//存储最小值和最大值
						sprintf(formatString, "%s%s%s", "%f", R_SEPARATE, "%f");
						sscanf(value, formatString, &minv, &maxv);//解析范围值
						int increment = sizeof(DOUBLE);//偏移增量
						if (ret == size)
						{
							int index = 0;//存储偏移
							while (index < size)
							{
								DOUBLE v = *(DOUBLE*)((char*)buf + index);
								//如果这个数据大于等于最小值并且小于等于最大值的话就加入最终搜索结果列表
								if (v >= minv && v <= maxv) {
									outcomeList.push_back(start + index);
								}
								index += increment;//偏移移动到下一个位置
							}
						}
					}
					break;
					case TYPE_QWORD:
					{
						QWORD minv, maxv;//存储最小值和最大值
						sprintf(formatString, "%s%s%s", "%lld", R_SEPARATE, "%lld");
						sscanf(value, formatString, &minv, &maxv);//解析范围值
						int increment = sizeof(QWORD);//偏移增量
						if (ret == size)
						{
							int index = 0;//存储偏移
							while (index < size)
							{
								QWORD v = *(QWORD*)((char*)buf + index);
								//如果这个数据大于等于最小值并且小于等于最大值的话就加入最终搜索结果列表
								if (v >= minv && v <= maxv) {
									outcomeList.push_back(start + index);
								}
								index += increment;//偏移移动到下一个位置
							}
						}
					}
					break;
					case TYPE_WORD:
					{
						WORD minv, maxv;//存储最小值和最大值
						sprintf(formatString, "%s%s%s", "%d", R_SEPARATE, "%d");
						sscanf(value, formatString, &minv, &maxv);//解析范围值
						int increment = sizeof(WORD);//偏移增量
						if (ret == size)
						{
							int index = 0;//存储偏移
							while (index < size)
							{
								WORD v = *(WORD*)((char*)buf + index);
								//如果这个数据大于等于最小值并且小于等于最大值的话就加入最终搜索结果列表
								if (v >= minv && v <= maxv) {
									outcomeList.push_back(start + index);
								}
								index += increment;//偏移移动到下一个位置
							}
						}
					}
					break;
					case TYPE_BYTE:
					{
						BYTE minv, maxv;//存储最小值和最大值
						sprintf(formatString, "%s%s%s", "%d", R_SEPARATE, "%d");
						sscanf(value, formatString, &minv, &maxv);//解析范围值
						int increment = sizeof(BYTE);//偏移增量
						if (ret == size)
						{
							int index = 0;//存储偏移
							while (index < size)
							{
								BYTE v = *(BYTE*)((char*)buf + index);
								//如果这个数据大于等于最小值并且小于等于最大值的话就加入最终搜索结果列表
								if (v >= minv && v <= maxv) {
									outcomeList.push_back(start + index);
								}
								index += increment;//偏移移动到下一个位置
							}
						}
					}
					break;
					}
					if (buf != NULL) {
						free(buf);
					}

				}
			}
		}
		if (mem >= 0) {
			close(mem);
		}

		if (maps) {
			fclose(maps);
		}
	}
	return outcomeList;
}



/// <summary>
/// 联合内存搜索 建议第一个值为搜索出来很少的值 因为第一个值决定了搜索速度 [注意：附近范围某些情况可能会比GG多4~8个字节 比如对于1~2;5:50这种情况gg的联合范围搜索只能按顺序 而这里是不按顺序的 对于联合范围加上::按顺序搜索就和GG联合范围一致了]
/// </summary>
/// <param name="value">联合搜索值 格式：值1;值2;值3;n个值:附近范围 (没有范围则使用默认范围 两个范围符::代表按顺序搜索) 示例：7F;2D;3E:30 或 7F;2D;3E(未设置范围则使用默认范围) 并且值也支持范围例如1~2;3:64</param>
/// <param name="type">默认联合搜索类型：对于未加类型符的值将使用此类型 例如1D;2;3E中的2将使用此类型</param>
/// <returns>搜索结果</returns>
vector < unsigned long > MemorySearchUnited(const char* value, int type) {
	if (isInit) {
		//LOGD("联合调试", "start");
		char* valueCopy = strdup(value);//创建副本内存因为之后要进行修改传入的字符串
		bool isOrder = false;//默认不按顺序搜索

		//获取联合搜索范围（如果存在）
		int unitedRange = U_DEFRANGE;//存储联合搜索范围
		char* colonPtr = strstr(valueCopy, U_RANGESEPARATE); //查找第一个范围字符的位置
		if (colonPtr != NULL) {
			//如果存在范围字符则保存范围字符后的所有数字作为联合搜索范围
			unitedRange = atoi(colonPtr + 1);
			//如果atoi返回的是0代表存在非数字字符(对于::100按顺序搜索的情况)
			if (unitedRange == 0) {
				isOrder = true;//是按顺序搜索
				unitedRange = atoi(colonPtr + 2);
				//如果在范围符后面第二个位置开始使用atoi转换时还是为0代表没有范围使用默认范围(对于::的情况)
				if (unitedRange == 0) {
					unitedRange = U_DEFRANGE;
				}
			}
			*colonPtr = '\0';//截断原始字符串的范围值部分
		}


		//获取联合搜索数值到列表
		vector < Federated > valueList; //存储分割出的所有数值的列表
		//获取第一个分割部分
		const char* token = strtok(valueCopy, U_SEPARATE);
		//逐个获取剩余的分割部分
		while (token != NULL) {
			valueList.emplace_back(token, type);  //保存分割出的值
			token = strtok(NULL, U_SEPARATE);  // 获取下一个分割部分
		}

		//开始联合搜索
		if (!valueList.empty()) {
			///先搜第一个值的内存地址 作为起始地址 [如果第一个值是范围值内部将自动进行范围搜索这里无需判断]
			MemorySearch(valueList[0].value, valueList[0].type);
			//搜索剩余值
			//打开mem内存文件
			int mem = open(memPath, O_RDONLY);
			if (mem >= 0) {
				vector < unsigned long >offsetFilterResults;
				for (int i = 0; i < outcomeList.size(); i++)
				{
					vector < Item > results;//存储当前起始地址附近找到的值列表
					//开始查找当前起始地址附近的值
					for (int j = 0; j < valueList.size(); j++)
					{
						switch (valueList[j].type)
						{
						case TYPE_DWORD:
						{
							DWORD v;
							DWORD minv;
							DWORD maxv;
							if (valueList[j].isRange) {
								minv = atoi(valueList[j].minValue);
								maxv = atoi(valueList[j].maxValue);
							}
							else {
								v = atoi(valueList[j].value);
							}
							int size = sizeof(DWORD);
							void* buf = (void*)malloc(size);
							int range = unitedRange;
							//范围根据数据类型自动对齐
							if (range % size != 0) {
								range = range + (size - (range % size));
							}
							int offset = 0;
							if (!isOrder) {
								offset = -range;
							}

							while (offset < range)
							{
								int ret = pread64(mem, buf, size, outcomeList[i] + offset);
								if (ret == size)
								{
									DWORD eV = *(DWORD*)buf;
									if (valueList[j].isRange) {
										//对于范围
										if (eV >= minv && eV <= maxv)
										{
											//goto add;
											Item table;
											table.value = strdup(valueList[j].value);
											table.addr = outcomeList[i] + offset;
											table.type = valueList[j].type;
											results.push_back(table);
											//break;
										}
									}
									else {
										//对于单值
										if (eV == v)
										{
											//add:
											Item table;
											table.value = strdup(valueList[j].value);
											table.addr = outcomeList[i] + offset;
											table.type = valueList[j].type;
											results.push_back(table);
											//break;
										}
									}

								}
								offset += size;
							}
							free(buf);
						}
						break;
						case TYPE_FLOAT:
						{
							FLOAT v;
							FLOAT minv;
							FLOAT maxv;
							if (valueList[j].isRange) {
								minv = atof(valueList[j].minValue);
								maxv = atof(valueList[j].maxValue);
							}
							else {
								v = atof(valueList[j].value);
							}
							int size = sizeof(FLOAT);
							void* buf = (void*)malloc(size);
							int range = unitedRange;
							//范围根据数据类型自动对齐
							if (range % size != 0) {
								range = range + (size - (range % size));
							}
							int offset = 0;
							if (!isOrder) {
								offset = -range;
							}

							while (offset < range)
							{
								int ret = pread64(mem, buf, size, outcomeList[i] + offset);
								if (ret == size)
								{
									FLOAT eV = *(FLOAT*)buf;
									if (valueList[j].isRange) {
										//对于范围
										if (eV >= minv && eV <= maxv)
										{
											//goto add;
											Item table;
											table.value = strdup(valueList[j].value);
											table.addr = outcomeList[i] + offset;
											table.type = valueList[j].type;
											results.push_back(table);
											//break;
										}
									}
									else {
										//对于单值
										if (eV == v)
										{
											//add:
											Item table;
											table.value = strdup(valueList[j].value);
											table.addr = outcomeList[i] + offset;
											table.type = valueList[j].type;
											results.push_back(table);
											//break;
										}
									}
								}
								offset += size;
							}
							free(buf);
						}
						break;
						case TYPE_DOUBLE:
						{
							DOUBLE v;
							DOUBLE minv;
							DOUBLE maxv;
							if (valueList[j].isRange) {
								minv = strtod(valueList[j].minValue, NULL);
								maxv = strtod(valueList[j].maxValue, NULL);
							}
							else {
								v = strtod(valueList[j].value, NULL);
							}
							int size = sizeof(DOUBLE);
							void* buf = (void*)malloc(size);
							int range = unitedRange;
							//范围根据数据类型自动对齐
							if (range % size != 0) {
								range = range + (size - (range % size));
							}
							int offset = 0;
							if (!isOrder) {
								offset = -range;
							}

							while (offset < range)
							{
								int ret = pread64(mem, buf, size, outcomeList[i] + offset);
								if (ret == size)
								{
									DOUBLE eV = *(DOUBLE*)buf;
									if (valueList[j].isRange) {
										//对于范围
										if (eV >= minv && eV <= maxv)
										{
											//goto add;
											Item table;
											table.value = strdup(valueList[j].value);
											table.addr = outcomeList[i] + offset;
											table.type = valueList[j].type;
											results.push_back(table);
											//break;
										}
									}
									else {
										//对于单值
										if (eV == v)
										{
											//add:
											Item table;
											table.value = strdup(valueList[j].value);
											table.addr = outcomeList[i] + offset;
											table.type = valueList[j].type;
											results.push_back(table);
											//break;
										}
									}
								}
								offset += size;
							}
							free(buf);
						}
						break;
						case TYPE_QWORD:
						{
							QWORD v;
							QWORD minv;
							QWORD maxv;
							if (valueList[j].isRange) {
								minv = atoll(valueList[j].minValue);
								maxv = atoll(valueList[j].maxValue);
							}
							else {
								v = atoll(valueList[j].value);
							}
							int size = sizeof(QWORD);
							void* buf = (void*)malloc(size);
							int range = unitedRange;
							//范围根据数据类型自动对齐
							if (range % size != 0) {
								range = range + (size - (range % size));
							}
							int offset = 0;
							if (!isOrder) {
								offset = -range;
							}

							while (offset < range)
							{
								int ret = pread64(mem, buf, size, outcomeList[i] + offset);
								if (ret == size)
								{
									QWORD eV = *(QWORD*)buf;
									if (valueList[j].isRange) {
										//对于范围
										if (eV >= minv && eV <= maxv)
										{
											//goto add;
											Item table;
											table.value = strdup(valueList[j].value);
											table.addr = outcomeList[i] + offset;
											table.type = valueList[j].type;
											results.push_back(table);
											//break;
										}
									}
									else {
										//对于单值
										if (eV == v)
										{
											//add:
											Item table;
											table.value = strdup(valueList[j].value);
											table.addr = outcomeList[i] + offset;
											table.type = valueList[j].type;
											results.push_back(table);
											//break;
										}
									}
								}
								offset += size;
							}
							free(buf);
						}
						break;
						case TYPE_WORD:
						{
							WORD v;
							WORD minv;
							WORD maxv;
							if (valueList[j].isRange) {
								minv = (WORD)atoi(valueList[j].minValue);
								maxv = (WORD)atoi(valueList[j].maxValue);
							}
							else {
								v = (WORD)atoi(valueList[j].value);
							}
							int size = sizeof(WORD);
							void* buf = (void*)malloc(size);
							int range = unitedRange;
							//范围根据数据类型自动对齐
							if (range % size != 0) {
								range = range + (size - (range % size));
							}
							int offset = 0;
							if (!isOrder) {
								offset = -range;
							}

							while (offset < range)
							{
								int ret = pread64(mem, buf, size, outcomeList[i] + offset);
								if (ret == size)
								{
									WORD eV = *(WORD*)buf;
									if (valueList[j].isRange) {
										//对于范围
										if (eV >= minv && eV <= maxv)
										{
											//goto add;
											Item table;
											table.value = strdup(valueList[j].value);
											table.addr = outcomeList[i] + offset;
											table.type = valueList[j].type;
											results.push_back(table);
											//break;
										}
									}
									else {
										//对于单值
										if (eV == v)
										{
											//add:
											Item table;
											table.value = strdup(valueList[j].value);
											table.addr = outcomeList[i] + offset;
											table.type = valueList[j].type;
											results.push_back(table);
											//break;
										}
									}
								}
								offset += size;
							}
							free(buf);
						}
						break;
						case TYPE_BYTE:
						{
							BYTE v;
							BYTE minv;
							BYTE maxv;
							if (valueList[j].isRange) {
								minv = (BYTE)atoi(valueList[j].minValue);
								maxv = (BYTE)atoi(valueList[j].maxValue);
							}
							else {
								v = (BYTE)atoi(valueList[j].value);
							}
							int size = sizeof(BYTE);
							void* buf = (void*)malloc(size);
							int range = unitedRange;
							//范围根据数据类型自动对齐
							if (range % size != 0) {
								range = range + (size - (range % size));
							}
							int offset = 0;
							if (!isOrder) {
								offset = -range;
							}

							while (offset < range)
							{
								int ret = pread64(mem, buf, size, outcomeList[i] + offset);
								if (ret == size)
								{
									BYTE eV = *(BYTE*)buf;
									if (valueList[j].isRange) {
										//对于范围
										if (eV >= minv && eV <= maxv)
										{
											//goto add;
											Item table;
											table.value = strdup(valueList[j].value);
											table.addr = outcomeList[i] + offset;
											table.type = valueList[j].type;
											results.push_back(table);
											//break;
										}
									}
									else {
										//对于单值
										if (eV == v)
										{
											//add:
											Item table;
											table.value = strdup(valueList[j].value);
											table.addr = outcomeList[i] + offset;
											table.type = valueList[j].type;
											results.push_back(table);
											//break;
										}
									}
								}
								offset += size;
							}
							free(buf);
						}
						break;
						}
					}

					if (results.size() >= valueList.size()) {
						//检查当前找到的附近值向量中是否包含搜索值向量中的所有元素 （包含所有才添加到结果）
						bool isAdd = true;
						for (int i = 0; i < valueList.size(); i++)
						{
							bool found = false;
							for (int j = 0; j < results.size(); j++)
							{
								if (strcmp(results[j].value, valueList[i].value) == 0) {
									found = true;
									break;
								}
							}
							if (!found) {
								isAdd = false;
								break;
							}
						}

						if (isAdd) {
							for (int h = 0; h < results.size(); h++)
							{
								//防止重复添加
								if (find(offsetFilterResults.begin(), offsetFilterResults.end(), results[h].addr) == offsetFilterResults.end()) {
									//if (labs(outcomeList[i] - results[h]) <= unitedRange) {
									offsetFilterResults.push_back(results[h].addr);
									//}
								}
							}
						}
					}
				}

				close(mem);
				//筛选完成则清空最终筛选结果列表
				outcomeList.clear();
				//将新筛选出的结果列表添加进最终筛选结果列表
				for (int i = 0; i < offsetFilterResults.size(); i++)
				{
					outcomeList.push_back(offsetFilterResults[i]);
				}
				//升序排序结果
				sort(outcomeList.begin(), outcomeList.end());
			}
		}
		free(valueCopy); //释放副本内存
	}
	return outcomeList;
}



/// <summary>
/// 从当前搜索结果中 筛选结果附近指定偏移处具有指定特征值的结果 [支持范围改善,联合改善]
/// </summary>
/// <param name="value">数据附近特征值</param>
/// <param name="type">特征值数据类型</param>
/// <param name="offset">特征值相对主数据的偏移量</param>
/// <returns>最终筛选结果列表</returns>
vector < unsigned long > ImproveOffset(const char* value, int type, unsigned long offset)
{
	if (isInit) {
		//如果包含分隔符则使用偏移联合改善
		if (strstr(value, U_SEPARATE)) {
			return ImproveOffsetUnited(value, type, offset);
		}
		//如果包含范围则使用偏移范围改善
		if (strstr(value, R_SEPARATE) && !strstr(value, U_SEPARATE)) {
			return ImproveOffsetRange(value, type, offset);
		}
		vector < unsigned long >offsetFilterResults;//临时筛选结果列表 - 临时存储当前偏移筛选出的附近拥有特征值的数据
		int fd = open(memPath, O_RDONLY);
		if (fd >= 0)
		{
			switch (type)
			{
			case TYPE_DWORD:
			{
				DWORD v = atoi(value);
				int size = sizeof(DWORD);
				void* buf = (void*)malloc(size);
				//遍历搜索到的数据的内存地址列表
				for (int i = 0; i < outcomeList.size(); i++)
				{
					//检查这个从内存地址偏移[offset]之后的内存地址指向的值是否为v
					int ret = pread64(fd, buf, size, outcomeList[i] + offset);
					if (ret == size)
					{
						if (*(DWORD*)buf == v)
						{
							//如果匹配成功则将这个内存地址添加进偏移筛选结果列表
							offsetFilterResults.push_back(outcomeList[i]);
						}
					}
				}
				free(buf);
			}
			break;
			case TYPE_FLOAT:
			{
				FLOAT v = atof(value);
				int size = sizeof(FLOAT);
				void* buf = (void*)malloc(size);
				//遍历搜索到的数据的内存地址列表
				for (int i = 0; i < outcomeList.size(); i++)
				{
					//检查这个从内存地址偏移[offset]之后的内存地址指向的值是否为v
					int ret = pread64(fd, buf, size, outcomeList[i] + offset);
					if (ret == size)
					{
						if (*(FLOAT*)buf == v)
						{
							//如果匹配成功则将这个内存地址添加进偏移筛选结果列表
							offsetFilterResults.push_back(outcomeList[i]);
						}
					}
				}
				free(buf);
			}
			break;
			case TYPE_DOUBLE:
			{
				DOUBLE v = strtod(value, NULL);
				int size = sizeof(DOUBLE);
				void* buf = (void*)malloc(size);
				//遍历搜索到的数据的内存地址列表
				for (int i = 0; i < outcomeList.size(); i++)
				{
					//检查这个从内存地址偏移[offset]之后的内存地址指向的值是否为v
					int ret = pread64(fd, buf, size, outcomeList[i] + offset);
					if (ret == size)
					{
						if (*(DOUBLE*)buf == v)
						{
							//如果匹配成功则将这个内存地址添加进偏移筛选结果列表
							offsetFilterResults.push_back(outcomeList[i]);
						}
					}
				}
				free(buf);
			}
			break;
			case TYPE_QWORD:
			{
				QWORD v = atoll(value);
				int size = sizeof(QWORD);
				void* buf = (void*)malloc(size);
				//遍历搜索到的数据的内存地址列表
				for (int i = 0; i < outcomeList.size(); i++)
				{
					//检查这个从内存地址偏移[offset]之后的内存地址指向的值是否为v
					int ret = pread64(fd, buf, size, outcomeList[i] + offset);
					if (ret == size)
					{
						if (*(QWORD*)buf == v)
						{
							//如果匹配成功则将这个内存地址添加进偏移筛选结果列表
							offsetFilterResults.push_back(outcomeList[i]);
						}
					}
				}
				free(buf);
			}
			break;
			case TYPE_WORD:
			{
				WORD v = (WORD)atoi(value);
				int size = sizeof(WORD);
				void* buf = (void*)malloc(size);
				//遍历搜索到的数据的内存地址列表
				for (int i = 0; i < outcomeList.size(); i++)
				{
					//检查这个从内存地址偏移[offset]之后的内存地址指向的值是否为v
					int ret = pread64(fd, buf, size, outcomeList[i] + offset);
					if (ret == size)
					{
						if (*(WORD*)buf == v)
						{
							//如果匹配成功则将这个内存地址添加进偏移筛选结果列表
							offsetFilterResults.push_back(outcomeList[i]);
						}
					}
				}
				free(buf);
			}
			break;
			case TYPE_BYTE:
			{
				BYTE v = (BYTE)atoi(value);
				int size = sizeof(BYTE);
				void* buf = (void*)malloc(size);
				//遍历搜索到的数据的内存地址列表
				for (int i = 0; i < outcomeList.size(); i++)
				{
					//检查这个从内存地址偏移[offset]之后的内存地址指向的值是否为v
					int ret = pread64(fd, buf, size, outcomeList[i] + offset);
					if (ret == size)
					{
						if (*(BYTE*)buf == v)
						{
							//如果匹配成功则将这个内存地址添加进偏移筛选结果列表
							offsetFilterResults.push_back(outcomeList[i]);
						}
					}
				}
				free(buf);
			}
			break;
			}
			close(fd);
			//筛选完成则清空最终筛选结果列表
			outcomeList.clear();
			//将新筛选出的结果列表添加进最终筛选结果列表
			for (int i = 0; i < offsetFilterResults.size(); i++)
			{
				outcomeList.push_back(offsetFilterResults[i]);
			}
		}
	}
	return outcomeList;
}

/// <summary>
/// 从当前搜索结果中 筛选指定偏移处的值在这个范围内的结果 [偏移范围改善] 适用于：某些特征码会变化但是只会在一个范围之内变化时 比如特征码始终为1或2或3时 可以使用偏移范围改善使用1~3即可
/// </summary>
/// <param name="value">范围值[格式：最小~最大 例如1~20]</param>
/// <param name="type">数据类型</param>
/// <returns></returns>
vector < unsigned long > ImproveOffsetRange(const char* value, int type, unsigned long offset) {
	if (isInit) {
		char minValue[64 + 2];
		char maxValue[64 + 2];
		const char* start = strstr(value, R_SEPARATE);
		if (start != NULL) {
			strncpy(minValue, value, start - value); //从开头到分隔符的部分为最小值
			minValue[start - value] = '\0'; //最小值最后的位置添加字符串结束符
			strcpy(maxValue, start + 1); //从分隔符后一个字符开始为最大值
		}
		vector < unsigned long >offsetFilterResults;//临时筛选结果列表 - 临时存储当前偏移筛选出的附近拥有特征值的数据
		int fd = open(memPath, O_RDONLY);
		if (fd >= 0)
		{
			switch (type)
			{
			case TYPE_DWORD:
			{
				DWORD minv = atoi(minValue);
				DWORD maxv = atoi(maxValue);
				int size = sizeof(DWORD);
				void* buf = (void*)malloc(size);
				//遍历搜索到的数据的内存地址列表
				for (int i = 0; i < outcomeList.size(); i++)
				{
					//检查这个从内存地址偏移[offset]之后的内存地址指向的值是否为v
					int ret = pread64(fd, buf, size, outcomeList[i] + offset);
					if (ret == size)
					{
						DWORD bV = *(DWORD*)buf;
						if (bV >= minv && bV <= maxv)
						{
							//如果匹配成功则将这个内存地址添加进偏移筛选结果列表
							offsetFilterResults.push_back(outcomeList[i]);
						}
					}
				}
				free(buf);
			}
			break;
			case TYPE_FLOAT:
			{
				FLOAT minv = atof(minValue);
				FLOAT maxv = atof(maxValue);
				int size = sizeof(FLOAT);
				void* buf = (void*)malloc(size);
				//遍历搜索到的数据的内存地址列表
				for (int i = 0; i < outcomeList.size(); i++)
				{
					//检查这个从内存地址偏移[offset]之后的内存地址指向的值是否为v
					int ret = pread64(fd, buf, size, outcomeList[i] + offset);
					if (ret == size)
					{
						FLOAT bV = *(FLOAT*)buf;
						if (bV >= minv && bV <= maxv)
						{
							//如果匹配成功则将这个内存地址添加进偏移筛选结果列表
							offsetFilterResults.push_back(outcomeList[i]);
						}
					}
				}
				free(buf);
			}
			break;
			case TYPE_DOUBLE:
			{
				DOUBLE minv = strtod(minValue, NULL);
				DOUBLE maxv = strtod(maxValue, NULL);
				int size = sizeof(DOUBLE);
				void* buf = (void*)malloc(size);
				//遍历搜索到的数据的内存地址列表
				for (int i = 0; i < outcomeList.size(); i++)
				{
					//检查这个从内存地址偏移[offset]之后的内存地址指向的值是否为v
					int ret = pread64(fd, buf, size, outcomeList[i] + offset);
					if (ret == size)
					{
						DOUBLE bV = *(DOUBLE*)buf;
						if (bV >= minv && bV <= maxv)
						{
							//如果匹配成功则将这个内存地址添加进偏移筛选结果列表
							offsetFilterResults.push_back(outcomeList[i]);
						}
					}
				}
				free(buf);
			}
			break;
			case TYPE_QWORD:
			{
				QWORD minv = atoll(minValue);
				QWORD maxv = atoll(maxValue);
				int size = sizeof(QWORD);
				void* buf = (void*)malloc(size);
				//遍历搜索到的数据的内存地址列表
				for (int i = 0; i < outcomeList.size(); i++)
				{
					//检查这个从内存地址偏移[offset]之后的内存地址指向的值是否为v
					int ret = pread64(fd, buf, size, outcomeList[i] + offset);
					if (ret == size)
					{
						QWORD bV = *(QWORD*)buf;
						if (bV >= minv && bV <= maxv)
						{
							//如果匹配成功则将这个内存地址添加进偏移筛选结果列表
							offsetFilterResults.push_back(outcomeList[i]);
						}
					}
				}
				free(buf);
			}
			break;
			case TYPE_WORD:
			{
				WORD minv = (WORD)atoi(minValue);
				WORD maxv = (WORD)atoi(maxValue);
				int size = sizeof(WORD);
				void* buf = (void*)malloc(size);
				//遍历搜索到的数据的内存地址列表
				for (int i = 0; i < outcomeList.size(); i++)
				{
					//检查这个从内存地址偏移[offset]之后的内存地址指向的值是否为v
					int ret = pread64(fd, buf, size, outcomeList[i] + offset);
					if (ret == size)
					{
						WORD bV = *(WORD*)buf;
						if (bV >= minv && bV <= maxv)
						{
							//如果匹配成功则将这个内存地址添加进偏移筛选结果列表
							offsetFilterResults.push_back(outcomeList[i]);
						}
					}
				}
				free(buf);
			}
			break;
			case TYPE_BYTE:
			{
				BYTE minv = (BYTE)atoi(minValue);
				BYTE maxv = (BYTE)atoi(maxValue);
				int size = sizeof(BYTE);
				void* buf = (void*)malloc(size);
				//遍历搜索到的数据的内存地址列表
				for (int i = 0; i < outcomeList.size(); i++)
				{
					//检查这个从内存地址偏移[offset]之后的内存地址指向的值是否为v
					int ret = pread64(fd, buf, size, outcomeList[i] + offset);
					if (ret == size)
					{
						BYTE bV = *(BYTE*)buf;
						if (bV >= minv && bV <= maxv)
						{
							//如果匹配成功则将这个内存地址添加进偏移筛选结果列表
							offsetFilterResults.push_back(outcomeList[i]);
						}
					}
				}
				free(buf);
			}
			break;
			}
			close(fd);
			//筛选完成则清空最终筛选结果列表
			outcomeList.clear();
			//将新筛选出的结果列表添加进最终筛选结果列表
			for (int i = 0; i < offsetFilterResults.size(); i++)
			{
				outcomeList.push_back(offsetFilterResults[i]);
			}
		}
	}
	return outcomeList;

}

/// <summary>
/// 从当前搜索结果中 筛选指定偏移处的值为联合值中的某一个值的结果 [偏移联合改善] 适用于：某些特征码会变化但是永远只会变为那几个固定值的情况 比如只会变化为22或15或27时可以使用偏移联合改善22;15;27
/// </summary>
/// <param name="value">联合筛选值：[格式：值1;值2;值3;n个值 示例：7F;2D;3E 并且值也支持范围例如1~2;3 注：改善不支持顺序改善和区间范围]</param>
/// <param name="type">默认类型：对于未将类型符的值使用此类型 例如1D;2;3E中的2将使用此类型</param>
/// <returns></returns>
vector < unsigned long > ImproveOffsetUnited(const char* value, int type, unsigned long offset) {
	if (isInit) {
		//LOGD("联合改善调试", "start");
		char* valueCopy = strdup(value);//创建副本内存因为之后要进行修改传入的字符串

		//获取联合改善数值到列表
		vector < Federated > valueList; //存储分割出的所有数值的列表
		//获取第一个分割部分
		const char* token = strtok(valueCopy, U_SEPARATE);
		//逐个获取剩余的分割部分
		while (token != NULL) {
			valueList.emplace_back(token, type);  //保存分割出的值
			token = strtok(NULL, U_SEPARATE);  // 获取下一个分割部分
		}

		//开始联合改善
		if (!valueList.empty()) {
			//打开mem内存文件
			int mem = open(memPath, O_RDONLY);
			if (mem >= 0) {
				vector < unsigned long >filterResults;//存储临时改善结果列表
				for (int i = 0; i < outcomeList.size(); i++)
				{
					for (int j = 0; j < valueList.size(); j++)
					{
						bool isF = false;//标记是否已找到
						switch (valueList[j].type)
						{
						case TYPE_DWORD:
						{
							int size = sizeof(DWORD);
							void* buf = (void*)malloc(size);
							int ret = pread64(mem, buf, size, outcomeList[i] + offset);
							DWORD eV = *(DWORD*)buf;
							if (ret == size)
							{
								if (valueList[j].isRange) {
									DWORD minv = atoi(valueList[j].minValue);
									DWORD maxv = atoi(valueList[j].maxValue);
									if (eV >= minv && eV <= maxv) {
										filterResults.push_back(outcomeList[i]);
										isF = true;
									}
								}
								else {
									DWORD v = atoi(valueList[j].value);
									if (eV == v) {
										filterResults.push_back(outcomeList[i]);
										isF = true;
									}
								}
							}
							free(buf);
						}
						break;
						case TYPE_FLOAT:
						{
							int size = sizeof(FLOAT);
							void* buf = (void*)malloc(size);
							int ret = pread64(mem, buf, size, outcomeList[i] + offset);
							FLOAT eV = *(FLOAT*)buf;
							if (ret == size)
							{
								if (valueList[j].isRange) {
									FLOAT minv = atof(valueList[j].minValue);
									FLOAT maxv = atof(valueList[j].maxValue);
									if (eV >= minv && eV <= maxv) {
										filterResults.push_back(outcomeList[i]);
										isF = true;
									}
								}
								else {
									FLOAT v = atof(valueList[j].value);
									if (eV == v) {
										filterResults.push_back(outcomeList[i]);
										isF = true;
									}
								}
							}
							free(buf);
						}
						break;
						case TYPE_DOUBLE:
						{
							int size = sizeof(DOUBLE);
							void* buf = (void*)malloc(size);
							int ret = pread64(mem, buf, size, outcomeList[i] + offset);
							DOUBLE eV = *(DOUBLE*)buf;
							if (ret == size)
							{
								if (valueList[j].isRange) {
									DOUBLE minv = strtod(valueList[j].minValue, NULL);
									DOUBLE maxv = strtod(valueList[j].maxValue, NULL);
									if (eV >= minv && eV <= maxv) {
										filterResults.push_back(outcomeList[i]);
										isF = true;
									}
								}
								else {
									DOUBLE v = strtod(valueList[j].value, NULL);
									if (eV == v) {
										filterResults.push_back(outcomeList[i]);
										isF = true;
									}
								}
							}
							free(buf);
						}
						break;
						case TYPE_QWORD:
						{
							int size = sizeof(QWORD);
							void* buf = (void*)malloc(size);
							int ret = pread64(mem, buf, size, outcomeList[i] + offset);
							QWORD eV = *(QWORD*)buf;
							if (ret == size)
							{
								if (valueList[j].isRange) {
									QWORD minv = atoll(valueList[j].minValue);
									QWORD maxv = atoll(valueList[j].maxValue);
									if (eV >= minv && eV <= maxv) {
										filterResults.push_back(outcomeList[i]);
										isF = true;
									}
								}
								else {
									QWORD v = atoll(valueList[j].value);
									if (eV == v) {
										filterResults.push_back(outcomeList[i]);
										isF = true;
									}
								}
							}
							free(buf);
						}
						break;
						case TYPE_WORD:
						{
							int size = sizeof(WORD);
							void* buf = (void*)malloc(size);
							int ret = pread64(mem, buf, size, outcomeList[i] + offset);
							WORD eV = *(WORD*)buf;
							if (ret == size)
							{
								if (valueList[j].isRange) {
									WORD minv = (WORD)atoi(valueList[j].minValue);
									WORD maxv = (WORD)atoi(valueList[j].maxValue);
									if (eV >= minv && eV <= maxv) {
										filterResults.push_back(outcomeList[i]);
										isF = true;
									}
								}
								else {
									WORD v = (WORD)atoi(valueList[j].value);
									if (eV == v) {
										filterResults.push_back(outcomeList[i]);
										isF = true;
									}
								}
							}
							free(buf);
						}
						break;
						case TYPE_BYTE:
						{
							int size = sizeof(BYTE);
							void* buf = (void*)malloc(size);
							int ret = pread64(mem, buf, size, outcomeList[i] + offset);
							BYTE eV = *(BYTE*)buf;
							if (ret == size)
							{
								if (valueList[j].isRange) {
									BYTE minv = (BYTE)atoi(valueList[j].minValue);
									BYTE maxv = (BYTE)atoi(valueList[j].maxValue);
									if (eV >= minv && eV <= maxv) {
										filterResults.push_back(outcomeList[i]);
										isF = true;
									}
								}
								else {
									BYTE v = (BYTE)atoi(valueList[j].value);
									if (eV == v) {
										filterResults.push_back(outcomeList[i]);
										isF = true;
									}
								}
							}
							free(buf);
						}
						break;
						}
						//找到则结束循环 开始匹配下一轮的值
						if (isF) {
							break;
						}
					}
				}

				close(mem);
				//筛选完成则清空最终筛选结果列表
				outcomeList.clear();
				//将新筛选出的结果列表添加进最终筛选结果列表
				for (int i = 0; i < filterResults.size(); i++)
				{
					outcomeList.push_back(filterResults[i]);
				}
				//升序排序结果
				//sort(outcomeList.begin(), outcomeList.end());
			}
		}
		free(valueCopy); //释放副本内存
	}
	return outcomeList;
}
/// <summary>
/// 从当前搜索结果中 直接改善 [支持范围改善和联合改善]
/// </summary>
/// <param name="value">改善值</param>
/// <param name="type">默认类型</param>
/// <returns>结果</returns>
vector < unsigned long > ImproveValue(const char* value, int type) {
	return ImproveOffset(value, type, 0);
}
/// <summary>
/// 从最终所有筛选结果的指定偏移处进行写入数据
/// </summary>
/// <param name="value">写入的数据</param>
/// <param name="type">写入数据类型</param>
/// <param name="offset">相对筛选结果处的偏移量</param>
/// <param name="isFree">是否冻结写入</param>
/// <returns>写入成功与否</returns>
int MemoryOffsetWrite(const char* value, int type, unsigned long offset, bool isFree)
{
	if (!isInit) {
		//没有进行初始化
		return -1;
	}

	int fd = open(memPath, O_RDWR | O_SYNC);
	//打开maps文件
	FILE* maps = fopen(mapsPath, "r");
	if (fd >= 0 && maps)
	{
		for (int i = 0; i < outcomeList.size(); i++) {
			if (isSecureWrites) {
               setAddrVisitP(outcomeList[i] + offset,6);
            }   
			if (isFree) {
				addFreezeItem(value, outcomeList[i] + offset, type);
				startAllFreeze();
			}
			else {
                
				switch (type)
				{
				case TYPE_DWORD:
				{
					DWORD v = atoi(value);
					pwrite64(fd, &v, sizeof(DWORD), outcomeList[i] + offset);
				}
				break;
				case TYPE_FLOAT:
				{
					FLOAT v = atof(value);
					pwrite64(fd, &v, sizeof(FLOAT), outcomeList[i] + offset);
				}
				break;
				case TYPE_DOUBLE:
				{
					DOUBLE v = strtod(value, NULL);
					pwrite64(fd, &v, sizeof(DOUBLE), outcomeList[i] + offset);
				}
				break;
				case TYPE_QWORD:
				{
					QWORD v = atoll(value);
					pwrite64(fd, &v, sizeof(QWORD), outcomeList[i] + offset);
				}
				break;
				case TYPE_WORD:
				{
					WORD v = (WORD)atoi(value);
					pwrite64(fd, &v, sizeof(WORD), outcomeList[i] + offset);
				}
				break;
				case TYPE_BYTE:
				{
					BYTE v = (BYTE)atoi(value);
					pwrite64(fd, &v, sizeof(BYTE), outcomeList[i] + offset);
				}
				break;
				}
			    
				removeFreezeItem(outcomeList[i] + offset);
               
			}
		}
		return 0;
	}
	if (fd >= 0) {
		close(fd);
	}

	if (maps) {
		fclose(maps);
	}
	return -1;//内存写入成功
}

/// <summary>
/// 获取最终搜索结果数量
/// </summary>
/// <returns>最终搜索结果数量</returns>
int getResultCount()
{
	return outcomeList.size();
}

/// <summary>
/// 获取最终搜索结果列表
/// </summary>
/// <returns>最终搜索结果列表</returns>
vector < unsigned long > getResultList()
{
	return outcomeList;
}

/// <summary>
/// 打印最终搜索结果列表到文件
/// </summary>
/// <param name="filePath">文件路径</param>
/// <returns>成功与否</returns>
int printResultListToFile(const char* filePath)
{
	FILE* memDebugFile = fopen(filePath, "a");//追加模式打开
	if (memDebugFile != NULL) {
		struct timeval tv;
		struct tm* tm_info;
		char timeString[100];

		gettimeofday(&tv, NULL);
		tm_info = localtime(&tv.tv_sec);

		strftime(timeString, sizeof(timeString), "%Y-%m-%d %H:%M:%S", tm_info);
		fprintf(memDebugFile, "\n\n\n");
		fprintf(memDebugFile, "======================================================================================================================\n");
		fprintf(memDebugFile, "[LogName] 日志名称：内存搜索结果列表\n");
		fprintf(memDebugFile, "[ABI] 处理器：%s\n", ABI);
		fprintf(memDebugFile, "[PackName] 进程包名：%s\n", packName);
		fprintf(memDebugFile, "[PID] 进程ID：%d\n", pid);
		fprintf(memDebugFile, "[PID] 搜索内存：%s\n", getMemoryAreaName());
		fprintf(memDebugFile, "[RCount] 搜索结果数量：%d\n", outcomeList.size());
		fprintf(memDebugFile, "[AddTime] 日志生成时间：%s.%ld\n", timeString, tv.tv_usec);
		fprintf(memDebugFile, "[Source] 来源：ByteCat-MemTool ^O^\n");
		fprintf(memDebugFile, "ByteCat：以下数据仅用于内存分析和调试，请勿用于违法用途！\n");
		fprintf(memDebugFile, "ByteCat: The above data is only used for memory analysis and debugging, please do not use it for illegal purposes!\n");
		fprintf(memDebugFile, "======================================================================================================================\n");
		fprintf(memDebugFile, "[Debug] Log format: Timestamp | Memory Area | Memory Address | DWORD Data | FLOAT Data | DOUBLE Data | WORD Data | BYTE Data | QWORD Data | Mem Map\n");
		fprintf(memDebugFile, "[调试]	日志格式: 时间戳 | 内存区域 | 内存地址 | DWORD类型数据 | FLOAT类型数据 | DOUBLE类型数据 | WORD类型数据 | BYTE类型数据 | QWORD类型数据 | 内存映射\n");
		for (int i = 0; i < outcomeList.size(); i++)
		{
			gettimeofday(&tv, NULL);
			tm_info = localtime(&tv.tv_sec);
			strftime(timeString, sizeof(timeString), "%Y-%m-%d %H:%M:%S", tm_info);
			char* mapLine = getMemoryAddrMapLine(outcomeList[i]);
			fprintf(memDebugFile, "%s.%06ld 📍 内存区域：%s 内存地址：0x%lX  D类型：%s  F类型：%s  E类型：%s  W类型：%s  B类型：%s  Q类型：%s  📑 内存映射：%s\n", timeString, tv.tv_usec,
				getMapLineMemoryAreaName(mapLine),
				outcomeList[i],
				getMemoryAddrData(outcomeList[i], TYPE_DWORD),
				getMemoryAddrData(outcomeList[i], TYPE_FLOAT),
				getMemoryAddrData(outcomeList[i], TYPE_DOUBLE),
				getMemoryAddrData(outcomeList[i], TYPE_WORD),
				getMemoryAddrData(outcomeList[i], TYPE_BYTE),
				getMemoryAddrData(outcomeList[i], TYPE_QWORD),
				mapLine);
		}
		fprintf(memDebugFile, "======================================================================================================================\n");
		fprintf(memDebugFile, "注：以上数据仅用于内存分析和调试，请勿用于违法用途！\n");
		fprintf(memDebugFile, "Note: The above data is only used for memory analysis and debugging, please do not use it for illegal purposes!\n");
		fprintf(memDebugFile, "======================================================================================================================\n");
		fclose(memDebugFile);
		return 0;
	}

	return -1;
}

/// <summary>
/// 清空最终搜索结果列表
/// </summary>
int clearResultList()
{
	if (outcomeList.empty()) {
		//空列表不做操作
		return -1;
	}
	//清空搜索结果列表
	outcomeList.clear();
	// 释放内存
	std::vector<unsigned long>().swap(outcomeList);
	return 0;
}

/// <summary>
/// 设置冻结修改延迟【毫秒】
/// </summary>
/// <param name="delay">延迟[MS]</param>
void setFreezeDelayMs(uint32_t delay) {
	freezeDelay = delay;
}

/// <summary>
/// 获取冻结修改项目列表
/// </summary>
/// <returns>冻结修改项目列表</returns>
vector < Item > getFreezeList() {
	return FreezeList;
}

/// <summary>
/// 获取冻结修改项目数量
/// </summary>
/// <returns>数量</returns>
int getFreezeNum() {
	return FreezeList.size();
}

/// <summary>
/// 添加一个冻结修改项目
/// </summary>
/// <param name="value">修改值</param>
/// <param name="addr">内存地址</param>
/// <param name="type">数据类型</param>
int addFreezeItem(const char* value, unsigned long addr, int type)
{
	//检查冻结修改项目列表是否已经存在此内存地址，防止重复添加冻结修改项目
	for (int i = 0; i < FreezeList.size(); i++)
	{
		if (addr == FreezeList[i].addr)
		{
			return -1;
		}
	}
	Item table;
	table.value = strdup(value);
	table.addr = addr;
	table.type = type;
	FreezeList.push_back(table);
	return 0;
}

/// <summary>
/// 移除一个冻结修改项目
/// </summary>
/// <param name="addr">内存地址</param>
int removeFreezeItem(unsigned long addr)
{
	for (int i = 0; i < FreezeList.size(); i++)
	{
		if (addr == FreezeList[i].addr)
		{
			FreezeList.erase(FreezeList.begin() + i);
			return 0;
		}
	}
	return -1;
}

/// <summary>
/// 移除所有冻结修改项目
/// </summary>
int removeAllFreezeItem() {
	if (FreezeList.empty()) {
		//空列表不做操作
		return -1;
	}
	// 清除所有数据
	FreezeList.clear();
	// 释放内存
	std::vector<Item>().swap(FreezeList);
	return 0;
}

/// <summary>
/// 冻结循环修改线程
/// </summary>
/// <param name="arg"></param>
/// <returns></returns>
void* freezeThread(void* arg)
{int pageSize = getpagesize();
	for (;;)
	{
		if (isInit) {
			//如果需要结束冻结或者冻结列表没有冻结项目则结束
			if (!isFreeze || FreezeList.size() == 0)
			{
				stopAllFreeze();
				break;
			}
			//每轮冻结才打开mem为了提升性能而不是在每次修改时都打开mem 避免频繁IO
			int fd = open(memPath, O_RDWR | O_SYNC);
			if (fd >= 0) {
				//遍历 内存修改 冻结列表的所有项目
				for (int i = 0; i < FreezeList.size(); i++)
				{
                    
					switch (FreezeList[i].type)
					{
					case TYPE_DWORD:
					{
						DWORD v = atoi(FreezeList[i].value);
						pwrite64(fd, &v, sizeof(DWORD), FreezeList[i].addr);
					}
					break;
					case TYPE_FLOAT:
					{
						FLOAT v = atof(FreezeList[i].value);
						pwrite64(fd, &v, sizeof(FLOAT), FreezeList[i].addr);
					}
					break;
					case TYPE_DOUBLE:
					{
						DOUBLE v = strtod(FreezeList[i].value, NULL);
						pwrite64(fd, &v, sizeof(DOUBLE), FreezeList[i].addr);
					}
					break;
					case TYPE_QWORD:
					{
						QWORD v = atoll(FreezeList[i].value);
						pwrite64(fd, &v, sizeof(QWORD), FreezeList[i].addr);
					}
					break;
					case TYPE_WORD:
					{
						WORD v = (WORD)atoi(FreezeList[i].value);
						pwrite64(fd, &v, sizeof(WORD), FreezeList[i].addr);
					}
					break;
					case TYPE_BYTE:
					{
						BYTE v = (BYTE)atoi(FreezeList[i].value);
						pwrite64(fd, &v, sizeof(BYTE), FreezeList[i].addr);
					}
					break;
					}
				}
				close(fd);
			}
			//延迟
			if (freezeDelay != 0) {
				usleep(freezeDelay * 1000);//转换为微秒
			}
		}

	}
	return NULL;
}

/// <summary>
/// 开始所有冻结修改项目
/// </summary>
int startAllFreeze()
{
	if (!isInit) {
		//没有进行初始化
		return -1;
	}
	if (!isFreeze)
	{
		//冻结列表有项目才开冻结线程
		if (FreezeList.size() > 0)
		{
			isFreeze = true;//正在冻结
			//开始启动冻结线程
			pthread_t t;
			pthread_create(&t, NULL, freezeThread, NULL);
			return 0;
		}
	}
	return -1;
}

/// <summary>
/// 停止所有冻结修改项目
/// </summary>
int stopAllFreeze()
{
	if (isFreeze)
	{
		isFreeze = false;
		return 0;
	}
	return -1;
}

/// <summary>
/// 打印冻结列表到指定文件
/// </summary>
/// <param name="filePath">文件绝对路径</param>
/// <returns>成功与否</returns>
int printFreezeListToFile(const char* filePath)
{
	FILE* memDebugFile = fopen(filePath, "a");//追加模式打开
	if (memDebugFile != NULL) {
		struct timeval tv;
		struct tm* tm_info;
		char timeString[100];

		gettimeofday(&tv, NULL);
		tm_info = localtime(&tv.tv_sec);

		strftime(timeString, sizeof(timeString), "%Y-%m-%d %H:%M:%S", tm_info);
		fprintf(memDebugFile, "\n\n\n");
		fprintf(memDebugFile, "======================================================================================================================\n");
		fprintf(memDebugFile, "[LogName] 日志名称：冻结修改列表\n");
		fprintf(memDebugFile, "[ABI] 处理器：%s\n", ABI);
		fprintf(memDebugFile, "[PackName] 进程包名：%s\n", packName);
		fprintf(memDebugFile, "[PID] 进程ID：%d\n", pid);
		fprintf(memDebugFile, "[RCount] 冻结修改数量：%d\n", FreezeList.size());
		fprintf(memDebugFile, "[AddTime] 日志生成时间：%s.%ld\n", timeString, tv.tv_usec);
		fprintf(memDebugFile, "[Source] 来源：ByteCat-MemTool ^O^\n");
		fprintf(memDebugFile, "ByteCat：以下数据仅用于内存分析和调试，请勿用于违法用途！\n");
		fprintf(memDebugFile, "ByteCat: The above data is only used for memory analysis and debugging, please do not use it for illegal purposes!\n");
		fprintf(memDebugFile, "======================================================================================================================\n");
		fprintf(memDebugFile, "[Debug] Log format: [❄ Freeze info] Timestamp | Memory Area | Memory Address | DWORD Data | FLOAT Data | DOUBLE Data | WORD Data | BYTE Data | QWORD Data | Mem Map\n");
		fprintf(memDebugFile, "[调试]	日志格式: [❄ 冻结信息] 时间戳 | 内存区域 | 内存地址 | DWORD类型数据 | FLOAT类型数据 | DOUBLE类型数据 | WORD类型数据 | BYTE类型数据 | QWORD类型数据 | 内存映射\n");
		for (int i = 0; i < FreezeList.size(); i++)
		{
			gettimeofday(&tv, NULL);
			tm_info = localtime(&tv.tv_sec);
			strftime(timeString, sizeof(timeString), "%Y-%m-%d %H:%M:%S", tm_info);
			char* mapLine = getMemoryAddrMapLine(FreezeList[i].addr);
			fprintf(memDebugFile, "%s.%06ld 【❄ 修改值：%s 修改类型：%s】 📍 内存区域：%s 内存地址：0x%lX  D类型：%s  F类型：%s  E类型：%s  W类型：%s  B类型：%s  Q类型：%s  📑 内存映射：%s\n", timeString, tv.tv_usec,
				FreezeList[i].value,
				getDataTypeName(FreezeList[i].type),
				getMapLineMemoryAreaName(mapLine),
				FreezeList[i].addr,
				getMemoryAddrData(FreezeList[i].addr, TYPE_DWORD),
				getMemoryAddrData(FreezeList[i].addr, TYPE_FLOAT),
				getMemoryAddrData(FreezeList[i].addr, TYPE_DOUBLE),
				getMemoryAddrData(FreezeList[i].addr, TYPE_WORD),
				getMemoryAddrData(FreezeList[i].addr, TYPE_BYTE),
				getMemoryAddrData(FreezeList[i].addr, TYPE_QWORD),
				mapLine);
		}
		fprintf(memDebugFile, "======================================================================================================================\n");
		fprintf(memDebugFile, "注：以上数据仅用于内存分析和调试，请勿用于违法用途！\n");
		fprintf(memDebugFile, "Note: The above data is only used for memory analysis and debugging, please do not use it for illegal purposes!\n");
		fprintf(memDebugFile, "======================================================================================================================\n");
		fclose(memDebugFile);
		return 0;
	}

	return -1;
}

/// <summary>
/// 获取指定内存地址的maps映射行
/// </summary>
/// <param name="address">内存地址</param>
/// <returns>maps映射行</returns>
char* getMemoryAddrMapLine(unsigned long address) {
	if (!isInit) {
		return "NULL";
	}
	//存储映射信息
	unsigned long start, end, offset;
	char perms[5], dev[6], path[1024];
	int inode;

	FILE* file;               //maps文件指针
	char line[4096];  //存储读取到的一行数据

	file = fopen(mapsPath, "r");
	if (file) {
		//逐行读取maps文件内容
		while (fgets(line, sizeof(line), file)) {

			sscanf(line, "%lx-%lx %4s %lx %5s %d %[^\n]",
				&start, &end, perms, &offset, dev, &inode, path);
			//如果给定的地址在当前行描述的内存区域范围内
			if (address >= start && address < end) {
				fclose(file); // 关闭文件
				return line;//返回映射行
			}
		}
		fclose(file); // 关闭文件
	}
	return "NULL";
}

/// <summary>
/// 获取Maps映射行所在内存区域名称
/// </summary>
/// <param name="mapLine"></param>
/// <returns>内存名称字符串</returns>
char* getMapLineMemoryAreaName(const char* mapLine) {
	//jh和j 模拟器cd和xa 

	if (BCMAPSFLAG(mapLine, RANGE_C_HEAP)) {
		return "C堆内存 [Ch: C++ heap]";
	}
	if (BCMAPSFLAG(mapLine, RANGE_C_ALLOC)) {
		return "C分配内存 [Ca: C++ alloc]";
	}
	if (BCMAPSFLAG(mapLine, RANGE_C_BSS)) {
		return "C未初始化数据 [Cb: C++ .bss]";
	}
	if (BCMAPSFLAG(mapLine, RANGE_ANONYMOUS)) {
		return "匿名内存 [A: Anonymous]";
	}
	if (BCMAPSFLAG(mapLine, RANGE_STACK)) {
		return "栈内存 [S: Stack]";
	}
	if (BCMAPSFLAG(mapLine, RANGE_ASHMEM)) {
		return "Android共享内存 [As: Ashmem]";
	}
	if (BCMAPSFLAG(mapLine, RANGE_VIDEO)) {
		//BCMEM_LOGI("此内存有错误");
		return "视频内存 [V: Video]";
	}
	if (BCMAPSFLAG(mapLine, RANGE_B_BAD)) {
		//BCMEM_LOGI("此内存有错误");
		return "错误内存 [B: Bad]";
	}
	if (BCMAPSFLAG(mapLine, RANGE_CODE_SYSTEM)) {
		return "系统代码 [Xs: Code system]";
	}

	//j内存和jh内存筛选特征相同
	/*if (BCMAPSFLAG(mapLine, RANGE_JAVA_HEAP)) {
		return "Java虚拟机堆内存 [Jh: Java heap]";
	}*/
	if (BCMAPSFLAG(mapLine, RANGE_JAVA)) {
		return "Java内存 [J: Java] 或 Java虚拟机堆内存 [Jh: Java heap]";
	}

	//cd和xa在模拟器可能错误 因此针对
#if defined(__arm__) || defined(__aarch64__) //arm32和arm64架构
	if (BCMAPSFLAG(mapLine, RANGE_C_DATA)) {
		return "C数据内存 [Cd: C++ .data]";
	}
	if (BCMAPSFLAG(mapLine, RANGE_CODE_APP)) {
		return "应用程序代码 [Xa: Code app]";
	}
#else//x86和x64架构 针对模拟器
	if (BCMAPSFLAG(mapLine, RANGE_C_DATA)) {
		return "C数据内存 [Cd: C++ .data] 或 应用程序代码 [Xa: Code app]";
	}
	if (BCMAPSFLAG(mapLine, RANGE_CODE_APP)) {
		return "应用程序代码 [Xa: Code app]";
	}
#endif


	//if (BCMAPSFLAG(mapLine, RANGE_OTHER)) {
	//	//BCMEM_LOGI("此内存有错误，无法完全排除");
	//	return "其他内存 [O: Other]";
	//}

	//以上都不是则在O
	return "其他内存 [O: Other]";
}


/// <summary>
/// 获取指定id的内存名称
/// </summary>
/// <param name="memid">内存id</param>
/// <returns>内存名称字符串</returns>
char* getMemoryAreaIdName(int memid) {
	if (memid == RANGE_ALL) {
		return "所有内存 [ALL]";
	}
	if (memid == RANGE_JAVA_HEAP) {
		return "Java虚拟机堆内存 [Jh: Java heap]";
	}
	if (memid == RANGE_C_HEAP) {
		return "C堆内存 [Ch: C++ heap]";
	}
	if (memid == RANGE_C_ALLOC) {
		return "C分配内存 [Ca: C++ alloc]";
	}
	if (memid == RANGE_C_DATA) {
		return "C数据内存 [Cd: C++ .data]";
	}
	if (memid == RANGE_C_BSS) {
		return "C未初始化数据 [Cb: C++ .bss]";
	}
	if (memid == RANGE_ANONYMOUS) {
		return "匿名内存 [A: Anonymous]";
	}
	if (memid == RANGE_JAVA) {
		return "Java内存 [J: Java]";
	}
	if (memid == RANGE_STACK) {
		return "栈内存 [S: Stack]";
	}
	if (memid == RANGE_ASHMEM) {
		return "Android共享内存 [As: Ashmem]";
	}
	if (memid == RANGE_VIDEO) {
		//BCMEM_LOGI("此内存有错误");
		return "视频内存 [V: Video]";
	}
	if (memid == RANGE_OTHER) {
		//BCMEM_LOGI("此内存有错误，无法完全排除");
		return "其他内存 [O: Other]";
	}
	if (memid == RANGE_B_BAD) {
		//BCMEM_LOGI("此内存有错误");
		return "错误内存 [B: Bad]";
	}
	if (memid == RANGE_CODE_APP) {
		return "应用程序代码 [Xa: Code app]";
	}
	if (memid == RANGE_CODE_SYSTEM) {
		return "系统代码 [Xs: Code system]";
	}

	return "未知内存 [NULL]";
}
/// <summary>
/// 获取当前内存名称
/// </summary>
/// <returns>内存名称字符串</returns>
char* getMemoryAreaName() {
	return getMemoryAreaIdName(memory);
}

/// <summary>
/// 获取数据类型名称
/// </summary>
/// <param name="typeId">类型id</param>
/// <returns>类型名称字符串</returns>
char* getDataTypeName(int typeId) {
	switch (typeId)
	{
	case TYPE_DWORD:
	{
		return "DWORD-32位有符号整数 [D: int32_t]";
	}
	break;
	case TYPE_FLOAT:
	{
		return "FLOAT-单精度浮点数 [F: float]";
	}
	break;
	case TYPE_DOUBLE:
	{
		return "DOUBLE-双精度浮点数 [E: double]";
	}
	break;
	case TYPE_QWORD:
	{
		return "QWORD-64位有符号整数 [Q: int64_t]";
	}
	break;
	case TYPE_WORD:
	{
		return "WORD-有符号短整型 [W: signed short]";
	}
	break;
	case TYPE_BYTE:
	{
		return "BYTE-有符号字符 [B: signed char]";
	}
	break;
	default:
	{
		return "未知类型 [NULL]";
	}
	break;
	}
}

/// <summary>
/// 杀掉指定包名的进程
/// </summary>
/// <param name="packageName">进程APK包名</param>
/// <returns>成功与否</returns>
int killProcess_Root(const char* packageName)
{
	int pid = getPID(packageName); //获取进程ID
	if (pid == -1)
	{
		return -1;
	}

	//SIGTERM信号杀死进程
	if (kill(pid, SIGTERM) == -1) {
		return -1;
	}

	return 0; //成功
}

/// <summary>
/// 暂停指定包名的进程
/// </summary>
/// <param name="packageName">进程包名</param>
/// <returns>成功与否</returns>
int stopProcess_Root(const char* packageName) {
	int pid = getPID(packageName);
	if (pid == -1) {
		return -1;
	}

	//SIGSTOP信号暂停进程
	if (kill(pid, SIGSTOP) == -1) {
		return -1;
	}
	return 0; //成功
}

/// <summary>
/// 恢复被暂停的指定包名的进程
/// </summary>
/// <param name="packageName">进程包名</param>
/// <returns>成功与否</returns>
int resumeProcess_Root(const char* packageName) {
	int pid = getPID(packageName);
	if (pid == -1) {
		return -1;
	}

	//SIGCONT信号恢复被暂停的进程
	if (kill(pid, SIGCONT) == -1) {
		return -1;
	}
	return 0; //成功
}
/// <summary>
/// 杀死所有inotify，防止游戏监视文件变化
/// </summary>
void killAllInotify_Root()
{
	//通过将内核inotify文件监视器的最大数量设置为0 这样就可以禁用所有inotify
	system("echo 0 > /proc/sys/fs/inotify/max_user_watches");
}

/// <summary>
/// 杀死GG修改器进程
/// </summary>
/// <returns>杀死的进程数量</returns>
int killGG_Root()
{
	DIR* dir = NULL;              //指向目录流的指针
	DIR* dirGG = NULL;            //指向子目录流的指针
	struct dirent* ptr = NULL;    //目录项结构体，用于存储目录中的条目
	struct dirent* ptrGG = NULL;  //目录项结构体，用于存储子目录中的条目
	char filepath[256];           //存储文件路径
	int num = 0;// 数量

	dir = opendir("/data/data");
	if (dir != NULL) {
		//检测data目录下每一个包名文件夹下是否为GG修改器
		while ((ptr = readdir(dir)) != NULL)
		{
			//跳过"."和".."目录和文件
			if ((strcmp(ptr->d_name, ".") == 0) || (strcmp(ptr->d_name, "..") == 0) || (ptr->d_type != DT_DIR)) {
				continue;
			}

			//生成当前包名的files文件夹的完整路径
			sprintf(filepath, "/data/data/%s/files", ptr->d_name);
			dirGG = opendir(filepath); //打开files
			if (dirGG != NULL)
			{
				while ((ptrGG = readdir(dirGG)) != NULL)
				{
					// 跳过"."和".."目录和文件
					if ((strcmp(ptrGG->d_name, ".") == 0) || (strcmp(ptrGG->d_name, "..") == 0) || (ptrGG->d_type != DT_DIR)) {
						continue;
					}

					if (strstr(ptrGG->d_name, "GG"))
					{
						//杀掉GG进程
						killProcess_Root(ptr->d_name);
						num++;// 成功杀死一个GG进程
					}
				}
				closedir(dirGG);
			}
		}
		closedir(dir);
	}
	return num;// 返回杀死的进程数量
}

/// <summary>
/// 杀死XS脚本进程
/// </summary>
/// <returns>杀死的进程数量</returns>
int killXscript_Root() {
	DIR* dir = NULL;                      // 目录流指针，用于打开目录
	DIR* dirXS = NULL;                       // 目录流指针，用于打开目录
	struct dirent* ptr = NULL;            // 目录项指针，用于读取目录项
	struct dirent* ptrXS = NULL;		  // 存储lib文件夹当前目录项
	char filepath[256];                   // 存储文件路径的缓冲区
	int num = 0;// 数量

	// 打开目录 "/data/data"
	dir = opendir("/data/data");

	if (dir != NULL) {
		// 循环读取目录下的每一个文件/文件夹
		while ((ptr = readdir(dir)) != NULL) {
			//跳过"."和".."目录和文件
			if ((strcmp(ptr->d_name, ".") == 0) || (strcmp(ptr->d_name, "..") == 0) || (ptr->d_type != DT_DIR)) {
				continue;
			}

			// 生成要读取的文件的路径
			sprintf(filepath, "/data/data/%s/lib", ptr->d_name);
			// 打开这个文件夹
			dirXS = opendir(filepath);
			if (dirXS != NULL)
			{
				//读取lib文件夹每一个文件
				while ((ptrXS = readdir(dirXS)) != NULL)
				{
					//如果动态库名称包含xs脚本则杀死
					if (strstr(ptrXS->d_name, "libxscript"))
					{
						//杀掉这个XS进程
						killProcess_Root(ptr->d_name);
						num++;//成功杀死一个XS进程
					}
				}
				closedir(dirXS);
			}
		}
		// 关闭目录流
		closedir(dir);
	}
	return num;//返回杀死的进程数量
}


/// <summary>
/// 重启手机
/// </summary>
/// <returns> 成功与否 </returns>
int rebootsystem_Root()
{
	return system("su -c 'reboot'");
}
/// <summary>
/// 静默安装 指定路径的APK安装包
/// </summary>
/// <param name="apkPackagePath"> apk安装包路径 </param>
/// <returns>成功与否</returns>
int installapk_Root(const char* apkPackagePath)
{
	char ml[256];
	sprintf(ml, "pm install %s", apkPackagePath);
	return system(ml);
}
/// <summary>
/// 静默卸载 指定包名的APK软件
/// </summary>
/// <param name="packageName">APK包名</param>
/// <returns>成功与否</returns>
int uninstallapk_Root(const char* packageName)
{
	char ml[256];
	sprintf(ml, "pm uninstall %s", packageName);
	return system(ml);
}
/// <summary>
/// 执行命令
/// </summary>
/// <param name="command">命令</param>
/// <returns>执行状态</returns>
int Cmd(const char* command) {
	int status = system(command);
	return WEXITSTATUS(status);
}
/// <summary>
/// 执行超级命令
/// </summary>
/// <param name="command">命令</param>
/// <returns>执行状态</returns>
int Cmd_Root(const char* command) {
	// 创建一个完整的命令字符串
	char fullCommand[256];
	snprintf(fullCommand, sizeof(fullCommand), "su -c '%s'", command);
	int status = system(fullCommand);
	return WEXITSTATUS(status);
}

