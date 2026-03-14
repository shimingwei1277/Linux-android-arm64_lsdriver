

/*
[核心逻辑修复记录]
 内存扫描功能:
 * 1. 修复多线程数据竞争 (Data Race) 导致“有总数但列表为空”的问题：
 *    - 诱因：多线程并发修改同一个 Byte 的不同位时相互覆盖，且非原子的 `setBits_--` 导致计数器溢出虚高。
 *    - 方案：引入 `__atomic_fetch_or/and` 保证硬件级原子位操作；废弃扫描过程中的动态递减计数，改为扫描完全结束后，统一使用 `__builtin_popcount` 遍历精确统计存活数量。
 *
 * 2. 修复精确数值扫描 (等于扫描) “任何数值均无结果 (0个)”的问题：
 *    - 诱因：底层匹配成功后，错误调用 `MemUtils::Normalize` 截断了真实内存地址，导致随后通过 `addrToBit` 在原始内存块 (regions_) 中反查映射时彻底丢失。
 *    - 方案：底层扫描收集结果时剥离所有 Normalize 操作，全程保留真实地址进行 Bitmap 映射。地址归一化仅交由 UI 层在展示侧处理。
 *
 * 3. 修复位索引 (Bit Index) 计算越界的隐患：
 *    - 诱因：内存块的大小不一定是目标数据类型 (如4字节) 的整数倍，存在尾部碎片，原计算逻辑会导致边界地址的索引溢出到下一个相邻内存块。
 *    - 方案：在 `addrToBit` 核心转换函数中，补充了严格的局部索引越界拦截 (`index >= regions_[lo].bitCount`)。
 */

#include <stdio.h>
#include <iostream>
#include <vector>
#include <list>
#include <thread>
#include <atomic>
#include <memory>
#include <string>
#include <cstdint>
#include <cstdlib>
#include <set>
#include <cmath>
#include <cstring>
#include <algorithm>
#include <chrono>
#include <map>
#include <sstream>
#include <fstream>
#include <functional>
#include <mutex>
#include <shared_mutex>
#include <span>
#include <ranges>
#include <format>
#include <concepts>
#include <variant>
#include <optional>
#include <charconv>
#include <unordered_set>
#include <stack>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <numeric>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <print>
#include <utility>
#include <numeric>
#include <cinttypes>
#include <atomic>
#include <algorithm>
#include <condition_variable>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <vector>

#include "DriverMemory.h"
#include "Android_draw/draw.h"
#include "imgui.h"
#include "ImGuiFloatingKeyboard.h"
#include "Disassembler.h"

// ============================================================================
// 配置模块 (Config)
// ============================================================================
namespace Config
{
    inline std::atomic<bool> g_Running{true};
    inline std::atomic<int> g_ItemsPerPage{100};

    struct Constants
    {
        static constexpr size_t MEM_VIEW_RANGE = 50;
        static constexpr size_t SCAN_BUFFER = 4096;
        static constexpr size_t BATCH_SIZE = 16384;
        static constexpr size_t MAX_READ_GAP = 64;
        static constexpr double FLOAT_EPSILON = 1e-4;
        static constexpr uintptr_t ADDR_MIN = 0x10000;
        static constexpr uintptr_t ADDR_MAX = 0x7FFFFFFFFFFF;
    };

    inline unsigned GetThreadCount() noexcept
    {
        if (auto n = std::thread::hardware_concurrency(); n > 0)
            return n;
        return 4;
    }

}

namespace Utils
{
    class ThreadPool
    {
        std::vector<std::jthread> workers_;
        std::queue<std::function<void()>> tasks_;
        std::mutex mtx_;
        std::condition_variable_any cv_;
        std::condition_variable done_cv_;
        size_t active_{0};

    public:
        explicit ThreadPool(size_t n = Config::GetThreadCount())
        {
            if (n == 0)
                n = 4;
            for (size_t i = 0; i < n; ++i)
            {
                workers_.emplace_back([this](std::stop_token st)
                                      {
                while (!st.stop_requested()) {
                    std::function<void()> task;
                    {
                        std::unique_lock lk(mtx_);
                        cv_.wait(lk, st, [&]{ return !tasks_.empty(); });
                    if(st.stop_requested()) return;
                        if (tasks_.empty()) continue;
                        task = std::move(tasks_.front());
                        tasks_.pop();
                        ++active_;
                    }
                    task();
                    {
                        std::lock_guard lk(mtx_);
                        --active_;
                        if (tasks_.empty() && active_ == 0)
                            done_cv_.notify_all();
                    }
                } });
            }
        }

        template <class F, class... Args>
        auto push(F &&f, Args &&...args) -> std::future<std::invoke_result_t<F, Args...>>
        {
            using R = std::invoke_result_t<F, Args...>;
            auto task = std::make_shared<std::packaged_task<R()>>(
                std::bind(std::forward<F>(f), std::forward<Args>(args)...));
            auto fut = task->get_future();
            {
                std::lock_guard lk(mtx_);
                tasks_.emplace([task]
                               { (*task)(); });
            }
            cv_.notify_one();
            return fut;
        }

        void wait_all()
        {
            std::unique_lock lk(mtx_);
            done_cv_.wait(lk, [&]
                          { return tasks_.empty() && active_ == 0; });
        }

        // 强行终止所有线程，不等待任务完成
        void force_stop()
        {
            {
                std::lock_guard lk(mtx_);
                while (!tasks_.empty()) // 清空待执行任务
                    tasks_.pop();
            }
            for (auto &w : workers_) // 请求所有线程停止
                w.request_stop();
            cv_.notify_all();
            for (auto &w : workers_) // detach 所有线程，不等待
            {
                if (w.joinable())
                    w.detach();
            }
            workers_.clear();
        }
    };

    // 定义全局唯一的线程池实例
    inline ThreadPool GlobalPool{Config::GetThreadCount()};
}

// ============================================================================
// 类型定义
// ============================================================================
namespace Types
{
    enum class DataType : uint8_t
    {
        I8 = 0,
        I16,
        I32,
        I64,
        Float,
        Double,
        Count
    };

    enum class FuzzyMode : uint8_t
    {
        Unknown = 0,
        Equal,
        Greater,
        Less,
        Increased,
        Decreased,
        Changed,
        Unchanged,
        Range,
        Pointer,
        Count
    };

    enum class ViewFormat : uint8_t
    {
        Hex = 0,
        Hex64,
        I8,
        I16,
        I32,
        I64,
        Float,
        Double,
        Disasm,
        Count
    };

    struct MemNode
    {
        uintptr_t addr;
        uintptr_t value;
        auto operator<=>(const MemNode &) const = default;
    };

    namespace Labels
    {
        constexpr std::array TYPE = {"Int8", "Int16", "Int32", "Int64", "Float", "Double"};
        constexpr std::array FUZZY = {"未知", "等于", "大于", "小于", "增加", "减少", "改变", "不变", "范围", "指针"};
        constexpr std::array FORMAT = {"HexDump", "Hex64", "I8", "I16", "I32", "I64", "Float", "Double", "Disasm"};
    }

    constexpr std::array<size_t, 6> DATA_SIZES = {1, 2, 4, 8, 4, 8};
    constexpr std::array<size_t, 9> VIEW_SIZES = {1, 8, 1, 2, 4, 8, 4, 8, 4};

    constexpr size_t GetDataSize(DataType type) noexcept
    {
        auto idx = std::to_underlying(type);
        return idx < DATA_SIZES.size() ? DATA_SIZES[idx] : 1;
    }

    constexpr size_t GetViewSize(ViewFormat fmt) noexcept
    {
        auto idx = std::to_underlying(fmt);
        return idx < VIEW_SIZES.size() ? VIEW_SIZES[idx] : 1;
    }
}

// ============================================================================
// 内存工具
// ============================================================================
namespace MemUtils
{
    using namespace Types;
    using namespace Config;

    // 去除MTE指针标签0xb40000
    constexpr uintptr_t Normalize(uintptr_t addr) noexcept
    {
        return addr & ~(0xFFULL << 56);
    }

    // 验证地址合法性，指针和地址才需要验证，值不需要
    constexpr bool IsValidAddr(uintptr_t addr) noexcept
    {
        uintptr_t a = Normalize(addr);
        return a > Constants::ADDR_MIN && a < Constants::ADDR_MAX;
    }

    // 辅助分发
    template <typename F>
    decltype(auto) DispatchType(DataType type, F &&fn)
    {
        switch (type)
        {
        case DataType::I8:
            return fn.template operator()<int8_t>();
        case DataType::I16:
            return fn.template operator()<int16_t>();
        case DataType::I32:
            return fn.template operator()<int32_t>();
        case DataType::I64:
            return fn.template operator()<int64_t>();
        case DataType::Float:
            return fn.template operator()<float>();
        case DataType::Double:
            return fn.template operator()<double>();
        default:
            return fn.template operator()<int32_t>();
        }
    }

    // 读取并格式化为字符串
    inline std::string ReadAsString(uintptr_t addr, DataType type)
    {
        addr = Normalize(addr);
        if (!addr)
            return "??";
        return DispatchType(type, [&]<typename T>() -> std::string
                            {
        T val = dr.Read<T>(addr);
        if constexpr (std::is_floating_point_v<T>)
            return std::format("{:.11f}", val);
        else if constexpr (sizeof(T) <= 4)
            return std::to_string(static_cast<int>(val));
        else
            return std::to_string(static_cast<long long>(val)); });
    }
    // 字符串解析写入
    inline bool WriteFromString(uintptr_t addr, DataType type, std::string_view str)
    {
        addr = Normalize(addr);
        if (!addr || str.empty())
            return false;
        try
        {
            std::string s(str);
            return DispatchType(type, [&]<typename T>() -> bool
                                {
            if constexpr (std::is_same_v<T, float>)
                return dr.Write<T>(addr, std::stof(s));
            else if constexpr (std::is_same_v<T, double>)
                return dr.Write<T>(addr, std::stod(s));
            else if constexpr (sizeof(T) <= 4)
                return dr.Write<T>(addr, static_cast<T>(std::stoi(s)));
            else
                return dr.Write<T>(addr, static_cast<T>(std::stoll(s))); });
        }
        catch (...)
        {
            return false;
        }
    }

    // 指针模式下读取地址处的int64，以Hex显示
    inline std::string ReadAsPointerString(uintptr_t addr)
    {
        addr = Normalize(addr);
        if (!addr)
            return "??";
        int64_t raw = dr.Read<int64_t>(addr);
        uintptr_t normalized = Normalize(static_cast<uintptr_t>(raw));
        return std::format("{:X}", normalized);
    }
    // 指针模式将Hex字符串解析为地址写入int64
    inline bool WritePointerFromString(uintptr_t addr, std::string_view str)
    {
        addr = Normalize(addr);
        if (!addr || str.empty())
            return false;
        try
        {
            std::string s(str);
            uintptr_t val = std::strtoull(s.c_str(), nullptr, 16);
            return dr.Write<int64_t>(addr, static_cast<int64_t>(val));
        }
        catch (...)
        {
            return false;
        }
    }

    template <typename T>
    bool Compare(T value, T target, FuzzyMode mode, double lastValue, double rangeMax = 0.0)
    {

        if constexpr (std::is_integral_v<T>)
        { // 整数使用精确比较
            T last = static_cast<T>(lastValue);
            switch (mode)
            {
            case FuzzyMode::Equal:
                return value == target;
            case FuzzyMode::Greater:
                return value > target;
            case FuzzyMode::Less:
                return value < target;
            case FuzzyMode::Increased:
                return value > last;
            case FuzzyMode::Decreased:
                return value < last;
            case FuzzyMode::Changed:
                return value != last;
            case FuzzyMode::Unchanged:
                return value == last;
            case FuzzyMode::Range:
            {
                T lo = target, hi = static_cast<T>(rangeMax);
                if (lo > hi)
                    std::swap(lo, hi);
                return value >= lo && value <= hi;
            }
            case FuzzyMode::Pointer:
            {
                uintptr_t normalizedValue = Normalize(static_cast<uintptr_t>(static_cast<std::make_unsigned_t<T>>(value)));
                uintptr_t normalizedTarget = Normalize(static_cast<uintptr_t>(static_cast<std::make_unsigned_t<T>>(target)));
                return normalizedValue == normalizedTarget;
            }
            default:
                return false;
            }
        }
        else
        {
            constexpr double eps = Constants::FLOAT_EPSILON;
            double v = static_cast<double>(value);
            double t = static_cast<double>(target);
            switch (mode)
            {
            case FuzzyMode::Equal:
                return std::abs(v - t) < eps;
            case FuzzyMode::Greater:
                return value > target;
            case FuzzyMode::Less:
                return value < target;
            case FuzzyMode::Increased:
                return value > static_cast<T>(lastValue);
            case FuzzyMode::Decreased:
                return value < static_cast<T>(lastValue);
            case FuzzyMode::Changed:
                return std::abs(v - lastValue) > eps;
            case FuzzyMode::Unchanged:
                return std::abs(v - lastValue) < eps;
            case FuzzyMode::Range:
            {
                double lo = t, hi = rangeMax;
                if (lo > hi)
                    std::swap(lo, hi); // 自动纠正反向输入
                return v >= lo - eps && v <= hi + eps;
            }
            case FuzzyMode::Pointer:
                return false; // 浮点类型不支持指针模式
            default:
                return false;
            }
        }
    }

    struct OffsetParseResult
    {
        uintptr_t offset;
        bool negative;
    };

    // 解析输入的HEX字符串
    inline std::optional<OffsetParseResult> ParseHexOffset(std::string_view str)
    {
        if (str.empty())
            return std::nullopt;

        size_t pos = 0;
        while (pos < str.size() && str[pos] == ' ')
            ++pos;
        if (pos >= str.size())
            return std::nullopt;

        bool negative = false;
        if (str[pos] == '-')
        {
            negative = true;
            ++pos;
        }
        else if (str[pos] == '+')
        {
            ++pos;
        }

        if (pos >= str.size())
            return std::nullopt;

        // 跳过0x前缀
        if (pos + 1 < str.size() && str[pos] == '0' && (str[pos + 1] == 'x' || str[pos + 1] == 'X'))
        {
            pos += 2;
        }

        uintptr_t offset = 0;
        std::string sub(str.substr(pos));
        if (std::sscanf(sub.c_str(), "%lx", &offset) != 1)
        {
            return std::nullopt;
        }

        return OffsetParseResult{offset, negative};
    }
}

// ============================================================================
// 内存扫描
// ============================================================================
class MemScanner
{
public:
    using Results = std::vector<uintptr_t>;
    using Values = std::vector<double>;

private:
    // ── Bitmap 模式数据 ──
    struct Region
    {
        uintptr_t start, end;
        size_t bitOffset, bitCount;
    };
    std::vector<Region> regions_;

    int bitmapFd_ = -1;
    uint8_t *bitmapMap_ = nullptr;
    size_t bitmapBytes_ = 0;
    size_t totalBits_ = 0;
    size_t setBits_ = 0;

    int valuesFd_ = -1;
    double *valuesMap_ = nullptr;
    size_t valuesCount_ = 0;
    size_t valueSize_ = 0;

    mutable std::shared_mutex mutex_;
    std::atomic<float> progress_{0.0f};
    std::atomic<bool> scanning_{false};
    double rangeMax_ = 0.0;

    // ── mmap 辅助 ──
    static int createTmpFd(size_t sz)
    {
        char tpl[] = "/data/local/tmp/memscan_XXXXXX";
        int fd = mkstemp(tpl);
        if (fd < 0)
            return -1;
        unlink(tpl);
        if (ftruncate(fd, static_cast<off_t>(sz)) != 0)
        {
            close(fd);
            return -1;
        }
        return fd;
    }

    static void *mapFd(int fd, size_t sz)
    {
        void *p = mmap(nullptr, sz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        return p == MAP_FAILED ? nullptr : p;
    }

    void freeBitmap()
    {
        if (bitmapMap_)
        {
            munmap(bitmapMap_, bitmapBytes_);
            bitmapMap_ = nullptr;
        }
        if (bitmapFd_ >= 0)
        {
            ::close(bitmapFd_);
            bitmapFd_ = -1;
        }
        bitmapBytes_ = totalBits_ = setBits_ = 0;
        regions_.clear();
    }

    void freeValues()
    {
        if (valuesMap_)
        {
            munmap(valuesMap_, valuesCount_ * sizeof(double));
            valuesMap_ = nullptr;
        }
        if (valuesFd_ >= 0)
        {
            ::close(valuesFd_);
            valuesFd_ = -1;
        }
        valuesCount_ = 0;
    }

    // ── Bitmap 操作 ──
    // ── Bitmap 操作 ──
    bool getBit(size_t i) const { return (bitmapMap_[i / 8] >> (i % 8)) & 1; }

    void setBitOn(size_t i)
    {
        uint8_t mask = (1u << (i % 8));
        __atomic_fetch_or(&bitmapMap_[i / 8], mask, __ATOMIC_RELAXED);
    }

    void setBitOff(size_t i)
    {
        uint8_t mask = ~(1u << (i % 8));
        __atomic_fetch_and(&bitmapMap_[i / 8], mask, __ATOMIC_RELAXED);
    }

    size_t addrToBit(uintptr_t addr) const
    {
        size_t lo = 0, hi = regions_.size();
        while (lo < hi)
        {
            size_t mid = (lo + hi) / 2;
            if (regions_[mid].end <= addr)
                lo = mid + 1;
            else
                hi = mid;
        }
        if (lo >= regions_.size() || addr < regions_[lo].start)
            return SIZE_MAX;

        size_t off = addr - regions_[lo].start;
        if (off % valueSize_ != 0)
            return SIZE_MAX;

        // 修复越界：防止由于计算误差导致访问到下个区块的位
        size_t index = off / valueSize_;
        if (index >= regions_[lo].bitCount)
            return SIZE_MAX;

        return regions_[lo].bitOffset + index;
    }

    uintptr_t bitToAddr(size_t globalBit) const
    {
        size_t lo = 0, hi = regions_.size();
        while (lo < hi)
        {
            size_t mid = (lo + hi) / 2;
            if (regions_[mid].bitOffset + regions_[mid].bitCount <= globalBit)
                lo = mid + 1;
            else
                hi = mid;
        }
        if (lo >= regions_.size())
            return 0;
        return regions_[lo].start + (globalBit - regions_[lo].bitOffset) * valueSize_;
    }

    bool initBitmap(size_t valSz,
                    const std::vector<std::pair<uintptr_t, uintptr_t>> &scanRegs,
                    bool allSet)
    {
        freeBitmap();
        freeValues();
        valueSize_ = valSz;
        totalBits_ = 0;
        regions_.reserve(scanRegs.size());
        for (auto &[s, e] : scanRegs)
        {
            if (e - s < valSz)
                continue;
            size_t bits = (e - s) / valSz;
            regions_.push_back({s, e, totalBits_, bits});
            totalBits_ += bits;
        }
        if (!totalBits_)
            return false;

        bitmapBytes_ = (totalBits_ + 7) / 8;
        bitmapFd_ = createTmpFd(bitmapBytes_);
        if (bitmapFd_ < 0)
            return false;
        bitmapMap_ = static_cast<uint8_t *>(mapFd(bitmapFd_, bitmapBytes_));
        if (!bitmapMap_)
        {
            ::close(bitmapFd_);
            bitmapFd_ = -1;
            return false;
        }

        if (allSet)
        {
            std::memset(bitmapMap_, 0xFF, bitmapBytes_);
            size_t tail = totalBits_ % 8;
            if (tail)
                bitmapMap_[bitmapBytes_ - 1] = static_cast<uint8_t>((1u << tail) - 1);
            setBits_ = totalBits_;
        }
        else
        {
            std::memset(bitmapMap_, 0, bitmapBytes_);
            setBits_ = 0;
        }

        valuesCount_ = totalBits_;
        valuesFd_ = createTmpFd(valuesCount_ * sizeof(double));
        if (valuesFd_ < 0)
            return false;
        valuesMap_ = static_cast<double *>(mapFd(valuesFd_, valuesCount_ * sizeof(double)));
        if (!valuesMap_)
        {
            ::close(valuesFd_);
            valuesFd_ = -1;
            return false;
        }
        madvise(valuesMap_, valuesCount_ * sizeof(double), MADV_SEQUENTIAL);

        return true;
    }

    // ── 值处理辅助 ──
    template <typename T>
    static double toDouble(T value, Types::FuzzyMode mode)
    {
        if constexpr (std::is_integral_v<T>)
        {
            if (mode == Types::FuzzyMode::Pointer)
                return static_cast<double>(MemUtils::Normalize(
                    static_cast<uintptr_t>(static_cast<std::make_unsigned_t<T>>(value))));
        }
        return static_cast<double>(value);
    }

    // ================================================================
    //  首扫 Unknown：bitmap全1 + 记录旧值到mmap
    // ================================================================

    template <typename T>
    void scanFirstUnknown(pid_t pid)
    {
        auto scanRegs = dr.GetScanRegions();
        if (scanRegs.empty())
            return;

        {
            std::unique_lock lock(mutex_);
            if (!initBitmap(sizeof(T), scanRegs, true))
                return;
        }

        unsigned tc = std::min(static_cast<size_t>(Config::GetThreadCount()), regions_.size());
        size_t chunk = (regions_.size() + tc - 1) / tc;
        std::atomic<size_t> done{0};
        std::vector<std::future<void>> futs;
        futs.reserve(tc);

        for (unsigned t = 0; t < tc; ++t)
        {
            futs.push_back(Utils::GlobalPool.push([&, t]
                                                  {
                size_t end = std::min(t * chunk + chunk, regions_.size());
                std::vector<uint8_t> buf(Config::Constants::SCAN_BUFFER);
                for (size_t ri = t * chunk; ri < end && Config::g_Running; ++ri)
                {
                    auto& reg = regions_[ri];
                    for (uintptr_t addr = reg.start; addr < reg.end;
                         addr += Config::Constants::SCAN_BUFFER)
                    {
                        size_t sz = std::min(static_cast<size_t>(reg.end - addr),
                                             Config::Constants::SCAN_BUFFER);
                        int readBytes = dr.Read(addr, buf.data(), sz);
                        if (readBytes <= 0)
                        {
                            for (size_t off = 0; off + sizeof(T) <= sz; off += sizeof(T))
                            {
                                size_t gb = reg.bitOffset + (addr + off - reg.start) / sizeof(T);
                                if (gb < totalBits_ && getBit(gb))
                                    setBitOff(gb);
                            }
                            continue;
                        }

                        size_t usable = static_cast<size_t>(readBytes);
                        for (size_t off = 0; off + sizeof(T) <= usable; off += sizeof(T))
                        {
                            T value;
                            std::memcpy(&value, buf.data() + off, sizeof(T));
                            size_t gb = reg.bitOffset + (addr + off - reg.start) / sizeof(T);
                            valuesMap_[gb] = static_cast<double>(value);
                        }
                        
                        for (size_t off = usable & ~(sizeof(T) - 1); off + sizeof(T) <= sz; off += sizeof(T))
                        {
                            size_t gb = reg.bitOffset + (addr + off - reg.start) / sizeof(T);
                            if (gb < totalBits_ && getBit(gb))
                                setBitOff(gb);
                        }
                    }
                    if ((done.fetch_add(1) & 0x3F) == 0)
                        progress_ = static_cast<float>(done) / regions_.size();
                } }));
        }
        for (auto &f : futs)
            f.get();

        // 终极修复：绝对安全地统计被保留下来的 1 的数量
        size_t actualSet = 0;
        for (size_t i = 0; i < bitmapBytes_; ++i)
        {
            uint8_t byteVal = bitmapMap_[i];
            if (byteVal)
            {
                // 回归本源的安全位移计算，防止任何编译器隐式越界转换
                for (int b = 0; b < 8; ++b)
                {
                    if ((byteVal >> b) & 1)
                        actualSet++;
                }
            }
        }

        std::unique_lock lock(mutex_);
        setBits_ = actualSet;
    }
    // ================================================================
    //  首扫有目标值 (强制写入 Bitmap)
    // ================================================================
    template <typename T>
    void scanFirst(pid_t pid, T target, Types::FuzzyMode mode)
    {
        auto scanRegs = dr.GetScanRegions();
        if (scanRegs.empty())
            return;

        {
            std::unique_lock lock(mutex_);
            if (!initBitmap(sizeof(T), scanRegs, false))
                return;
        }

        unsigned tc = std::min(static_cast<size_t>(Config::GetThreadCount()), scanRegs.size());
        std::vector<std::deque<uintptr_t>> tR(tc);
        std::vector<std::deque<double>> tV(tc);
        std::atomic<size_t> done{0};
        size_t chunk = (scanRegs.size() + tc - 1) / tc;
        double rmx = rangeMax_;

        std::vector<std::future<void>> futs;
        futs.reserve(tc);

        for (unsigned t = 0; t < tc; ++t)
        {
            futs.push_back(Utils::GlobalPool.push([&, t, rmx]
                                                  {
                size_t end = std::min(t * chunk + chunk, scanRegs.size());
                std::vector<uint8_t> buf(Config::Constants::SCAN_BUFFER);
                for (size_t i = t * chunk; i < end && Config::g_Running; ++i)
                {
                    auto [rStart, rEnd] = scanRegs[i];
                    if (rEnd - rStart < sizeof(T)) continue;
                    for (uintptr_t addr = rStart; addr < rEnd;
                         addr += Config::Constants::SCAN_BUFFER)
                    {
                        size_t sz = std::min(static_cast<size_t>(rEnd - addr),
                                             Config::Constants::SCAN_BUFFER);
                        
                        int readBytes = dr.Read(addr, buf.data(), sz);
                        if (readBytes <= 0) continue; 
                        
                        size_t usable = static_cast<size_t>(readBytes);
                        for (size_t off = 0; off + sizeof(T) <= usable; off += sizeof(T))
                        {
                            T value;
                            std::memcpy(&value, buf.data() + off, sizeof(T));
                            if (MemUtils::Compare(value, target, mode, 0, rmx))
                            {
                                tR[t].push_back(addr + off); 
                                tV[t].push_back(toDouble(value, mode));
                            }
                        }
                    }
                    if ((done.fetch_add(1) & 0x7F) == 0)
                        progress_ = static_cast<float>(done) / scanRegs.size();
                } }));
        }
        for (auto &f : futs)
            f.get();

        std::unique_lock lock(mutex_);
        size_t actualSet = 0;
        for (unsigned t = 0; t < tc; ++t)
        {
            for (size_t i = 0; i < tR[t].size(); ++i)
            {
                size_t gb = addrToBit(tR[t][i]);
                if (gb != SIZE_MAX)
                {
                    setBitOn(gb);
                    valuesMap_[gb] = tV[t][i];
                    ++actualSet;
                }
            }
        }
        setBits_ = actualSet;
    }
    // ================================================================
    //  二次扫描 Bitmap 模式
    // ================================================================
    template <typename T>
    void scanNext(T target, Types::FuzzyMode mode)
    {
        unsigned tc = std::min(static_cast<size_t>(Config::GetThreadCount()), regions_.size());
        size_t chunk = (regions_.size() + tc - 1) / tc;
        double rmx = rangeMax_;

        std::atomic<size_t> done{0};
        std::atomic<size_t> survived{0};

        std::vector<std::future<void>> futs;
        futs.reserve(tc);

        for (unsigned t = 0; t < tc; ++t)
        {
            futs.push_back(Utils::GlobalPool.push([&, t, rmx]
                                                  {
                size_t end = std::min(t * chunk + chunk, regions_.size());
                std::vector<uint8_t> buf(Config::Constants::SCAN_BUFFER);

                for (size_t ri = t * chunk; ri < end && Config::g_Running; ++ri)
                {
                    auto& reg = regions_[ri];
                    for (uintptr_t addr = reg.start; addr < reg.end;
                         addr += Config::Constants::SCAN_BUFFER)
                    {
                        size_t sz = std::min(static_cast<size_t>(reg.end - addr),
                                             Config::Constants::SCAN_BUFFER);
                        int readBytes = dr.Read(addr, buf.data(), sz);
                        if (readBytes <= 0)
                        {
                            for (size_t off = 0; off + sizeof(T) <= sz; off += sizeof(T))
                            {
                                size_t gb = reg.bitOffset + (addr + off - reg.start) / sizeof(T);
                                if (gb < totalBits_ && getBit(gb))
                                    setBitOff(gb);
                            }
                            continue;
                        }

                        size_t usable = static_cast<size_t>(readBytes);
                        for (size_t off = 0; off + sizeof(T) <= usable; off += sizeof(T))
                        {
                            size_t gb = reg.bitOffset + (addr + off - reg.start) / sizeof(T);
                            if (!getBit(gb)) continue;

                            T value;
                            std::memcpy(&value, buf.data() + off, sizeof(T));
                            double oldVal = valuesMap_[gb];

                            if (MemUtils::Compare(value, target, mode, oldVal, rmx))
                            {
                                valuesMap_[gb] = toDouble(value, mode);
                                survived.fetch_add(1, std::memory_order_relaxed);
                            }
                            else
                            {
                                setBitOff(gb);
                            }
                        }
                        
                        for (size_t off = usable & ~(sizeof(T) - 1); off + sizeof(T) <= sz; off += sizeof(T))
                        {
                            size_t gb = reg.bitOffset + (addr + off - reg.start) / sizeof(T);
                            if (gb < totalBits_ && getBit(gb))
                                setBitOff(gb);
                        }
                    }
                    if ((done.fetch_add(1) & 0x3F) == 0)
                        progress_ = static_cast<float>(done) / regions_.size();
                } }));
        }
        for (auto &f : futs)
            f.get();

        std::unique_lock lock(mutex_);
        setBits_ = survived.load();
    }

public:
    MemScanner() = default;
    ~MemScanner()
    {
        freeBitmap();
        freeValues();
    }
    MemScanner(const MemScanner &) = delete;
    MemScanner &operator=(const MemScanner &) = delete;

    bool isScanning() const noexcept { return scanning_; }
    float progress() const noexcept { return progress_; }

    size_t count() const
    {
        std::shared_lock lock(mutex_);
        return setBits_;
    }

    Results getPage(size_t start, size_t cnt) const
    {
        std::shared_lock lock(mutex_);
        if (!bitmapMap_ || setBits_ == 0 || start >= setBits_)
            return {};

        Results r;
        r.reserve(cnt);
        size_t found = 0, skipped = 0;

        for (auto &reg : regions_)
        {
            if (found >= cnt)
                break;
            size_t byteS = reg.bitOffset / 8;
            size_t byteE = (reg.bitOffset + reg.bitCount + 7) / 8;

            for (size_t b = byteS; b < byteE && found < cnt; ++b)
            {
                uint8_t byte = bitmapMap_[b];
                if (!byte)
                    continue;
                for (int bit = 0; bit < 8 && found < cnt; ++bit)
                {
                    if (!(byte & (1 << bit)))
                        continue;
                    size_t gb = b * 8 + bit;
                    if (gb < reg.bitOffset || gb >= reg.bitOffset + reg.bitCount)
                        continue;

                    if (skipped < start)
                    {
                        ++skipped;
                        continue;
                    }
                    r.push_back(bitToAddr(gb));
                    ++found;
                }
            }
        }
        return r;
    }

    void clear()
    {
        std::unique_lock lock(mutex_);
        freeBitmap();
        freeValues();
    }

    void remove(uintptr_t addr)
    {
        std::unique_lock lock(mutex_);
        size_t gb = addrToBit(addr);
        if (gb != SIZE_MAX && getBit(gb))
        {
            setBitOff(gb);
            --setBits_;
        }
    }

    void add(uintptr_t addr)
    {
        std::unique_lock lock(mutex_);
        size_t gb = addrToBit(addr);
        if (gb != SIZE_MAX && !getBit(gb))
        {
            setBitOn(gb);
            ++setBits_;
        }
    }

    void applyOffset(int64_t offset)
    {
        std::unique_lock lock(mutex_);
        if (!bitmapMap_ || setBits_ == 0)
            return;

        // 1. 提取当前 Bitmap 内仍然有效的地址及旧值
        std::vector<std::pair<uintptr_t, double>> temp;
        temp.reserve(setBits_);
        for (auto &reg : regions_)
        {
            size_t byteS = reg.bitOffset / 8;
            size_t byteE = (reg.bitOffset + reg.bitCount + 7) / 8;
            for (size_t b = byteS; b < byteE; ++b)
            {
                uint8_t byte = bitmapMap_[b];
                if (!byte)
                    continue;
                for (int bit = 0; bit < 8; ++bit)
                {
                    if (byte & (1 << bit))
                    {
                        size_t gb = b * 8 + bit;
                        if (gb >= reg.bitOffset && gb < reg.bitOffset + reg.bitCount)
                        {
                            uintptr_t oldAddr = bitToAddr(gb);
                            uintptr_t newAddr = offset > 0 ? oldAddr + static_cast<uintptr_t>(offset)
                                                           : oldAddr - static_cast<uintptr_t>(-offset);
                            temp.push_back({newAddr, valuesMap_[gb]});
                        }
                    }
                }
            }
        }

        // 2. 根据新内存布局重建纯净的 Bitmap
        auto scanRegs = dr.GetScanRegions();
        if (!initBitmap(valueSize_, scanRegs, false))
            return;

        // 3. 将偏移后的结果映射回新的 Bitmap 中
        size_t actualSet = 0;
        for (const auto &[addr, val] : temp)
        {
            size_t gb = addrToBit(addr);
            if (gb != SIZE_MAX)
            {
                setBitOn(gb);
                valuesMap_[gb] = val;
                actualSet++;
            }
        }
        setBits_ = actualSet;
    }

    template <typename T>
    void scan(pid_t pid, T target, Types::FuzzyMode mode, bool isFirst, double rangeMax = 0.0)
    {
        if (scanning_.exchange(true))
            return;
        struct Guard
        {
            std::atomic<bool> &s;
            std::atomic<float> &p;
            ~Guard()
            {
                s = false;
                p = 1.0f;
            }
        } guard{scanning_, progress_};

        progress_ = 0.0f;
        rangeMax_ = rangeMax;

        if (isFirst)
        {
            if (mode == Types::FuzzyMode::Unknown)
                scanFirstUnknown<T>(pid);
            else
                scanFirst<T>(pid, target, mode);
        }
        else
        {
            scanNext<T>(target, mode);
        }
    }
};

// ============================================================================
// 指针管理器
// ============================================================================
class PointerManager
{
public:
    struct PtrData
    {
        uintptr_t address, value;
        PtrData() : address(0), value(0) {}
        PtrData(uintptr_t a, uintptr_t v) : address(a), value(v) {}
    };

    struct PtrDir
    {
        uintptr_t address, value;
        uint32_t start, end;
        PtrDir() : address(0), value(0), start(0), end(0) {}
        PtrDir(uintptr_t a, uintptr_t v, uint32_t s = 0, uint32_t e = 0)
            : address(a), value(v), start(s), end(e) {}
    };

    struct PtrRange
    {
        int level;
        int moduleIdx = -1;
        int segIdx = -1;
        bool isManual;
        bool isArray;
        uintptr_t manualBase;
        uintptr_t arrayBase;
        size_t arrayIndex;
        std::vector<PtrDir> results;
        PtrRange() : level(0), moduleIdx(-1), segIdx(-1), isManual(false),
                     isArray(false), manualBase(0), arrayBase(0), arrayIndex(0) {}
    };

    struct BinHeader
    {
        char sign[32];
        int module_count;
        int version;
        int size;
        int level;
        uint8_t scanBaseMode;
        uint64_t scanManualBase;
        uint64_t scanArrayBase;
        uint64_t scanArrayCount;
        uint64_t scanTarget;
    };

    struct BinSym
    {
        uint64_t start;
        char name[128];
        int segment;
        int pointer_count;
        int level;
        bool isBss;
        uint8_t sourceMode;
        uint64_t manualBase;
        uint64_t arrayBase;
        uint64_t arrayIndex;
    };

    struct BinLevel
    {
        unsigned int count;
        int level;
    };

    enum class BaseMode : int
    {
        Module = 0,
        Manual,
        Array
    };

private:
    std::mutex block_mtx_;
    std::condition_variable block_cv_;
    std::vector<PtrData> pointers_;
    std::vector<std::pair<uintptr_t, uintptr_t>> regions_;
    std::atomic<bool> scanning_{false};
    std::atomic<float> scanProgress_{0.0f};
    size_t chainCount_ = 0;

    static std::string NextBinName()
    {
        char path[256];
        snprintf(path, sizeof(path), "Pointer.bin");
        if (access(path, F_OK) != 0)
            return path;
        for (int i = 1; i < 9999; i++)
        {
            snprintf(path, sizeof(path), "Pointer_%d.bin", i);
            if (access(path, F_OK) != 0)
                return path;
        }
        return "Pointer.bin";
    }

    template <typename F>
    void with_buffer_block(char **bufs, int &idx, uintptr_t start, size_t len, F &&call)
    {
        char *buf;
        {
            std::unique_lock<std::mutex> lk(block_mtx_);
            block_cv_.wait(lk, [&idx]
                           { return idx >= 0; });
            buf = bufs[idx--];
        }
        struct BufGuard
        {
            char **b;
            int &i;
            char *p;
            std::mutex &m;
            std::condition_variable &cv;
            ~BufGuard()
            {
                std::lock_guard<std::mutex> lk(m);
                b[++i] = p;
                cv.notify_one();
            }
        } guard{bufs, idx, buf, block_mtx_, block_cv_};

        call(buf, start, len);
    }

    void collect_pointers_block(char *buf, uintptr_t start, size_t len, FILE *&out)
    {
        out = tmpfile();
        if (!out)
            return;

        if (dr.Read(start, buf, len) <= 0)
        {
            fclose(out);
            out = nullptr;
            return;
        }

        uintptr_t *vals = reinterpret_cast<uintptr_t *>(buf);
        size_t ptr_count = len / sizeof(uintptr_t);

        for (size_t i = 0; i < ptr_count; i++)
            vals[i] = MemUtils::Normalize(vals[i]);

        uintptr_t min_addr = regions_.front().first;
        uintptr_t sub = regions_.back().second - min_addr;

        PtrData d;
        for (size_t i = 0; i < ptr_count; i++)
        {
            if ((vals[i] - min_addr) > sub)
                continue;

            int lo = 0, hi = static_cast<int>(regions_.size()) - 1;
            while (lo <= hi)
            {
                int mid = (lo + hi) >> 1;
                if (regions_[mid].second <= vals[i])
                    lo = mid + 1;
                else
                    hi = mid - 1;
            }

            if (static_cast<size_t>(lo) >= regions_.size() || vals[i] < regions_[lo].first)
                continue;

            d.address = MemUtils::Normalize(start + i * sizeof(uintptr_t));
            d.value = vals[i];
            fwrite(&d, sizeof(d), 1, out);
        }
        fflush(out);
    }

    template <typename C, typename F, typename V>
    static void bin_search(C &c, F &&cmp, V target, size_t sz, int &lo, int &hi)
    {
        lo = 0;
        hi = static_cast<int>(sz) - 1;
        while (lo <= hi)
        {
            int mid = (lo + hi) >> 1;
            if (cmp(c[mid], target))
                lo = mid + 1;
            else
                hi = mid - 1;
        }
    }

    void search_in_pointers(std::vector<PtrDir> &input, std::vector<PtrData *> &out, size_t offset, bool use_limit, size_t limit)
    {
        if (input.empty() || pointers_.empty())
            return;

        uintptr_t min_addr = regions_.front().first;
        uintptr_t sub = regions_.back().second - min_addr;
        size_t isz = input.size();
        std::vector<PtrData *> result;

        for (auto &pd : pointers_)
        {

            uintptr_t v = MemUtils::Normalize(pd.value);
            if ((v - min_addr) > sub)
                continue;

            int lo, hi;
            bin_search(input, [](auto &n, auto t)
                       { return n.address < t; }, v, isz, lo, hi);

            if (static_cast<size_t>(lo) >= isz)
                continue;

            if (MemUtils::Normalize(input[lo].address) - v > offset)
                continue;

            result.push_back(&pd);
        }

        size_t lim = use_limit ? std::min(limit, result.size()) : result.size();
        out.reserve(lim);
        for (size_t i = 0; i < lim; i++)
            out.push_back(result[i]);
    }

    void filter_to_ranges_module(std::vector<std::vector<PtrDir>> &dirs, std::vector<PtrRange> &ranges, std::vector<PtrData *> &curr, int level, const std::string &filterModule)
    {
        std::unordered_set<PtrData *> matched;
        const auto &info = dr.GetMemoryInfoRef();
        std::println("当前进程模块数量: {}", info.module_count);

        for (int mi = 0; mi < info.module_count; ++mi)
        {
            const auto &mod = info.modules[mi];
            std::string_view fullPath(mod.name);
            if (auto slash = fullPath.rfind('/'); slash != std::string_view::npos)
                fullPath = fullPath.substr(slash + 1);

            if (!filterModule.empty() && fullPath.find(filterModule) == std::string_view::npos)
                continue;

            for (int si = 0; si < mod.seg_count; ++si)
            {

                uintptr_t segStart = MemUtils::Normalize(mod.segs[si].start);
                uintptr_t segEnd = MemUtils::Normalize(mod.segs[si].end);

                PtrRange pr;
                pr.level = level;
                pr.moduleIdx = mi;
                pr.segIdx = si;
                pr.isManual = false;
                pr.isArray = false;
                for (auto *p : curr)
                {
                    uintptr_t addr = MemUtils::Normalize(p->address);
                    if (addr >= segStart && addr < segEnd)
                    {
                        if (matched.insert(p).second)
                            pr.results.emplace_back(addr, MemUtils::Normalize(p->value), 0u, 1u);
                    }
                }
                if (!pr.results.empty())
                    ranges.push_back(std::move(pr));
            }
        }
        push_unmatched(dirs, matched, curr, level);
    }

    void filter_to_ranges_combined(std::vector<std::vector<PtrDir>> &dirs, std::vector<PtrRange> &ranges, std::vector<PtrData *> &curr, int level, BaseMode scanMode, const std::string &filterModule, uintptr_t manualBase, size_t manualMaxOffset, uintptr_t arrayBase, const std::vector<std::pair<size_t, uintptr_t>> &arrayEntries, size_t maxOffset)
    {
        std::unordered_set<PtrData *> matched;
        const auto &info = dr.GetMemoryInfoRef();

        struct FlatSeg
        {
            uintptr_t start, end;
            int modIdx, segIdx;
        };
        std::vector<FlatSeg> flatSegs;
        for (int mi = 0; mi < info.module_count; ++mi)
        {
            const auto &mod = info.modules[mi];
            std::string_view fullPath(mod.name);
            if (auto slash = fullPath.rfind('/'); slash != std::string_view::npos)
                fullPath = fullPath.substr(slash + 1);

            if (!filterModule.empty() && fullPath.find(filterModule) == std::string_view::npos)
                continue;

            for (int si = 0; si < mod.seg_count; ++si)
            {

                flatSegs.push_back({MemUtils::Normalize(mod.segs[si].start),
                                    MemUtils::Normalize(mod.segs[si].end),
                                    mi, si});
            }
        }
        std::sort(flatSegs.begin(), flatSegs.end(), [](const auto &a, const auto &b)
                  { return a.start < b.start; });

        std::map<std::pair<int, int>, PtrRange> modRangeMap;

        for (auto *p : curr)
        {
            uintptr_t addr = MemUtils::Normalize(p->address);
            auto it = std::upper_bound(flatSegs.begin(), flatSegs.end(), addr, [](uintptr_t a, const FlatSeg &b)
                                       { return a < b.start; });
            if (it != flatSegs.begin())
            {
                auto prev = std::prev(it);
                if (addr >= prev->start && addr < prev->end)
                {
                    if (matched.insert(p).second)
                    {
                        auto &pr = modRangeMap[{prev->modIdx, prev->segIdx}];
                        if (pr.results.empty())
                        {
                            pr.level = level;
                            pr.moduleIdx = prev->modIdx;
                            pr.segIdx = prev->segIdx;
                            pr.isManual = false;
                            pr.isArray = false;
                        }
                        pr.results.emplace_back(addr, MemUtils::Normalize(p->value), 0u, 1u);
                    }
                }
            }
        }

        for (auto &[k, v] : modRangeMap)
            ranges.push_back(std::move(v));

        if (scanMode == BaseMode::Manual && manualBase)
        {
            uintptr_t normManualBase = MemUtils::Normalize(manualBase);
            PtrRange pr;
            pr.level = level;
            pr.moduleIdx = -1;
            pr.segIdx = -1;
            pr.isManual = true;
            pr.isArray = false;
            pr.manualBase = normManualBase;
            for (auto *p : curr)
            {
                uintptr_t addr = MemUtils::Normalize(p->address);
                if (addr >= normManualBase && (addr - normManualBase) <= manualMaxOffset)
                {
                    if (matched.insert(p).second)
                        pr.results.emplace_back(addr, MemUtils::Normalize(p->value), 0u, 1u);
                }
            }
            if (!pr.results.empty())
                ranges.push_back(std::move(pr));
        }

        if (scanMode == BaseMode::Array && !arrayEntries.empty())
        {
            for (const auto &[idx, objAddr] : arrayEntries)
            {

                PtrRange pr;
                pr.level = level;
                pr.moduleIdx = -1;
                pr.segIdx = -1;
                pr.isManual = false;
                pr.isArray = true;
                pr.arrayBase = MemUtils::Normalize(arrayBase);
                pr.arrayIndex = idx;
                for (auto *p : curr)
                {
                    uintptr_t addr = MemUtils::Normalize(p->address);
                    if (addr >= objAddr && (addr - objAddr) <= maxOffset)
                    {
                        if (matched.insert(p).second)
                            pr.results.emplace_back(addr, MemUtils::Normalize(p->value), 0u, 1u);
                    }
                }
                if (!pr.results.empty())
                    ranges.push_back(std::move(pr));
            }
        }

        push_unmatched(dirs, matched, curr, level);
    }

    void push_unmatched(std::vector<std::vector<PtrDir>> &dirs, std::unordered_set<PtrData *> &matched, std::vector<PtrData *> &curr, int level)
    {
        for (auto *p : curr)
        {
            if (matched.find(p) == matched.end())
                dirs[level].emplace_back(MemUtils::Normalize(p->address), MemUtils::Normalize(p->value), 0u, 1u);
        }
    }

    void assoc_index(std::vector<PtrDir> &prev, PtrDir *start, size_t count, size_t offset)
    {
        size_t sz = prev.size();
        for (size_t i = 0; i < count; i++)
        {
            int lo, hi;
            uintptr_t normVal = MemUtils::Normalize(start[i].value);
            bin_search(prev, [](auto &x, auto t)
                       { return x.address < t; }, normVal, sz, lo, hi);
            start[i].start = lo;
            bin_search(prev, [](auto &x, auto t)
                       { return x.address <= t; }, normVal + offset, sz, lo, hi);
            start[i].end = lo;
        }
    }

    std::vector<std::future<void>> create_assoc_index(std::vector<PtrDir> &prev, std::vector<PtrDir> &curr, size_t offset)
    {
        std::vector<std::future<void>> futures;
        if (curr.empty())
            return futures;
        size_t total = curr.size(), pos = 0;
        while (pos < total)
        {
            size_t chunk = std::min(total - pos, static_cast<size_t>(10000));
            futures.push_back(Utils::GlobalPool.push(
                [this, &prev, s = &curr[pos], chunk, offset]
                { assoc_index(prev, s, chunk, offset); }));
            pos += chunk;
        }
        return futures;
    }

    struct DirTree
    {
        std::vector<std::vector<size_t>> counts;
        std::vector<std::vector<PtrDir *>> contents;
        bool valid = false;
    };

    void merge_dirs(const std::vector<PtrDir *> &sorted_ptrs, PtrDir *base_dir, std::vector<PtrDir *> &out)
    {
        size_t dist = 0;
        uint32_t right = 0;
        out.reserve(sorted_ptrs.size());

        for (auto *p : sorted_ptrs)
        {
            if (right <= p->start)
            {
                dist += p->start - right;
                for (uint32_t j = p->start; j < p->end; j++)
                    out.push_back(&base_dir[j]);
                right = p->end;
            }
            else if (right < p->end)
            {
                for (uint32_t j = right; j < p->end; j++)
                    out.push_back(&base_dir[j]);
                right = p->end;
            }
            p->start -= static_cast<uint32_t>(dist);
            p->end -= static_cast<uint32_t>(dist);
        }
    }

    DirTree build_dir_tree(std::vector<std::vector<PtrDir>> &dirs, std::vector<PtrRange> &ranges)
    {
        DirTree tree;
        if (ranges.empty())
            return tree;

        int max_level = 0;
        for (auto &r : ranges)
            max_level = std::max(max_level, r.level);

        std::vector<std::vector<PtrRange *>> level_ranges(dirs.size());
        for (auto &r : ranges)
            level_ranges[r.level].push_back(&r);

        tree.counts.resize(max_level + 1);
        tree.contents.resize(max_level + 1);

        for (int i = max_level; i > 0; i--)
        {
            std::vector<PtrDir *> stn;
            for (auto *r : level_ranges[i])
                for (auto &v : r->results)
                    stn.push_back(&v);
            for (auto *p : tree.contents[i])
                stn.push_back(p);

            std::sort(stn.begin(), stn.end(), [](auto a, auto b)
                      { return a->start < b->start; });

            std::vector<PtrDir *> merged_out;
            merge_dirs(stn, dirs[i - 1].data(), merged_out);

            if (merged_out.empty())
                return tree;

            tree.contents[i - 1] = std::move(merged_out);
        }

        tree.counts[0] = {0, 1};
        for (int i = 1; i <= max_level; i++)
        {
            auto &cc = tree.counts[i];
            size_t c = 0;
            cc.reserve(tree.contents[i - 1].size() + 1);
            cc.push_back(c);
            for (size_t j = 0; j < tree.contents[i - 1].size(); j++)
            {
                c += tree.counts[i - 1][tree.contents[i - 1][j]->end] - tree.counts[i - 1][tree.contents[i - 1][j]->start];
                cc.push_back(c);
            }
        }

        tree.valid = true;
        return tree;
    }

    void write_bin_file(std::vector<std::vector<PtrDir *>> &contents, std::vector<PtrRange> &ranges, FILE *f, BaseMode scanMode, uintptr_t target, uintptr_t manualBase, uintptr_t arrayBase, size_t arrayCount)
    {
        const auto &memInfo = dr.GetMemoryInfoRef();
        BinHeader hdr{};
        strcpy(hdr.sign, ".bin pointer chain");
        hdr.size = sizeof(uintptr_t);
        hdr.version = 102;
        hdr.module_count = static_cast<int>(ranges.size());
        hdr.level = static_cast<int>(contents.size()) - 1;
        hdr.scanBaseMode = static_cast<uint8_t>(scanMode);
        hdr.scanManualBase = MemUtils::Normalize(manualBase);
        hdr.scanArrayBase = MemUtils::Normalize(arrayBase);
        hdr.scanArrayCount = arrayCount;
        hdr.scanTarget = MemUtils::Normalize(target);
        fwrite(&hdr, sizeof(hdr), 1, f);

        for (auto &r : ranges)
        {
            BinSym sym{};
            if (r.isManual)
            {
                sym.sourceMode = 1;
                sym.manualBase = MemUtils::Normalize(r.manualBase);
                sym.start = sym.manualBase;
                strncpy(sym.name, "manual", sizeof(sym.name) - 1);
                sym.segment = 0;
                sym.isBss = false;
            }
            else if (r.isArray)
            {
                sym.sourceMode = 2;
                sym.arrayBase = MemUtils::Normalize(r.arrayBase);
                sym.arrayIndex = r.arrayIndex;

                uintptr_t objAddr = 0;
                dr.Read(MemUtils::Normalize(r.arrayBase) + r.arrayIndex * sizeof(uintptr_t), &objAddr, sizeof(objAddr));
                sym.start = MemUtils::Normalize(objAddr);
                char arrName[128];
                snprintf(arrName, sizeof(arrName), "array[%zu]", r.arrayIndex);
                strncpy(sym.name, arrName, sizeof(sym.name) - 1);
                sym.segment = 0;
                sym.isBss = false;
            }
            else
            {
                const auto &mod = memInfo.modules[r.moduleIdx];
                const auto &seg = mod.segs[r.segIdx];

                sym.start = MemUtils::Normalize(seg.start);
                sym.segment = seg.index;
                sym.isBss = (seg.index == -1);

                std::string_view fullPath(mod.name);
                if (auto slash = fullPath.rfind('/'); slash != std::string_view::npos)
                    fullPath = fullPath.substr(slash + 1);
                strncpy(sym.name, fullPath.data(), std::min(fullPath.size(), sizeof(sym.name) - 1));
                sym.sourceMode = 0;
            }
            sym.level = r.level;
            sym.pointer_count = static_cast<int>(r.results.size());
            fwrite(&sym, sizeof(sym), 1, f);
            fwrite(r.results.data(), sizeof(PtrDir), r.results.size(), f);
        }

        for (size_t i = 0; i + 1 < contents.size(); i++)
        {
            BinLevel ll{};
            ll.level = static_cast<int>(i);
            ll.count = static_cast<unsigned int>(contents[i].size());
            fwrite(&ll, sizeof(ll), 1, f);
            for (auto *p : contents[i])
                fwrite(p, sizeof(PtrDir), 1, f);
        }
        fflush(f);
    }

public:
    PointerManager() = default;
    ~PointerManager() = default;

    bool isScanning() const noexcept { return scanning_; }
    float scanProgress() const noexcept { return scanProgress_; }
    size_t count() const noexcept { return chainCount_; }

    size_t CollectPointers(int buf_count = 10, int buf_size = 1 << 20)
    {
        pointers_.clear();
        if (regions_.empty())
            return 0;
        int idx = buf_count - 1;
        std::vector<char *> bufs(buf_count);
        for (int i = 0; i < buf_count; i++)
            bufs[i] = new char[buf_size];
        std::vector<FILE *> tmp_files;
        std::mutex tmp_mtx;
        std::vector<std::future<void>> futures;
        for (auto &[rstart, rend] : regions_)
        {
            for (uintptr_t pos = rstart; pos < rend; pos += buf_size)
            {
                futures.push_back(Utils::GlobalPool.push(
                    [this, &bufs, &idx, pos, chunk = std::min(static_cast<size_t>(rend - pos), static_cast<size_t>(buf_size)), &tmp_files, &tmp_mtx]
                    {
                        FILE *out = nullptr;
                        with_buffer_block(bufs.data(), idx, pos, chunk,
                                          [this, &out](char *buf, uintptr_t s, size_t l)
                                          { collect_pointers_block(buf, s, l, out); });
                        if (out)
                        {
                            std::lock_guard<std::mutex> lk(tmp_mtx);
                            tmp_files.push_back(out);
                        }
                    }));
            }
        }
        for (auto &f : futures)
            f.get();

        FILE *merged = tmpfile();
        auto *mbuf = new char[1 << 20];
        for (auto *tf : tmp_files)
        {
            rewind(tf);
            size_t sz;
            while ((sz = fread(mbuf, 1, 1 << 20, tf)) > 0)
                fwrite(mbuf, sz, 1, merged);
            fclose(tf);
        }
        delete[] mbuf;
        fflush(merged);

        struct stat st;
        fstat(fileno(merged), &st);
        size_t total = st.st_size / sizeof(PtrData);
        if (total > 0)
        {
            pointers_.resize(total);
            rewind(merged);
            fread(pointers_.data(), sizeof(PtrData), total, merged);
        }
        fclose(merged);

        for (int i = 0; i < buf_count; i++)
            delete[] bufs[i];

        return pointers_.size();
    }

    void scan(pid_t pid, uintptr_t target, int depth, int maxOffset, bool useManual, uintptr_t manualBase, int manualMaxOffset, bool useArray, uintptr_t arrayBase, size_t arrayCount, const std::string &filterModule)
    {
        if (scanning_.exchange(true))
            return;

        struct ScanGuard
        {
            std::atomic<bool> &scanning;
            std::atomic<float> &progress;
            ~ScanGuard()
            {
                scanning = false;
                progress = 1.0f;
            }
        } guard{scanning_, scanProgress_};

        scanProgress_ = 0.0f;
        chainCount_ = 0;

        target = MemUtils::Normalize(target);
        manualBase = MemUtils::Normalize(manualBase);
        arrayBase = MemUtils::Normalize(arrayBase);

        std::println("=== 开始指针扫描 ===");
        std::println("目标: {:x}, 深度: {}, 偏移: {}", target, depth, maxOffset);

        regions_ = dr.GetScanRegions();

        for (auto &[rstart, rend] : regions_)
        {
            rstart = MemUtils::Normalize(rstart);
            rend = MemUtils::Normalize(rend);
        }
        std::sort(regions_.begin(), regions_.end());

        if (CollectPointers() == 0 || pointers_.empty())
        {
            std::println(stderr, "扫描失败: 内存快照为空");
            return;
        }
        std::println("内存快照数量: {}", pointers_.size());

        BaseMode scanMode = useManual ? BaseMode::Manual : (useArray ? BaseMode::Array : BaseMode::Module);

        FILE *outfile = tmpfile();
        if (!outfile)
        {
            std::println(stderr, "无法创建临时文件");
            return;
        }

        std::vector<PtrRange> ranges;
        std::vector<std::vector<PtrDir>> dirs(depth + 1);
        size_t fidx = 0;
        uint64_t totalChains = 0;

        std::vector<std::pair<size_t, uintptr_t>> arrayEntries;
        if (scanMode == BaseMode::Array && arrayBase && arrayCount > 0)
        {
            for (size_t i = 0; i < arrayCount; i++)
            {
                uintptr_t ptr = 0;

                if (dr.Read(arrayBase + i * sizeof(uintptr_t), &ptr, sizeof(ptr)))
                {
                    ptr = MemUtils::Normalize(ptr);
                    if (MemUtils::IsValidAddr(ptr))
                        arrayEntries.emplace_back(i, ptr);
                }
            }
        }

        dirs[0].emplace_back(target, 0, 0, 1);
        std::sort(dirs[0].begin(), dirs[0].end(), [](const PtrDir &a, const PtrDir &b)
                  { return a.address < b.address; });
        std::println("Level 0 初始化完成，目标地址数量: {}", dirs[0].size());

        std::vector<std::future<void>> allFutures;

        for (int level = 1; level <= depth; level++)
        {
            std::vector<PtrData *> curr;
            search_in_pointers(dirs[level - 1], curr, static_cast<size_t>(maxOffset), false, 0);

            if (curr.empty())
            {
                std::println("扫描在 Level {} 结束: 未找到指向上级的指针", level);
                break;
            }

            std::println("Level {} 搜索结果: 找到 {} 个指针", level, curr.size());
            std::sort(curr.begin(), curr.end(), [](auto a, auto b)
                      { return a->address < b->address; });

            filter_to_ranges_combined(dirs, ranges, curr, level, scanMode, filterModule, manualBase, static_cast<size_t>(manualMaxOffset), arrayBase, arrayEntries, static_cast<size_t>(maxOffset));

            for (auto &f : create_assoc_index(dirs[level - 1], dirs[level], static_cast<size_t>(maxOffset)))
                allFutures.push_back(std::move(f));

            scanProgress_ = static_cast<float>(level + 1) / (depth + 2);
        }

        for (; fidx < ranges.size(); fidx++)
        {
            if (ranges[fidx].level > 0)
            {
                for (auto &f : create_assoc_index(dirs[ranges[fidx].level - 1], ranges[fidx].results, static_cast<size_t>(maxOffset)))
                    allFutures.push_back(std::move(f));
            }
        }

        for (auto &f : allFutures)
        {
            if (f.valid())
                f.get();
        }
        allFutures.clear();

        if (!ranges.empty())
        {
            auto tree = build_dir_tree(dirs, ranges);
            if (tree.valid)
            {
                for (auto &r : ranges)
                {
                    if (static_cast<size_t>(r.level) < tree.counts.size())
                    {
                        for (auto &v : r.results)
                        {
                            if (v.end < tree.counts[r.level].size() && v.start < tree.counts[r.level].size())
                                totalChains += tree.counts[r.level][v.end] - tree.counts[r.level][v.start];
                        }
                    }
                }

                std::println("开始写入文件，正在保存 {} 条链条...", totalChains);
                write_bin_file(tree.contents, ranges, outfile, scanMode, target, manualBase, arrayBase, arrayCount);
                std::println("文件写入完成，总链数: {}", totalChains);
            }
        }
        else
        {
            std::println("结果为空: ranges vector is empty");
        }

        std::string autoName = NextBinName();
        if (FILE *saveFile = fopen(autoName.c_str(), "w+b"))
        {
            rewind(outfile);
            char buf[1 << 16];
            size_t sz;
            while ((sz = fread(buf, 1, sizeof(buf), outfile)) > 0)
                fwrite(buf, sz, 1, saveFile);
            fflush(saveFile);
            fclose(saveFile);
            std::println("结果已保存至: {}", autoName);
        }
        else
        {
            std::println(stderr, "无法保存文件: {}", autoName);
        }

        fclose(outfile);
        chainCount_ = static_cast<size_t>(totalChains);
    }

    struct MemoryGraph
    {
        BinHeader hdr{};
        struct Block
        {
            BinSym sym;
            std::vector<PtrDir> roots;
        };
        std::vector<Block> blocks;
        std::vector<std::vector<PtrDir>> levels;

        bool load(const std::string &path)
        {
            int fd = open(path.c_str(), O_RDONLY);
            if (fd < 0)
                return false;
            struct stat st;
            fstat(fd, &st);
            if (st.st_size < (long)sizeof(BinHeader))
            {
                close(fd);
                return false;
            }

            char *raw = (char *)mmap(nullptr, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
            if (raw == MAP_FAILED)
            {
                close(fd);
                return false;
            }

            char *cur = raw;
            char *eof = raw + st.st_size;
            hdr = *(BinHeader *)cur;
            cur += sizeof(BinHeader);

            if (hdr.level + 1 < 0 || hdr.level + 1 > 100)
            {
                munmap(raw, st.st_size);
                close(fd);
                return false;
            }

            blocks.clear();
            levels.clear();
            for (int i = 0; i < hdr.module_count; ++i)
            {
                if (cur + sizeof(BinSym) > eof)
                    break;
                BinSym *s = (BinSym *)cur;
                cur += sizeof(BinSym);
                long need = s->pointer_count * sizeof(PtrDir);
                if (cur + need > eof)
                    break;

                Block blk;
                blk.sym = *s;
                blk.roots.assign((PtrDir *)cur, (PtrDir *)(cur + need));
                blocks.push_back(std::move(blk));
                cur += need;
            }

            levels.resize(hdr.level + 1 > 0 ? hdr.level + 1 : 1);
            while (cur + sizeof(BinLevel) <= eof)
            {
                BinLevel *bl = (BinLevel *)cur;
                cur += sizeof(BinLevel);
                if (bl->level < 0 || bl->level >= (int)levels.size())
                    break;
                long need = bl->count * sizeof(PtrDir);
                if (cur + need > eof)
                    break;
                levels[bl->level].assign((PtrDir *)cur, (PtrDir *)(cur + need));
                cur += need;
            }
            munmap(raw, st.st_size);
            close(fd);
            return true;
        }

        bool save(const std::string &path)
        {
            FILE *f = fopen(path.c_str(), "wb");
            if (!f)
                return false;
            fwrite(&hdr, sizeof(BinHeader), 1, f);
            for (const auto &blk : blocks)
            {
                fwrite(&blk.sym, sizeof(BinSym), 1, f);
                if (!blk.roots.empty())
                    fwrite(blk.roots.data(), sizeof(PtrDir), blk.roots.size(), f);
            }
            for (int i = 0; i < (int)levels.size(); ++i)
            {
                BinLevel bl;
                bl.level = i;
                bl.count = levels[i].size();
                fwrite(&bl, sizeof(BinLevel), 1, f);
                if (!levels[i].empty())
                    fwrite(levels[i].data(), sizeof(PtrDir), levels[i].size(), f);
            }
            fclose(f);
            return true;
        }
    };

    bool prune_dfs(const PtrDir &nodeA, const PtrDir &nodeB, int current_level, const MemoryGraph &GA, const MemoryGraph &GB, std::vector<std::vector<uint8_t>> &memo)
    {
        // 成功触底，返回 true
        if (current_level < 0)
            return true;

        const auto &layerA = GA.levels[current_level];
        uint32_t startA = std::min((uint32_t)layerA.size(), nodeA.start);
        uint32_t endA = std::min((uint32_t)layerA.size(), nodeA.end);
        if (startA >= endA)
            return false;

        const auto &layerB = (current_level < (int)GB.levels.size()) ? GB.levels[current_level] : std::vector<PtrDir>();
        uint32_t startB = std::min((uint32_t)layerB.size(), nodeB.start);
        uint32_t endB = std::min((uint32_t)layerB.size(), nodeB.end);

        bool any_valid = false;

        for (uint32_t i = startA; i < endA; ++i)
        {
            // 通过偏移量在进程 B 中计算期望的下级地址
            uint64_t expected_addr_B = nodeB.value + (layerA[i].address - nodeA.value);

            if (startB < endB)
            {
                auto it = std::lower_bound(layerB.begin() + startB, layerB.begin() + endB, expected_addr_B,
                                           [](const PtrDir &n, uint64_t val)
                                           { return n.address < val; });

                if (it != layerB.begin() + endB && it->address == expected_addr_B)
                {
                    // 找到了进程 B 中对应的子节点，进行下一步验证
                    if (memo[current_level][i] == 1)
                    {
                        any_valid = true;
                    }
                    else if (prune_dfs(layerA[i], *it, current_level - 1, GA, GB, memo))
                    {
                        memo[current_level][i] = 1; // 只记录成功的验证，防止假阳性污染
                        any_valid = true;
                    }
                }
            }
        }
        return any_valid;
    }
    void MergeBins()
    {
        std::thread([this]()
                    {
            std::println("=== [MergeBins] 开始基于图裁剪算法的极速合并 ===");

            std::vector<std::string> files;
            if (access("Pointer.bin", F_OK) == 0) files.push_back("Pointer.bin");
            for (int i = 1; i < 9999; ++i) {
                char buf[64]; snprintf(buf, 64, "Pointer_%d.bin", i);
                if (access(buf, F_OK) == 0) files.push_back(buf); else if (i > 50) break;
            }

            if (files.size() < 2) { std::println("文件不足({})，跳过合并。", files.size()); return; }

            MemoryGraph GA;
            std::println("加载基准指针图: {}", files[0]);
            if (!GA.load(files[0])) return;

            for (size_t f_idx = 1; f_idx < files.size(); ++f_idx) {
                std::println("正在比对并裁剪: {}", files[f_idx]);
                MemoryGraph GB;
                if (!GB.load(files[f_idx])) continue;

                std::vector<std::vector<uint8_t>> memo_levels(GA.levels.size());
                for (size_t i = 0; i < GA.levels.size(); ++i)
                    memo_levels[i].resize(GA.levels[i].size(), 0);

                std::vector<std::vector<uint8_t>> memo_roots(GA.blocks.size());

                for (size_t b = 0; b < GA.blocks.size(); ++b) {
                    memo_roots[b].resize(GA.blocks[b].roots.size(), 0); // 默认为0即可

                    int match_b = -1;
                    for (size_t j = 0; j < GB.blocks.size(); ++j) {
                        if (GA.blocks[b].sym.sourceMode == GB.blocks[j].sym.sourceMode &&
                            GA.blocks[b].sym.segment == GB.blocks[j].sym.segment &&
                            strcmp(GA.blocks[b].sym.name, GB.blocks[j].sym.name) == 0) {
                            match_b = j; break;
                        }
                    }
                    if (match_b == -1) continue;

                    uint64_t baseA = (GA.blocks[b].sym.sourceMode == 1) ? GA.blocks[b].sym.manualBase : GA.blocks[b].sym.start;
                    uint64_t baseB = (GB.blocks[match_b].sym.sourceMode == 1) ? GB.blocks[match_b].sym.manualBase : GB.blocks[match_b].sym.start;

                    for (size_t r = 0; r < GA.blocks[b].roots.size(); ++r) {
                        auto it = std::lower_bound(GB.blocks[match_b].roots.begin(), GB.blocks[match_b].roots.end(),
                            baseB + (GA.blocks[b].roots[r].address - baseA),
                            [](const PtrDir& n, uint64_t val) { return n.address < val; });

                        if (it != GB.blocks[match_b].roots.end() && it->address == baseB + (GA.blocks[b].roots[r].address - baseA)) {
                            // 修复：从 sym.level - 1 向下遍历
                            if (prune_dfs(GA.blocks[b].roots[r], *it, GA.blocks[b].sym.level - 1, GA, GB, memo_levels))
                                memo_roots[b][r] = 1;
                        }
                    }
                }

                MemoryGraph G_next;
                G_next.hdr = GA.hdr;
                G_next.levels.resize(GA.levels.size());

                std::vector<std::vector<uint32_t>> new_idx(GA.levels.size());
                for (int L = 0; L < (int)GA.levels.size(); ++L) {
                    new_idx[L].resize(GA.levels[L].size(), 0);
                    for (size_t i = 0; i < GA.levels[L].size(); ++i) {
                        if (memo_levels[L][i] == 1) {
                            new_idx[L][i] = G_next.levels[L].size();
                            G_next.levels[L].push_back(GA.levels[L][i]);
                        }
                    }
                }

                for (size_t b = 0; b < GA.blocks.size(); ++b) {
                    MemoryGraph::Block next_blk;
                    next_blk.sym = GA.blocks[b].sym;
                    for (size_t r = 0; r < GA.blocks[b].roots.size(); ++r) {
                        if (memo_roots[b][r] == 1) next_blk.roots.push_back(GA.blocks[b].roots[r]);
                    }
                    if (!next_blk.roots.empty()) {
                        next_blk.sym.pointer_count = next_blk.roots.size();
                        G_next.blocks.push_back(std::move(next_blk));
                    }
                }
                G_next.hdr.module_count = G_next.blocks.size();

                auto repair_links = [](std::vector<PtrDir>& parents, const std::vector<uint8_t>& child_memos, const std::vector<uint32_t>& child_new_idx) {
                    uint32_t max_child = child_memos.size();
                    for (auto& p : parents) {
                        uint32_t n_start = 0, n_end = 0; bool found = false;
                        for (uint32_t i = std::min(max_child, p.start); i < std::min(max_child, p.end); ++i) {
                            if (child_memos[i] == 1) {
                                if (!found) { n_start = child_new_idx[i]; found = true; }
                                n_end = child_new_idx[i] + 1;
                            }
                        }
                        p.start = n_start; p.end = n_end;
                    }
                };

                // 修复：重新连接树枝时匹配对应正确的下级 Level
                for (auto& blk : G_next.blocks) {
                    int child_level = blk.sym.level - 1;
                    if (child_level >= 0 && child_level < (int)memo_levels.size()) {
                        repair_links(blk.roots, memo_levels[child_level], new_idx[child_level]);
                    } else {
                        for (auto& r : blk.roots) { r.start = 0; r.end = 0; }
                    }
                }
                for (int L = 1; L < (int)G_next.levels.size(); ++L) {
                    repair_links(G_next.levels[L], memo_levels[L - 1], new_idx[L - 1]);
                }

                GA = std::move(G_next);

                size_t remaining_roots = 0;
                for(auto& blk : GA.blocks) remaining_roots += blk.roots.size();
                std::println("  该轮裁剪完毕，剩余有效起始节点: {} 个", remaining_roots);
                if (GA.blocks.empty()) break;
            }

            GA.save("Pointer_Merged.tmp");
            for (const auto& fn : files) remove(fn.c_str());
            rename("Pointer_Merged.tmp", "Pointer.bin");

            std::println("图层合并结束！已成功剔除失效的指针树分支并生成 Pointer.bin"); })
            .detach();
    }

    void ExportToTxt()
    {
        std::println("=== 导出文本链条  ===");

        MemoryGraph G;
        if (!G.load("Pointer.bin"))
        {
            std::println(stderr, "无法加载文件");
            return;
        }

        FILE *fOut = fopen("Pointer_Export.txt", "w");
        if (!fOut)
            return;

        fprintf(fOut, "// Pointer Scan Export\n");
        fprintf(fOut, "// Version: %d, Depth: %d\n", G.hdr.version, G.hdr.level);
        fprintf(fOut, "// Target: 0x%llX\n", (unsigned long long)G.hdr.scanTarget);
        fprintf(fOut, "// Base Mode: %d (0=Module, 1=Manual, 2=Array)\n", G.hdr.scanBaseMode);
        fprintf(fOut, "// ========================================\n\n");

        size_t chainCount = 0;
        int64_t offsets[32];
        int offsetCount = 0;
        std::string currentBasePrefix;

        // 修复：从高层级向低层级递归
        std::function<void(int, const PtrDir &)> dfs = [&](int current_level, const PtrDir &node)
        {
            // < 0 证明我们成功触底到了 Target 级别
            if (current_level < 0)
            {
                fprintf(fOut, "%s", currentBasePrefix.c_str());
                for (int i = 0; i < offsetCount; ++i)
                {
                    if (offsets[i] >= 0)
                        fprintf(fOut, " + 0x%llX", (unsigned long long)offsets[i]);
                    else
                        fprintf(fOut, " - 0x%llX", (unsigned long long)(-offsets[i]));
                }
                fprintf(fOut, "\n");
                chainCount++;
                return;
            }

            // 跳过半路夭折的断头链路
            if (node.start >= node.end)
                return;

            for (uint32_t i = node.start; i < node.end; ++i)
            {
                if (offsetCount < 32)
                {
                    offsets[offsetCount++] = (int64_t)G.levels[current_level][i].address - (int64_t)node.value;
                    dfs(current_level - 1, G.levels[current_level][i]); // 向下找
                    offsetCount--;
                }
            }
        };

        for (const auto &blk : G.blocks)
        {
            char baseStr[256];
            uint64_t baseAddr;

            switch (blk.sym.sourceMode)
            {
            case 1:
                snprintf(baseStr, sizeof(baseStr), "\"Manual_0x%llX\"", (unsigned long long)blk.sym.manualBase);
                baseAddr = blk.sym.manualBase;
                break;
            case 2:
                snprintf(baseStr, sizeof(baseStr), "\"Array[%llu]\"", (unsigned long long)blk.sym.arrayIndex);
                baseAddr = blk.sym.start;
                break;
            default:
                snprintf(baseStr, sizeof(baseStr), "\"%s[%d]\"", blk.sym.name, blk.sym.segment);
                baseAddr = blk.sym.start;
                break;
            }

            for (const auto &root : blk.roots)
            {
                int64_t rootOff = (int64_t)root.address - (int64_t)baseAddr;
                char prefixBuf[512];
                if (rootOff >= 0)
                    snprintf(prefixBuf, sizeof(prefixBuf), "[%s + 0x%llX]", baseStr, (unsigned long long)rootOff);
                else
                    snprintf(prefixBuf, sizeof(prefixBuf), "[%s - 0x%llX]", baseStr, (unsigned long long)(-rootOff));

                currentBasePrefix = prefixBuf;
                offsetCount = 0;
                // 修复：传入 Root 真实的所属级别（向下找）
                dfs(blk.sym.level - 1, root);
            }
        }

        fclose(fOut);
        std::println("导出完成: 成功向外输出了 {} 条链条！", chainCount);
    }
};

// ============================================================================
// 锁定管理器
// ============================================================================
class LockManager
{
private:
    struct LockItem
    {
        uintptr_t addr;
        Types::DataType type;
        std::string value;
    };
    std::list<LockItem> locks_;
    mutable std::mutex mutex_;
    std::jthread writeThread_;

    auto find(uintptr_t addr)
    {
        return std::ranges::find_if(locks_, [addr](auto &i)
                                    { return i.addr == addr; });
    }

    void writeLoop(std::stop_token stoken)
    {
        while (!stoken.stop_requested() && Config::g_Running)
        {
            {
                std::lock_guard lock(mutex_);
                for (auto &item : locks_)
                    MemUtils::WriteFromString(item.addr, item.type, item.value);
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
    }

public:
    LockManager()
        : writeThread_([this](std::stop_token st)
                       { writeLoop(st); }) {}

    ~LockManager() { writeThread_.request_stop(); }

    bool isLocked(uintptr_t addr) const
    {
        std::lock_guard lock(mutex_);
        return std::ranges::any_of(locks_, [addr](const auto &i)
                                   { return i.addr == addr; });
    }

    void toggle(uintptr_t addr, Types::DataType type)
    {
        std::lock_guard lock(mutex_);
        if (auto it = find(addr); it != locks_.end())
            locks_.erase(it);
        else
            locks_.push_back({addr, type, MemUtils::ReadAsString(addr, type)});
    }

    void lock(uintptr_t addr, Types::DataType type, const std::string &value)
    {
        std::lock_guard lk(mutex_);
        if (find(addr) == locks_.end())
            locks_.push_back({addr, type, value});
    }

    void unlock(uintptr_t addr)
    {
        std::lock_guard lk(mutex_);
        std::erase_if(locks_, [addr](const auto &item)
                      { return item.addr == addr; });
    }

    void lockBatch(std::span<const uintptr_t> addrs, Types::DataType type)
    {
        std::lock_guard lk(mutex_);
        for (auto addr : addrs)
        {
            if (!std::ranges::any_of(locks_, [addr](const auto &item)
                                     { return item.addr == addr; }))
                locks_.emplace_back(addr, type, MemUtils::ReadAsString(addr, type));
        }
    }

    void unlockBatch(std::span<const uintptr_t> addrs)
    {
        std::lock_guard lk(mutex_);
        for (auto addr : addrs)
            std::erase_if(locks_, [addr](const auto &item)
                          { return item.addr == addr; });
    }

    void clear()
    {
        std::lock_guard lk(mutex_);
        locks_.clear();
    }
};

// ============================================================================
// 内存浏览器
// ============================================================================
class MemViewer
{
private:
    uintptr_t base_ = 0;
    Types::ViewFormat format_ = Types::ViewFormat::Hex;
    std::vector<uint8_t> buffer_;
    bool visible_ = false;
    bool readSuccess_ = false;
    Disasm::Disassembler disasm_;
    std::vector<Disasm::DisasmLine> disasmCache_;
    int disasmScrollIdx_ = 0;

public:
    MemViewer() : buffer_(Config::Constants::MEM_VIEW_RANGE * 2) {}

    bool isVisible() const noexcept { return visible_; }
    void setVisible(bool v) noexcept { visible_ = v; }
    Types::ViewFormat format() const noexcept { return format_; }
    bool readSuccess() const noexcept { return readSuccess_; }
    uintptr_t base() const noexcept { return base_; }
    const std::vector<uint8_t> &buffer() const noexcept { return buffer_; }
    const std::vector<Disasm::DisasmLine> &getDisasm() const noexcept { return disasmCache_; }
    int disasmScrollIdx() const noexcept { return disasmScrollIdx_; }

    void setFormat(Types::ViewFormat fmt)
    {
        format_ = fmt;
        disasmScrollIdx_ = 0;
        refresh();
    }

    void open(uintptr_t addr)
    {
        if (format_ == Types::ViewFormat::Disasm)
            addr &= ~static_cast<uintptr_t>(3);
        base_ = addr;
        disasmScrollIdx_ = 0;
        refresh();
        visible_ = true;
    }

    void move(int lines, size_t step)
    {
        if (format_ == Types::ViewFormat::Disasm)
        {
            moveDisasm(lines);
        }
        else
        {
            int64_t delta = static_cast<int64_t>(lines) * static_cast<int64_t>(step);
            if (delta < 0 && base_ < static_cast<uintptr_t>(-delta))
                base_ = 0;
            else
                base_ += delta;
            refresh();
        }
    }

    void refresh()
    {
        if (base_ > Config::Constants::ADDR_MAX)
        {
            readSuccess_ = false;
            disasmCache_.clear();
            return;
        }
        std::ranges::fill(buffer_, 0);
        readSuccess_ = (dr.Read(base_, buffer_.data(), buffer_.size()));
        if (!readSuccess_)
        {
            disasmCache_.clear();
            return;
        }
        if (format_ == Types::ViewFormat::Disasm)
        {
            disasmCache_.clear();
            disasmScrollIdx_ = 0;
            if (disasm_.IsValid() && !buffer_.empty())
                disasmCache_ = disasm_.Disassemble(base_, buffer_.data(), buffer_.size(), 0);
        }
    }

    bool applyOffset(std::string_view offsetStr)
    {
        auto result = MemUtils::ParseHexOffset(offsetStr);
        if (!result)
            return false;
        open(result->negative ? (base_ - result->offset) : (base_ + result->offset));
        return true;
    }

private:
    void moveDisasm(int lines)
    {
        if (lines == 0)
            return;

        if (disasmCache_.empty())
        {
            if (lines > 0)
                base_ += lines * 4;
            else
                base_ = (base_ > static_cast<size_t>(-lines) * 4) ? (base_ - static_cast<size_t>(-lines) * 4) : 0;
            base_ &= ~static_cast<uintptr_t>(3);
            disasmScrollIdx_ = 0;
            refresh();
            return;
        }

        int newIdx = disasmScrollIdx_ + lines;
        static constexpr int MARGIN = 50;

        if (newIdx < 0)
        {
            base_ = (base_ > static_cast<size_t>(-newIdx) * 4) ? (base_ - static_cast<size_t>(-newIdx) * 4) : 0;
            base_ &= ~static_cast<uintptr_t>(3);
            disasmScrollIdx_ = 0;
            refresh();
        }
        else if (newIdx + MARGIN >= static_cast<int>(disasmCache_.size()))
        {
            base_ = disasmCache_[std::min(static_cast<size_t>(newIdx), disasmCache_.size() - 1)].address;
            disasmScrollIdx_ = 0;
            refresh();
        }
        else
        {
            disasmScrollIdx_ = newIdx;
        }
    }
};

// ============================================================================
// UI 构建器
// ============================================================================
class UIStyle
{
public:
    float scale = 2.0f, margin = 40.0f;
    constexpr float S(float v) const noexcept { return v * scale; }
    void apply() const
    {
        auto &s = ImGui::GetStyle();
        s.FramePadding = {S(10), S(10)};
        s.ItemSpacing = {S(6), S(6)};
        s.TouchExtraPadding = {8, 8};
        s.ScrollbarSize = S(22);
        s.GrabMinSize = S(18);
        s.WindowRounding = S(8);
        s.ChildRounding = S(6);
        s.FrameRounding = S(5);
        s.WindowPadding = {S(8), S(8)};
        s.WindowBorderSize = 0;
    }
};

// ============================================================================
// 布局构建器
// ============================================================================
namespace UI
{
    inline void Space(float y) { ImGui::Dummy({0, y}); }

    inline void Text(ImVec4 col, const char *fmt, ...)
    {
        va_list a;
        va_start(a, fmt);
        ImGui::TextColoredV(col, fmt, a);
        va_end(a);
    }

    inline bool Btn(const char *label, ImVec2 size, ImVec4 col = {})
    {
        if (col.w > 0)
            ImGui::PushStyleColor(ImGuiCol_Button, col);
        bool r = ImGui::Button(label, size);
        if (col.w > 0)
            ImGui::PopStyleColor();
        return r;
    }

    inline bool KbBtn(const char *text, const char *empty, ImVec2 size,
                      char *buf, int maxLen, const char *title)
    {
        ImGui::PushID((const void *)buf);
        bool r = ImGui::Button(strlen(text) ? text : empty, size) &&
                 (ImGuiFloatingKeyboard::Open(buf, maxLen, title), true);
        ImGui::PopID();
        return r;
    }

    // ---- 高级布局组件 ----

    // 带颜色的子窗口块
    template <typename F>
    void ColorChild(const char *id, ImVec2 size, ImVec4 bg, F &&body,
                    ImGuiWindowFlags flags = 0)
    {
        ImGui::PushStyleColor(ImGuiCol_ChildBg, bg);
        if (ImGui::BeginChild(id, size, true, flags))
            body();
        ImGui::EndChild();
        ImGui::PopStyleColor();
    }

    // 一行多按钮，自动 SameLine
    struct BtnDef
    {
        const char *label;
        ImVec4 col;
        std::function<void()> action;
    };
    inline void ButtonRow(float totalW, float h, std::initializer_list<BtnDef> btns,
                          float gap = 0)
    {
        float bw = (totalW - gap * (btns.size() - 1)) / btns.size();
        int i = 0;
        for (auto &b : btns)
        {
            if (i++ > 0)
                ImGui::SameLine();
            if (Btn(b.label, {bw, h}, b.col) && b.action)
                b.action();
        }
    }

    // 标签 + 值 行
    inline void LabelValue(ImVec4 labelCol, const char *label,
                           ImVec4 valCol, const char *fmt, ...)
    {
        Text(labelCol, "%s", label);
        ImGui::SameLine();
        va_list a;
        va_start(a, fmt);
        ImGui::TextColoredV(valCol, fmt, a);
        va_end(a);
    }

    // 输入行：KB按钮 + 动作按钮
    inline bool InputAction(char *buf, const char *hint, float inputW, float btnW,
                            float h, const char *btnLabel, ImVec4 btnCol,
                            const char *kbTitle)
    {
        KbBtn(buf, hint, {inputW - btnW - 6, h}, buf, 31, kbTitle);
        ImGui::SameLine();
        return Btn(btnLabel, {btnW, h}, btnCol);
    }

    // 上下箭头滚动条
    inline void ArrowScroll(const char *id, float w, float h,
                            int &idx, int minIdx, int maxIdx)
    {
        if (ImGui::BeginChild(id, {w, h}, false, ImGuiWindowFlags_NoScrollbar))
        {
            ImGui::PushStyleColor(ImGuiCol_Button, {0.2f, 0.3f, 0.4f, 1.0f});
            ImGui::BeginDisabled(idx <= minIdx);
            if (ImGui::Button("▲", {w, h / 2 - 3}))
                --idx;
            ImGui::EndDisabled();
            ImGui::BeginDisabled(idx >= maxIdx);
            if (ImGui::Button("▼", {w, h / 2 - 3}))
                ++idx;
            ImGui::EndDisabled();
            ImGui::PopStyleColor();
        }
        ImGui::EndChild();
    }

    // 通用选择器弹窗
    template <typename T>
    bool SelectorPopup(const char *title, bool *show, float sx, float sy, float sw, float sh,
                       const char *const *items, int count, T *sel)
    {
        float S = 2.0f; // 或从外部传入
        float pw = sw * 0.75f;
        float ph = std::min(count * 46.0f + 50.0f, sh * 0.7f);
        ImGui::SetNextWindowPos({sx + (sw - pw) / 2, sy + (sh - ph) / 2});
        ImGui::SetNextWindowSize({pw, ph});
        ImGui::PushStyleColor(ImGuiCol_WindowBg, {0.1f, 0.1f, 0.13f, 0.98f});
        bool changed = false;
        if (ImGui::Begin(title, show, ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove))
        {
            float fw = ImGui::GetContentRegionAvail().x;
            for (int i = 0; i < count; ++i)
            {
                ImVec4 c = (i == static_cast<int>(*sel))
                               ? ImVec4{0.2f, 0.35f, 0.25f, 1}
                               : ImVec4{0.13f, 0.13f, 0.16f, 1};
                if (Btn(items[i], {fw, 42}, c))
                {
                    *sel = static_cast<T>(i);
                    *show = false;
                    changed = true;
                }
            }
        }
        ImGui::End();
        ImGui::PopStyleColor();
        return changed;
    }
}
namespace Colors
{
    constexpr ImVec4 BG_DARK = {0.06f, 0.06f, 0.08f, 1.0f};
    constexpr ImVec4 BG_MID = {0.08f, 0.08f, 0.1f, 1.0f};
    constexpr ImVec4 BG_PANEL = {0.1f, 0.1f, 0.12f, 1.0f};
    constexpr ImVec4 BG_CARD = {0.12f, 0.12f, 0.14f, 1.0f};
    constexpr ImVec4 LABEL = {0.6f, 0.6f, 0.65f, 1};
    constexpr ImVec4 HINT = {0.5f, 0.5f, 0.5f, 1};
    constexpr ImVec4 ADDR_GREEN = {0.5f, 1, 0.5f, 1};
    constexpr ImVec4 ADDR_CYAN = {0.5f, 0.85f, 0.85f, 1};
    constexpr ImVec4 VAL_YELLOW = {1, 1, 0.6f, 1};
    constexpr ImVec4 WARN = {1, 0.8f, 0.2f, 1};
    constexpr ImVec4 ERR = {1, 0.4f, 0.4f, 1};
    constexpr ImVec4 OK = {0.4f, 0.9f, 0.4f, 1};
    constexpr ImVec4 TITLE = {0.9f, 0.7f, 0.4f, 1};
    constexpr ImVec4 LOCKED = {0.2f, 0.08f, 0.08f, 1};
    constexpr ImVec4 INFO_CYAN = {0.4f, 0.8f, 1.0f, 1};

    // 按钮颜色
    constexpr ImVec4 BTN_GREEN = {0.12f, 0.38f, 0.18f, 1.0f};
    constexpr ImVec4 BTN_BLUE = {0.12f, 0.25f, 0.4f, 1.0f};
    constexpr ImVec4 BTN_RED = {0.38f, 0.15f, 0.15f, 1.0f};
    constexpr ImVec4 BTN_TEAL = {0.15f, 0.28f, 0.4f, 1.0f};
    constexpr ImVec4 BTN_PURPLE = {0.35f, 0.25f, 0.45f, 1.0f};
    constexpr ImVec4 BTN_ORANGE = {0.35f, 0.25f, 0.15f, 1.0f};
    constexpr ImVec4 BTN_MINIMIZE = {0.15f, 0.4f, 0.6f, 1.0f};
    constexpr ImVec4 BTN_EXIT = {0.65f, 0.15f, 0.15f, 1.0f};
    constexpr ImVec4 BTN_LOCK = {0.15f, 0.28f, 0.4f, 1};
    constexpr ImVec4 BTN_UNLOCK = {0.4f, 0.15f, 0.15f, 1};
    constexpr ImVec4 BTN_COPY = {0.25f, 0.35f, 0.5f, 1};
    constexpr ImVec4 BTN_DEL = {0.4f, 0.1f, 0.1f, 1};
    constexpr ImVec4 BTN_ACTIVE = {0.2f, 0.32f, 0.5f, 1};
    constexpr ImVec4 BTN_INACTIVE = {0.12f, 0.12f, 0.15f, 1};
}

// ============================================================================
// 主界面
// ============================================================================
class MainUI
{
private:
    MemScanner scanner_;
    PointerManager ptrManager_;
    LockManager lockManager_;
    MemViewer memViewer_;

    struct ScanParams
    {
        Types::DataType dataType = Types::DataType::I32;
        Types::FuzzyMode fuzzyMode = Types::FuzzyMode::Unknown;
        int page = 0;
    } scanParams_;

    struct PtrParams
    {
        uintptr_t target = 0;
        int depth = 3, maxOffset = 1000;
        bool useManual = false, useArray = false;
        uintptr_t manualBase = 0, arrayBase = 0;
        size_t arrayCount = 0;
        std::string filterModule;
    } ptrParams_;

    struct SigParams
    {
        uintptr_t scanAddr = 0, verifyAddr = 0;
        int range = 20, lastChanged = -1, lastTotal = 0, lastScanCount = -1;
    } sigParams_;

    struct BpParams
    {
        uintptr_t address = 0;
        int bpType = 1, bpScope = 2, lenBytes = 4;
        bool active = false;
    } bpParams_;

    std::vector<std::string> offsetLabels_;
    std::vector<int> offsetValues_;
    int selectedOffsetIdx_ = 1;
    UIStyle style_;

    struct Buf
    {
        char pid[32] = {}, value[64] = {}, addAddr[32] = {}, base[32] = {}, page[16] = "20";
        char modify[64] = {}, memOffset[32] = {}, resultOffset[32] = {}, moduleSearch[64] = {};
        char ptrTarget[32] = {}, arrayBase[32] = {}, arrayCount[16] = "100", filterModule[64] = {};
        char sigScanAddr[32] = {}, sigVerifyAddr[32] = {};
        char viewAddr[32] = {}, bpAddr[32] = {}, bpLen[16] = "4";
    } buf_;

    struct State
    {
        int tab = 0, resultScrollIdx = 0;
        uintptr_t modifyAddr = 0;
        bool showModify = false, floating = false, dragging = false;
        ImVec2 floatPos = {50, 200}, dragOffset = {};
        bool showType = false, showMode = false, showDepth = false,
             showOffset = false, showScale = false, showFormat = false;
        bool showBpType = false, showBpScope = false;
    } state_;

    float S(float v) const { return style_.S(v); }

    // ---- 扫描逻辑 ----
    void startScan(std::string_view valueStr, bool isFirst)
    {
        scanParams_.page = 0;
        auto type = scanParams_.dataType;
        auto mode = scanParams_.fuzzyMode;
        auto pid = dr.GetGlobalPid();
        std::string valCopy(valueStr);
        double rangeMax = 0.0;

        if (mode == Types::FuzzyMode::Pointer)
        {
            type = Types::DataType::I64;
            Utils::GlobalPool.push([=, this]
                                   {
                try {
                    auto addr = MemUtils::Normalize(std::strtoull(valCopy.c_str(), nullptr, 16));
                    scanner_.scan<int64_t>(pid, static_cast<int64_t>(addr), mode, isFirst, 0.0);
                } catch (...) {} });
            return;
        }
        if (mode == Types::FuzzyMode::Range)
        {
            auto pos = valCopy.find('~');
            if (pos == std::string::npos)
                return;
            try
            {
                rangeMax = std::stod(valCopy.substr(pos + 1));
                valCopy = valCopy.substr(0, pos);
            }
            catch (...)
            {
                return;
            }
        }
        Utils::GlobalPool.push([=, this]
                               {
            try {
                MemUtils::DispatchType(type, [&]<typename T>() {
                    T val;
                    if constexpr (std::is_floating_point_v<T>) val = static_cast<T>(std::stod(valCopy));
                    else if constexpr (sizeof(T) <= 4) val = static_cast<T>(std::stoi(valCopy));
                    else val = static_cast<T>(std::stoll(valCopy));
                    scanner_.scan<T>(pid, val, mode, isFirst, rangeMax);
                });
            } catch (...) {} });
    }

    void startPtrScan()
    {
        auto p = ptrParams_;
        p.maxOffset = offsetValues_[selectedOffsetIdx_];
        auto pid = dr.GetGlobalPid();
        Utils::GlobalPool.push([=, this]
                               { ptrManager_.scan(pid, p.target, p.depth, p.maxOffset, p.useManual,
                                                  p.manualBase, p.maxOffset, p.useArray, p.arrayBase,
                                                  p.arrayCount, p.filterModule); });
    }

    void copyAddress(uintptr_t addr)
    {
        ImGui::SetClipboardText(std::format("{:X}", addr).c_str());
    }

public:
    MainUI()
    {
        for (int i = 500; i <= 100000; i += 500)
        {
            offsetLabels_.push_back(std::to_string(i));
            offsetValues_.push_back(i);
        }
        snprintf(buf_.page, sizeof(buf_.page), "%d", Config::g_ItemsPerPage.load());
        SetInputBlocking(true);
    }

    void draw()
    {
        style_.apply();
        if (state_.floating)
            drawFloatButton();
        else
        {
            float m = style_.margin;
            float w = RenderVK::displayInfo.width - 2 * m;
            float h = RenderVK::displayInfo.height - 2 * m;
            drawMainWindow(m, m, w, h);
            drawPopups(m, m, w, h);
        }
        ImGuiFloatingKeyboard::Draw();
    }

private:
    // ---- 悬浮按钮 ----
    void drawFloatButton()
    {
        float sw = RenderVK::displayInfo.width, sh = RenderVK::displayInfo.height;
        float sz = S(65), m = style_.margin;
        state_.floatPos.x = std::clamp(state_.floatPos.x, m, sw - sz - m);
        state_.floatPos.y = std::clamp(state_.floatPos.y, m, sh - sz - m);
        ImGui::SetNextWindowPos(state_.floatPos);
        ImGui::SetNextWindowSize({sz, sz});
        ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, sz / 2);
        ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, {0, 0});
        ImGui::PushStyleColor(ImGuiCol_WindowBg, {0.2f, 0.5f, 0.8f, 0.9f});
        if (ImGui::Begin("##Float", nullptr, ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove))
        {
            auto &io = ImGui::GetIO();
            if (ImGui::IsWindowHovered() && io.MouseDown[0] && !state_.dragging)
            {
                state_.dragging = true;
                state_.dragOffset = {io.MousePos.x - ImGui::GetWindowPos().x,
                                     io.MousePos.y - ImGui::GetWindowPos().y};
            }
            if (state_.dragging)
            {
                if (io.MouseDown[0])
                    state_.floatPos = {io.MousePos.x - state_.dragOffset.x,
                                       io.MousePos.y - state_.dragOffset.y};
                else
                    state_.dragging = false;
            }
            if (ImGui::Button("M", {sz, sz}) && !state_.dragging)
            {
                state_.floating = false;
                SetInputBlocking(true);
            }
        }
        ImGui::End();
        ImGui::PopStyleColor();
        ImGui::PopStyleVar(2);
    }

    // ---- 主窗口 ----
    void drawMainWindow(float x, float y, float w, float h)
    {
        ImGui::SetNextWindowPos({x, y});
        ImGui::SetNextWindowSize({w, h});
        ImGui::PushStyleColor(ImGuiCol_WindowBg, Colors::BG_DARK);
        if (ImGui::Begin("##Main", nullptr, ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove))
        {
            float cw = ImGui::GetContentRegionAvail().x;
            drawTopBar(cw, S(55));
            UI::Space(S(4));
            float contentH = ImGui::GetContentRegionAvail().y - S(60) - S(4);
            drawContent(cw, contentH);
            UI::Space(S(4));
            drawTabs(cw, S(60));
        }
        ImGui::End();
        ImGui::PopStyleColor();
    }

    // ---- 顶栏 ----
    void drawTopBar(float w, float h)
    {
        UI::ColorChild("Top", {w, h}, Colors::BG_PANEL, [&]
                       {
            float bh = h - S(12);
            if (UI::Btn("收起", {S(55), bh}, Colors::BTN_MINIMIZE)) {
                state_.floating = true; SetInputBlocking(false);
            }
            ImGui::SameLine();
            ImGui::SetCursorPosX((w - ImGui::CalcTextSize("内存扫描").x) / 2);
            ImGui::SetCursorPosY((h - ImGui::GetTextLineHeight()) / 2);
            ImGui::Text("内存扫描");
            ImGui::SameLine(w - (S(50) + S(85) + S(50) + S(18)));
            ImGui::SetCursorPosY(S(6));
            char sc[16]; snprintf(sc, sizeof(sc), "%.0f%%", style_.scale * 100);
            if (ImGui::Button(sc, {S(50), bh})) state_.showScale = !state_.showScale;
            ImGui::SameLine();
            UI::KbBtn(buf_.pid, "PID", {S(85), bh}, buf_.pid, 31, "PID");
            ImGui::SameLine();
            if (!ImGuiFloatingKeyboard::IsVisible()) dr.SetGlobalPid(atoi(buf_.pid));
            ImGui::SameLine();
            if (UI::Btn("退出", {S(50), bh}, Colors::BTN_EXIT)) Config::g_Running = false; }, ImGuiWindowFlags_NoScrollbar);
    }

    // ---- 内容区 ----
    void drawContent(float w, float h)
    {
        using DrawFn = void (MainUI::*)();
        static constexpr int TAB_COUNT = 7;
        DrawFn tabs[] = {
            &MainUI::drawScanTab, &MainUI::drawResultTab, &MainUI::drawViewerTab,
            &MainUI::drawModuleTab, &MainUI::drawPointerTab,
            &MainUI::drawSignatureTab, &MainUI::drawBreakpointTab};
        UI::ColorChild("Content", {w, h}, Colors::BG_MID, [&]
                       { (this->*tabs[state_.tab])(); });
    }

    // ---- 标签栏 ----
    void drawTabs(float w, float h)
    {
        UI::ColorChild("Tabs", {w, h}, Colors::BG_PANEL, [&]
                       {
            constexpr int N = 7;
            float bw = (w - S(36)) / N;
            const char* labels[] = {"扫描", "结果", "浏览", "模块", "指针", "特征", "断点"};
            for (int i = 0; i < N; ++i) {
                if (i > 0) ImGui::SameLine();
                ImVec4 c = state_.tab == i ? Colors::BTN_ACTIVE : Colors::BTN_INACTIVE;
                if (UI::Btn(labels[i], {bw, h - S(14)}, c)) {
                    state_.tab = i;
                    if (i == 3 || i == 5) dr.GetMemoryInformation();
                    if (i == 2 && memViewer_.base()) memViewer_.refresh();
                }
            } }, ImGuiWindowFlags_NoScrollbar);
    }

    // ================================================================
    // 扫描页
    // ================================================================
    void drawScanTab()
    {
        float w = ImGui::GetContentRegionAvail().x;
        bool isPtrMode = scanParams_.fuzzyMode == Types::FuzzyMode::Pointer;

        // 数据类型
        UI::Text(Colors::LABEL, "数据类型:");
        if (isPtrMode)
        {
            ImGui::BeginDisabled();
            ImGui::Button("Int64 (指针模式固定)", {w, S(45)});
            ImGui::EndDisabled();
        }
        else
        {
            if (ImGui::Button(Types::Labels::TYPE[static_cast<int>(scanParams_.dataType)], {w, S(45)}))
                state_.showType = true;
        }

        UI::Space(S(6));
        UI::Text(Colors::LABEL, "搜索模式:");
        if (ImGui::Button(Types::Labels::FUZZY[static_cast<int>(scanParams_.fuzzyMode)], {w, S(45)}))
            state_.showMode = true;

        UI::Space(S(6));
        UI::Text(Colors::LABEL, isPtrMode ? "目标地址(Hex):" : "搜索数值:");
        UI::KbBtn(buf_.value, isPtrMode ? "输入Hex地址..." : "点击输入...",
                  {w, S(52)}, buf_.value, 63, isPtrMode ? "目标地址(Hex)" : "数值");

        if (isPtrMode)
            UI::Text(Colors::INFO_CYAN, "输入16进制地址，搜索指向该地址的指针");
        else if (scanParams_.fuzzyMode == Types::FuzzyMode::Range)
            UI::Text(Colors::INFO_CYAN, "格式: 最小值~最大值  例: 0~45  -2~2  0.1~6.5");

        UI::Space(S(10));
        ImGui::BeginDisabled(scanner_.isScanning());
        UI::ButtonRow(w, S(52), {{"首次扫描", Colors::BTN_GREEN, [&]
                                  { startScan(buf_.value, true); }},
                                 {"再次扫描", Colors::BTN_BLUE, [&]
                                  { startScan(buf_.value, false); }},
                                 {"清空", Colors::BTN_RED, [&]
                                  { scanner_.clear(); }}},
                      S(6));
        ImGui::EndDisabled();

        UI::Space(S(6));
        if (scanner_.isScanning())
        {
            UI::Text(Colors::WARN, "扫描中...");
            ImGui::ProgressBar(scanner_.progress(), {w, S(18)});
        }
        else
        {
            scanner_.count() ? UI::Text(Colors::OK, "找到 %zu 个", scanner_.count())
                             : UI::Text(Colors::HINT, "暂无结果");
        }
    }

    // ================================================================
    // 结果页
    // ================================================================
    void drawResultTab()
    {
        size_t total = scanner_.count();
        float w = ImGui::GetContentRegionAvail().x, bh = S(40);

        // 添加地址行
        UI::KbBtn(buf_.addAddr, "Hex地址...", {w - S(76), bh}, buf_.addAddr, 31, "Hex地址");
        ImGui::SameLine();
        if (UI::Btn("添加", {S(70), bh}, Colors::BTN_GREEN))
        {
            uintptr_t addr = 0;
            if (sscanf(buf_.addAddr, "%lx", &addr) == 1 && addr)
            {
                scanner_.add(addr);
                buf_.addAddr[0] = 0;
            }
        }
        if (!total)
        {
            UI::Text(Colors::HINT, "暂无结果");
            return;
        }

        int perPage = Config::g_ItemsPerPage.load();
        int maxPage = static_cast<int>((total - 1) / perPage);
        scanParams_.page = std::clamp(scanParams_.page, 0, maxPage);
        auto data = scanner_.getPage(scanParams_.page * perPage, perPage);

        // 翻页行
        UI::Space(S(4));
        drawPagination(w, bh, maxPage);
        UI::Space(S(4));
        drawResultToolbar(w, data);
        ImGui::Separator();

        // 结果列表 + 箭头
        float listH = ImGui::GetContentRegionAvail().y;
        float contentW = w - S(56);
        int maxIdx = std::max(0, (int)data.size() - (int)(listH / S(93)));
        state_.resultScrollIdx = std::clamp(state_.resultScrollIdx, 0, maxIdx);

        if (ImGui::BeginChild("ListContent", {contentW, listH}, false, ImGuiWindowFlags_NoScrollbar))
        {
            int endIdx = state_.resultScrollIdx + (int)(listH / S(93)) + 1;
            for (int i = state_.resultScrollIdx; i < (int)data.size() && i < endIdx; ++i)
                drawCard(data[i], contentW - S(10));
        }
        ImGui::EndChild();
        ImGui::SameLine();
        UI::ArrowScroll("ListArrows", S(50), listH, state_.resultScrollIdx, 0, maxIdx);
    }

    void drawPagination(float w, float bh, int maxPage)
    {
        float pgW = S(65);
        ImGui::BeginDisabled(scanParams_.page <= 0);
        if (ImGui::Button("上页", {pgW, bh}))
        {
            --scanParams_.page;
            state_.resultScrollIdx = 0;
        }
        ImGui::EndDisabled();
        ImGui::SameLine();

        char info[64];
        snprintf(info, sizeof(info), "%d/%d (共%zu)", scanParams_.page + 1, maxPage + 1, scanner_.count());
        float infoW = w - pgW * 2 - S(12);
        UI::ColorChild("PageInfo", {infoW, bh}, Colors::BG_PANEL, [&]
                       {
            ImGui::SetCursorPos({(infoW - ImGui::CalcTextSize(info).x) / 2,
                                 (bh - ImGui::GetTextLineHeight()) / 2 - S(4)});
            ImGui::Text("%s", info); }, ImGuiWindowFlags_NoScrollbar);
        ImGui::SameLine();

        ImGui::BeginDisabled(scanParams_.page >= maxPage);
        if (ImGui::Button("下页", {pgW, bh}))
        {
            ++scanParams_.page;
            state_.resultScrollIdx = 0;
        }
        ImGui::EndDisabled();
    }

    void drawResultToolbar(float w, const std::vector<uintptr_t> &data)
    {
        ImGui::Text("每页:");
        ImGui::SameLine();
        UI::KbBtn(buf_.page, buf_.page, {S(55), S(36)}, buf_.page, 10, "每页数量");
        if (buf_.page[0] && !ImGuiFloatingKeyboard::IsVisible())
        {
            int v = atoi(buf_.page);
            if (v >= 1 && v <= 500)
            {
                if (v != Config::g_ItemsPerPage.load())
                {
                    Config::g_ItemsPerPage = v;
                    scanParams_.page = state_.resultScrollIdx = 0;
                }
            }
            else
                snprintf(buf_.page, sizeof(buf_.page), "%d", Config::g_ItemsPerPage.load());
        }
        ImGui::SameLine();

        bool anyLocked = std::ranges::any_of(data, [&](auto a)
                                             { return lockManager_.isLocked(a); });
        if (anyLocked)
        {
            if (UI::Btn("解锁页", {S(70), S(36)}, {0.2f, 0.25f, 0.42f, 1}))
                lockManager_.unlockBatch(data);
        }
        else
        {
            if (UI::Btn("锁定页", {S(70), S(36)}, {0.42f, 0.28f, 0.1f, 1}))
                lockManager_.lockBatch(data, scanParams_.dataType);
        }
        ImGui::SameLine();

        if (UI::Btn("偏移", {S(55), S(36)}, Colors::BTN_ORANGE))
        {
            buf_.resultOffset[0] = 0;
            ImGuiFloatingKeyboard::Open(buf_.resultOffset, 31, "偏移量(Hex,可负)");
        }
        if (buf_.resultOffset[0] && !ImGuiFloatingKeyboard::IsVisible())
        {
            if (auto r = MemUtils::ParseHexOffset(buf_.resultOffset))
                scanner_.applyOffset(r->negative ? -(int64_t)r->offset : (int64_t)r->offset);
            buf_.resultOffset[0] = 0;
        }
    }

    void drawCard(uintptr_t addr, float w)
    {
        bool locked = lockManager_.isLocked(addr);
        bool isPtrMode = scanParams_.fuzzyMode == Types::FuzzyMode::Pointer;

        ImGui::PushID((void *)addr);
        UI::ColorChild("Card", {w, S(85)}, locked ? Colors::LOCKED : Colors::BG_PANEL, [&]
                       {
            float cw = ImGui::GetContentRegionAvail().x;

            // 地址 + 值
            UI::LabelValue({0.5f,0.6f,0.7f,1}, "地址:",
                locked ? ImVec4{1,0.5f,0.5f,1} : Colors::ADDR_GREEN, "%lX", addr);
            ImGui::SameLine(cw * 0.45f);
            if (isPtrMode)
                UI::LabelValue({0.5f,0.6f,0.7f,1}, "指向:", Colors::VAL_YELLOW, "%s",
                               MemUtils::ReadAsPointerString(addr).c_str());
            else
                UI::LabelValue({0.5f,0.6f,0.7f,1}, "数值:", Colors::VAL_YELLOW, "%s",
                               MemUtils::ReadAsString(addr, scanParams_.dataType).c_str());
            if (locked) { ImGui::SameLine(); UI::Text({1,0.3f,0.3f,1}, "[锁定]"); }

            // 操作按钮
            UI::Space(S(4));
            float bw = (cw - S(15)) / 4;
            if (ImGui::Button("改", {bw, S(36)})) {
                state_.modifyAddr = addr;
                strcpy(buf_.modify, isPtrMode ? MemUtils::ReadAsPointerString(addr).c_str()
                                              : MemUtils::ReadAsString(addr, scanParams_.dataType).c_str());
                state_.showModify = true;
                ImGuiFloatingKeyboard::Open(buf_.modify, 63, isPtrMode ? "新地址(Hex)" : "新数值");
            }
            ImGui::SameLine();
            if (UI::Btn(locked ? "解锁" : "锁定", {bw, S(36)},
                        locked ? Colors::BTN_UNLOCK : Colors::BTN_LOCK))
                lockManager_.toggle(addr, isPtrMode ? Types::DataType::I64 : scanParams_.dataType);
            ImGui::SameLine();
            if (UI::Btn("复制", {bw, S(36)}, Colors::BTN_COPY)) copyAddress(addr);
            ImGui::SameLine();
            if (UI::Btn("删除", {bw, S(36)}, Colors::BTN_DEL)) {
                if (locked) lockManager_.unlock(addr);
                scanner_.remove(addr);
            } }, ImGuiWindowFlags_NoScrollbar);
        ImGui::PopID();
        UI::Space(S(4));
    }

    // ================================================================
    // 内存浏览页
    // ================================================================
    void drawViewerTab()
    {
        float w = ImGui::GetContentRegionAvail().x, bh = S(42);
        float goW = S(55), ofsW = S(55), fmtW = S(85), refW = S(55);
        float inputW = w - goW - ofsW - fmtW - refW - S(24);

        // 工具栏：一行五按钮
        UI::KbBtn(buf_.viewAddr, "输入Hex地址...", {inputW, bh}, buf_.viewAddr, 31, "Hex地址");
        ImGui::SameLine();
        if (UI::Btn("跳转", {goW, bh}, {0.15f, 0.4f, 0.25f, 1}))
        {
            uintptr_t addr = 0;
            if (sscanf(buf_.viewAddr, "%lx", &addr) == 1 && addr)
                memViewer_.open(addr);
        }
        ImGui::SameLine();
        if (UI::Btn("偏移", {ofsW, bh}, Colors::BTN_ORANGE))
        {
            buf_.memOffset[0] = 0;
            ImGuiFloatingKeyboard::Open(buf_.memOffset, 31, "偏移量(Hex,可负)");
        }
        if (buf_.memOffset[0] && !ImGuiFloatingKeyboard::IsVisible())
        {
            memViewer_.applyOffset(buf_.memOffset);
            buf_.memOffset[0] = 0;
        }
        ImGui::SameLine();
        if (UI::Btn(Types::Labels::FORMAT[(int)memViewer_.format()], {fmtW, bh}, {0.18f, 0.25f, 0.35f, 1}))
            state_.showFormat = true;
        ImGui::SameLine();
        if (UI::Btn("刷新", {refW, bh}, Colors::BTN_TEAL))
            memViewer_.refresh();

        // 基址信息
        UI::Space(S(2));
        if (memViewer_.base())
        {
            UI::LabelValue(Colors::ADDR_CYAN, "基址: ", Colors::ADDR_GREEN, "%lX", memViewer_.base());
            if (!memViewer_.readSuccess())
            {
                ImGui::SameLine();
                UI::Text(Colors::ERR, "[读取失败]");
            }
        }
        else
        {
            UI::Text(Colors::HINT, "输入地址后点击跳转开始浏览");
        }
        ImGui::Separator();
        if (!memViewer_.base())
            return;

        // 读取失败提示
        if (!memViewer_.readSuccess())
        {
            UI::Space(S(20));
            ImGui::PushStyleColor(ImGuiCol_Text, {1, 0.5f, 0.5f, 1});
            ImGui::TextWrapped("无法读取内存，请检查：\n\n1. PID 是否正确并已同步\n"
                               "2. 目标地址是否有效\n3. 驱动是否正常工作\n4. 目标进程是否仍在运行");
            ImGui::PopStyleColor();
            UI::Space(S(10));
            if (ImGui::Button("重试", {S(80), S(36)}))
                memViewer_.refresh();
            return;
        }

        // 数据显示 + 箭头
        auto fmt = memViewer_.format();
        size_t step = fmt == Types::ViewFormat::Disasm ? 1
                                                       : (fmt == Types::ViewFormat::Hex ? 4 : Types::GetViewSize(fmt));
        float cH = ImGui::GetContentRegionAvail().y, aW = S(50);
        float cW = ImGui::GetContentRegionAvail().x - aW - S(6);
        float rH = ImGui::GetTextLineHeight() +
                   (fmt == Types::ViewFormat::Disasm ? S(14)
                    : fmt == Types::ViewFormat::Hex  ? S(8)
                                                     : S(12));
        int rows = (int)(cH / rH) + 2;

        if (ImGui::BeginChild("MemContent", {cW, cH}, false, ImGuiWindowFlags_NoScrollbar))
        {
            if (fmt == Types::ViewFormat::Disasm)
                drawDisasmView(memViewer_.base(), memViewer_.getDisasm(), rows, memViewer_.disasmScrollIdx());
            else if (fmt == Types::ViewFormat::Hex)
                drawHexDump(memViewer_.base(), memViewer_.buffer(), rows);
            else
                drawTypedView(fmt, memViewer_.base(), memViewer_.buffer(), rows);
        }
        ImGui::EndChild();
        ImGui::SameLine();

        if (ImGui::BeginChild("MemArrows", {aW, cH}, false, ImGuiWindowFlags_NoScrollbar))
        {
            ImGui::PushStyleColor(ImGuiCol_Button, {0.2f, 0.3f, 0.4f, 1});
            if (ImGui::Button("▲##view", {aW, cH / 2 - S(3)}))
                memViewer_.move(-1, step);
            if (ImGui::Button("▼##view", {aW, cH / 2 - S(3)}))
                memViewer_.move(1, step);
            ImGui::PopStyleColor();
        }
        ImGui::EndChild();
    }

    // ================================================================
    // 模块页
    // ================================================================
    void drawModuleTab()
    {
        float w = ImGui::GetContentRegionAvail().x;
        UI::KbBtn(buf_.moduleSearch, "搜索模块名和dump模块", {w, S(42)},
                  buf_.moduleSearch, 63, "输入模块名进行搜索或Dump");
        UI::Space(S(4));
        if (UI::Btn("刷新模块", {w, S(48)}, Colors::BTN_TEAL))
            dr.GetMemoryInformation();
        UI::Space(S(6));
        if (UI::Btn("Dump 模块 (保存至 /sdcard/dump/)", {w, S(48)}, Colors::BTN_PURPLE))
        {
            if (strlen(buf_.moduleSearch) > 0)
            {
                std::string mod = buf_.moduleSearch;
                Utils::GlobalPool.push([mod]
                                       { dr.DumpModule(mod); });
            }
        }
        UI::Space(S(6));

        if (ImGui::BeginChild("ModList", {0, 0}, false))
        {
            const auto &info = dr.GetMemoryInfoRef();
            if (info.module_count == 0)
            {
                UI::Text(Colors::HINT, "暂无模块");
            }
            else
            {
                int displayCount = 0;
                for (int i = 0; i < info.module_count; ++i)
                {
                    const auto &mod = info.modules[i];
                    std::string_view name = mod.name;
                    if (auto s = name.rfind('/'); s != std::string_view::npos)
                        name = name.substr(s + 1);
                    if (buf_.moduleSearch[0] && name.find(buf_.moduleSearch) == std::string_view::npos)
                        continue;
                    for (int j = 0; j < mod.seg_count; ++j)
                    {
                        const auto &seg = mod.segs[j];
                        displayCount++;
                        ImGui::PushID(i * 1000 + j);
                        UI::ColorChild("Mod", {w - S(20), 0}, Colors::BG_CARD, [&]
                                       {
                            UI::Text({0.7f,0.85f,1,1}, "%.*s", (int)name.size(), name.data());
                            seg.index == -1
                                ? UI::Text({0.9f,0.6f,0.3f,1}, "Segment: BSS")
                                : UI::Text(Colors::ADDR_GREEN, "Segment: %d", seg.index);
                            UI::Text(Colors::HINT, "Range: "); ImGui::SameLine();
                            UI::Text({0.4f,1,0.4f,1}, "%llX - ", (unsigned long long)seg.start);
                            ImGui::SameLine();
                            UI::Text({1,0.6f,0.4f,1}, "%llX", (unsigned long long)seg.end); }, ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_AlwaysAutoResize);
                        ImGui::PopID();
                        UI::Space(S(4));
                    }
                }
                if (!displayCount)
                    UI::Text({0.6f, 0.4f, 0.4f, 1}, "未找到匹配 \"%s\" 的模块", buf_.moduleSearch);
            }
        }
        ImGui::EndChild();
    }

    // ================================================================
    // 指针扫描页
    // ================================================================
    void drawPointerTab()
    {
        float w = ImGui::GetContentRegionAvail().x, bh = S(45);
        ImGui::PushID("PtrScan");
        UI::Text(Colors::TITLE, "━━ 指针扫描 ━━");
        UI::Space(S(4));

        if (!ptrManager_.isScanning())
        {
            ImGui::Text("目标地址:");
            UI::KbBtn(buf_.ptrTarget, "点击输入Hex", {w, bh}, buf_.ptrTarget, 31, "目标地址(Hex)");
            UI::Space(S(4));

            // 深度和偏移
            ImGui::Text("深度:");
            ImGui::SameLine();
            char dLbl[8];
            snprintf(dLbl, sizeof(dLbl), "%d层", ptrParams_.depth);
            if (ImGui::Button(dLbl, {S(70), bh}))
                state_.showDepth = true;
            ImGui::SameLine();
            ImGui::Text("偏移:");
            ImGui::SameLine();
            if (ImGui::Button(offsetLabels_[selectedOffsetIdx_].c_str(), {S(70), bh}))
                state_.showOffset = true;

            UI::Space(S(4));
            UI::Text(Colors::LABEL, "指定模块 (可选):");
            UI::KbBtn(buf_.filterModule, "全部模块", {w - S(60), bh}, buf_.filterModule, 63, "模块名(如il2cpp)");
            ImGui::SameLine();
            if (ImGui::Button("清##scanFilter", {S(50), bh}))
                buf_.filterModule[0] = 0;

            // 手动/数组基址
            ImGui::Checkbox("手动基址##scan", &ptrParams_.useManual);
            if (ptrParams_.useManual)
            {
                ptrParams_.useArray = false;
                UI::KbBtn(buf_.base, "基址(Hex)##scanBase", {w, bh}, buf_.base, 30, "Hex基址");
            }
            ImGui::Checkbox("数组基址##scan", &ptrParams_.useArray);
            if (ptrParams_.useArray)
            {
                ptrParams_.useManual = false;
                float hw = (w - S(6)) / 2;
                UI::KbBtn(buf_.arrayBase, "数组地址(Hex)", {hw, bh}, buf_.arrayBase, 30, "数组首地址");
                ImGui::SameLine();
                UI::KbBtn(buf_.arrayCount, "数量", {hw, bh}, buf_.arrayCount, 15, "元素数量");
            }

            UI::Space(S(6));
            if (UI::Btn("开始扫描", {w, S(48)}, Colors::BTN_GREEN))
            {
                if (sscanf(buf_.ptrTarget, "%lx", &ptrParams_.target) == 1 && ptrParams_.target)
                {
                    ptrParams_.filterModule = buf_.filterModule;
                    if (ptrParams_.useManual && buf_.base[0])
                        ptrParams_.manualBase = strtoull(buf_.base, nullptr, 16);
                    if (ptrParams_.useArray)
                    {
                        if (buf_.arrayBase[0])
                            ptrParams_.arrayBase = strtoull(buf_.arrayBase, nullptr, 16);
                        if (buf_.arrayCount[0])
                            ptrParams_.arrayCount = strtoull(buf_.arrayCount, nullptr, 10);
                    }
                    startPtrScan();
                }
            }

            // 文件操作
            UI::Space(S(12));
            ImGui::Separator();
            UI::Space(S(8));
            UI::Text({0.6f, 0.7f, 0.8f, 1}, "文件操作 (Pointer.bin)");
            UI::Space(S(4));
            UI::ButtonRow(w, S(40), {{"开始对比", Colors::BTN_PURPLE, [&]
                                      { ptrManager_.MergeBins(); }},
                                     {"格式化输出", {0.45f, 0.35f, 0.2f, 1}, [&]
                                      { ptrManager_.ExportToTxt(); }}},
                          S(8));

            if (auto cnt = ptrManager_.count(); cnt > 0)
            {
                UI::Space(S(6));
                UI::Text({0.4f, 1, 0.4f, 1}, "扫描完成！找到 %zu 条指针链", cnt);
            }
            else if (ptrManager_.scanProgress() >= 1.0f)
            {
                UI::Space(S(6));
                UI::Text(Colors::ERR, "扫描完成，未找到结果");
            }
            UI::Text(Colors::HINT, "保存到 Pointer.bin");
        }
        else
        {
            UI::Text(Colors::WARN, "扫描中...");
            ImGui::ProgressBar(ptrManager_.scanProgress(), {w, S(22)});
        }
        ImGui::PopID();
    }

    // ================================================================
    // 特征码页
    // ================================================================
    void drawSignatureTab()
    {
        float w = ImGui::GetContentRegionAvail().x, bh = S(45);

        // 扫描部分
        UI::Text(Colors::TITLE, "━━ 特征码扫描 ━━");
        UI::Space(S(4));
        ImGui::Text("目标地址:");
        UI::KbBtn(buf_.sigScanAddr, "点击输入Hex", {w, bh}, buf_.sigScanAddr, 31, "目标地址(Hex)");
        UI::Space(S(4));
        ImGui::Text("范围 (上下各N字节):");
        ImGui::SetNextItemWidth(w);
        ImGui::SliderInt("##sigRange", &sigParams_.range, 1, SignatureScanner::SIG_MAX_RANGE, "%d");

        // 快速范围按钮
        float qbw = (w - S(12)) / 4;
        for (int r : {10, 20, 50, 100})
        {
            char lb[8];
            snprintf(lb, sizeof(lb), "%d", r);
            if (ImGui::Button(lb, {qbw, S(30)}))
                sigParams_.range = r;
            if (r != 100)
                ImGui::SameLine();
        }

        UI::Space(S(8));
        if (UI::Btn("扫描保存", {w, S(48)}, Colors::BTN_GREEN))
        {
            uintptr_t addr = 0;
            if (sscanf(buf_.sigScanAddr, "%lx", &addr) == 1 && addr)
                SignatureScanner::ScanAddressSignature(addr, sigParams_.range);
        }
        UI::Text(Colors::HINT, "保存到 Signature.txt");

        // 过滤部分
        UI::Space(S(20));
        ImGui::Separator();
        UI::Space(S(10));
        UI::Text(Colors::TITLE, "━━ 特征码过滤 ━━");
        UI::Space(S(4));
        ImGui::Text("过滤地址:");
        UI::KbBtn(buf_.sigVerifyAddr, "点击输入Hex", {w, bh}, buf_.sigVerifyAddr, 31, "过滤地址(Hex)");
        UI::Space(S(8));

        if (UI::Btn("过滤并更新", {w, S(48)}, {0.4f, 0.3f, 0.15f, 1}))
        {
            if (sscanf(buf_.sigVerifyAddr, "%lx", &sigParams_.verifyAddr) == 1 && sigParams_.verifyAddr)
            {
                auto vr = SignatureScanner::FilterSignature(sigParams_.verifyAddr);
                sigParams_.lastChanged = vr.success ? vr.changedCount : -2;
                if (vr.success)
                    sigParams_.lastTotal = vr.totalCount;
                sigParams_.lastScanCount = -1;
            }
        }
        if (sigParams_.lastChanged >= 0)
        {
            sigParams_.lastChanged == 0
                ? UI::Text(Colors::OK, "完美! 无变动 (%d字节)", sigParams_.lastTotal)
                : UI::Text(Colors::WARN, "变动: %d/%d (已更新)", sigParams_.lastChanged, sigParams_.lastTotal);
        }
        else if (sigParams_.lastChanged == -2)
            UI::Text(Colors::ERR, "失败! 检查Signature.txt");

        UI::Space(S(10));
        if (UI::Btn("扫描特征码", {w, S(48)}, Colors::BTN_PURPLE))
            sigParams_.lastScanCount = (int)SignatureScanner::ScanSignatureFromFile().size();
        if (sigParams_.lastScanCount >= 0)
        {
            sigParams_.lastScanCount == 0
                ? UI::Text(Colors::ERR, "未找到匹配地址")
                : UI::Text({0.5f, 0.9f, 1, 1}, "找到 %d 个地址", sigParams_.lastScanCount);
        }
        UI::Text(Colors::HINT, "结果保存到 Signature.txt");
    }

    // ================================================================
    // 断点页
    // ================================================================
    void drawBreakpointTab()
    {
        float w = ImGui::GetContentRegionAvail().x, bh = S(45);
        static const char *bpTypeLabels[] = {"读取", "写入", "读写", "执行"};
        static const char *bpScopeLabels[] = {"仅主线程", "仅子线程", "全部线程"};

        UI::Text(Colors::TITLE, "━━ 硬件断点 ━━");
        UI::Space(S(4));

        // 硬件信息
        const auto &info = dr.GetHwbpInfoRef();
        UI::LabelValue(Colors::ADDR_CYAN, "执行断点寄存器: ", Colors::ADDR_GREEN,
                       "%llu", (unsigned long long)info.num_brps);
        ImGui::SameLine();
        UI::LabelValue(Colors::ADDR_CYAN, "  访问断点寄存器: ", Colors::ADDR_GREEN,
                       "%llu", (unsigned long long)info.num_wrps);

        UI::Space(S(6));
        ImGui::Separator();
        UI::Space(S(6));

        // 配置
        ImGui::Text("断点地址:");
        UI::KbBtn(buf_.bpAddr, "点击输入Hex地址", {w, bh}, buf_.bpAddr, 31, "断点地址(Hex)");
        UI::Space(S(4));

        ImGui::Text("断点类型:");
        if (ImGui::Button(bpTypeLabels[bpParams_.bpType], {w, bh}))
            state_.showBpType = true;
        UI::Space(S(4));

        ImGui::Text("线程范围:");
        if (ImGui::Button(bpScopeLabels[bpParams_.bpScope], {w, bh}))
            state_.showBpScope = true;
        UI::Space(S(4));

        ImGui::Text("监控长度(字节):");
        UI::KbBtn(buf_.bpLen, "4", {w, bh}, buf_.bpLen, 15, "监控字节数");
        UI::Space(S(8));

        // 操作按钮
        float halfW = (w - S(8)) / 2;
        ImGui::BeginDisabled(bpParams_.active);
        if (UI::Btn("设置断点", {halfW, S(52)}, Colors::BTN_GREEN))
        {
            uintptr_t addr = 0;
            if (sscanf(buf_.bpAddr, "%lx", &addr) == 1 && addr)
            {
                int len = std::max(atoi(buf_.bpLen), 1);
                bpParams_.address = addr;
                bpParams_.lenBytes = len;
                if (dr.SetProcessHwbpRef(addr,
                                         static_cast<decltype(dr)::bp_type>(bpParams_.bpType),
                                         static_cast<decltype(dr)::bp_scope>(bpParams_.bpScope), len) == 0)
                    bpParams_.active = true;
            }
        }
        ImGui::EndDisabled();
        ImGui::SameLine();
        ImGui::BeginDisabled(!bpParams_.active);
        if (UI::Btn("移除断点", {halfW, S(52)}, {0.5f, 0.15f, 0.15f, 1}))
        {
            dr.RemoveProcessHwbpRef();
            bpParams_.active = false;
        }
        ImGui::EndDisabled();

        UI::Space(S(8));
        bpParams_.active
            ? UI::Text(Colors::OK, "● 断点已激活  地址: 0x%lX", bpParams_.address)
            : UI::Text(Colors::HINT, "○ 断点未激活");
        if (info.hit_addr)
            UI::Text(Colors::ADDR_CYAN, "监控地址: 0x%llX", (unsigned long long)info.hit_addr);

        UI::Space(S(8));
        ImGui::Separator();
        UI::Space(S(6));
        UI::Text(Colors::TITLE, "━━ 命中信息 ━━");
        UI::Space(S(4));

        if (info.record_count > 0)
            drawBpRecords(info, w);
        else
            UI::Text(Colors::HINT, "暂无命中记录");
    }

    void drawBpRecords(const auto &info, float w)
    {
        uint64_t totalHits = 0;
        for (int r = 0; r < info.record_count; ++r)
            totalHits += info.records[r].hit_count;
        UI::Text(Colors::WARN, "不同PC数: %d  总命中: %llu", info.record_count, (unsigned long long)totalHits);
        UI::Space(S(6));

        static bool expandState[0x100] = {};
        int deleteIdx = -1;

        for (int r = 0; r < info.record_count; ++r)
        {
            const auto &rec = info.records[r];
            ImGui::PushID(r);
            float btnW = S(55), expandW = S(45);

            // 摘要行
            UI::Text({0.7f, 0.85f, 1, 1}, "[%d]", r);
            ImGui::SameLine();
            UI::Text(Colors::ADDR_GREEN, "PC:0x%llX", (unsigned long long)rec.pc);
            ImGui::SameLine();
            UI::Text(Colors::WARN, "x%llu", (unsigned long long)rec.hit_count);

            ImGui::SameLine(w - btnW);
            if (UI::Btn("删除", {btnW, S(32)}, {0.6f, 0.15f, 0.15f, 1}))
                deleteIdx = r;
            ImGui::SameLine(w - btnW - expandW - S(4));
            if (UI::Btn(expandState[r] ? "收起" : "展开", {expandW, S(32)}, {0.2f, 0.3f, 0.45f, 1}))
                expandState[r] = !expandState[r];

            if (expandState[r])
            {
                ImGui::Indent(S(8));
                drawBpRecordDetail(rec, r);
                ImGui::Unindent(S(8));
            }

            UI::Space(S(4));
            ImGui::Separator();
            UI::Space(S(4));
            ImGui::PopID();
        }
        if (deleteIdx >= 0)
            dr.RemoveHwbpRecord(deleteIdx);
    }

    void drawBpRecordDetail(const auto &rec, int r)
    {
        // PC/LR/SP 带复制按钮
        auto regLine = [&](const char *name, uint64_t val, const char *copyId)
        {
            UI::Text({0.7f, 0.85f, 1, 1}, "%s: ", name);
            ImGui::SameLine();
            UI::Text(Colors::ADDR_GREEN, "0x%llX", (unsigned long long)val);
            ImGui::SameLine();
            char id[16];
            snprintf(id, sizeof(id), "复制##%s", copyId);
            if (UI::Btn(id, {S(50), S(28)}, Colors::BTN_COPY))
            {
                char tmp[32];
                snprintf(tmp, sizeof(tmp), "%llX", (unsigned long long)val);
                ImGui::SetClipboardText(tmp);
            }
        };
        regLine("PC", rec.pc, "pc");
        regLine("LR", rec.lr, "lr");
        regLine("SP", rec.sp, "sp");
        UI::Space(S(4));

        UI::Text(Colors::LABEL, "PSTATE:  0x%llX", (unsigned long long)rec.pstate);
        UI::Text(Colors::LABEL, "SYSCALL: %llu", (unsigned long long)rec.syscallno);
        UI::Text(Colors::LABEL, "ORIG_X0: 0x%llX", (unsigned long long)rec.orig_x0);
        UI::Text(Colors::WARN, "命中次数: %llu", (unsigned long long)rec.hit_count);
        UI::Space(S(6));

        // 寄存器表格
        UI::Text(Colors::TITLE, "━━ 通用寄存器 ━━");
        UI::Space(S(4));
        char tableId[32];
        snprintf(tableId, sizeof(tableId), "Regs##%d", r);
        ImGui::PushStyleVar(ImGuiStyleVar_CellPadding, {S(4), S(4)});
        if (ImGui::BeginTable(tableId, 3, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg))
        {
            ImGui::TableSetupColumn("寄存器", ImGuiTableColumnFlags_WidthFixed, S(55));
            ImGui::TableSetupColumn("值", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableSetupColumn("操作", ImGuiTableColumnFlags_WidthFixed, S(50));
            ImGui::TableHeadersRow();
            for (int i = 0; i < 30; ++i)
            {
                ImGui::TableNextRow();
                ImGui::PushID(i);
                ImGui::TableSetColumnIndex(0);
                UI::Text({0.7f, 0.85f, 1, 1}, "X%d", i);
                ImGui::TableSetColumnIndex(1);
                UI::Text(Colors::ADDR_GREEN, "0x%llX", (unsigned long long)rec.regs[i]);
                ImGui::TableSetColumnIndex(2);
                if (UI::Btn("复制", {S(42), S(28)}, Colors::BTN_COPY))
                {
                    char tmp[32];
                    snprintf(tmp, sizeof(tmp), "%llX", (unsigned long long)rec.regs[i]);
                    ImGui::SetClipboardText(tmp);
                }
                ImGui::PopID();
            }
            ImGui::EndTable();
        }
        ImGui::PopStyleVar();
    }

    // ================================================================
    // 弹窗统一管理
    // ================================================================
    void drawPopups(float sx, float sy, float sw, float sh)
    {
        // 缩放弹窗
        if (state_.showScale)
        {
            drawListPopup("缩放", &state_.showScale, sx, sy, sw, sh, S(180), S(160), [&](float fw)
                          {
                ImGui::Text("UI: %.0f%%", style_.scale * 100);
                ImGui::SliderFloat("##s", &style_.scale, 0.5f, 2.0f, "");
                float bw = fw / 3 - S(3);
                if (ImGui::Button("75%", {bw, S(28)})) style_.scale = 0.75f; ImGui::SameLine();
                if (ImGui::Button("100%", {bw, S(28)})) style_.scale = 1.0f; ImGui::SameLine();
                if (ImGui::Button("150%", {bw, S(28)})) style_.scale = 1.5f;
                ImGui::Text("边距: %.0f", style_.margin);
                ImGui::SliderFloat("##m", &style_.margin, 0, 80, ""); });
        }

        // 通用选择器
        auto doSelector = [&](const char *title, bool *show, auto items, int count, auto *sel)
        {
            int s = static_cast<int>(*sel);
            drawListPopup(title, show, sx, sy, sw, sh, sw * 0.75f,
                          std::min(count * (S(42) + S(4)) + S(50), sh * 0.7f), [&](float fw)
                          {
                for (int i = 0; i < count; ++i)
                    if (UI::Btn(items[i], {fw, S(42)},
                        i == s ? ImVec4{0.2f,0.35f,0.25f,1} : ImVec4{0.13f,0.13f,0.16f,1}))
                    { s = i; *show = false; } });
            *sel = static_cast<std::remove_pointer_t<decltype(sel)>>(s);
        };

        if (state_.showType)
            doSelector("类型", &state_.showType, Types::Labels::TYPE.data(),
                       (int)Types::Labels::TYPE.size(), &scanParams_.dataType);
        if (state_.showMode)
            doSelector("模式", &state_.showMode, Types::Labels::FUZZY.data(),
                       (int)Types::Labels::FUZZY.size(), &scanParams_.fuzzyMode);
        if (state_.showFormat)
        {
            auto fmt = memViewer_.format();
            doSelector("格式", &state_.showFormat, Types::Labels::FORMAT.data(),
                       (int)Types::ViewFormat::Count, &fmt);
            memViewer_.setFormat(fmt);
        }
        if (state_.showBpType)
        {
            static const char *items[] = {"读取", "写入", "读写", "执行"};
            doSelector("断点类型", &state_.showBpType, items, 4, &bpParams_.bpType);
        }
        if (state_.showBpScope)
        {
            static const char *items[] = {"仅主线程", "仅子线程", "全部线程"};
            doSelector("线程范围", &state_.showBpScope, items, 3, &bpParams_.bpScope);
        }

        // 深度选择
        if (state_.showDepth)
        {
            drawListPopup("深度", &state_.showDepth, sx, sy, sw, sh, S(160), S(320), [&](float fw)
                          {
                for (int i = 1; i <= 20; ++i) {
                    char lbl[8]; snprintf(lbl, sizeof(lbl), "%d层", i);
                    if (UI::Btn(lbl, {fw, S(28)}, i == ptrParams_.depth
                        ? ImVec4{0.2f,0.35f,0.25f,1} : ImVec4{0.13f,0.13f,0.16f,1}))
                    { ptrParams_.depth = i; state_.showDepth = false; }
                } });
        }

        // 偏移选择
        if (state_.showOffset)
        {
            drawListPopup("偏移", &state_.showOffset, sx, sy, sw, sh, S(160),
                          std::min((float)offsetLabels_.size() * S(32) + S(40), sh * 0.6f), [&](float fw)
                          {
                if (ImGui::BeginChild("List", {0, 0}, false)) {
                    for (size_t i = 0; i < offsetLabels_.size(); ++i)
                        if (UI::Btn(offsetLabels_[i].c_str(), {fw, S(28)},
                            (int)i == selectedOffsetIdx_
                                ? ImVec4{0.2f,0.35f,0.25f,1} : ImVec4{0.13f,0.13f,0.16f,1}))
                        { selectedOffsetIdx_ = i; state_.showOffset = false; }
                }
                ImGui::EndChild(); });
        }

        // 修改弹窗
        if (state_.showModify && !ImGuiFloatingKeyboard::IsVisible())
        {
            if (state_.modifyAddr && strlen(buf_.modify))
            {
                if (scanParams_.fuzzyMode == Types::FuzzyMode::Pointer)
                    MemUtils::WritePointerFromString(state_.modifyAddr, buf_.modify);
                else
                    MemUtils::WriteFromString(state_.modifyAddr, scanParams_.dataType, buf_.modify);
            }
            state_.showModify = false;
            state_.modifyAddr = 0;
            buf_.modify[0] = 0;
        }
    }

    template <typename F>
    void drawListPopup(const char *title, bool *show, float sx, float sy, float sw, float sh,
                       float pw, float ph, F &&drawItems)
    {
        ImGui::SetNextWindowPos({sx + (sw - pw) / 2, sy + (sh - ph) / 2});
        ImGui::SetNextWindowSize({pw, ph});
        ImGui::PushStyleColor(ImGuiCol_WindowBg, {0.1f, 0.1f, 0.13f, 0.98f});
        if (ImGui::Begin(title, show, ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove))
            drawItems(ImGui::GetContentRegionAvail().x);
        ImGui::End();
        ImGui::PopStyleColor();
    }

    // ================================================================
    // 内存视图渲染 (保持不变，已经很紧凑)
    // ================================================================
    void drawTypedView(Types::ViewFormat format, uintptr_t base,
                       std::span<const uint8_t> buffer, int rows)
    {
        ImGui::PushStyleVar(ImGuiStyleVar_CellPadding, {S(6), S(6)});
        if (ImGui::BeginTable("Typed", 4, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg))
        {
            ImGui::TableSetupColumn("地址", ImGuiTableColumnFlags_WidthFixed, S(100));
            ImGui::TableSetupColumn("数值", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableSetupColumn("存", ImGuiTableColumnFlags_WidthFixed, S(50));
            ImGui::TableSetupColumn("跳", ImGuiTableColumnFlags_WidthFixed, S(50));
            ImGui::TableHeadersRow();
            size_t step = Types::GetViewSize(format);
            for (int i = 0; i < rows; ++i)
            {
                size_t off = i * step;
                if (off + step > buffer.size())
                    break;
                uintptr_t addr = base + off;
                const uint8_t *p = buffer.data() + off;
                uint64_t ptrVal = 0;
                ImGui::TableNextRow();
                ImGui::PushID((void *)addr);
                ImGui::TableSetColumnIndex(0);
                UI::Text(i == 0 ? ImVec4{0.4f, 1, 0.4f, 1} : Colors::ADDR_CYAN, "%lX", addr);
                ImGui::TableSetColumnIndex(1);
                switch (format)
                {
                case Types::ViewFormat::Hex64:
                    ptrVal = *(const uint64_t *)p;
                    UI::Text({0.6f, 1, 0.6f, 1}, "%lX", ptrVal);
                    break;
                case Types::ViewFormat::I8:
                    ImGui::Text("%d", *(const int8_t *)p);
                    break;
                case Types::ViewFormat::I16:
                    ImGui::Text("%d", *(const int16_t *)p);
                    break;
                case Types::ViewFormat::I32:
                    ptrVal = *(const uint32_t *)p;
                    ImGui::Text("%d", *(const int32_t *)p);
                    break;
                case Types::ViewFormat::I64:
                    ptrVal = *(const uint64_t *)p;
                    ImGui::Text("%lld", (long long)*(const int64_t *)p);
                    break;
                case Types::ViewFormat::Float:
                    ImGui::Text("%.11f", *(const float *)p);
                    break;
                case Types::ViewFormat::Double:
                    ImGui::Text("%.11lf", *(const double *)p);
                    break;
                default:
                    ImGui::Text("?");
                }
                ImGui::TableSetColumnIndex(2);
                if (UI::Btn("存", {S(42), S(28)}, {0.2f, 0.4f, 0.25f, 1}))
                    scanner_.add(addr);
                ImGui::TableSetColumnIndex(3);
                uintptr_t jump = MemUtils::Normalize(ptrVal);
                bool canJump = (format == Types::ViewFormat::I32 || format == Types::ViewFormat::I64 || format == Types::ViewFormat::Hex64) && MemUtils::IsValidAddr(jump);
                if (canJump)
                {
                    if (UI::Btn("->", {S(42), S(28)}, Colors::BTN_PURPLE))
                        memViewer_.open(jump);
                }
                else
                {
                    ImGui::BeginDisabled();
                    ImGui::Button("-", {S(42), S(28)});
                    ImGui::EndDisabled();
                }
                ImGui::PopID();
            }
            ImGui::EndTable();
        }
        ImGui::PopStyleVar();
    }

    void drawHexDump(uintptr_t base, std::span<const uint8_t> buffer, int rows)
    {
        if (buffer.empty())
        {
            UI::Text(Colors::HINT, "无数据");
            return;
        }
        ImGui::PushStyleVar(ImGuiStyleVar_CellPadding, {S(3), S(3)});
        if (ImGui::BeginTable("Hex", 8, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg))
        {
            ImGui::TableSetupColumn("地址", ImGuiTableColumnFlags_WidthFixed, S(85));
            for (int i = 0; i < 4; ++i)
            {
                char h[4];
                snprintf(h, sizeof(h), "%X", i);
                ImGui::TableSetupColumn(h, ImGuiTableColumnFlags_WidthFixed, S(24));
            }
            ImGui::TableSetupColumn("ASCII", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableSetupColumn("存", ImGuiTableColumnFlags_WidthFixed, S(38));
            ImGui::TableSetupColumn("跳", ImGuiTableColumnFlags_WidthFixed, S(38));
            ImGui::TableHeadersRow();
            for (int i = 0; i < rows; ++i)
            {
                size_t off = i * 4;
                if (off >= buffer.size())
                    break;
                uintptr_t rowAddr = base + off;
                ImGui::TableNextRow();
                ImGui::PushID((void *)rowAddr);
                ImGui::TableSetColumnIndex(0);
                UI::Text(i == 0 ? ImVec4{0.4f, 1, 0.4f, 1} : ImVec4{0.5f, 0.75f, 0.85f, 1}, "%lX", rowAddr);
                char ascii[5] = "....";
                for (int c = 0; c < 4; ++c)
                {
                    ImGui::TableSetColumnIndex(c + 1);
                    if (off + c < buffer.size())
                    {
                        uint8_t b = buffer[off + c];
                        b == 0 ? UI::Text({0.4f, 0.4f, 0.4f, 1}, ".") : ImGui::Text("%02X", b);
                        ascii[c] = (b >= 32 && b < 127) ? (char)b : '.';
                    }
                    else
                    {
                        UI::Text({0.3f, 0.3f, 0.3f, 1}, "??");
                        ascii[c] = ' ';
                    }
                }
                ImGui::TableSetColumnIndex(5);
                UI::Text({0.65f, 0.65f, 0.5f, 1}, "%s", ascii);
                ImGui::TableSetColumnIndex(6);
                if (UI::Btn("存", {S(32), S(22)}, {0.2f, 0.4f, 0.25f, 1}))
                    scanner_.add(rowAddr);
                ImGui::TableSetColumnIndex(7);
                // 跳转逻辑
                uintptr_t ptrVal = 0;
                bool canJump = false;
                size_t avail = off < buffer.size() ? buffer.size() - off : 0;
                if (avail >= 8)
                {
                    uint64_t raw = 0;
                    memcpy(&raw, buffer.data() + off, 8);
                    ptrVal = MemUtils::Normalize(raw);
                    canJump = MemUtils::IsValidAddr(ptrVal);
                }
                else if (avail >= 4)
                {
                    uint32_t raw = 0;
                    memcpy(&raw, buffer.data() + off, 4);
                    ptrVal = MemUtils::Normalize((uint64_t)raw);
                    canJump = ptrVal > 0x10000 && ptrVal < 0xFFFFFFFF;
                }
                if (canJump)
                {
                    if (UI::Btn("->", {S(32), S(22)}, Colors::BTN_PURPLE))
                        memViewer_.open(ptrVal);
                    if (ImGui::IsItemHovered())
                        ImGui::SetTooltip("跳转到: %lX", ptrVal);
                }
                else
                {
                    ImGui::BeginDisabled();
                    ImGui::Button("-", {S(32), S(22)});
                    ImGui::EndDisabled();
                }
                ImGui::PopID();
            }
            ImGui::EndTable();
        }
        ImGui::PopStyleVar();
    }

    void drawDisasmView(uintptr_t base, std::span<const Disasm::DisasmLine> lines, int rows, int scrollIdx)
    {
        if (lines.empty())
        {
            UI::Text(Colors::ERR, "无法反汇编 (无效地址或非代码段)");
            return;
        }
        if (scrollIdx >= (int)lines.size())
            scrollIdx = 0;
        auto visible = lines.subspan(scrollIdx);
        ImGui::PushStyleVar(ImGuiStyleVar_CellPadding, {S(4), S(4)});
        if (ImGui::BeginTable("Disasm", 5, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg))
        {
            ImGui::TableSetupColumn("地址", ImGuiTableColumnFlags_WidthFixed, S(110));
            ImGui::TableSetupColumn("字节码", ImGuiTableColumnFlags_WidthFixed, S(90));
            ImGui::TableSetupColumn("指令", ImGuiTableColumnFlags_WidthFixed, S(60));
            ImGui::TableSetupColumn("操作数", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableSetupColumn("操作", ImGuiTableColumnFlags_WidthFixed, S(80));
            ImGui::TableHeadersRow();
            for (int i = 0; i < std::min((int)visible.size(), rows); ++i)
            {
                const auto &line = visible[i];
                if (!line.valid)
                    continue;
                ImGui::TableNextRow();
                ImGui::PushID((void *)line.address);
                ImGui::TableSetColumnIndex(0);
                UI::Text(line.address == base ? ImVec4{0.4f, 1, 0.4f, 1} : ImVec4{0.5f, 0.85f, 0.9f, 1},
                         "%llX", (unsigned long long)line.address);
                ImGui::TableSetColumnIndex(1);
                char bytes[48] = {};
                for (size_t j = 0; j < line.size && j < 8; ++j)
                {
                    char tmp[4];
                    snprintf(tmp, sizeof(tmp), "%02X ", line.bytes[j]);
                    strcat(bytes, tmp);
                }
                UI::Text({0.6f, 0.6f, 0.6f, 1}, "%s", bytes);
                ImGui::TableSetColumnIndex(2);
                UI::Text(getMnemonicColor(line.mnemonic), "%s", line.mnemonic);
                ImGui::TableSetColumnIndex(3);
                UI::Text({0.9f, 0.9f, 0.7f, 1}, "%s", line.op_str);
                ImGui::TableSetColumnIndex(4);
                if (isJumpInstruction(line.mnemonic))
                {
                    if (auto t = parseJumpTarget(line.op_str))
                        if (UI::Btn("跳", {S(35), S(24)}, Colors::BTN_PURPLE))
                            memViewer_.open(t);
                    ImGui::SameLine();
                }
                if (UI::Btn("存", {S(35), S(24)}, {0.2f, 0.4f, 0.25f, 1}))
                    scanner_.add(line.address);
                ImGui::PopID();
            }
            ImGui::EndTable();
        }
        ImGui::PopStyleVar();
    }

    static ImVec4 getMnemonicColor(const char *m)
    {
        if (!m)
            return {1, 1, 1, 1};
        if (m[0] == 'b' || !strncmp(m, "cb", 2) || !strncmp(m, "tb", 2) || !strcmp(m, "ret"))
            return {0.8f, 0.5f, 1, 1};
        if (!strncmp(m, "ld", 2) || !strncmp(m, "st", 2))
            return {0.5f, 0.7f, 1, 1};
        if (!strncmp(m, "add", 3) || !strncmp(m, "sub", 3) || !strncmp(m, "mul", 3) || !strncmp(m, "div", 3))
            return {0.5f, 1, 0.5f, 1};
        if (!strncmp(m, "cmp", 3) || !strncmp(m, "tst", 3))
            return {1, 1, 0.5f, 1};
        if (!strncmp(m, "mov", 3))
            return {0.5f, 1, 1, 1};
        if (!strcmp(m, "nop"))
            return {0.5f, 0.5f, 0.5f, 1};
        return {1, 1, 1, 1};
    }
    static bool isJumpInstruction(const char *m)
    {
        return m && (m[0] == 'B' || !strncmp(m, "CB", 2) || !strncmp(m, "TB", 2) || !strcmp(m, "BL") || !strcmp(m, "BLR"));
    }
    static uintptr_t parseJumpTarget(const char *op)
    {
        if (!op)
            return 0;
        auto p = strstr(op, "#0X");
        if (p)
            return strtoull(p + 1, nullptr, 16);
        p = strstr(op, "0X");
        return p ? strtoull(p, nullptr, 16) : 0;
    }
};

// 信号处理函数
void CrashSignalHandler(int sig, siginfo_t *info, void *context)
{
    dr.~Driver();

    // 恢复该信号的默认处理方式，防止死循环
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_DFL;
    sigemptyset(&sa.sa_mask);
    sigaction(sig, &sa, nullptr);

    // 重新发送信号，让系统执行默认的崩溃/退出流程
    // 否则 debuggerd 不会生成 tombstone 崩溃日志
    raise(sig);
}
void RegisterCrashSignals()
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = CrashSignalHandler;
    sigemptyset(&sa.sa_mask);

    // SA_SIGINFO: 获取额外信号信息
    // SA_ONSTACK: 避免因栈溢出导致的崩溃无法捕获
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK;

    // 注册 Android ARM64 常见的意外退出和崩溃信号
    const int signals[] = {
        SIGSEGV, // 段错误 (内存访问越界、野指针)
        SIGBUS,  // 总线错误
        SIGILL,  // 非法指令
        SIGFPE,  // 浮点异常
        SIGABRT, // abort() 调用或 C++ 抛出未捕获异常
        SIGINT,  // Ctrl+C
        SIGTERM, // kill <pid> (默认终止信号)
        SIGQUIT  // Quit 信号
    };

    for (size_t i = 0; i < sizeof(signals) / sizeof(signals[0]); ++i)
    {
        sigaction(signals[i], &sa, nullptr);
    }
}

// ============================================================================
// 主函数
// ============================================================================
int main()
{
    // 注册所有意外退出信号
    RegisterCrashSignals();

    if (RenderVK::init())
    {
        if (!Touch_Init())
        {
            std::println(stderr, "[Error] 初始化触摸失败");
            return 1;
        }
    }
    else
    {
        std::println(stderr, "[Error] 初始化图形引擎失败");
        return 1;
    }

    MainUI ui;
    //  渲染循环
    while (Config::g_Running)
    {

        Touch_UpdateImGui(); // 更新imgui输入事件

        RenderVK::drawBegin();

        ui.draw();

        RenderVK::drawEnd();

        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    // 清理触摸
    Touch_Shutdown();
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    RenderVK::shutdown();

    // 停所有线程
    Utils::GlobalPool.force_stop();

    return 0;
}

struct RoundResult
{
    // 空IO
    double nullIoTotalMs;
    double nullIoAvgNs;
    double nullIoThroughputK; // K ops/s

    // 读取
    double readTotalMs;
    double readAvgNs;
    double readNetAvgNs;
    double readThroughputK;
    double readBandwidthMB;
    int readFailCount;

    // 写入
    double writeTotalMs;
    double writeAvgNs;
    double writeNetAvgNs;
    double writeThroughputK;
    double writeBandwidthMB;
    int writeFailCount;

    // IO通信占比
    double readOverheadPct;
    double writeOverheadPct;
};

int mainno()
{
    constexpr int TEST_COUNT = 1200000;
    constexpr int ROUND_COUNT = 12;

    pid_t selfPid = getpid();
    dr.SetGlobalPid(selfPid);

    std::println(stdout, "================================================================");
    std::println(stdout, "  驱动读写性能基准测试 (连续 {} 轮, 每轮 {} 次操作)", ROUND_COUNT, TEST_COUNT);
    std::println(stdout, "================================================================");
    std::println(stdout, "目标PID: {} (自身进程)", selfPid);
    std::println(stdout, "================================================================\n");

    // 测试变量
    volatile uint64_t testVar = 0xDEADBEEFCAFEBABE;
    uint64_t testAddr = reinterpret_cast<uint64_t>(&testVar);

    std::array<RoundResult, ROUND_COUNT> results{};

    // ================================================================
    // 连续执行 12 轮测试
    // ================================================================
    for (int round = 0; round < ROUND_COUNT; ++round)
    {
        RoundResult &r = results[round];

        std::println(stdout, "──────────────────────────────────────────");
        std::println(stdout, "  第 {:>2}/{} 轮测试", round + 1, ROUND_COUNT);
        std::println(stdout, "──────────────────────────────────────────");

        // ======== 空IO测试 ========
        {
            auto t0 = std::chrono::high_resolution_clock::now();
            for (int i = 0; i < TEST_COUNT; ++i)
            {
                dr.NullIo();
            }
            auto t1 = std::chrono::high_resolution_clock::now();
            auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count();

            r.nullIoTotalMs = ns / 1e6;
            r.nullIoAvgNs = static_cast<double>(ns) / TEST_COUNT;
            r.nullIoThroughputK = (TEST_COUNT / (ns / 1e9)) / 1000.0;
        }

        // ======== 读取测试 ========
        {
            testVar = 0xDEADBEEFCAFEBABE; // 重置
            uint64_t readResult = 0;
            r.readFailCount = 0;

            auto t0 = std::chrono::high_resolution_clock::now();
            for (int i = 0; i < TEST_COUNT; ++i)
            {
                readResult = dr.Read<uint64_t>(testAddr);
                if (readResult != 0xDEADBEEFCAFEBABE)
                    r.readFailCount++;
            }
            auto t1 = std::chrono::high_resolution_clock::now();
            auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count();

            double totalS = ns / 1e9;
            r.readTotalMs = ns / 1e6;
            r.readAvgNs = static_cast<double>(ns) / TEST_COUNT;
            r.readNetAvgNs = r.readAvgNs - r.nullIoAvgNs;
            r.readThroughputK = (TEST_COUNT / totalS) / 1000.0;
            r.readBandwidthMB = (TEST_COUNT * 8.0) / totalS / (1024.0 * 1024.0);
        }

        // ======== 写入测试 ========
        {
            r.writeFailCount = 0;

            auto t0 = std::chrono::high_resolution_clock::now();
            for (int i = 0; i < TEST_COUNT; ++i)
            {
                uint64_t wv = 0x1000000000000000ULL + static_cast<uint64_t>(i);
                bool ok = dr.Write<uint64_t>(testAddr, wv);
                if (ok)
                    r.writeFailCount++;
            }
            auto t1 = std::chrono::high_resolution_clock::now();
            auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count();

            double totalS = ns / 1e9;
            r.writeTotalMs = ns / 1e6;
            r.writeAvgNs = static_cast<double>(ns) / TEST_COUNT;
            r.writeNetAvgNs = r.writeAvgNs - r.nullIoAvgNs;
            r.writeThroughputK = (TEST_COUNT / totalS) / 1000.0;
            r.writeBandwidthMB = (TEST_COUNT * 8.0) / totalS / (1024.0 * 1024.0);
        }

        // 通信占比
        r.readOverheadPct = (r.nullIoAvgNs / r.readAvgNs) * 100.0;
        r.writeOverheadPct = (r.nullIoAvgNs / r.writeAvgNs) * 100.0;

        // 写入数据校验
        uint64_t verifyVal = dr.Read<uint64_t>(testAddr);
        uint64_t expectedLast = 0x1000000000000000ULL + static_cast<uint64_t>(TEST_COUNT - 1);

        std::println(stdout, "  空IO:  总 {:>10.3f}ms  均 {:>8.2f}ns  吞吐 {:>8.2f}K/s",
                     r.nullIoTotalMs, r.nullIoAvgNs, r.nullIoThroughputK);
        std::println(stdout, "  读取:  总 {:>10.3f}ms  均 {:>8.2f}ns  净 {:>8.2f}ns  吞吐 {:>8.2f}K/s  带宽 {:>6.2f}MB/s  失败 {}",
                     r.readTotalMs, r.readAvgNs, r.readNetAvgNs, r.readThroughputK, r.readBandwidthMB, r.readFailCount);
        std::println(stdout, "  写入:  总 {:>10.3f}ms  均 {:>8.2f}ns  净 {:>8.2f}ns  吞吐 {:>8.2f}K/s  带宽 {:>6.2f}MB/s  失败 {}",
                     r.writeTotalMs, r.writeAvgNs, r.writeNetAvgNs, r.writeThroughputK, r.writeBandwidthMB, r.writeFailCount);
        std::println(stdout, "  校验:  0x{:016X} {} 0x{:016X} {}",
                     verifyVal, verifyVal == expectedLast ? "==" : "!=", expectedLast,
                     verifyVal == expectedLast ? "✓" : "✗");
        std::println(stdout, "");
    }

    // ================================================================
    // 计算 12 轮平均值
    // ================================================================
    RoundResult avg{};
    int totalReadFail = 0, totalWriteFail = 0;

    for (int i = 0; i < ROUND_COUNT; ++i)
    {
        const auto &r = results[i];
        avg.nullIoTotalMs += r.nullIoTotalMs;
        avg.nullIoAvgNs += r.nullIoAvgNs;
        avg.nullIoThroughputK += r.nullIoThroughputK;

        avg.readTotalMs += r.readTotalMs;
        avg.readAvgNs += r.readAvgNs;
        avg.readNetAvgNs += r.readNetAvgNs;
        avg.readThroughputK += r.readThroughputK;
        avg.readBandwidthMB += r.readBandwidthMB;
        totalReadFail += r.readFailCount;

        avg.writeTotalMs += r.writeTotalMs;
        avg.writeAvgNs += r.writeAvgNs;
        avg.writeNetAvgNs += r.writeNetAvgNs;
        avg.writeThroughputK += r.writeThroughputK;
        avg.writeBandwidthMB += r.writeBandwidthMB;
        totalWriteFail += r.writeFailCount;

        avg.readOverheadPct += r.readOverheadPct;
        avg.writeOverheadPct += r.writeOverheadPct;
    }

    avg.nullIoTotalMs /= ROUND_COUNT;
    avg.nullIoAvgNs /= ROUND_COUNT;
    avg.nullIoThroughputK /= ROUND_COUNT;

    avg.readTotalMs /= ROUND_COUNT;
    avg.readAvgNs /= ROUND_COUNT;
    avg.readNetAvgNs /= ROUND_COUNT;
    avg.readThroughputK /= ROUND_COUNT;
    avg.readBandwidthMB /= ROUND_COUNT;

    avg.writeTotalMs /= ROUND_COUNT;
    avg.writeAvgNs /= ROUND_COUNT;
    avg.writeNetAvgNs /= ROUND_COUNT;
    avg.writeThroughputK /= ROUND_COUNT;
    avg.writeBandwidthMB /= ROUND_COUNT;

    avg.readOverheadPct /= ROUND_COUNT;
    avg.writeOverheadPct /= ROUND_COUNT;

    // ================================================================
    // 计算标准差 (衡量稳定性)
    // ================================================================
    double nullIoAvgNsStd = 0, readAvgNsStd = 0, writeAvgNsStd = 0;
    for (int i = 0; i < ROUND_COUNT; ++i)
    {
        nullIoAvgNsStd += (results[i].nullIoAvgNs - avg.nullIoAvgNs) * (results[i].nullIoAvgNs - avg.nullIoAvgNs);
        readAvgNsStd += (results[i].readAvgNs - avg.readAvgNs) * (results[i].readAvgNs - avg.readAvgNs);
        writeAvgNsStd += (results[i].writeAvgNs - avg.writeAvgNs) * (results[i].writeAvgNs - avg.writeAvgNs);
    }
    nullIoAvgNsStd = std::sqrt(nullIoAvgNsStd / ROUND_COUNT);
    readAvgNsStd = std::sqrt(readAvgNsStd / ROUND_COUNT);
    writeAvgNsStd = std::sqrt(writeAvgNsStd / ROUND_COUNT);

    // ================================================================
    // 找出最快和最慢轮次
    // ================================================================
    int fastestRead = 0, slowestRead = 0;
    int fastestWrite = 0, slowestWrite = 0;
    int fastestNullIo = 0, slowestNullIo = 0;

    for (int i = 1; i < ROUND_COUNT; ++i)
    {
        if (results[i].nullIoAvgNs < results[fastestNullIo].nullIoAvgNs)
            fastestNullIo = i;
        if (results[i].nullIoAvgNs > results[slowestNullIo].nullIoAvgNs)
            slowestNullIo = i;
        if (results[i].readAvgNs < results[fastestRead].readAvgNs)
            fastestRead = i;
        if (results[i].readAvgNs > results[slowestRead].readAvgNs)
            slowestRead = i;
        if (results[i].writeAvgNs < results[fastestWrite].writeAvgNs)
            fastestWrite = i;
        if (results[i].writeAvgNs > results[slowestWrite].writeAvgNs)
            slowestWrite = i;
    }

    // ================================================================
    // 输出综合汇总
    // ================================================================
    std::println(stdout, "================================================================");
    std::println(stdout, "  {} 轮测试综合汇总 (每轮 {} 次, 共 {} 次操作)",
                 ROUND_COUNT, TEST_COUNT, static_cast<long long>(ROUND_COUNT) * TEST_COUNT);
    std::println(stdout, "================================================================");

    // 每轮详细表格
    std::println(stdout, "\n┌──────┬────────────────────────┬────────────────────────┬────────────────────────┐");
    std::println(stdout, "│ 轮次 │     空IO 均耗(ns)      │     读取 均耗(ns)      │     写入 均耗(ns)      │");
    std::println(stdout, "├──────┼────────────────────────┼────────────────────────┼────────────────────────┤");
    for (int i = 0; i < ROUND_COUNT; ++i)
    {
        std::println(stdout, "│  {:>2}  │ {:>20.2f}  │ {:>20.2f}  │ {:>20.2f}  │",
                     i + 1,
                     results[i].nullIoAvgNs,
                     results[i].readAvgNs,
                     results[i].writeAvgNs);
    }
    std::println(stdout, "├──────┼────────────────────────┼────────────────────────┼────────────────────────┤");
    std::println(stdout, "│ 平均 │ {:>20.2f}  │ {:>20.2f}  │ {:>20.2f}  │",
                 avg.nullIoAvgNs, avg.readAvgNs, avg.writeAvgNs);
    std::println(stdout, "│ 标差 │ {:>20.2f}  │ {:>20.2f}  │ {:>20.2f}  │",
                 nullIoAvgNsStd, readAvgNsStd, writeAvgNsStd);
    std::println(stdout, "└──────┴────────────────────────┴────────────────────────┴────────────────────────┘");

    // 平均指标汇总
    std::println(stdout, "\n╔══════════════════════════════════════════════════════════════╗");
    std::println(stdout, "║                    平均指标汇总                              ║");
    std::println(stdout, "╠════════════╦══════════════╦══════════════╦══════════════════╣");
    std::println(stdout, "║    项目    ║ 总耗时(ms)   ║ 单次均(ns)   ║  吞吐(K ops/s)   ║");
    std::println(stdout, "╠════════════╬══════════════╬══════════════╬══════════════════╣");
    std::println(stdout, "║  空IO      ║ {:>12.3f} ║ {:>12.2f} ║ {:>16.2f} ║",
                 avg.nullIoTotalMs, avg.nullIoAvgNs, avg.nullIoThroughputK);
    std::println(stdout, "║  读取      ║ {:>12.3f} ║ {:>12.2f} ║ {:>16.2f} ║",
                 avg.readTotalMs, avg.readAvgNs, avg.readThroughputK);
    std::println(stdout, "║  写入      ║ {:>12.3f} ║ {:>12.2f} ║ {:>16.2f} ║",
                 avg.writeTotalMs, avg.writeAvgNs, avg.writeThroughputK);
    std::println(stdout, "╚════════════╩══════════════╩══════════════╩══════════════════╝");

    std::println(stdout, "\n╔══════════════════════════════════════════════════════════════╗");
    std::println(stdout, "║                    纯操作耗时 (去除空IO)                     ║");
    std::println(stdout, "╠════════════╦══════════════╦══════════════════════════════════╣");
    std::println(stdout, "║    项目    ║  净均耗(ns)  ║            说明                  ║");
    std::println(stdout, "╠════════════╬══════════════╬══════════════════════════════════╣");
    std::println(stdout, "║  读取      ║ {:>12.2f} ║ 纯内核读取内存操作耗时           ║", avg.readNetAvgNs);
    std::println(stdout, "║  写入      ║ {:>12.2f} ║ 纯内核写入内存操作耗时           ║", avg.writeNetAvgNs);
    std::println(stdout, "╚════════════╩══════════════╩══════════════════════════════════╝");

    std::println(stdout, "\n  数据带宽:");
    std::println(stdout, "    读取平均带宽: {:.2f} MB/s", avg.readBandwidthMB);
    std::println(stdout, "    写入平均带宽: {:.2f} MB/s", avg.writeBandwidthMB);

    std::println(stdout, "\n  IO通信开销占比:");
    std::println(stdout, "    读取中通信占比: {:.2f}%", avg.readOverheadPct);
    std::println(stdout, "    写入中通信占比: {:.2f}%", avg.writeOverheadPct);

    std::println(stdout, "\n  稳定性 (标准差越小越稳定):");
    std::println(stdout, "    空IO: ±{:.2f} ns", nullIoAvgNsStd);
    std::println(stdout, "    读取: ±{:.2f} ns", readAvgNsStd);
    std::println(stdout, "    写入: ±{:.2f} ns", writeAvgNsStd);

    std::println(stdout, "\n  极值统计:");
    std::println(stdout, "    空IO: 最快 第{}轮 {:.2f}ns  最慢 第{}轮 {:.2f}ns  波动 {:.2f}ns",
                 fastestNullIo + 1, results[fastestNullIo].nullIoAvgNs,
                 slowestNullIo + 1, results[slowestNullIo].nullIoAvgNs,
                 results[slowestNullIo].nullIoAvgNs - results[fastestNullIo].nullIoAvgNs);
    std::println(stdout, "    读取: 最快 第{}轮 {:.2f}ns  最慢 第{}轮 {:.2f}ns  波动 {:.2f}ns",
                 fastestRead + 1, results[fastestRead].readAvgNs,
                 slowestRead + 1, results[slowestRead].readAvgNs,
                 results[slowestRead].readAvgNs - results[fastestRead].readAvgNs);
    std::println(stdout, "    写入: 最快 第{}轮 {:.2f}ns  最慢 第{}轮 {:.2f}ns  波动 {:.2f}ns",
                 fastestWrite + 1, results[fastestWrite].writeAvgNs,
                 slowestWrite + 1, results[slowestWrite].writeAvgNs,
                 results[slowestWrite].writeAvgNs - results[fastestWrite].writeAvgNs);

    std::println(stdout, "\n  累计失败统计:");
    std::println(stdout, "    读取总失败: {} / {} ({:.6f}%)",
                 totalReadFail, static_cast<long long>(ROUND_COUNT) * TEST_COUNT,
                 totalReadFail * 100.0 / (static_cast<double>(ROUND_COUNT) * TEST_COUNT));
    std::println(stdout, "    写入总失败: {} / {} ({:.6f}%)",
                 totalWriteFail, static_cast<long long>(ROUND_COUNT) * TEST_COUNT,
                 totalWriteFail * 100.0 / (static_cast<double>(ROUND_COUNT) * TEST_COUNT));

    std::println(stdout, "\n================================================================");
    std::println(stdout, "  全部 {} 轮测试完成", ROUND_COUNT);
    std::println(stdout, "================================================================");

    return 0;
}