#pragma once

#include <condition_variable>
#include <functional>
#include <future>
#include <mutex>
#include <queue>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

namespace Utils
{
    inline unsigned GetThreadCount() noexcept
    {
        if (auto n = std::thread::hardware_concurrency(); n > 0)
            return n;
        return 4;
    }

    class ThreadPool
    {
        std::vector<std::jthread> workers_;
        std::queue<std::function<void()>> tasks_;
        std::mutex mtx_;
        std::condition_variable_any cv_;
        std::condition_variable done_cv_;
        size_t active_{0};

    public:
        explicit ThreadPool(size_t n = GetThreadCount())
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
                            if (st.stop_requested()) return;
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

        void force_stop()
        {
            {
                std::lock_guard lk(mtx_);
                while (!tasks_.empty())
                    tasks_.pop();
            }
            for (auto &w : workers_)
                w.request_stop();
            cv_.notify_all();
            for (auto &w : workers_)
            {
                if (w.joinable())
                    w.detach();
            }
            workers_.clear();
        }
    };

    inline ThreadPool GlobalPool{GetThreadCount()};
}
