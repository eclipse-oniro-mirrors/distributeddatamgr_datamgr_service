/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef DISTRIBUTEDDATAMGR_SECURITY_GUARD_LOG_LIMITER_H
#define DISTRIBUTEDDATAMGR_SECURITY_GUARD_LOG_LIMITER_H

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <optional>

namespace OHOS::DistributedData {
class SecurityGuardLogLimiter {
public:
    enum class Event { PROVIDER_READY, PROVIDER_FAILED, SNAPSHOT, REQUEST_REJECTED, COUNT };
    using Clock = std::chrono::steady_clock;
    std::optional<uint64_t> Take(Event event, Clock::time_point now = Clock::now())
    {
        auto index = static_cast<size_t>(event);
        if (index >= states_.size()) {
            return std::nullopt;
        }
        std::lock_guard<std::mutex> lock(mutex_);
        auto &state = states_[index];
        if (state.logged && now - state.last < INTERVAL) {
            ++state.suppressed;
            return std::nullopt;
        }
        auto suppressed = state.suppressed;
        state = { true, now, 0 };
        return suppressed;
    }

private:
    static constexpr std::chrono::seconds INTERVAL{ 5 };
    struct State {
        bool logged = false;
        Clock::time_point last{};
        uint64_t suppressed = 0;
    };
    std::mutex mutex_;
    std::array<State, static_cast<size_t>(Event::COUNT)> states_{};
};
} // namespace OHOS::DistributedData
#endif // DISTRIBUTEDDATAMGR_SECURITY_GUARD_LOG_LIMITER_H
