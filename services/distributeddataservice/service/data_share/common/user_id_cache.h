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
#ifndef DATASHARESERVICE_USER_ID_CACHE_H
#define DATASHARESERVICE_USER_ID_CACHE_H

#include <chrono>
#include <cstdint>
#include <mutex>
#include <vector>

namespace OHOS::DataShare {
class UserIdCache {
public:
    static UserIdCache *GetInstance();
    // Return cached user ids, lazily initialized on first call;
    // retry with throttle if the initial query failed.
    std::vector<int32_t> GetUserIds();
    // Event-driven full refresh, always executes.
    void Refresh();
    // Throttled refresh for miss-fallback, return true only if a refresh was executed.
    bool TryRefresh();
    // Reset cached state, only for test.
    void Reset();

private:
    UserIdCache() = default;
    ~UserIdCache() = default;
    UserIdCache(const UserIdCache &) = delete;
    UserIdCache &operator=(const UserIdCache &) = delete;
    bool QueryAllCreatedUsers(std::vector<int32_t> &users);
    void DoRefresh();

    std::mutex mutex_;
    std::vector<int32_t> userIds_;
    bool initialized_ = false;
    std::chrono::steady_clock::time_point lastAttemptTime_;
    static constexpr std::chrono::milliseconds MIN_REFRESH_INTERVAL { 1000 };
};
} // namespace OHOS::DataShare
#endif // DATASHARESERVICE_USER_ID_CACHE_H
