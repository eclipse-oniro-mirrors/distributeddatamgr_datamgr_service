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
#define LOG_TAG "UserIdCache"

#include "user_id_cache.h"

#include <algorithm>

#include "account/account_delegate.h"
#include "log_print.h"

namespace OHOS::DataShare {
UserIdCache *UserIdCache::GetInstance()
{
    static UserIdCache instance;
    return &instance;
}

std::vector<int32_t> UserIdCache::GetUserIds()
{
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (initialized_) {
            return userIds_;
        }
        auto now = std::chrono::steady_clock::now();
        if (lastAttemptTime_.time_since_epoch().count() != 0 && now - lastAttemptTime_ < MIN_REFRESH_INTERVAL) {
            return userIds_;
        }
        lastAttemptTime_ = now;
    }
    // query outside the lock to avoid ipc under lock
    std::vector<int32_t> users;
    if (!QueryAllCreatedUsers(users)) {
        ZLOGE("QueryAllCreatedUsers failed, keep empty cache");
        std::lock_guard<std::mutex> lock(mutex_);
        return userIds_;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    userIds_ = std::move(users);
    initialized_ = true;
    return userIds_;
}

void UserIdCache::Refresh()
{
    // query outside the lock to avoid ipc under lock
    std::vector<int32_t> users;
    bool success = QueryAllCreatedUsers(users);
    std::lock_guard<std::mutex> lock(mutex_);
    lastAttemptTime_ = std::chrono::steady_clock::now();
    if (!success) {
        ZLOGW("QueryAllCreatedUsers failed, keep previous cache, size:%{public}zu", userIds_.size());
        return;
    }
    userIds_ = std::move(users);
    initialized_ = true;
}

bool UserIdCache::TryRefresh()
{
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto now = std::chrono::steady_clock::now();
        if (lastAttemptTime_.time_since_epoch().count() != 0 && now - lastAttemptTime_ < MIN_REFRESH_INTERVAL) {
            return false;
        }
    }
    Refresh();
    return true;
}

void UserIdCache::Reset()
{
    std::lock_guard<std::mutex> lock(mutex_);
    userIds_.clear();
    initialized_ = false;
    lastAttemptTime_ = std::chrono::steady_clock::time_point {};
}

bool UserIdCache::QueryAllCreatedUsers(std::vector<int32_t> &users)
{
    auto *delegate = OHOS::DistributedData::AccountDelegate::GetInstance();
    if (delegate == nullptr) {
        ZLOGE("AccountDelegate is null");
        return false;
    }
    std::vector<int> queriedUsers;
    if (!delegate->QueryAllCreatedUsers(queriedUsers)) {
        ZLOGE("QueryAllCreatedUsers from delegate failed");
        return false;
    }
    users.clear();
    users.reserve(queriedUsers.size() + 1);
    for (int user : queriedUsers) {
        users.push_back(static_cast<int32_t>(user));
    }
    // always include the default user 0
    if (std::find(users.begin(), users.end(), 0) == users.end()) {
        users.push_back(0);
    }
    std::sort(users.begin(), users.end());
    users.erase(std::unique(users.begin(), users.end()), users.end());
    return true;
}
} // namespace OHOS::DataShare
