/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#define LOG_TAG "StoreCache"
#include "store_cache.h"

#include "log_print.h"
#include "runtime_store.h"
#include "account/account_delegate.h"

namespace OHOS {
namespace UDMF {
StoreCache &StoreCache::GetInstance()
{
    static StoreCache instance;
    return instance;
}

std::shared_ptr<Store> StoreCache::GetStore(std::string intention)
{
    std::shared_ptr<Store> store;
    int foregroundUserId = 0;
    bool ret = DistributedData::AccountDelegate::GetInstance()->QueryForegroundUserId(foregroundUserId);
    if (!ret) {
        ZLOGE("QueryForegroundUserId failed.");
        return nullptr;
    }
    std::string key = intention;
    key.append(std::to_string(foregroundUserId));
    stores_.Compute(key, [&store, intention](const auto &key, std::shared_ptr<Store> &storePtr) -> bool {
        if (storePtr != nullptr) {
            store = storePtr;
            return true;
        }

        if (IsValidIntention(intention)) {
            storePtr = std::make_shared<RuntimeStore>(intention);
            if (!storePtr->Init()) {
                ZLOGE("Init runtime store failed.");
                return false;
            }
            store = storePtr;
            return true;
        }
        return false;
    });
    std::unique_lock<std::mutex> lock(taskMutex_);
    if (taskId_ == ExecutorPool::INVALID_TASK_ID && executorPool_ != nullptr) {
        taskId_ = executorPool_->Schedule(std::chrono::minutes(INTERVAL), std::bind(&StoreCache::GarbageCollect, this));
    }
    return store;
}

void StoreCache::GarbageCollect()
{
    auto current = std::chrono::steady_clock::now();
    stores_.EraseIf([&current](auto &key, std::shared_ptr<Store> &storePtr) {
        if (*storePtr < current) {
            ZLOGI("GarbageCollect, stores:%{public}s time limit, will be close.", key.c_str());
            return true;
        }
        return false;
    });
    std::unique_lock<std::mutex> lock(taskMutex_);
    if (!stores_.Empty() && executorPool_ != nullptr) {
        ZLOGD("GarbageCollect, stores size:%{public}zu", stores_.Size());
        taskId_ = executorPool_->Schedule(std::chrono::minutes(INTERVAL), std::bind(&StoreCache::GarbageCollect, this));
    } else {
        taskId_ = ExecutorPool::INVALID_TASK_ID;
    }
}

void StoreCache::SetThreadPool(std::shared_ptr<ExecutorPool> executors)
{
    executorPool_ = executors;
}

void StoreCache::CloseStores()
{
    ZLOGI("CloseStores, stores size:%{public}zu", stores_.Size());
    stores_.Clear();
}

void StoreCache::RemoveStore(const std::string &intention)
{
    ZLOGI("RemoveStore, intention:%{public}s", intention.c_str());
    int foregroundUserId = 0;
    if (!DistributedData::AccountDelegate::GetInstance()->QueryForegroundUserId(foregroundUserId)) {
        ZLOGE("QueryForegroundUserId failed.");
        return;
    }
    std::string key = intention;
    key.append(std::to_string(foregroundUserId));
    stores_.Erase(key);
}

bool StoreCache::IsValidIntention(const std::string &intention)
{
    return UnifiedDataUtils::GetIntentionByString(intention) != UD_INTENTION_BUTT;
}
} // namespace UDMF
} // namespace OHOS
