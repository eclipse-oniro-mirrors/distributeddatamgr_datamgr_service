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
#define LOG_TAG "LifeCyclePolicy"

#include "lifecycle_policy.h"

#include <algorithm>

#include "log_print.h"
#include "preprocess/preprocess_utils.h"

namespace OHOS {
namespace UDMF {
using namespace std::chrono;
const LifeCyclePolicy::Duration LifeCyclePolicy::INTERVAL = milliseconds(60 * 60 * 1000);
const std::string LifeCyclePolicy::DATA_PREFIX = "udmf://";

Status LifeCyclePolicy::DeleteOnGet(const UnifiedKey &key)
{
    auto store = storeCache_.GetStore(key.intention);
    if (store == nullptr) {
        ZLOGE("Get store failed, intention: %{public}s.", key.intention.c_str());
        return E_DB_ERROR;
    }
    if (store->Delete(key.key) != E_OK) {
        ZLOGE("Remove data failed, intention: %{public}s.", key.intention.c_str());
        return E_DB_ERROR;
    }
    return E_OK;
}

Status LifeCyclePolicy::DeleteOnStart(const std::string &intention)
{
    auto store = storeCache_.GetStore(intention);
    if (store == nullptr) {
        ZLOGE("Get store failed, intention: %{public}s.", intention.c_str());
        return E_DB_ERROR;
    }
    if (store->Clear() != E_OK) {
        ZLOGE("Remove data failed, intention: %{public}s.", intention.c_str());
        return E_DB_ERROR;
    }
    return E_OK;
}

Status LifeCyclePolicy::DeleteOnTimeout(const std::string &intention)
{
    auto store = storeCache_.GetStore(intention);
    if (store == nullptr) {
        ZLOGE("Get store failed, intention: %{public}s.", intention.c_str());
        return E_DB_ERROR;
    }
    std::vector<std::string> timeoutKeys;
    auto status = GetTimeoutKeys(store, INTERVAL, timeoutKeys);
    if (status != E_OK) {
        ZLOGE("Get timeout keys failed.");
        return E_DB_ERROR;
    }
    if (store->DeleteBatch(timeoutKeys) != E_OK) {
        ZLOGE("Remove data failed, intention: %{public}s.", intention.c_str());
        return E_DB_ERROR;
    }
    return E_OK;
}

Status LifeCyclePolicy::GetTimeoutKeys(
    const std::shared_ptr<Store> &store, Duration interval, std::vector<std::string> &timeoutKeys)
{
    std::vector<UnifiedData> datas;
    auto status = store->GetBatchData(DATA_PREFIX, datas);
    if (status != E_OK) {
        ZLOGE("Get data failed.");
        return E_DB_ERROR;
    }
    if (datas.empty()) {
        ZLOGD("entries is empty.");
        return E_OK;
    }
    auto curTime = PreProcessUtils::GetTimeStamp();
    for (const auto &data : datas) {
        if (curTime > data.GetRuntime()->createTime + duration_cast<milliseconds>(interval).count()
            || curTime < data.GetRuntime()->createTime) {
            timeoutKeys.push_back(data.GetRuntime()->key.key);
        }
    }
    return E_OK;
}
} // namespace UDMF
} // namespace OHOS