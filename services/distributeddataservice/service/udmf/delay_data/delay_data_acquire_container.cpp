/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#define LOG_TAG "DelayDataAcquireContainer"

#include "delay_data_acquire_container.h"

#include "log_print.h"
#include "udmf_notifier_proxy.h"

namespace OHOS {
namespace UDMF {

DelayDataAcquireContainer &DelayDataAcquireContainer::GetInstance()
{
    static DelayDataAcquireContainer instance;
    return instance;
}

bool DelayDataAcquireContainer::RegisterDelayDataCallback(
    const std::string &key, const DelayGetDataInfo &info, Request *registered)
{
    std::lock_guard<std::mutex> lock(delayDataMutex_);
    auto it = delayDataCallback_.find(key);
    if (key.empty() || (it != delayDataCallback_.end() && it->second.info.tokenId != info.tokenId)) {
        return false;
    }
    Request request{ info, ++nextGeneration_ };
    delayDataCallback_.insert_or_assign(key, request);
    if (registered != nullptr) {
        *registered = request;
    }
    return true;
}

sptr<IRemoteObject> DelayDataAcquireContainer::TakeDelayDataCallback(const std::string &key, const Request &expected)
{
    std::lock_guard<std::mutex> lock(delayDataMutex_);
    auto it = delayDataCallback_.find(key);
    if (it == delayDataCallback_.end() || expected.generation == 0 || it->second.generation != expected.generation) {
        return nullptr;
    }
    auto callback = it->second.info.dataCallback;
    delayDataCallback_.erase(it);
    return callback;
}

bool DelayDataAcquireContainer::HandleDelayDataCallback(const std::string &key, const UnifiedData &unifiedData)
{
    Request request;
    if (!QueryDelayDataRequest(key, request)) {
        return false;
    }
    auto callback = iface_cast<IDelayDataCallback>(TakeDelayDataCallback(key, request));
    if (callback == nullptr) {
        return false;
    }
    callback->DelayDataCallback(key, unifiedData);
    return true;
}

bool DelayDataAcquireContainer::QueryDelayDataRequest(const std::string &key, Request &request)
{
    std::lock_guard<std::mutex> lock(delayDataMutex_);
    auto it = delayDataCallback_.find(key);
    if (it == delayDataCallback_.end()) {
        return false;
    }
    request = it->second;
    return true;
}

bool DelayDataAcquireContainer::QueryDelayGetDataInfo(const std::string &key, DelayGetDataInfo &getDataInfo)
{
    Request request;
    if (!QueryDelayDataRequest(key, request)) {
        return false;
    }
    getDataInfo = request.info;
    return true;
}

std::vector<std::string> DelayDataAcquireContainer::QueryAllDelayKeys()
{
    std::lock_guard<std::mutex> lock(delayDataMutex_);
    std::vector<std::string> keys;
    for (const auto &[key, _] : delayDataCallback_) {
        if (key.empty()) {
            continue;
        }
        keys.emplace_back(key);
    }
    return keys;
}

bool DelayDataAcquireContainer::IsContainDelayData(const std::string &key)
{
    std::lock_guard<std::mutex> lock(delayDataMutex_);
    return delayDataCallback_.find(key) != delayDataCallback_.end();
}

} // namespace UDMF
} // namespace OHOS