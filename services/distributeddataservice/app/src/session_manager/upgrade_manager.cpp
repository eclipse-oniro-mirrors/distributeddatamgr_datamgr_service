/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#define LOG_TAG "UpgradeManager"

#include "upgrade_manager.h"

#include "device_manager_adapter.h"
#include "log_print.h"
#include "metadata/meta_data_manager.h"
#include "utils/anonymous.h"

namespace OHOS::DistributedData {
using namespace OHOS::DistributedKv;
using DmAdapter = DistributedData::DeviceManagerAdapter;
UpgradeManager &UpgradeManager::GetInstance()
{
    static UpgradeManager instance;
    return instance;
}

void UpgradeManager::Init(std::shared_ptr<ExecutorPool> executors)
{
    MetaDataManager::GetInstance().Subscribe(
        CapMetaRow::KEY_PREFIX, [this](const std::string &key, const std::string &value, int32_t flag) -> auto {
            CapMetaData capMeta;
            if (value.empty()) {
                MetaDataManager::GetInstance().LoadMeta(key, capMeta);
            } else {
                CapMetaData::Unmarshall(value, capMeta);
            }
            auto deviceId = CapMetaRow::GetDeviceId(key);
            if (deviceId.empty()) {
                ZLOGE("deviceId is empty, key:%{public}s, flag:%{public}d", Anonymous::Change(key).c_str(), flag);
                return false;
            }
            if (deviceId == DmAdapter::GetInstance().GetLocalDevice().uuid) {
                return true;
            }
            capMeta.deviceId = capMeta.deviceId.empty() ? deviceId : capMeta.deviceId;
            ZLOGI("CapMetaData has change, deviceId:%{public}s, version:%{public}d, flag:%{public}d",
                Anonymous::Change(capMeta.deviceId).c_str(), capMeta.version, flag);
            if (flag == MetaDataManager::INSERT || flag == MetaDataManager::UPDATE) {
                capabilities_.InsertOrAssign(capMeta.deviceId, capMeta);
            } else if (flag == MetaDataManager::DELETE) {
                capabilities_.Erase(capMeta.deviceId);
            }
            return true;
        });
    if (executors != nullptr) {
        executors_ = std::move(executors);
        executors_->Execute(GetTask());
    }
}

ExecutorPool::Task UpgradeManager::GetTask()
{
    return [this] {
        if (InitLocalCapability() || executors_ == nullptr) {
            return;
        }
        executors_->Schedule(std::chrono::milliseconds(RETRY_INTERVAL), GetTask());
    };
}

CapMetaData UpgradeManager::GetCapability(const std::string &deviceId, bool &status)
{
    status = true;
    auto index = capabilities_.Find(deviceId);
    if (index.first) {
        return index.second;
    }
    ZLOGI("load capability from meta");
    CapMetaData capMetaData;
    auto dbKey = CapMetaRow::GetKeyFor(deviceId);
    ZLOGD("cap key:%{public}s", Anonymous::Change(std::string(dbKey.begin(), dbKey.end())).c_str());
    status = MetaDataManager::GetInstance().LoadMeta(std::string(dbKey.begin(), dbKey.end()), capMetaData);
    if (status) {
        capabilities_.Insert(deviceId, capMetaData);
    }
    ZLOGI("device:%{public}s, version:%{public}d, insert:%{public}d", Anonymous::Change(deviceId).c_str(),
        capMetaData.version, status);
    return capMetaData;
}

bool UpgradeManager::InitLocalCapability()
{
    auto localDeviceId = DmAdapter::GetInstance().GetLocalDevice().uuid;
    CapMetaData capMetaData;
    capMetaData.version = CapMetaData::CURRENT_VERSION;
    capMetaData.deviceId = localDeviceId;
    auto dbKey = CapMetaRow::GetKeyFor(localDeviceId);
    bool status = MetaDataManager::GetInstance().SaveMeta({ dbKey.begin(), dbKey.end() }, capMetaData);
    if (status) {
        capabilities_.Insert(localDeviceId, capMetaData);
    }
    ZLOGI("put capability meta data ret %{public}d", status);
    return status;
}
} // namespace OHOS::DistributedData
