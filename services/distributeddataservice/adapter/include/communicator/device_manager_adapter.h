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

#ifndef DISTRIBUTEDDATAMGR_DATAMGR_DEVICE_MANAGER_ADAPTER_H
#define DISTRIBUTEDDATAMGR_DATAMGR_DEVICE_MANAGER_ADAPTER_H

#include <set>
#include <string>
#include <vector>
#include "app_device_change_listener.h"
#include "commu_types.h"
#include "concurrent_map.h"
#include "device_manager.h"
#include "device_manager_callback.h"
#include "device_manager/device_manager_delegate.h"
#include "dm_device_info.h"
#include "executor_pool.h"
#include "lru_bucket.h"

namespace OHOS {
namespace DistributedData {
class API_EXPORT DeviceManagerAdapter : public DeviceManagerDelegate {
public:
    enum DeviceState {
        DEVICE_ONLINE,
        DEVICE_ONREADY,
        DEVICE_BUTT
    };
    using DmDeviceInfo =  OHOS::DistributedHardware::DmDeviceInfo;
    using DeviceInfo = OHOS::AppDistributedKv::DeviceInfo;
    using PipeInfo = OHOS::AppDistributedKv::PipeInfo;
    using AppDeviceChangeListener = OHOS::AppDistributedKv::AppDeviceChangeListener;
    using Status = OHOS::DistributedKv::Status;
    using Time = std::chrono::steady_clock::time_point;
    using AccessCaller = OHOS::AppDistributedKv::AccessCaller;
    using AccessCallee = OHOS::AppDistributedKv::AccessCallee;
    static DeviceManagerAdapter &GetInstance();
    static constexpr const char *CLOUD_DEVICE_UUID = "cloudDeviceUuid";
    static constexpr const char *CLOUD_DEVICE_UDID = "cloudDeviceUdid";

    void Init(std::shared_ptr<ExecutorPool> executors);
    Status StartWatchDeviceChange(const AppDeviceChangeListener *observer, const PipeInfo &pipeInfo);
    Status StopWatchDeviceChange(const AppDeviceChangeListener *observer, const PipeInfo &pipeInfo);
    DeviceInfo GetLocalDevice() override;
    std::vector<DeviceInfo> GetRemoteDevices();
    std::vector<DeviceInfo> GetOnlineDevices();
    bool IsDeviceReady(const std::string &id);
    bool IsOHOSType(const std::string &id);
    std::string GetEncryptedUuidByNetworkId(const std::string &networkId);
    size_t GetOnlineSize();
    DeviceInfo GetDeviceInfo(const std::string &id);
    std::string GetUuidByNetworkId(const std::string &networkId);
    std::string GetUdidByNetworkId(const std::string &networkId);
    std::string CalcClientUuid(const std::string &appId, const std::string &uuid);
    std::string ToUUID(const std::string &id);
    std::string ToUDID(const std::string &id);
    static std::vector<std::string> ToUUID(const std::vector<std::string> &devices);
    static std::vector<std::string> ToUUID(std::vector<DeviceInfo> devices);
    std::string ToNetworkID(const std::string &id);
    void NotifyReadyEvent(const std::string &uuid);
    int32_t GetAuthType(const std::string& id);
    bool IsSameAccount(const std::string &id);
    bool IsSameAccount(const AccessCaller &accCaller, const AccessCallee &accCallee);
    bool CheckAccessControl(const AccessCaller &accCaller, const AccessCallee &accCallee);
    void Offline(const DmDeviceInfo &info);
    void OnReady(const DmDeviceInfo &info);
    friend class DataMgrDmStateCall;
    friend class NetConnCallbackObserver;

private:
    DeviceManagerAdapter();
    ~DeviceManagerAdapter();
    std::function<void()> RegDevCallback();
    bool GetDeviceInfo(const DmDeviceInfo &dmInfo, DeviceInfo &dvInfo);
    void SaveDeviceInfo(const DeviceInfo &deviceInfo, const AppDistributedKv::DeviceChangeType &type);
    void InitDeviceInfo(bool onlyCache = true);
    DeviceInfo GetLocalDeviceInfo();
    DeviceInfo GetDeviceInfoFromCache(const std::string &id);
    void Online(const DmDeviceInfo &info);
    void OnChanged(const DmDeviceInfo &info);
    std::vector<const AppDeviceChangeListener *> GetObservers();
    void ResetLocalDeviceInfo();
    static inline uint64_t GetTimeStamp()
    {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch())
            .count();
    }

    std::mutex devInfoMutex_ {};
    DeviceInfo localInfo_ {};
    const DmDeviceInfo cloudDmInfo;
    ConcurrentMap<const AppDeviceChangeListener *, const AppDeviceChangeListener *> observers_ {};
    LRUBucket<std::string, DeviceInfo> deviceInfos_ {64};
    LRUBucket<std::string, DeviceInfo> otherDeviceInfos_ {64};
    static constexpr size_t TIME_TASK_CAPACITY = 50;
    static constexpr int32_t SYNC_TIMEOUT = 60 * 1000; // ms
    static constexpr int32_t OH_OS_TYPE = 10;
    ConcurrentMap<std::string, std::string> syncTask_ {};
    std::shared_ptr<ExecutorPool> executors_;
    ConcurrentMap<std::string, std::pair<DeviceState, DeviceInfo>> readyDevices_;
};
}  // namespace DistributedData
}  // namespace OHOS
#endif // DISTRIBUTEDDATAMGR_DATAMGR_DEVICE_MANAGER_ADAPTER_H