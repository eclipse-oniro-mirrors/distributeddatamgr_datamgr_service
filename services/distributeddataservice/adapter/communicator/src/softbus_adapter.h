/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef DISTRIBUTEDDATAFWK_SRC_SOFTBUS_ADAPTER_H
#define DISTRIBUTEDDATAFWK_SRC_SOFTBUS_ADAPTER_H
#include <condition_variable>
#include <map>
#include <mutex>
#include <set>
#include <tuple>
#include <memory>
#include <vector>
#include <concurrent_map.h>
#include "app_data_change_listener.h"
#include "platform_specific.h"
#include "session.h"
#include "softbus_bus_center.h"
namespace OHOS {
namespace AppDistributedKv {
enum IdType {
    NETWORKID,
    UUID,
    UDID,
};

template <typename T>
class BlockData {
public:
    explicit BlockData(uint32_t interval, const T &invalid = T()) : INTERVAL(interval), data_(invalid) {}
    ~BlockData() {}

public:
    void SetValue(T &data)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        data_ = data;
        isSet_ = true;
        cv_.notify_one();
    }

    T GetValue()
    {
        std::unique_lock<std::mutex> lock(mutex_);
        cv_.wait_for(lock, std::chrono::seconds(INTERVAL), [this]() { return isSet_; });
        T data = data_;
        cv_.notify_one();
        return data;
    }

    void Clear(const T &invalid = T())
    {
        std::lock_guard<std::mutex> lock(mutex_);
        isSet_ = false;
        data_ = invalid;
        cv_.notify_one();
    }

private:
    bool isSet_ = false;
    const uint32_t INTERVAL;
    T data_;
    std::mutex mutex_;
    std::condition_variable cv_;
};

class SoftBusAdapter {
public:
    SoftBusAdapter();
    ~SoftBusAdapter();
    static std::shared_ptr<SoftBusAdapter> GetInstance();

    static std::string ToBeAnonymous(const std::string &name);

    // add DataChangeListener to watch data change;
    Status StartWatchDataChange(const AppDataChangeListener *observer, const PipeInfo &pipeInfo);

    // stop DataChangeListener to watch data change;
    Status StopWatchDataChange(const AppDataChangeListener *observer, const PipeInfo &pipeInfo);

    // Send data to other device, function will be called back after sent to notify send result.
    Status SendData(const PipeInfo &pipeInfo, const DeviceId &deviceId, const uint8_t *ptr, int size,
                    const MessageInfo &info);

    bool IsSameStartedOnPeer(const struct PipeInfo &pipeInfo, const struct DeviceId &peer);

    void SetMessageTransFlag(const PipeInfo &pipeInfo, bool flag);

    int CreateSessionServerAdapter(const std::string &sessionName);

    int RemoveSessionServerAdapter(const std::string &sessionName) const;

    void InsertSession(const std::string &sessionName);

    void DeleteSession(const std::string &sessionName);

    void NotifyDataListeners(const uint8_t *ptr, int size, const std::string &deviceId, const PipeInfo &pipeInfo);

    int32_t GetSessionStatus(int32_t sessionId);

    void OnSessionOpen(int32_t sessionId, int32_t status);

    void OnSessionClose(int32_t sessionId);

private:
    std::shared_ptr<BlockData<int32_t>> GetSemaphore(int32_t sessinId);
    static std::shared_ptr<SoftBusAdapter> instance_;
    std::mutex dataChangeMutex_ {};
    std::map<std::string, const AppDataChangeListener *> dataChangeListeners_ {};
    std::mutex busSessionMutex_ {};
    std::map<std::string, bool> busSessionMap_ {};
    bool flag_ = true; // only for br flag
    ISessionListener sessionListener_ {};
    std::mutex statusMutex_ {};
    std::map<int32_t, std::shared_ptr<BlockData<int32_t>>> sessionsStatus_;
};
}  // namespace AppDistributedKv
}  // namespace OHOS
#endif /* DISTRIBUTEDDATAFWK_SRC_SOFTBUS_ADAPTER_H */
