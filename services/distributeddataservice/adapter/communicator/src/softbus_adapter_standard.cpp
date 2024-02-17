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
#include <mutex>
#include <string>
#include <thread>

#include "communicator_context.h"
#include "device_manager_adapter.h"
#include "dfx_types.h"
#include "kvstore_utils.h"
#include "log_print.h"
#include "reporter.h"
#include "securec.h"
#include "softbus_adapter.h"
#include "softbus_bus_center.h"
#include "softbus_error_code.h"
#ifdef LOG_TAG
#undef LOG_TAG
#endif
#define LOG_TAG "SoftBusAdapter"

namespace OHOS {
namespace AppDistributedKv {
using Context = DistributedData::CommunicatorContext;
constexpr uint32_t DEFAULT_MTU_SIZE = 4096u;
constexpr uint32_t DEFAULT_TIMEOUT = 30 * 1000;
using namespace std;
using namespace OHOS::DistributedDataDfx;
using namespace OHOS::DistributedKv;
using DmAdapter = OHOS::DistributedData::DeviceManagerAdapter;

class AppDataListenerWrap {
public:
    static void SetDataHandler(SoftBusAdapter *handler);

    static void OnClientShutdown(int32_t socket, ShutdownReason reason);
    static void OnClientBytesReceived(int32_t socket, const void *data, uint32_t dataLen);

    static void OnServerBind(int32_t socket, PeerSocketInfo info);
    static void OnServerShutdown(int32_t socket, ShutdownReason reason);
    static void OnServerBytesReceived(int32_t socket, const void *data, uint32_t dataLen);
    static std::string GetPipeId(const std::string &name);

public:
    // notify all listeners when received message
    static void NotifyDataListeners(const uint8_t *data, const int size, const std::string &deviceId,
        const PipeInfo &pipeInfo);

private:
    static SoftBusAdapter *softBusAdapter_;
};
SoftBusAdapter *AppDataListenerWrap::softBusAdapter_;
std::shared_ptr<SoftBusAdapter> SoftBusAdapter::instance_;

namespace {
void NotCareEvent(NodeBasicInfo *info)
{
    return;
}

void NotCareEvent(NodeBasicInfoType type, NodeBasicInfo *info)
{
    return;
}

void OnCareEvent(NodeStatusType type, NodeStatus *status)
{
    if (type != TYPE_DATABASE_STATUS || status == nullptr) {
        return;
    }
    auto uuid = DmAdapter::GetInstance().GetUuidByNetworkId(status->basicInfo.networkId);
    SoftBusAdapter::GetInstance()->OnBroadcast({ uuid }, status->dataBaseStatus);
}

INodeStateCb g_callback = {
    .events = EVENT_NODE_STATUS_CHANGED,
    .onNodeOnline = NotCareEvent,
    .onNodeOffline = NotCareEvent,
    .onNodeBasicInfoChanged = NotCareEvent,
    .onNodeStatusChanged = OnCareEvent,
};
} // namespace
SoftBusAdapter::SoftBusAdapter()
{
    ZLOGI("begin");
    AppDataListenerWrap::SetDataHandler(this);

    clientListener_.OnShutdown = AppDataListenerWrap::OnClientShutdown;
    clientListener_.OnBytes = AppDataListenerWrap::OnClientBytesReceived;
    clientListener_.OnMessage = AppDataListenerWrap::OnClientBytesReceived;

    serverListener_.OnBind = AppDataListenerWrap::OnServerBind;
    serverListener_.OnShutdown = AppDataListenerWrap::OnServerShutdown;
    serverListener_.OnBytes = AppDataListenerWrap::OnServerBytesReceived;
    serverListener_.OnMessage = AppDataListenerWrap::OnServerBytesReceived;

    auto status = DmAdapter::GetInstance().StartWatchDeviceChange(this, { "softBusAdapter" });
    if (status != Status::SUCCESS) {
        ZLOGW("register device change failed, status:%d", static_cast<int>(status));
    }
}

SoftBusAdapter::~SoftBusAdapter()
{
    ZLOGI("begin");
    if (onBroadcast_) {
        UnregNodeDeviceStateCb(&g_callback);
    }
    connects_.Clear();
}

std::shared_ptr<SoftBusAdapter> SoftBusAdapter::GetInstance()
{
    static std::once_flag onceFlag;
    std::call_once(onceFlag, [&] {
        instance_ = std::make_shared<SoftBusAdapter>();
    });
    return instance_;
}

Status SoftBusAdapter::StartWatchDataChange(const AppDataChangeListener *observer, const PipeInfo &pipeInfo)
{
    ZLOGD("begin");
    if (observer == nullptr) {
        return Status::INVALID_ARGUMENT;
    }

    auto ret = dataChangeListeners_.Insert(pipeInfo.pipeId, observer);
    if (!ret) {
        ZLOGW("Add listener error or repeated adding.");
        return Status::ERROR;
    }

    return Status::SUCCESS;
}

Status SoftBusAdapter::StopWatchDataChange(__attribute__((unused)) const AppDataChangeListener *observer,
    const PipeInfo &pipeInfo)
{
    ZLOGD("begin");
    if (dataChangeListeners_.Erase(pipeInfo.pipeId) != 0) {
        return Status::SUCCESS;
    }
    ZLOGW("stop data observer error, pipeInfo:%{public}s", pipeInfo.pipeId.c_str());
    return Status::ERROR;
}

Status SoftBusAdapter::SendData(const PipeInfo &pipeInfo, const DeviceId &deviceId, const DataInfo &dataInfo,
    uint32_t length, const MessageInfo &info)
{
    std::shared_ptr<SoftBusClient> conn;
    bool isReady = DmAdapter::GetInstance().IsDeviceReady(deviceId.deviceId);
    uint32_t qosType = isReady ? SoftBusClient::QOS_HML : SoftBusClient::QOS_BR;
    connects_.Compute(deviceId.deviceId,
        [&pipeInfo, &deviceId, &conn, qosType](const auto &key,
            std::vector<std::shared_ptr<SoftBusClient>> &connects) -> bool {
            for (auto &connect : connects) {
                if (connect->GetQoSType() == qosType) {
                    conn = connect;
                    return true;
                }
            }

            auto connect = std::make_shared<SoftBusClient>(pipeInfo, deviceId, qosType);
            connects.emplace_back(connect);
            conn = connect;
            return true;
        });
    if (conn == nullptr) {
        return Status::ERROR;
    }

    auto status = conn->SendData(dataInfo, &clientListener_);
    if ((status != Status::NETWORK_ERROR) && (status != Status::RATE_LIMIT)) {
        Time now = std::chrono::steady_clock::now();
        auto expireTime = conn->GetExpireTime() > now ? conn->GetExpireTime() : now;
        lock_guard<decltype(taskMutex_)> lock(taskMutex_);
        if (taskId_ != ExecutorPool::INVALID_TASK_ID && expireTime < next_) {
            taskId_ = Context::GetInstance().GetThreadPool()->Reset(taskId_, expireTime - now);
            next_ = expireTime;
            if (taskId_ == ExecutorPool::INVALID_TASK_ID) {
                return status;
            }
        }
        if (taskId_ == ExecutorPool::INVALID_TASK_ID) {
            taskId_ = Context::GetInstance().GetThreadPool()->Schedule(expireTime - now, GetCloseSessionTask());
            next_ = expireTime;
        }
    }
    return status;
}

SoftBusAdapter::Task SoftBusAdapter::GetCloseSessionTask()
{
    return [this]() mutable {
        Time now = std::chrono::steady_clock::now();
        std::vector<std::shared_ptr<SoftBusClient>> connToClose;
        connects_.ForEach([&now, &connToClose](const auto &key, auto &connects) -> bool {
            std::vector<std::shared_ptr<SoftBusClient>> holdConnects;
            for (auto conn : connects) {
                if (conn == nullptr) {
                    continue;
                }
                auto expireTime = conn->GetExpireTime();
                if (expireTime <= now) {
                    ZLOGI("[timeout] close session socket:%{public}d", conn->GetSocket());
                    connToClose.emplace_back(conn);
                } else {
                    holdConnects.emplace_back(conn);
                }
            }
            connects = std::move(holdConnects);
            return false;
        });
        connects_.EraseIf([](const auto &key, const auto &conn) -> bool {
            return conn.empty();
        });

        Time next = INVALID_NEXT;
        lock_guard<decltype(taskMutex_)> lg(taskMutex_);
        connects_.ForEach([&next](const auto &key, auto &connects) -> bool {
            for (auto conn : connects) {
                if (conn == nullptr) {
                    continue;
                }
                auto expireTime = conn->GetExpireTime();
                if (expireTime < next) {
                    next = expireTime;
                }
            }
            return false;
        });
        if (next == INVALID_NEXT) {
            taskId_ = ExecutorPool::INVALID_TASK_ID;
            return;
        }
        taskId_ =
            Context::GetInstance().GetThreadPool()->Schedule(next > now ? next - now : ExecutorPool::INVALID_DELAY,
                GetCloseSessionTask());
        next_ = next;
    };
}

uint32_t SoftBusAdapter::GetMtuSize(const DeviceId &deviceId)
{
    uint32_t mtuSize = DEFAULT_MTU_SIZE;
    connects_.ComputeIfPresent(deviceId.deviceId, [&mtuSize](auto, auto &connects) {
        uint32_t mtu = 0;
        for (auto conn : connects) {
            if (conn == nullptr) {
                continue;
            }
            if (mtu < conn->GetMtuSize()) {
                mtu = conn->GetMtuSize();
            }
        }
        if (mtu != 0) {
            mtuSize = mtu;
        }
        return true;
    });
    return mtuSize;
}

uint32_t SoftBusAdapter::GetTimeout(const DeviceId &deviceId)
{
    uint32_t interval = DEFAULT_TIMEOUT;
    connects_.ComputeIfPresent(deviceId.deviceId, [&interval](auto, auto &connects) {
        uint32_t time = 0;
        for (auto conn : connects) {
            if (conn == nullptr) {
                continue;
            }
            if (time < conn->GetTimeout()) {
                time = conn->GetTimeout();
            }
        }
        if (time != 0) {
            interval = time;
        }
        return true;
    });
    return interval;
}

std::string SoftBusAdapter::DelConnect(int32_t socket)
{
    std::string name;
    connects_.ForEach([socket, &name](const auto &deviceId, auto &connects) -> bool {
        for (auto iter = connects.begin(); iter != connects.end();) {
            if (*iter != nullptr && **iter == socket) {
                name += deviceId;
                name += " ";
                iter = connects.erase(iter);
            } else {
                iter++;
            }
        }
        return false;
    });
    return name;
}

std::string SoftBusAdapter::OnClientShutdown(int32_t socket)
{
    return DelConnect(socket);
}

bool SoftBusAdapter::IsSameStartedOnPeer(const struct PipeInfo &pipeInfo,
    __attribute__((unused)) const struct DeviceId &peer)
{
    ZLOGI("pipeInfo:%{public}s deviceId:%{public}s", pipeInfo.pipeId.c_str(),
        KvStoreUtils::ToBeAnonymous(peer.deviceId).c_str());
    return true;
}

void SoftBusAdapter::SetMessageTransFlag(const PipeInfo &pipeInfo, bool flag)
{
    ZLOGI("pipeInfo: %s flag: %d", pipeInfo.pipeId.c_str(), flag);
    flag_ = flag;
}

int SoftBusAdapter::CreateSessionServerAdapter(const std::string &sessionName)
{
    ZLOGD("begin");
    SocketInfo socketInfo;
    std::string sessionServerName = sessionName;
    socketInfo.name = const_cast<char *>(sessionServerName.c_str());
    std::string pkgName = "ohos.distributeddata";
    socketInfo.pkgName = pkgName.data();
    socket_ = Socket(socketInfo);
    return Listen(socket_, Qos, QOS_COUNT, &serverListener_);
}

int SoftBusAdapter::RemoveSessionServerAdapter(const std::string &sessionName) const
{
    ZLOGD("begin");
    Shutdown(socket_);
    return 0;
}

void SoftBusAdapter::NotifyDataListeners(const uint8_t *data, int size, const std::string &deviceId,
    const PipeInfo &pipeInfo)
{
    ZLOGD("begin");
    auto ret = dataChangeListeners_.ComputeIfPresent(pipeInfo.pipeId,
        [&data, &size, &deviceId, &pipeInfo](const auto &key, const AppDataChangeListener *&value) {
            ZLOGD("ready to notify, pipeName:%{public}s, deviceId:%{public}s.", pipeInfo.pipeId.c_str(),
                KvStoreUtils::ToBeAnonymous(deviceId).c_str());
            DeviceInfo deviceInfo = DmAdapter::GetInstance().GetDeviceInfo(deviceId);
            value->OnMessage(deviceInfo, data, size, pipeInfo);
            TrafficStat ts{ pipeInfo.pipeId, deviceId, 0, size };
            Reporter::GetInstance()->TrafficStatistic()->Report(ts);
            return true;
        });
    if (!ret) {
        ZLOGW("no listener %{public}s.", pipeInfo.pipeId.c_str());
    }
}

int32_t SoftBusAdapter::Broadcast(const PipeInfo &pipeInfo, uint16_t mask)
{
    return SetNodeDataChangeFlag(pipeInfo.pipeId.c_str(), DmAdapter::GetInstance().GetLocalDevice().networkId.c_str(),
        mask);
}

void SoftBusAdapter::OnBroadcast(const DeviceId &device, uint16_t mask)
{
    ZLOGI("device:%{public}s mask:0x%{public}x", KvStoreUtils::ToBeAnonymous(device.deviceId).c_str(), mask);
    if (!onBroadcast_) {
        ZLOGW("no listener device:%{public}s mask:0x%{public}x", KvStoreUtils::ToBeAnonymous(device.deviceId).c_str(),
            mask);
        return;
    }
    onBroadcast_(device.deviceId, mask);
}

int32_t SoftBusAdapter::ListenBroadcastMsg(const PipeInfo &pipeInfo,
    std::function<void(const std::string &, uint16_t)> listener)
{
    if (onBroadcast_) {
        return SOFTBUS_ALREADY_EXISTED;
    }
    onBroadcast_ = std::move(listener);
    return RegNodeDeviceStateCb(pipeInfo.pipeId.c_str(), &g_callback);
}

void AppDataListenerWrap::SetDataHandler(SoftBusAdapter *handler)
{
    ZLOGI("begin");
    softBusAdapter_ = handler;
}

void AppDataListenerWrap::OnClientShutdown(int32_t socket, ShutdownReason reason)
{
    // when the local close the session, this callback function will not be triggered;
    // when the current function is called, soft bus has released the session resource, only connId is valid;
    std::string name = softBusAdapter_->OnClientShutdown(socket);
    ZLOGI("[shutdown] socket:%{public}d, name:%{public}s", socket, KvStoreUtils::ToBeAnonymous(name).c_str());
}

void AppDataListenerWrap::OnClientBytesReceived(int32_t socket, const void *data, uint32_t dataLen) {}

void AppDataListenerWrap::OnServerBind(int32_t socket, PeerSocketInfo info)
{
    softBusAdapter_->OnBind(socket, info);
    std::string peerDevUuid = DmAdapter::GetInstance().GetUuidByNetworkId(std::string(info.networkId));

    ZLOGI("[OnServerBind] socket:%{public}d, peer name:%{public}s, peer devId:%{public}s", socket, info.name,
        KvStoreUtils::ToBeAnonymous(peerDevUuid).c_str());
}

void AppDataListenerWrap::OnServerShutdown(int32_t socket, ShutdownReason reason)
{
    softBusAdapter_->OnServerShutdown(socket);
    ZLOGI("Shut down reason:%{public}d socket id:%{public}d", reason, socket);
}

void AppDataListenerWrap::OnServerBytesReceived(int32_t socket, const void *data, uint32_t dataLen)
{
    SoftBusAdapter::ServerSocketInfo info;
    if (!softBusAdapter_->GetPeerSocketInfo(socket, info)) {
        ZLOGE("Get peer socket info failed, socket id %{public}d", socket);
        return;
    };
    std::string peerDevUuid = DmAdapter::GetInstance().GetUuidByNetworkId(std::string(info.networkId));

    ZLOGD("[OnBytesReceived] socket:%{public}d, peer name:%{public}s, peer devId:%{public}s, data len:%{public}u",
        socket, info.name.c_str(), KvStoreUtils::ToBeAnonymous(peerDevUuid).c_str(), dataLen);

    std::string pipeId = GetPipeId(info.name);
    if (pipeId.empty()) {
        ZLOGE("pipId is invalid");
        return;
    }

    NotifyDataListeners(reinterpret_cast<const uint8_t *>(data), dataLen, peerDevUuid, { pipeId, "" });
}

std::string AppDataListenerWrap::GetPipeId(const std::string &name)
{
    auto pos = name.find('_');
    if (pos != std::string::npos) {
        return name.substr(0, pos);
    }
    return "";
}

void AppDataListenerWrap::NotifyDataListeners(const uint8_t *data, const int size, const std::string &deviceId,
    const PipeInfo &pipeInfo)
{
    softBusAdapter_->NotifyDataListeners(data, size, deviceId, pipeInfo);
}

bool SoftBusAdapter::GetPeerSocketInfo(int32_t socket, ServerSocketInfo &info)
{
    auto it = peerSocketInfos_.Find(socket);
    if (it.first) {
        info = it.second;
        return true;
    }
    return false;
}

void SoftBusAdapter::OnBind(int32_t socket, PeerSocketInfo info)
{
    ServerSocketInfo socketInfo;
    socketInfo.name = info.name;
    socketInfo.networkId = info.networkId;
    socketInfo.pkgName = info.pkgName;
    peerSocketInfos_.Insert(socket, socketInfo);
}

void SoftBusAdapter::OnServerShutdown(int32_t socket)
{
    peerSocketInfos_.Erase(socket);
}

void SoftBusAdapter::OnDeviceChanged(const AppDistributedKv::DeviceInfo &info,
    const AppDistributedKv::DeviceChangeType &type) const
{
    return;
}
} // namespace AppDistributedKv
} // namespace OHOS