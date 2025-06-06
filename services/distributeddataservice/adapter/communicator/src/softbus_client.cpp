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

#define LOG_TAG "SoftBusClient"
#include "softbus_client.h"

#include "communicator_context.h"
#include "communication/connect_manager.h"
#include "device_manager_adapter.h"
#include "inner_socket.h"
#include "kvstore_utils.h"
#include "log_print.h"
#include "softbus_error_code.h"

namespace OHOS::AppDistributedKv {
using namespace OHOS::DistributedKv;
using DmAdapter = OHOS::DistributedData::DeviceManagerAdapter;
using Context = DistributedData::CommunicatorContext;
SoftBusClient::SoftBusClient(const PipeInfo& pipeInfo, const DeviceId& deviceId, const std::string& networkId,
    uint32_t type) : type_(type), pipe_(pipeInfo), device_(deviceId), networkId_(networkId)
{
    mtu_ = DEFAULT_MTU_SIZE;
}

SoftBusClient::~SoftBusClient()
{
    ZLOGI("Shutdown socket:%{public}d, deviceId:%{public}s", socket_,
        KvStoreUtils::ToBeAnonymous(device_.deviceId).c_str());
    if (socket_ > 0) {
        Shutdown(socket_);
    }
}

bool SoftBusClient::operator==(int32_t socket) const
{
    return socket_ == socket;
}

bool SoftBusClient::operator==(const std::string &deviceId) const
{
    return device_.deviceId == deviceId;
}

uint32_t SoftBusClient::GetMtuSize() const
{
    ZLOGD("get mtu size socket:%{public}d mtu:%{public}d", socket_, mtu_);
    return mtu_;
}

uint32_t SoftBusClient::GetTimeout() const
{
    return DEFAULT_TIMEOUT;
}

Status SoftBusClient::SendData(const DataInfo &dataInfo, const ISocketListener *listener)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto result = CheckStatus();
    if (result != Status::SUCCESS) {
        return result;
    }
    ZLOGD("send data socket:%{public}d, data size:%{public}u.", socket_, dataInfo.length);
    int32_t ret = SendBytes(socket_, dataInfo.data, dataInfo.length);
    if (ret != SOFTBUS_OK) {
        expireTime_ = std::chrono::steady_clock::now();
        ZLOGE("send data to socket%{public}d failed, ret:%{public}d.", socket_, ret);
        softBusError_ = ret;
        return Status::ERROR;
    }
    softBusError_ = 0;
    expireTime_ = CalcExpireTime();
    return Status::SUCCESS;
}

int32_t SoftBusClient::GetSoftBusError()
{
    std::lock_guard<std::mutex> lock(mutex_);
    return softBusError_;
}

Status SoftBusClient::OpenConnect(const ISocketListener *listener)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto status = CheckStatus();
    if (status == Status::SUCCESS || status == Status::RATE_LIMIT) {
        return status;
    }
    if (isOpening_.exchange(true)) {
        return Status::RATE_LIMIT;
    }
    int32_t clientSocket = CreateSocket();
    if (clientSocket <= 0) {
        isOpening_.store(false);
        return Status::NETWORK_ERROR;
    }
    auto task = [type = type_, clientSocket, listener, client = shared_from_this()]() {
        if (client == nullptr) {
            ZLOGE("OpenSessionByAsync client is nullptr.");
            return;
        }
        ZLOGI("Bind Start, device:%{public}s socket:%{public}d type:%{public}u",
            KvStoreUtils::ToBeAnonymous(client->device_.deviceId).c_str(), clientSocket, type);
        int32_t status = client->Open(clientSocket, type, listener);
        Context::GetInstance().NotifySessionReady(client->device_.deviceId, status);
        client->isOpening_.store(false);
    };
    Context::GetInstance().GetThreadPool()->Execute(task);
    return Status::RATE_LIMIT;
}

int32_t SoftBusClient::CreateSocket() const
{
    SocketInfo socketInfo;
    std::string peerName = pipe_.pipeId;
    socketInfo.peerName = const_cast<char *>(peerName.c_str());
    auto networkId = GetNetworkId();
    socketInfo.peerNetworkId = const_cast<char *>(networkId.c_str());
    std::string clientName = pipe_.pipeId;
    socketInfo.name = const_cast<char *>(clientName.c_str());
    std::string pkgName = "ohos.distributeddata";
    socketInfo.pkgName = pkgName.data();
    socketInfo.dataType = DATA_TYPE_BYTES;
    int32_t socket = Socket(socketInfo);
    if (socket <= 0) {
        ZLOGE("Create the client Socket:%{public}d failed, peerName:%{public}s", socket, socketInfo.peerName);
    }
    return socket;
}

Status SoftBusClient::CheckStatus()
{
    if (bindState_ == 0) {
        return Status::SUCCESS;
    }
    if (isOpening_.load()) {
        return Status::RATE_LIMIT;
    }
    if (bindState_ == 0) {
        return Status::SUCCESS;
    }
    return Status::ERROR;
}

int32_t SoftBusClient::Open(int32_t socket, uint32_t type, const ISocketListener *listener, bool async)
{
    int32_t status = ::Bind(socket, QOS_INFOS[type % QOS_BUTT], QOS_COUNTS[type % QOS_BUTT], listener);
    auto networkId = GetNetworkId();
    ZLOGI("Bind device:%{public}s,session:%{public}s,socketId:%{public}d,networkId:%{public}s",
        KvStoreUtils::ToBeAnonymous(device_.deviceId).c_str(), pipe_.pipeId.c_str(), socket,
        KvStoreUtils::ToBeAnonymous(networkId).c_str());

    if (status != 0) {
        ZLOGE("[Bind] device:%{public}s socket failed, session:%{public}s,result:%{public}d",
            KvStoreUtils::ToBeAnonymous(device_.deviceId).c_str(), pipe_.pipeId.c_str(), status);
        ::Shutdown(socket);
        return status;
    }
    UpdateExpireTime(async);
    uint32_t mtu = 0;
    std::tie(status, mtu) = GetMtu(socket);
    if (status != SOFTBUS_OK) {
        ZLOGE("GetMtu failed, session:%{public}s, socket:%{public}d, status:%{public}d", pipe_.pipeId.c_str(), socket_,
            status);
        ::Shutdown(socket);
        return status;
    }
    UpdateBindInfo(socket, mtu, status, async);
    ZLOGI("open %{public}s, session:%{public}s success, socket:%{public}d",
        KvStoreUtils::ToBeAnonymous(device_.deviceId).c_str(), pipe_.pipeId.c_str(), socket_);
    ConnectManager::GetInstance()->OnSessionOpen(networkId);
    return status;
}

SoftBusClient::Time SoftBusClient::GetExpireTime() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return expireTime_;
}

int32_t SoftBusClient::GetSocket() const
{
    return socket_;
}

void SoftBusClient::UpdateExpireTime(bool async)
{
    auto expireTime = CalcExpireTime();
    if (async) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (expireTime > expireTime_) {
            expireTime_ = expireTime;
        }
    } else {
        if (expireTime > expireTime_) {
            expireTime_ = expireTime;
        }
    }
}

void SoftBusClient::UpdateBindInfo(int32_t socket, uint32_t mtu, int32_t status, bool async)
{
    if (async) {
        std::lock_guard<std::mutex> lock(mutex_);
        socket_ = socket;
        mtu_ = mtu;
        bindState_ = status;
    } else {
        socket_ = socket;
        mtu_ = mtu;
        bindState_ = status;
    }
}

std::pair<int32_t, uint32_t> SoftBusClient::GetMtu(int32_t socket)
{
    uint32_t mtu = 0;
    auto ret = ::GetMtuSize(socket, &mtu);
    return { ret, mtu };
}

uint32_t SoftBusClient::GetQoSType() const
{
    return type_ % QOS_BUTT;
}

SoftBusClient::Time SoftBusClient::CalcExpireTime() const
{
    auto delay = type_ == QOS_BR ? BR_CLOSE_DELAY : HML_CLOSE_DELAY;
    return std::chrono::steady_clock::now() + delay;
}

Status SoftBusClient::ReuseConnect(const ISocketListener *listener)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto checkStatus = CheckStatus();
    if (checkStatus == Status::SUCCESS) {
        UpdateExpireTime(false);
        return Status::SUCCESS;
    }
    int32_t socket = CreateSocket();
    if (socket <= 0) {
        return Status::NETWORK_ERROR;
    }
    ZLOGI("Reuse Start, device:%{public}s session:%{public}s socket:%{public}d",
        KvStoreUtils::ToBeAnonymous(device_.deviceId).c_str(), pipe_.pipeId.c_str(), socket);
    int32_t status = Open(socket, QOS_REUSE, listener, false);
    return status == SOFTBUS_OK ? Status::SUCCESS : Status::NETWORK_ERROR;
}

std::string SoftBusClient::GetNetworkId() const
{
    std::lock_guard<std::mutex> lock(networkIdMutex_);
    return networkId_;
}

void SoftBusClient::UpdateNetworkId(const std::string& networkId)
{
    std::lock_guard<std::mutex> lock(networkIdMutex_);
    networkId_ = networkId;
}
} // namespace OHOS::AppDistributedKv