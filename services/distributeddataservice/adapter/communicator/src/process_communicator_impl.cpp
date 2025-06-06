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

#define LOG_TAG "processCommunication"

#include "communicator_context.h"
#include "device_manager_adapter.h"
#include "log_print.h"
#include "softbus_adapter.h"
#include "process_communicator_impl.h"
#include "utils/anonymous.h"
namespace OHOS {
namespace AppDistributedKv {
using namespace DistributedDB;
using namespace OHOS::DistributedData;
using DmAdapter = OHOS::DistributedData::DeviceManagerAdapter;
ProcessCommunicatorImpl::ProcessCommunicatorImpl()
{
}

ProcessCommunicatorImpl::~ProcessCommunicatorImpl()
{
    ZLOGE("destructor.");
}

ProcessCommunicatorImpl *ProcessCommunicatorImpl::GetInstance()
{
    static ProcessCommunicatorImpl *processCommunicatorImpl = new ProcessCommunicatorImpl();
    return processCommunicatorImpl;
}

void ProcessCommunicatorImpl::SetRouteHeadHandlerCreator(RouteHeadHandlerCreator handlerCreator)
{
    routeHeadHandlerCreator_ = std::move(handlerCreator);
}

DBStatus ProcessCommunicatorImpl::Start(const std::string &processLabel)
{
    ZLOGI("init commProvider");
    thisProcessLabel_ = processLabel;
    PipeInfo pi = {thisProcessLabel_, ""};
    Status errCode = CommunicationProvider::GetInstance().Start(pi);
    if (errCode != Status::SUCCESS) {
        ZLOGE("commProvider_ Start Fail.");
        return DBStatus::DB_ERROR;
    }
    return DBStatus::OK;
}

DBStatus ProcessCommunicatorImpl::Stop()
{
    PipeInfo pi = {thisProcessLabel_, ""};
    Status errCode = CommunicationProvider::GetInstance().Stop(pi);
    if (errCode != Status::SUCCESS) {
        ZLOGE("commProvider_ Stop Fail.");
        return DBStatus::DB_ERROR;
    }
    return DBStatus::OK;
}

DBStatus ProcessCommunicatorImpl::RegOnDeviceChange(const OnDeviceChange &callback)
{
    {
        std::lock_guard<std::mutex> onDeviceChangeLockGard(onDeviceChangeMutex_);
        onDeviceChangeHandler_ = callback;
    }

    PipeInfo pi = {thisProcessLabel_, ""};
    if (callback) {
        Status errCode = DmAdapter::GetInstance().StartWatchDeviceChange(this, pi);
        if (errCode != Status::SUCCESS) {
            ZLOGE("commProvider_ StartWatchDeviceChange Fail.");
            return DBStatus::DB_ERROR;
        }
    } else {
        Status errCode = DmAdapter::GetInstance().StopWatchDeviceChange(this, pi);
        if (errCode != Status::SUCCESS) {
            ZLOGE("commProvider_ StopWatchDeviceChange Fail.");
            return DBStatus::DB_ERROR;
        }
    }

    return DBStatus::OK;
}

DBStatus ProcessCommunicatorImpl::RegOnDataReceive(const OnDataReceive &callback)
{
    {
        std::lock_guard<std::mutex> onDataReceiveLockGard(onDataReceiveMutex_);
        onDataReceiveHandler_ = callback;
    }

    PipeInfo pi = {thisProcessLabel_, ""};
    if (callback) {
        Status errCode = CommunicationProvider::GetInstance().StartWatchDataChange(this, pi);
        if (errCode != Status::SUCCESS) {
            ZLOGE("commProvider_ StartWatchDataChange Fail.");
            return DBStatus::DB_ERROR;
        }
    } else {
        Status errCode = CommunicationProvider::GetInstance().StopWatchDataChange(this, pi);
        if (errCode != Status::SUCCESS) {
            ZLOGE("commProvider_ StopWatchDataChange Fail.");
            return DBStatus::DB_ERROR;
        }
    }
    return DBStatus::OK;
}

void ProcessCommunicatorImpl::RegOnSendAble(const OnSendAble &sendAbleCallback)
{
    {
        std::lock_guard<decltype(sessionMutex_)> lock(sessionMutex_);
        sessionListener_ = sendAbleCallback;
    }
    if (!sendAbleCallback) {
        ZLOGE("send callback is nullptr.");
        return;
    }
    auto status = CommunicatorContext::GetInstance().RegSessionListener(this);
    ZLOGD("reg status:%{public}d", status);
}

DBStatus ProcessCommunicatorImpl::SendData(const DeviceInfos &dstDevInfo, const uint8_t *data, uint32_t length)
{
    uint32_t totalLength = 0;
    return SendData(dstDevInfo, data, length, totalLength);
}

DBStatus ProcessCommunicatorImpl::SendData(const DeviceInfos &dstDevInfo, const uint8_t *data, uint32_t length,
    uint32_t totalLength)
{
    PipeInfo pi = {thisProcessLabel_, ""};
    const DataInfo dataInfo = { const_cast<uint8_t *>(data), length};
    DeviceId destination;
    destination.deviceId = dstDevInfo.identifier;
    auto [errCode, softBusErrCode] =
        CommunicationProvider::GetInstance().SendData(pi, destination, dataInfo, totalLength);
    if (errCode == Status::RATE_LIMIT) {
        ZLOGD("commProvider_ opening session, status:%{public}d.", static_cast<int>(softBusErrCode));
        return DBStatus::RATE_LIMIT;
    }
    if (errCode != Status::SUCCESS) {
        ZLOGE("commProvider_ SendData Fail. code:%{public}d", softBusErrCode);
        if (softBusErrCode == 0) {
            return DBStatus::DB_ERROR;
        }
        return static_cast<DBStatus>(softBusErrCode);
    }
    return DBStatus::OK;
}

uint32_t ProcessCommunicatorImpl::GetMtuSize()
{
    return MTU_SIZE;
}

uint32_t ProcessCommunicatorImpl::GetMtuSize(const DeviceInfos &devInfo)
{
    return SoftBusAdapter::GetInstance()->GetMtuSize({ devInfo.identifier });
}

uint32_t ProcessCommunicatorImpl::GetTimeout(const DeviceInfos &devInfo)
{
    return SoftBusAdapter::GetInstance()->GetTimeout({ devInfo.identifier });
}

DeviceInfos ProcessCommunicatorImpl::GetLocalDeviceInfos()
{
    DeviceInfos localDevInfos;
    DeviceInfo devInfo = DmAdapter::GetInstance().GetLocalDevice();
    localDevInfos.identifier = devInfo.uuid;
    return localDevInfos;
}

std::vector<DeviceInfos> ProcessCommunicatorImpl::GetRemoteOnlineDeviceInfosList()
{
    std::vector<DeviceInfos> remoteDevInfos;
    std::vector<DeviceInfo> devInfoVec = DmAdapter::GetInstance().GetRemoteDevices();
    for (auto const &entry : devInfoVec) {
        DeviceInfos remoteDev;
        remoteDev.identifier = entry.uuid;
        remoteDevInfos.push_back(remoteDev);
    }
    return remoteDevInfos;
}

bool ProcessCommunicatorImpl::IsSameProcessLabelStartedOnPeerDevice(const DeviceInfos &peerDevInfo)
{
    PipeInfo pi = {thisProcessLabel_, ""};
    DeviceId di = {peerDevInfo.identifier};
    return CommunicationProvider::GetInstance().IsSameStartedOnPeer(pi, di);
}

void ProcessCommunicatorImpl::OnMessage(const DeviceInfo &info, const uint8_t *ptr, const int size,
                                        __attribute__((unused)) const PipeInfo &pipeInfo) const
{
    std::lock_guard<std::mutex> onDataReceiveLockGuard(onDataReceiveMutex_);
    if (onDataReceiveHandler_ == nullptr) {
        ZLOGE("onDataReceiveHandler_ invalid.");
        return;
    }
    DeviceInfos devInfo;
    devInfo.identifier = info.uuid;
    onDataReceiveHandler_(devInfo, ptr, static_cast<uint32_t>(size));
}

void ProcessCommunicatorImpl::OnDeviceChanged(const DeviceInfo &info, const DeviceChangeType &type) const
{
    if (type == DeviceChangeType::DEVICE_ONREADY || info.uuid == DmAdapter::CLOUD_DEVICE_UUID) {
        return;
    }
    std::lock_guard<std::mutex> onDeviceChangeLockGuard(onDeviceChangeMutex_);
    if (onDeviceChangeHandler_ == nullptr) {
        ZLOGE("onDeviceChangeHandler_ invalid.");
        return;
    }
    DeviceInfos devInfo;
    devInfo.identifier = info.uuid;
    onDeviceChangeHandler_(devInfo, (type == DeviceChangeType::DEVICE_ONLINE));
}

void ProcessCommunicatorImpl::OnSessionReady(const DeviceInfo &info, int32_t errCode) const
{
    std::lock_guard<decltype(sessionMutex_)> lock(sessionMutex_);
    if (sessionListener_ == nullptr) {
        return;
    }
    DeviceInfos devInfos;
    devInfos.identifier = info.uuid;
    sessionListener_(devInfos, errCode);
}

std::shared_ptr<ExtendHeaderHandle> ProcessCommunicatorImpl::GetExtendHeaderHandle(const ExtendInfo &info)
{
    if (routeHeadHandlerCreator_ != nullptr) {
        return routeHeadHandlerCreator_(info);
    }
    return {};
}

DBStatus ProcessCommunicatorImpl::GetDataHeadInfo(DataHeadInfo dataHeadInfo, uint32_t &headLength)
{
    if (routeHeadHandlerCreator_ == nullptr) {
        ZLOGE("header handler creator not registered");
        return DBStatus::DB_ERROR;
    }
    auto handler = routeHeadHandlerCreator_({});
    if (handler == nullptr) {
        ZLOGE("failed to get header handler");
        return DBStatus::DB_ERROR;
    }
    auto ret = handler->ParseHeadDataLen(dataHeadInfo.data, dataHeadInfo.totalLen, headLength, dataHeadInfo.device);
    if (!ret) {
        ZLOGE("illegal head format, dataLen:%{public}u, headLength:%{public}u, device:%{public}s",
            dataHeadInfo.totalLen, headLength, Anonymous::Change(dataHeadInfo.device).c_str());
        return DBStatus::INVALID_FORMAT;
    }
    return DBStatus::OK;
}

DBStatus ProcessCommunicatorImpl::GetDataUserInfo(DataUserInfo dataUserInfo, std::vector<UserInfo> &userInfos)
{
    if (routeHeadHandlerCreator_ == nullptr) {
        ZLOGE("header handler creator not registered");
        return DBStatus::DB_ERROR;
    }
    auto handler = routeHeadHandlerCreator_({});
    if (handler == nullptr) {
        ZLOGE("failed to get header handler");
        return DBStatus::DB_ERROR;
    }
    auto ret = handler->ParseHeadDataUser(dataUserInfo.data, dataUserInfo.totalLen, dataUserInfo.label, userInfos);
    if (!ret) {
        ZLOGE("illegal head format, dataLen:%{public}u, label:%{public}s, device:%{public}s",
            dataUserInfo.totalLen, Anonymous::Change(dataUserInfo.label).c_str(),
            Anonymous::Change(dataUserInfo.device).c_str());
        return DBStatus::INVALID_FORMAT;
    }
    if (userInfos.empty()) {
        ZLOGW("no valid user");
        return DBStatus::NO_PERMISSION;
    }
    ZLOGD("ok, userInfos.size:%{public}zu", userInfos.size());
    return DBStatus::OK;
}

Status ProcessCommunicatorImpl::ReuseConnect(const DeviceId &deviceId)
{
    PipeInfo pi = {thisProcessLabel_, ""};
    return CommunicationProvider::GetInstance().ReuseConnect(pi, deviceId);
}
} // namespace AppDistributedKv
} // namespace OHOS