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

#define LOG_TAG "DataShareServiceStub"

#include "data_share_service_stub.h"

#include <cinttypes>
#include "accesstoken_kit.h"
#include "tokenid_kit.h"
#include "data_share_obs_proxy.h"
#include "hiview_adapter.h"
#include "hiview_fault_adapter.h"
#include "ipc_skeleton.h"
#include "ishared_result_set.h"
#include "itypes_util.h"
#include "log_print.h"
#include "qos.h"
#include "utils/anonymous.h"

namespace OHOS {
namespace DataShare {

class DataShareServiceStub::QosManager {
public:
    QosManager()
    {
        // set thread qos QOS_USER_INTERACTIVE
        QOS::SetThreadQos(QOS::QosLevel::QOS_USER_INTERACTIVE);
    }
    ~QosManager()
    {
        QOS::ResetThreadQos();
    }
};

bool DataShareServiceStub::CheckInterfaceToken(MessageParcel &data)
{
    auto localDescriptor = IDataShareService::GetDescriptor();
    auto remoteDescriptor = data.ReadInterfaceToken();
    if (remoteDescriptor != localDescriptor) {
        ZLOGE("interface token is not equal");
        return false;
    }
    return true;
}

int32_t DataShareServiceStub::OnInsertEx(MessageParcel &data, MessageParcel &reply)
{
    std::string uri;
    std::string extUri;
    DataShareValuesBucket bucket;
    if (!ITypesUtil::Unmarshal(data, uri, extUri, bucket.valuesMap)) {
        ZLOGE("Unmarshal uri:%{public}s bucket size:%{public}zu", DistributedData::Anonymous::Change(uri).c_str(),
            bucket.valuesMap.size());
        return IPC_STUB_INVALID_DATA_ERR;
    }
    auto [errCode, status] = InsertEx(uri, extUri, bucket);
    if (!ITypesUtil::Marshal(reply, errCode, status)) {
        ZLOGE("Marshal errCode: 0x%{public}x, status: 0x%{public}x", errCode, status);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return 0;
}

int32_t DataShareServiceStub::OnUpdateEx(MessageParcel &data, MessageParcel &reply)
{
    std::string uri;
    std::string extUri;
    DataSharePredicates predicate;
    DataShareValuesBucket bucket;
    if (!ITypesUtil::Unmarshal(data, uri, extUri, predicate, bucket.valuesMap)) {
        ZLOGE("Unmarshal uri:%{public}s bucket size:%{public}zu", DistributedData::Anonymous::Change(uri).c_str(),
            bucket.valuesMap.size());
        return IPC_STUB_INVALID_DATA_ERR;
    }
    auto [errCode, status] = UpdateEx(uri, extUri, predicate, bucket);
    if (!ITypesUtil::Marshal(reply, errCode, status)) {
        ZLOGE("Marshal errCode: 0x%{public}x, status: 0x%{public}x", errCode, status);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return 0;
}

int32_t DataShareServiceStub::OnDeleteEx(MessageParcel &data, MessageParcel &reply)
{
    std::string uri;
    std::string extUri;
    DataSharePredicates predicate;
    if (!ITypesUtil::Unmarshal(data, uri, extUri, predicate)) {
        ZLOGE("Unmarshal uri:%{public}s", DistributedData::Anonymous::Change(uri).c_str());
        return IPC_STUB_INVALID_DATA_ERR;
    }
    auto [errCode, status] = DeleteEx(uri, extUri, predicate);
    if (!ITypesUtil::Marshal(reply, errCode, status)) {
        ZLOGE("Marshal errCode: 0x%{public}x, status: 0x%{public}x", errCode, status);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return 0;
}

int32_t DataShareServiceStub::OnQuery(MessageParcel &data, MessageParcel &reply)
{
    std::string uri;
    std::string extUri;
    DataSharePredicates predicate;
    std::vector<std::string> columns;
    if (!ITypesUtil::Unmarshal(data, uri, extUri, predicate, columns)) {
        ZLOGE("Unmarshal uri:%{public}s columns size:%{public}zu", DistributedData::Anonymous::Change(uri).c_str(),
            columns.size());
        return IPC_STUB_INVALID_DATA_ERR;
    }
    int status = 0;
    auto result = ISharedResultSet::WriteToParcel(Query(uri, extUri, predicate, columns, status), reply);
    if (!ITypesUtil::Marshal(reply, status)) {
        ZLOGE("Marshal status:0x%{public}x", status);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return 0;
}

int32_t DataShareServiceStub::OnAddTemplate(MessageParcel &data, MessageParcel &reply)
{
    std::string uri;
    int64_t subscriberId;
    Template tpl;
    if (!ITypesUtil::Unmarshal(data, uri, subscriberId, tpl.update_, tpl.predicates_,  tpl.scheduler_)) {
        ZLOGW("read device list failed.");
        return -1;
    }
    int32_t status = AddTemplate(uri, subscriberId, tpl);
    if (!ITypesUtil::Marshal(reply, status)) {
        ZLOGE("Marshal status:0x%{public}x", status);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return 0;
}

int32_t DataShareServiceStub::OnDelTemplate(MessageParcel &data, MessageParcel &reply)
{
    std::string uri;
    int64_t subscriberId;
    if (!ITypesUtil::Unmarshal(data, uri, subscriberId)) {
        ZLOGW("read device list failed.");
        return -1;
    }
    int32_t status = DelTemplate(uri, subscriberId);
    if (!ITypesUtil::Marshal(reply, status)) {
        ZLOGE("Marshal status:0x%{public}x", status);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return 0;
}

int32_t DataShareServiceStub::OnPublish(MessageParcel &data, MessageParcel &reply)
{
    Data publishData;
    std::string bundleName;
    if (!ITypesUtil::Unmarshal(data, publishData.datas_, publishData.version_, bundleName)) {
        ZLOGW("read device list failed.");
        return -1;
    }
    std::vector<OperationResult> results = Publish(publishData, bundleName);
    if (!ITypesUtil::Marshal(reply, results)) {
        ZLOGE("ITypesUtil::Marshal(reply, results) failed");
        return -1;
    }
    return 0;
}

int32_t DataShareServiceStub::OnGetData(MessageParcel &data, MessageParcel &reply)
{
    std::string bundleName;
    if (!ITypesUtil::Unmarshal(data, bundleName)) {
        ZLOGW("read device list failed.");
        return -1;
    }
    ZLOGI("bundleName is %{public}s", bundleName.c_str());
    int errorCode = E_OK;
    auto results = GetData(bundleName, errorCode);
    if (!ITypesUtil::Marshal(reply, results.datas_, errorCode)) {
        ZLOGE("ITypesUtil::Marshal(reply, results) failed");
        return -1;
    }
    return 0;
}

int32_t DataShareServiceStub::OnSubscribeRdbData(MessageParcel &data, MessageParcel &reply)
{
    std::vector<std::string> uris;
    TemplateId templateId;
    if (!ITypesUtil::Unmarshal(data, uris, templateId)) {
        ZLOGE("read device list failed.");
        return -1;
    }
    auto remoteObj = data.ReadRemoteObject();
    sptr<IDataProxyRdbObserver> observer = new (std::nothrow)RdbObserverProxy(remoteObj);
    if (observer == nullptr) {
        ZLOGE("obServer is nullptr");
        return -1;
    }
    std::vector<OperationResult> results = SubscribeRdbData(uris, templateId, observer);
    if (!ITypesUtil::Marshal(reply, results)) {
        ZLOGE("ITypesUtil::Marshal(reply, results) failed");
        return -1;
    }
    return 0;
}

int32_t DataShareServiceStub::OnUnsubscribeRdbData(MessageParcel &data, MessageParcel &reply)
{
    std::vector<std::string> uris;
    TemplateId templateId;
    if (!ITypesUtil::Unmarshal(data, uris, templateId)) {
        ZLOGE("read device list failed.");
        return -1;
    }
    std::vector<OperationResult> results = UnsubscribeRdbData(uris, templateId);
    if (!ITypesUtil::Marshal(reply, results)) {
        ZLOGE("ITypesUtil::Marshal(reply, results) failed");
        return -1;
    }
    return 0;
}

int32_t DataShareServiceStub::OnEnableRdbSubs(MessageParcel &data, MessageParcel &reply)
{
    std::vector<std::string> uris;
    TemplateId templateId;
    if (!ITypesUtil::Unmarshal(data, uris, templateId)) {
        ZLOGE("read device list failed.");
        return -1;
    }
    std::vector<OperationResult> results = EnableRdbSubs(uris, templateId);
    if (!ITypesUtil::Marshal(reply, results)) {
        ZLOGE("ITypesUtil::Marshal(reply, results) failed");
        return -1;
    }
    return 0;
}

int32_t DataShareServiceStub::OnDisableRdbSubs(MessageParcel &data, MessageParcel &reply)
{
    std::vector<std::string> uris;
    TemplateId templateId;
    if (!ITypesUtil::Unmarshal(data, uris, templateId)) {
        ZLOGE("read device list failed.");
        return -1;
    }
    std::vector<OperationResult> results = DisableRdbSubs(uris, templateId);
    if (!ITypesUtil::Marshal(reply, results)) {
        ZLOGE("ITypesUtil::Marshal(reply, results) failed");
        return -1;
    }
    return 0;
}

int32_t DataShareServiceStub::OnSubscribePublishedData(MessageParcel &data, MessageParcel &reply)
{
    std::vector<std::string> uris;
    int64_t subscriberId;
    if (!ITypesUtil::Unmarshal(data, uris, subscriberId)) {
        ZLOGE("read device list failed.");
        return -1;
    }
    sptr<PublishedDataObserverProxy> observer = new (std::nothrow)PublishedDataObserverProxy(data.ReadRemoteObject());
    if (observer == nullptr) {
        ZLOGE("obServer is nullptr");
        return -1;
    }
    std::vector<OperationResult> results = SubscribePublishedData(uris, subscriberId, observer);
    if (!ITypesUtil::Marshal(reply, results)) {
        ZLOGE("ITypesUtil::Marshal(reply, results) failed");
        return -1;
    }
    return 0;
}

int32_t DataShareServiceStub::OnUnsubscribePublishedData(MessageParcel &data, MessageParcel &reply)
{
    std::vector<std::string> uris;
    int64_t subscriberId;
    if (!ITypesUtil::Unmarshal(data, uris, subscriberId)) {
        ZLOGE("read device list failed.");
        return -1;
    }
    std::vector<OperationResult> results = UnsubscribePublishedData(uris, subscriberId);
    if (!ITypesUtil::Marshal(reply, results)) {
        ZLOGE("ITypesUtil::Marshal(reply, results) failed");
        return -1;
    }
    return 0;
}

int32_t DataShareServiceStub::OnEnablePubSubs(MessageParcel &data, MessageParcel &reply)
{
    std::vector<std::string> uris;
    int64_t subscriberId;
    if (!ITypesUtil::Unmarshal(data, uris, subscriberId)) {
        ZLOGE("read device list failed.");
        return -1;
    }
    std::vector<OperationResult> results = EnablePubSubs(uris, subscriberId);
    if (!ITypesUtil::Marshal(reply, results)) {
        ZLOGE("ITypesUtil::Marshal(reply, results) failed");
        return -1;
    }
    return 0;
}

int32_t DataShareServiceStub::OnDisablePubSubs(MessageParcel &data, MessageParcel &reply)
{
    std::vector<std::string> uris;
    int64_t subscriberId;
    if (!ITypesUtil::Unmarshal(data, uris, subscriberId)) {
        ZLOGE("read device list failed.");
        return -1;
    }
    std::vector<OperationResult> results = DisablePubSubs(uris, subscriberId);
    if (!ITypesUtil::Marshal(reply, results)) {
        ZLOGE("ITypesUtil::Marshal(reply, results) failed");
        return -1;
    }
    return 0;
}

int32_t DataShareServiceStub::OnNotifyConnectDone(MessageParcel &data, MessageParcel &reply)
{
    OnConnectDone();
    return 0;
}

bool DataShareServiceStub::CheckProxyCallingPermission(uint32_t tokenId)
{
    Security::AccessToken::ATokenTypeEnum tokenType =
        Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(tokenId);
    return (tokenType == Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE ||
        tokenType == Security::AccessToken::ATokenTypeEnum::TOKEN_SHELL);
}

// GetTokenType use tokenId, and IsSystemApp use fullTokenId, these are different
bool DataShareServiceStub::CheckSystemUidCallingPermission(uint32_t tokenId, uint64_t fullTokenId)
{
    if (CheckProxyCallingPermission(tokenId)) {
        return true;
    }
    // IsSystemAppByFullTokenID here is not IPC
    return Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(fullTokenId);
}

int DataShareServiceStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    // set thread qos
    DataShareServiceStub::QosManager qos;
    // check thread qos
    QOS::QosLevel curLevel;
    int qosRet = QOS::GetThreadQos(curLevel);

    int tryTimes = TRY_TIMES;
    while (!isReady_.load() && tryTimes > 0) {
        tryTimes--;
        std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_TIME));
    }
    auto callingPid = IPCSkeleton::GetCallingPid();
    if (code >= DATA_SHARE_CMD_SYSTEM_CODE) {
        auto fullTokenId = IPCSkeleton::GetCallingFullTokenID();
        if (!CheckSystemUidCallingPermission(IPCSkeleton::GetCallingTokenID(), fullTokenId)) {
            ZLOGE("CheckSystemUidCallingPermission fail, token:%{public}" PRIx64
                ", callingPid:%{public}d, code:%{public}u", fullTokenId, callingPid, code);
            return E_NOT_SYSTEM_APP;
        }
        code = code - DATA_SHARE_CMD_SYSTEM_CODE;
    }
    if (code != DATA_SHARE_SERVICE_CMD_QUERY && code != DATA_SHARE_SERVICE_CMD_GET_SILENT_PROXY_STATUS) {
        ZLOGI("code:%{public}u, callingPid:%{public}d, qosRet:%{public}d, curLevel:%{public}d",
            code, callingPid, qosRet, curLevel);
    }
    if (!CheckInterfaceToken(data)) {
        return DATA_SHARE_ERROR;
    }
    int res = -1;
    if (code < DATA_SHARE_SERVICE_CMD_MAX) {
        auto callingTokenid = IPCSkeleton::GetCallingTokenID();
        auto start = std::chrono::steady_clock::now();
        res = (this->*HANDLERS[code])(data, reply);
        auto finish = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(finish - start);
        CallerInfo callerInfo(callingTokenid, IPCSkeleton::GetCallingUid(), callingPid, duration.count(), code);
        if (duration >= TIME_THRESHOLD) {
            int64_t milliseconds = duration.count();
            ZLOGW("over time, code:%{public}u callingPid:%{public}d, cost:%{public}" PRIi64 "ms",
                code, callingPid, milliseconds);
            callerInfo.isSlowRequest = true;
        }
        HiViewAdapter::GetInstance().ReportDataStatistic(callerInfo);
    }
    return res;
}

int32_t DataShareServiceStub::OnNotifyObserver(MessageParcel &data, MessageParcel &reply)
{
    std::string uri;
    if (!ITypesUtil::Unmarshal(data, uri)) {
        ZLOGE("read device list failed.");
        return -1;
    }
    NotifyObserver(uri);
    return 0;
}

int32_t DataShareServiceStub::OnSetSilentSwitch(MessageParcel &data, MessageParcel &reply)
{
    std::string uri;
    bool enable = false;
    if (!ITypesUtil::Unmarshal(data, uri, enable)) {
        ZLOGE("Unmarshal set silent switch failed. uri: %{public}s", DistributedData::Anonymous::Change(uri).c_str());
        return IPC_STUB_INVALID_DATA_ERR;
    }
    int32_t status = EnableSilentProxy(uri, enable);
    if (!ITypesUtil::Marshal(reply, status)) {
        ZLOGE("Marshal status:0x%{public}x", status);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return E_OK;
}

int32_t DataShareServiceStub::OnGetSilentProxyStatus(MessageParcel &data, MessageParcel &reply)
{
    std::string uri;
    if (!ITypesUtil::Unmarshal(data, uri)) {
        ZLOGE("Unmarshal silent enable failed. uri: %{public}s", DistributedData::Anonymous::Change(uri).c_str());
        return IPC_STUB_INVALID_DATA_ERR;
    }
    int32_t enable = GetSilentProxyStatus(uri);
    if (!ITypesUtil::Marshal(reply, enable)) {
        ZLOGE("Marshal enable:%{public}d failed.", enable);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return E_OK;
}

int32_t DataShareServiceStub::OnRegisterObserver(MessageParcel &data, MessageParcel &reply)
{
    return DATA_SHARE_ERROR;
}

int32_t DataShareServiceStub::OnUnregisterObserver(MessageParcel &data, MessageParcel &reply)
{
    return DATA_SHARE_ERROR;
}

void DataShareServiceStub::SetServiceReady()
{
    isReady_.store(true);
}
} // namespace DataShare
} // namespace OHOS