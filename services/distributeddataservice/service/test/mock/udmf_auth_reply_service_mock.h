/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef UDMF_AUTH_REPLY_SERVICE_MOCK_H
#define UDMF_AUTH_REPLY_SERVICE_MOCK_H
#include "gmock/gmock.h"
#include "udmf_service_stub.h"
namespace OHOS::UDMF {
class UdmfAuthReplyServiceMock : public UdmfServiceStub {
public:
    MOCK_METHOD(int32_t, SetData, (CustomOption &, UnifiedData &, Summary &, std::string &), (override));
    MOCK_METHOD(int32_t, GetData, (const QueryOption &, UnifiedData &), (override));
    MOCK_METHOD(int32_t, GetBatchData, (const QueryOption &, std::vector<UnifiedData> &), (override));
    MOCK_METHOD(int32_t, UpdateData, (const QueryOption &, UnifiedData &), (override));
    MOCK_METHOD(int32_t, DeleteData, (const QueryOption &, std::vector<UnifiedData> &), (override));
    MOCK_METHOD(int32_t, GetSummary, (const QueryOption &, Summary &), (override));
    MOCK_METHOD(int32_t, AddPrivilege, (const QueryOption &, Privilege &), (override));
    MOCK_METHOD(int32_t, Sync, (const QueryOption &, const std::vector<std::string> &), (override));
    MOCK_METHOD(int32_t, IsRemoteData, (const QueryOption &, bool &), (override));
    MOCK_METHOD(int32_t, SetAppShareOption, (const std::string &, int32_t), (override));
    MOCK_METHOD(int32_t, GetAppShareOption, (const std::string &, int32_t &), (override));
    MOCK_METHOD(int32_t, RemoveAppShareOption, (const std::string &), (override));
    MOCK_METHOD(int32_t, ObtainAsynProcess, (AsyncProcessInfo &), (override));
    MOCK_METHOD(int32_t, ClearAsynProcessByKey, (const std::string &), (override));
    MOCK_METHOD(int32_t, SetDelayInfo, (const DataLoadInfo &, sptr<IRemoteObject>, std::string &), (override));
    MOCK_METHOD(int32_t, PushDelayData, (const std::string &, UnifiedData &, Summary &), (override));
    MOCK_METHOD(int32_t, RegisterVirtualEntry,
        (const std::string &, uint32_t, const VirtualEntry &, sptr<IRemoteObject>), (override));
    MOCK_METHOD(int32_t, GetDataIfAvailable,
        (const std::string &, const DataLoadInfo &, sptr<IRemoteObject>, std::shared_ptr<UnifiedData>), (override));
};
} // namespace OHOS::UDMF
#endif // UDMF_AUTH_REPLY_SERVICE_MOCK_H
