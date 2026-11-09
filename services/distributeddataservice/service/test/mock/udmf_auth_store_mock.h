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

#ifndef UDMF_AUTH_STORE_MOCK_H
#define UDMF_AUTH_STORE_MOCK_H
#include <gmock/gmock.h>

#include "store.h"
namespace OHOS::UDMF {
class AuthStoreMock : public Store {
public:
    virtual ~AuthStoreMock() = default;
    MOCK_METHOD(Status, Put, (const UnifiedData &, Summary &), (override));
    MOCK_METHOD(Status, Get, (const std::string &, UnifiedData &), (override));
    MOCK_METHOD(Status, GetSummary, (UnifiedKey &, Summary &), (override));
    MOCK_METHOD(Status, Update, (const UnifiedData &, Summary &), (override));
    MOCK_METHOD(Status, Delete, (const std::string &), (override));
    MOCK_METHOD(Status, DeleteBatch, (const std::vector<std::string> &), (override));
    MOCK_METHOD(Status, Sync, (const std::vector<std::string> &), (override));
    MOCK_METHOD(Status, Sync, (const std::vector<std::string> &, ProcessCallback), (override));
    MOCK_METHOD(Status, Clear, (), (override));
    MOCK_METHOD(Status, GetBatchData, (const std::string &, std::vector<UnifiedData> &), (override));
    MOCK_METHOD(Status, PutLocal, (const std::string &, const std::string &), (override));
    MOCK_METHOD(Status, GetLocal, (const std::string &, std::string &), (override));
    MOCK_METHOD(Status, DeleteLocal, (const std::string &), (override));
    MOCK_METHOD(Status, PutRuntime, (const std::string &, const Runtime &), (override));
    MOCK_METHOD(Status, GetRuntime, (const std::string &, Runtime &), (override));
    MOCK_METHOD(Status, GetBatchRuntime, (const std::string &, std::vector<Runtime> &), (override));
    MOCK_METHOD(Status, PutSummary, (UnifiedKey &, const Summary &), (override));
    MOCK_METHOD(Status, SetRemotePullStartNotify, (), (override));
    MOCK_METHOD(Status, RegisterDataChangedObserver, (const std::string &), (override));
    MOCK_METHOD(Status, PutDelayData, (const UnifiedData &, const DataLoadInfo &), (override));
    MOCK_METHOD(Status, PushSync, (const std::vector<std::string> &), (override));
    MOCK_METHOD(bool, Init, (), (override));
};
struct AuthStoreRegistry {
    static std::shared_ptr<Store> current;
};
} // namespace OHOS::UDMF
#endif
