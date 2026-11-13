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

#ifndef OHOS_DISTRIBUTED_DATA_MOCK_BUNDLE_MANAGER_H
#define OHOS_DISTRIBUTED_DATA_MOCK_BUNDLE_MANAGER_H

#include <gmock/gmock.h>

#include "bundlemgr/bundle_mgr_interface.h"
#include "if_system_ability_manager.h"
#include "iremote_stub.h"

namespace OHOS::AppExecFwk {
class BundleMgrMock : public IRemoteStub<IBundleMgr> {
public:
    MOCK_METHOD(std::string, GetAppIdByBundleName, (const std::string &, const int), (override));
    MOCK_METHOD(ErrCode, GetBundleInfoV9, (const std::string &, int32_t, BundleInfo &, int32_t), (override));
    MOCK_METHOD(bool, AddDeathRecipient, (const sptr<IRemoteObject::DeathRecipient> &), (override));
    MOCK_METHOD(bool, RemoveDeathRecipient, (const sptr<IRemoteObject::DeathRecipient> &), (override));
};

class SystemAbilityManagerMock : public ISystemAbilityManager {
public:
    MOCK_METHOD(sptr<IRemoteObject>, AsObject, (), (override));
    MOCK_METHOD(std::vector<std::u16string>, ListSystemAbilities, (unsigned int), (override));
    MOCK_METHOD(sptr<IRemoteObject>, GetSystemAbility, (int32_t), (override));
    MOCK_METHOD(sptr<IRemoteObject>, CheckSystemAbility, (int32_t), (override));
    MOCK_METHOD(int32_t, RemoveSystemAbility, (int32_t), (override));
    MOCK_METHOD(int32_t, SubscribeSystemAbility, (int32_t, const sptr<ISystemAbilityStatusChange> &), (override));
    MOCK_METHOD(int32_t, UnSubscribeSystemAbility, (int32_t, const sptr<ISystemAbilityStatusChange> &), (override));
    MOCK_METHOD(sptr<IRemoteObject>, GetSystemAbility, (int32_t, const std::string &), (override));
    MOCK_METHOD(sptr<IRemoteObject>, CheckSystemAbility, (int32_t, const std::string &), (override));
    MOCK_METHOD(int32_t, AddOnDemandSystemAbilityInfo, (int32_t, const std::u16string &), (override));
    MOCK_METHOD(sptr<IRemoteObject>, CheckSystemAbility, (int32_t, bool &), (override));
    MOCK_METHOD(int32_t, AddSystemAbility,
        (int32_t, const sptr<IRemoteObject> &, const ISystemAbilityManager::SAExtraProp &), (override));
    MOCK_METHOD(int32_t, AddSystemProcess, (const std::u16string &, const sptr<IRemoteObject> &), (override));
    MOCK_METHOD(sptr<IRemoteObject>, LoadSystemAbility, (int32_t, int32_t), (override));
    MOCK_METHOD(int32_t, LoadSystemAbility, (int32_t, const sptr<ISystemAbilityLoadCallback> &), (override));
    MOCK_METHOD(int32_t, LoadSystemAbility,
        (int32_t, const std::string &, const sptr<ISystemAbilityLoadCallback> &), (override));
    MOCK_METHOD(int32_t, UnloadSystemAbility, (int32_t), (override));
    MOCK_METHOD(int32_t, CancelUnloadSystemAbility, (int32_t), (override));
    MOCK_METHOD(int32_t, UnloadAllIdleSystemAbility, (), (override));
    MOCK_METHOD(int32_t, GetSystemProcessInfo, (int32_t, SystemProcessInfo &), (override));
    MOCK_METHOD(int32_t, GetRunningSystemProcess, (std::list<SystemProcessInfo> &), (override));
    MOCK_METHOD(int32_t, SubscribeSystemProcess, (const sptr<ISystemProcessStatusChange> &), (override));
    MOCK_METHOD(int32_t, SendStrategy, (int32_t, std::vector<int32_t> &, int32_t, std::string &), (override));
    MOCK_METHOD(int32_t, UnSubscribeSystemProcess, (const sptr<ISystemProcessStatusChange> &), (override));
    MOCK_METHOD(int32_t, GetExtensionSaIds, (const std::string &, std::vector<int32_t> &), (override));
    MOCK_METHOD(int32_t, GetExtensionRunningSaList,
        (const std::string &, std::vector<sptr<IRemoteObject>> &), (override));
    MOCK_METHOD(int32_t, GetRunningSaExtensionInfoList,
        (const std::string &, std::vector<ISystemAbilityManager::SaExtensionInfo> &), (override));
    MOCK_METHOD(int32_t, GetCommonEventExtraDataIdlist,
        (int32_t, std::vector<int64_t> &, const std::string &), (override));
    MOCK_METHOD(int32_t, GetOnDemandReasonExtraData, (int64_t, MessageParcel &), (override));
    MOCK_METHOD(int32_t, GetOnDemandPolicy,
        (int32_t, OnDemandPolicyType, std::vector<SystemAbilityOnDemandEvent> &), (override));
    MOCK_METHOD(int32_t, UpdateOnDemandPolicy,
        (int32_t, OnDemandPolicyType, const std::vector<SystemAbilityOnDemandEvent> &), (override));
    MOCK_METHOD(int32_t, GetOnDemandSystemAbilityIds, (std::vector<int32_t> &), (override));
};
} // namespace OHOS::AppExecFwk
#endif // OHOS_DISTRIBUTED_DATA_MOCK_BUNDLE_MANAGER_H
