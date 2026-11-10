/*
* Copyright (c) 2025 Huawei Device Co., Ltd.
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

#define LOG_TAG "UdmfServiceImplMockTest"
#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <future>
#include <limits>
#include <mutex>
#include <thread>

#include "accesstoken_kit.h"
#include "bootstrap.h"
#include "delay_data_acquire_container.h"
#include "delay_data_prepare_container.h"
#include "device_manager_adapter_mock.h"
#include "drag_lifecycle_policy.h"
#include "error_code.h"
#include "executor_pool.h"
#include "gtest/gtest.h"
#include "ipc_skeleton.h"
#include "iremote_stub.h"
#include "kvstore_meta_manager.h"
#include "mock/access_token_mock.h"
#include "mock/meta_data_manager_mock.h"
#include "nativetoken_kit.h"
#include "preprocess_utils.h"
#include "security_guard_delegate_mock.h"
#include "system_ability_definition.h"
#include "text.h"
#include "token_setproc.h"
#include "udmf_auth_store_mock.h"
#include "udmf_fuse_controller.h"
#include "udmf_fuse_session_manager.h"
#include "udmf_service_impl.h"
#include "virtual_entry_provider.h"
#include "virtual_entry_read_callback_proxy.h"
using namespace OHOS::DistributedData;
using namespace OHOS::Security::AccessToken;
using namespace OHOS::UDMF;
using namespace testing::ext;
using namespace testing;

namespace OHOS::Test {
namespace DistributedDataTest {
class UdmfAuthGuardMock : public SecurityGuardDelegate {
public:
    Status Start() override
    {
        ++starts_;
        return start_;
    }
    void Stop() override
    {
    }
    bool IsReady() const override
    {
        return ready_;
    }
    ClientSnapshot GetClientSnapshot() const override
    {
        return snapshot_;
    }
    DispatchStatus Request(const Event &event, Completion complete) override
    {
        ++requests_;
        event_ = event;
        if (dispatch_ == DispatchStatus::DISPATCHED) {
            auto action = beforeComplete_;
            if (action) {
                action();
            }
            complete({ result_, clients_ });
        }
        return dispatch_;
    }
    Status start_ = Status::READY;
    int starts_ = 0;
    bool ready_ = true;
    int requests_ = 0;
    Strategy result_ = Strategy::ALLOW;
    std::vector<ClientResult> clients_;
    DispatchStatus dispatch_ = DispatchStatus::DISPATCHED;
    ClientSnapshot snapshot_;
    Event event_;
    std::function<void()> beforeComplete_;
};
class AuthPermissionCheckerMock : public UDMF::CheckerManager::Checker {
public:
    virtual ~AuthPermissionCheckerMock() = default;
    MOCK_METHOD(bool, IsValid, (const std::vector<Privilege> &, const UDMF::CheckerManager::CheckInfo &), (override));
};
NiceMock<AuthPermissionCheckerMock> &GetAuthPermissionChecker()
{
    static NiceMock<AuthPermissionCheckerMock> checker;
    return checker;
}
class UdmfServiceAuthEntryTest : public testing::Test {
public:
    static constexpr int32_t nativeLookupSourceSwitch = 2;
    static constexpr int32_t testUserId = 100;
    static constexpr uint32_t sourceTokenId = 17;
    static constexpr uint32_t receiverTokenId = 19;

    void SetUp() override
    {
        tokens_ = std::make_shared<NiceMock<AccessTokenKitMock>>();
        BAccessTokenKit::accessTokenkit = tokens_;
        ON_CALL(*tokens_, GetTokenTypeFlag(_)).WillByDefault(Return(TOKEN_HAP));
        ON_CALL(*tokens_, GetHapTokenInfo(_, _)).WillByDefault([](auto, HapTokenInfo &info) {
            info.bundleName = "com.test.auth";
            info.instIndex = 0;
            info.userID = testUserId;
            return 0;
        });
        devices_ = std::make_shared<NiceMock<DeviceManagerAdapterMock>>();
        BDeviceManagerAdapter::deviceManagerAdapter = devices_;
        ON_CALL(*devices_, CalcClientUuid(_, _)).WillByDefault(Return("local-auth-device"));
        ON_CALL(GetAuthPermissionChecker(), IsValid(_, _)).WillByDefault(Return(true));
        UDMF::CheckerManager::GetInstance().RegisterChecker(
            "DataChecker", []() { return &GetAuthPermissionChecker(); });
        UDMF::CheckerManager::GetInstance().LoadCheckers();
        store_ = std::make_shared<NiceMock<AuthStoreMock>>();
        AuthStoreRegistry::current = store_;
        SecurityGuardTestRegistry::instance = &guard_;
    }
    void TearDown() override
    {
        for (const auto &[key, token] : keys_) {
            DelayDataPrepareContainer::GetInstance().Remove(key);
            DelayDataAcquireContainer::GetInstance().HandleDelayDataCallback(key, UnifiedData());
        }
        Mock::VerifyAndClear(&GetAuthPermissionChecker());
        AuthStoreRegistry::current.reset();
        SecurityGuardTestRegistry::instance = nullptr;
        BAccessTokenKit::accessTokenkit = nullptr;
        BDeviceManagerAdapter::deviceManagerAdapter = nullptr;
    }
    BlockDelayData Prepare(const std::string &key, uint32_t token = receiverTokenId)
    {
        keys_.push_back({ key, token });
        auto &container = DelayDataPrepareContainer::GetInstance();
        sptr<IRemoteObject> remote;
        container.RegisterDataLoadCallback(key, new UdmfNotifierProxy(remote));
        QueryOption query;
        query.key = key;
        query.tokenId = token;
        UnifiedData ignored;
        container.HandleDelayLoad(query, ignored);
        BlockDelayData pending;
        container.QueryBlockDelayData(key, pending);
        return pending;
    }
    UnifiedData Payload(size_t length = 8)
    {
        UnifiedData payload;
        auto record = std::make_shared<UnifiedRecord>(PLAIN_TEXT, std::string(length, 'x'));
        record->SetUid("record-auth-1");
        payload.AddRecord(record);
        Runtime runtime;
        runtime.tokenId = sourceTokenId;
        runtime.recordTotalNum = 1;
        runtime.deviceId = "remote-auth-device";
        runtime.sourcePackage = "com.test.auth";
        payload.SetRuntime(runtime);
        return payload;
    }
    QueryOption Query(const std::string &key)
    {
        QueryOption query;
        query.key = key;
        query.intention = UD_INTENTION_DRAG;
        query.tokenId = receiverTokenId;
        return query;
    }
    void UseNativeDelayIdentity()
    {
        nativeLookups_ = 0;
        auto token = static_cast<uint32_t>(IPCSkeleton::GetCallingTokenID());
        ON_CALL(*tokens_, GetTokenTypeFlag(token)).WillByDefault(Return(TOKEN_NATIVE));
        ON_CALL(*tokens_, GetTokenType(token)).WillByDefault(Return(TOKEN_NATIVE));
        ON_CALL(*tokens_, GetNativeTokenInfo(token, _)).WillByDefault([this](auto, NativeTokenInfo &info) {
            // Source identity changes at the saved-identity check so this native-only fixture reaches SG.
            info.processName = ++nativeLookups_ == nativeLookupSourceSwitch ? "replaced" : "msdp";
            return 0;
        });
    }
    int32_t PushAuthPayload(UdmfServiceImpl &service, const std::string &key, size_t length = 8)
    {
        nativeLookups_ = 0;
        auto payload = Payload(length);
        Summary summary;
        return service.PushDelayData(key, payload, summary);
    }
    int nativeLookups_ = 0;
    std::shared_ptr<NiceMock<AuthStoreMock>> store_;
    UdmfAuthGuardMock guard_;
    std::shared_ptr<NiceMock<AccessTokenKitMock>> tokens_;
    std::shared_ptr<NiceMock<DeviceManagerAdapterMock>> devices_;
    std::vector<std::pair<std::string, uint32_t>> keys_;
};
/**
 * @tc.name: GetData_CachedReadDeny_PreservesPendingAndErasesReturnedPayload
 * @tc.desc: Verify public behavior, failure propagation and observable state.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfServiceAuthEntryTest, GetData_CachedReadDeny_PreservesPendingAndErasesReturnedPayload, TestSize.Level1)
{
    const std::string key = "udmf://drag/com.test.auth/read-denied";
    auto pending = Prepare(key);
    ASSERT_NE(pending.blockData, nullptr);
    pending.blockData->SetValue(DelayDeliveryResult{ Payload(), UDMF::E_OK, false });
    guard_.result_ = SecurityGuardDelegate::Strategy::DENY;
    UdmfServiceImpl service;
    UnifiedData output;
    EXPECT_EQ(service.GetData(Query(key), output), UDMF::E_NO_PERMISSION);
    EXPECT_TRUE(output.IsEmpty());
    EXPECT_EQ(output.GetRuntime(), nullptr);
    ASSERT_EQ(guard_.requests_, 1);
    EXPECT_EQ(guard_.event_.eventId, 0x0F810000);
    EXPECT_EQ(guard_.event_.version, "1.0");
    auto json = Serializable::json::parse(guard_.event_.jsonContent);
    EXPECT_EQ(json["sourceTokenId"], sourceTokenId);
    EXPECT_EQ(json["targetTokenId"], receiverTokenId);
    EXPECT_FALSE(json["content"]["entries"].empty());
    EXPECT_FALSE(DelayDataPrepareContainer::GetInstance().QueryBlockDelayData(key, pending));
}
/**
 * @tc.name: GetData_CachedLargePayload_DeliversFullDataAfterPreviewAllow
 * @tc.desc: Verify public behavior, failure propagation and observable state.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(
    UdmfServiceAuthEntryTest, GetData_CachedLargePayload_DeliversFullDataAfterPreviewAllow, TestSize.Level1)
{
    const std::string key = "udmf://drag/com.test.auth/read-oversize";
    auto pending = Prepare(key);
    ASSERT_NE(pending.blockData, nullptr);
    pending.blockData->SetValue(DelayDeliveryResult{ Payload(100 * 1024), UDMF::E_OK, false });
    UdmfServiceImpl service;
    UnifiedData output;
    EXPECT_EQ(service.GetData(Query(key), output), UDMF::E_OK);
    ASSERT_EQ(output.GetRecords().size(), 1u);
    EXPECT_EQ(std::get<std::string>(output.GetRecords()[0]->GetOriginValue()).size(), 100 * 1024u);
    EXPECT_EQ(guard_.requests_, 1);
    EXPECT_LE(guard_.event_.jsonContent.size(), 10 * 1024u);
    auto preview = Serializable::json::parse(guard_.event_.jsonContent);
    auto text = preview["content"]["entries"][0]["entries"][output.GetRecords()[0]->GetUtdId()][VALUE_TYPE];
    ASSERT_TRUE(text.is_string());
    EXPECT_LT(text.get<std::string>().size(), 100 * 1024u);
    EXPECT_FALSE(DelayDataPrepareContainer::GetInstance().QueryBlockDelayData(key, pending));
}
/**
 * @tc.name: GetData_CachedAllow_ConsumesOnlyAfterAuthorizationAndPreservesContent
 * @tc.desc: Verify public behavior, failure propagation and observable state.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(
    UdmfServiceAuthEntryTest, GetData_CachedAllow_ConsumesOnlyAfterAuthorizationAndPreservesContent, TestSize.Level1)
{
    const std::string key = "udmf://drag/com.test.auth/read-allow";
    auto pending = Prepare(key);
    ASSERT_NE(pending.blockData, nullptr);
    pending.blockData->SetValue(DelayDeliveryResult{ Payload(), UDMF::E_OK, false });
    UdmfServiceImpl service;
    UnifiedData output;
    EXPECT_EQ(service.GetData(Query(key), output), UDMF::E_OK);
    ASSERT_EQ(output.GetRecords().size(), 1u);
    EXPECT_EQ(guard_.requests_, 1);
    EXPECT_FALSE(DelayDataPrepareContainer::GetInstance().QueryBlockDelayData(key, pending));
}
/**
 * @tc.name: GetData_AlreadyPreparedRead_DoesNotDispatchSecondEvent
 * @tc.desc: Verify public behavior, failure propagation and observable state.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfServiceAuthEntryTest, GetData_AlreadyPreparedRead_DoesNotDispatchSecondEvent, TestSize.Level1)
{
    const std::string key = "udmf://drag/com.test.auth/read-prepared";
    auto pending = Prepare(key);
    ASSERT_NE(pending.blockData, nullptr);
    pending.blockData->SetValue(DelayDeliveryResult{ Payload(), UDMF::E_OK, true });
    guard_.result_ = SecurityGuardDelegate::Strategy::DENY;
    UdmfServiceImpl service;
    UnifiedData output;
    EXPECT_EQ(service.GetData(Query(key), output), UDMF::E_OK);
    EXPECT_EQ(output.GetRecords().size(), 1u);
    EXPECT_EQ(guard_.requests_, 0);
    EXPECT_FALSE(DelayDataPrepareContainer::GetInstance().QueryBlockDelayData(key, pending));
}
/**
 * @tc.name: GetData_PendingDelivery_ReturnsNotFoundWithoutAuthOrCacheConsumption
 * @tc.desc: Verify the extracted load routing keeps an unresolved delivery pending.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(
    UdmfServiceAuthEntryTest, GetData_PendingDelivery_ReturnsNotFoundWithoutAuthOrCacheConsumption, TestSize.Level1)
{
    const std::string key = "udmf://drag/com.test.auth/read-pending";
    auto pending = Prepare(key);
    ASSERT_NE(pending.blockData, nullptr);
    UdmfServiceImpl service;
    UnifiedData output;
    EXPECT_EQ(service.GetData(Query(key), output), UDMF::E_NOT_FOUND);
    EXPECT_TRUE(output.IsEmpty());
    EXPECT_EQ(guard_.requests_, 0);
    BlockDelayData retained;
    EXPECT_TRUE(DelayDataPrepareContainer::GetInstance().QueryBlockDelayData(key, retained));
    EXPECT_EQ(retained.tokenId, pending.tokenId);
    EXPECT_EQ(retained.blockData, pending.blockData);
}
/**
 * @tc.name: GetData_DeliveryFailures_UseExistingStatusesAndReleaseCache
 * @tc.desc: Verify public behavior, failure propagation and observable state.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfServiceAuthEntryTest, GetData_DeliveryFailures_UseExistingStatusesAndReleaseCache, TestSize.Level1)
{
    int sequence = 0;
    for (auto expected : { UDMF::E_NO_PERMISSION, UDMF::E_INVALID_PARAMETERS, UDMF::E_ERROR }) {
        const std::string key = "udmf://drag/com.test.auth/read-error-" + std::to_string(sequence++);
        auto pending = Prepare(key);
        ASSERT_NE(pending.blockData, nullptr);
        pending.blockData->SetValue(DelayDeliveryResult{ Payload(), expected, false });
        UdmfServiceImpl service;
        UnifiedData output;
        EXPECT_EQ(service.GetData(Query(key), output), expected);
        EXPECT_TRUE(output.IsEmpty());
        EXPECT_EQ(guard_.requests_, 0);
        EXPECT_FALSE(DelayDataPrepareContainer::GetInstance().QueryBlockDelayData(key, pending));
    }
}
/**
 * @tc.name: GetData_IncompleteCachedPayload_FailsBeforeSgAndReleasesPending
 * @tc.desc: Verify public behavior, failure propagation and observable state.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfServiceAuthEntryTest, GetData_IncompleteCachedPayload_FailsBeforeSgAndReleasesPending, TestSize.Level1)
{
    const std::string key = "udmf://drag/com.test.auth/read-incomplete";
    auto pending = Prepare(key);
    ASSERT_NE(pending.blockData, nullptr);
    pending.blockData->SetValue(DelayDeliveryResult{ UnifiedData(), UDMF::E_OK, false });
    UdmfServiceImpl service;
    UnifiedData output;
    EXPECT_EQ(service.GetData(Query(key), output), UDMF::E_ERROR);
    EXPECT_TRUE(output.IsEmpty());
    EXPECT_EQ(guard_.requests_, 0);
    EXPECT_FALSE(DelayDataPrepareContainer::GetInstance().QueryBlockDelayData(key, pending));
}
/**
 * @tc.name: GetData_UnavailableAndRejectedSg_MaintainCurrentFailOpenPolicy
 * @tc.desc: Verify public behavior, failure propagation and observable state.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfServiceAuthEntryTest, GetData_UnavailableAndRejectedSg_MaintainCurrentFailOpenPolicy, TestSize.Level1)
{
    int sequence = 0;
    for (bool ready : { false, true }) {
        const std::string key = "udmf://drag/com.test.auth/read-unavailable-" + std::to_string(sequence++);
        auto pending = Prepare(key);
        ASSERT_NE(pending.blockData, nullptr);
        pending.blockData->SetValue(DelayDeliveryResult{ Payload(), UDMF::E_OK, false });
        guard_.ready_ = ready;
        guard_.dispatch_ = SecurityGuardDelegate::DispatchStatus::REJECTED;
        UdmfServiceImpl service;
        UnifiedData output;
        EXPECT_EQ(service.GetData(Query(key), output), UDMF::E_OK);
        EXPECT_EQ(output.GetRecords().size(), 1u);
        EXPECT_FALSE(DelayDataPrepareContainer::GetInstance().QueryBlockDelayData(key, pending));
    }
    EXPECT_EQ(guard_.requests_, 1);
}

/**
 * @tc.name: GetData_OnlyVerifiedLocalSameApp_SkipsBlocking
 * @tc.desc: Verify public behavior, failure propagation and observable state.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfServiceAuthEntryTest, GetData_OnlyVerifiedLocalSameApp_SkipsBlocking, TestSize.Level1)
{
    struct Scenario {
        std::string device;
        uint32_t source;
        std::string bundle;
        bool skip;
    };
    const std::vector<Scenario> cases = {
        { "local-auth-device", receiverTokenId, "com.test.auth", true },
        { "remote-auth-device", receiverTokenId, "com.test.auth", false },
        { "local-auth-device", sourceTokenId, "com.test.auth", false },
        { "local-auth-device", receiverTokenId, "com.test.replaced", false },
        { "", receiverTokenId, "com.test.auth", false },
    };
    int index = 0;
    guard_.result_ = SecurityGuardDelegate::Strategy::DENY;
    for (const auto &item : cases) {
        const std::string key = "udmf://drag/com.test.auth/identity-" + std::to_string(index++);
        auto pending = Prepare(key);
        ASSERT_NE(pending.blockData, nullptr);
        auto payload = Payload();
        auto runtime = payload.GetRuntime();
        ASSERT_NE(runtime, nullptr);
        runtime->deviceId = item.device;
        runtime->tokenId = item.source;
        runtime->sourcePackage = item.bundle;
        pending.blockData->SetValue(DelayDeliveryResult{ payload, UDMF::E_OK, false });
        UdmfServiceImpl service;
        UnifiedData output;
        auto requestsBefore = guard_.requests_;
        EXPECT_EQ(service.GetData(Query(key), output), item.skip ? UDMF::E_OK : UDMF::E_NO_PERMISSION);
        EXPECT_EQ(guard_.requests_ - requestsBefore, item.skip ? 0 : 1);
        EXPECT_EQ(output.GetRecords().size(), item.skip ? 1u : 0u);
        EXPECT_FALSE(DelayDataPrepareContainer::GetInstance().QueryBlockDelayData(key, pending));
    }
}
/**
 * @tc.name: GetDataIfAvailable_InvalidArguments_DoNotReachBlockingFramework
 * @tc.desc: Verify public behavior, failure propagation and observable state.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfServiceAuthEntryTest, GetDataIfAvailable_InvalidArguments_DoNotReachBlockingFramework, TestSize.Level1)
{
    UdmfServiceImpl service;
    DataLoadInfo info;
    sptr<IRemoteObject> notifier;
    EXPECT_EQ(service.GetDataIfAvailable("invalid", info, notifier, nullptr), UDMF::E_ERROR);
    auto output = std::make_shared<UnifiedData>();
    EXPECT_EQ(service.GetDataIfAvailable("invalid", info, notifier, output), UDMF::E_INVALID_PARAMETERS);
    EXPECT_TRUE(output->IsEmpty());
    EXPECT_EQ(guard_.requests_, 0);
}

/**
 * @tc.name: PushDelayData_OriginHandoff_DoesNotRunReceiverAuthorization
 * @tc.desc: Verify public behavior, failure propagation and observable state.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfServiceAuthEntryTest, PushDelayData_OriginHandoff_DoesNotRunReceiverAuthorization, TestSize.Level1)
{
    const std::string key = "udmf://drag/com.test.auth/originhandoff";
    auto token = static_cast<uint32_t>(IPCSkeleton::GetCallingTokenID());
    ON_CALL(*tokens_, GetTokenTypeFlag(token)).WillByDefault(Return(TOKEN_NATIVE));
    ON_CALL(*tokens_, GetTokenType(token)).WillByDefault(Return(TOKEN_NATIVE));
    EXPECT_CALL(*tokens_, GetNativeTokenInfo(token, _))
        .Times(AtLeast(1))
        .WillRepeatedly([](auto, NativeTokenInfo &info) {
            info.processName = "msdp";
            return 0;
        });
    auto pending = Prepare(key, token);
    ASSERT_NE(pending.blockData, nullptr);
    guard_.result_ = SecurityGuardDelegate::Strategy::DENY;
    UdmfServiceImpl service;
    auto payload = Payload();
    Summary summary;
    EXPECT_EQ(service.PushDelayData(key, payload, summary), UDMF::E_OK);
    EXPECT_EQ(guard_.requests_, 0);
    auto delivered = pending.blockData->GetValue();
    ASSERT_TRUE(delivered.has_value());
    EXPECT_EQ(delivered->status, UDMF::E_OK);
    EXPECT_FALSE(delivered->prepared);
    EXPECT_EQ(delivered->data.GetRecords().size(), 1u);
}
/**
 * @tc.name: GetData_UriPreparationFailsAfterAllow_ReturnsPermissionFailureAndReleasesPending
 * @tc.desc: Verify public behavior, failure propagation and observable state.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfServiceAuthEntryTest, GetData_UriPreparationFailsAfterAllow_ReturnsPermissionFailureAndReleasesPending,
    TestSize.Level1)
{
    const std::string key = "udmf://drag/com.test.auth/uri-preparation";
    auto pending = Prepare(key);
    ASSERT_NE(pending.blockData, nullptr);
    pending.blockData->SetValue(DelayDeliveryResult{ Payload(), UDMF::E_OK, false });
    EXPECT_CALL(*tokens_, GetHapTokenInfo(receiverTokenId, _))
        .WillOnce([](auto, HapTokenInfo &info) {
            info.bundleName = "com.test.auth";
            return 0;
        })
        .WillOnce(Return(-1));
    UdmfServiceImpl service;
    UnifiedData output;
    EXPECT_EQ(service.GetData(Query(key), output), UDMF::E_NO_PERMISSION);
    EXPECT_EQ(guard_.requests_, 1);
    EXPECT_TRUE(output.IsEmpty());
    EXPECT_FALSE(DelayDataPrepareContainer::GetInstance().QueryBlockDelayData(key, pending));
}

class RecordingDelayOrigin final : public IRemoteStub<IUdmfNotifier> {
public:
    void HandleDelayObserver(const std::string &, const DataLoadInfo &) override
    {
        ++calls;
    }
    int calls = 0;
};

class RecordingAuthDelivery : public IRemoteStub<IDelayDataCallback> {
public:
    void DelayDataCallback(const std::string &key, const UnifiedData &data) override
    {
        ++calls;
        deliveredKey = key;
        delivered = data;
    }
    int calls = 0;
    std::string deliveredKey;
    UnifiedData delivered;
};
/**
 * @tc.name: PushDelayData_AsyncDeniedThenLargeAllowed_DeliversFullData
 * @tc.desc: Public read, source push and completion retain retryable origin until accepted delivery.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfServiceAuthEntryTest, PushDelayData_AsyncDeniedThenLargeAllowed_DeliversFullData, TestSize.Level1)
{
    UseNativeDelayIdentity();
    std::string key;
    sptr<RecordingDelayOrigin> origin = new RecordingDelayOrigin();
    auto &prepare = DelayDataPrepareContainer::GetInstance();
    EXPECT_CALL(*store_, PutDelayData(_, _)).WillOnce(Return(UDMF::E_OK));
    EXPECT_CALL(*store_, SetRemotePullStartNotify()).WillOnce(Return(UDMF::E_OK));
    UdmfServiceImpl service;
    DataLoadInfo load;
    load.sequenceKey = "asyncretrycomplete";
    load.recordCount = 1;
    ASSERT_EQ(service.SetDelayInfo(load, origin->AsObject(), key), UDMF::E_OK);
    keys_.push_back({ key, 0 });
    EXPECT_CALL(*store_, Get(key, _)).WillRepeatedly([&](const auto &, UnifiedData &output) {
        output = Payload();
        output.GetRuntime()->recordTotalNum = 2;
        return UDMF::E_OK;
    });
    int attempts = 0;
    for (auto expected : { UDMF::E_NO_PERMISSION, UDMF::E_OK }) {
        sptr<RecordingAuthDelivery> receiver = new RecordingAuthDelivery();
        auto output = std::make_shared<UnifiedData>();
        EXPECT_EQ(service.GetDataIfAvailable(key, DataLoadInfo(), receiver->AsObject(), output), UDMF::E_OK);
        EXPECT_EQ(origin->calls, ++attempts);
        guard_.result_ = expected == UDMF::E_NO_PERMISSION ? SecurityGuardDelegate::Strategy::DENY
                                                           : SecurityGuardDelegate::Strategy::ALLOW;
        EXPECT_EQ(PushAuthPayload(service, key, expected == UDMF::E_OK ? 100 * 1024 : 8), expected);
        EXPECT_EQ(receiver->calls, 1);
        EXPECT_EQ(receiver->delivered.IsEmpty(), expected != UDMF::E_OK);
        EXPECT_EQ(prepare.QueryDataLoadCallbackSize(), expected == UDMF::E_OK ? 0 : 1);
    }
    EXPECT_EQ(guard_.requests_, 2);
    EXPECT_LE(guard_.event_.jsonContent.size(), 10 * 1024u);
}

/**
 * @tc.name: PushDelayData_ReceiverReplacedDuringAuth_OldResultCannotConsumeNewRequest
 * @tc.desc: Replacement at the SG boundary cannot inherit old ALLOW or DENY or lose source registration.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfServiceAuthEntryTest, PushDelayData_ReceiverReplacedDuringAuth_OldResultCannotConsumeNewRequest,
    TestSize.Level1)
{
    UseNativeDelayIdentity();
    const std::string key = "udmf://drag/com.test.auth/asyncreplaced";
    keys_.push_back({ key, 0 });
    auto token = static_cast<uint32_t>(IPCSkeleton::GetCallingTokenID());
    sptr<RecordingDelayOrigin> origin = new RecordingDelayOrigin();
    auto &prepare = DelayDataPrepareContainer::GetInstance();
    auto &acquire = DelayDataAcquireContainer::GetInstance();
    UdmfServiceImpl service;
    for (auto decision : { SecurityGuardDelegate::Strategy::ALLOW, SecurityGuardDelegate::Strategy::DENY }) {
        ASSERT_TRUE(prepare.RegisterDataLoadCallback(key, origin, token));
        sptr<RecordingAuthDelivery> first = new RecordingAuthDelivery();
        sptr<RecordingAuthDelivery> next = new RecordingAuthDelivery();
        DelayGetDataInfo info{ .tokenId = token, .dataCallback = first->AsObject() };
        ASSERT_TRUE(acquire.RegisterDelayDataCallback(key, info));
        guard_.result_ = decision;
        guard_.beforeComplete_ = [&] {
            info.dataCallback = next->AsObject();
            DelayDataAcquireContainer::Request replacement;
            acquire.RegisterDelayDataCallback(key, info, &replacement);
            prepare.ExecDataLoadCallback(key, DataLoadInfo(), replacement.generation);
        };
        EXPECT_EQ(PushAuthPayload(service, key), UDMF::E_ERROR);
        EXPECT_EQ(nativeLookups_, 2);
        EXPECT_EQ(first->calls, 0);
        EXPECT_EQ(next->calls, 0);
        EXPECT_TRUE(acquire.IsContainDelayData(key));
        EXPECT_EQ(prepare.QueryDataLoadCallbackSize(), 1);
        guard_.beforeComplete_ = {};
        guard_.result_ = SecurityGuardDelegate::Strategy::ALLOW;
        EXPECT_EQ(PushAuthPayload(service, key, 9), UDMF::E_OK);
        EXPECT_EQ(next->calls, 1);
        EXPECT_FALSE(next->delivered.IsEmpty());
        EXPECT_FALSE(acquire.IsContainDelayData(key));
        EXPECT_EQ(prepare.QueryDataLoadCallbackSize(), 0);
    }
    EXPECT_EQ(guard_.requests_, 4);
}

/**
 * @tc.name: HandleRemoteDelayData_ReplacedDuringAuth_DropsOldResultBeforeConsumption
 * @tc.desc: Remote read also claims the exact receiver before URI grants and store consumption.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfServiceAuthEntryTest, HandleRemoteDelayData_ReplacedDuringAuth_DropsOldResultBeforeConsumption,
    TestSize.Level1)
{
    const std::string key = "udmf://drag/com.test.auth/remotereplaced";
    keys_.push_back({ key, receiverTokenId });
    EXPECT_CALL(*store_, Get(key, _)).WillRepeatedly([&](const auto &, UnifiedData &output) {
        output = Payload();
        output.GetRuntime()->privileges = { { receiverTokenId, "readAndKeep", "" } };
        return UDMF::E_OK;
    });
    EXPECT_CALL(*store_, Delete(_)).Times(0);
    sptr<RecordingAuthDelivery> first = new RecordingAuthDelivery();
    sptr<RecordingAuthDelivery> next = new RecordingAuthDelivery();
    DelayGetDataInfo info{ .tokenId = receiverTokenId, .dataCallback = first->AsObject() };
    auto &acquire = DelayDataAcquireContainer::GetInstance();
    ASSERT_TRUE(acquire.RegisterDelayDataCallback(key, info));
    guard_.result_ = SecurityGuardDelegate::Strategy::ALLOW;
    guard_.beforeComplete_ = [&] {
        info.dataCallback = next->AsObject();
        acquire.RegisterDelayDataCallback(key, info);
    };
    UdmfServiceImpl service;
    EXPECT_CALL(*tokens_, GetHapTokenInfo(receiverTokenId, _)).Times(0);
    EXPECT_EQ(service.HandleRemoteDelayData(key), UDMF::E_ERROR);
    EXPECT_TRUE(Mock::VerifyAndClearExpectations(tokens_.get()));
    EXPECT_EQ(first->calls, 0);
    EXPECT_EQ(next->calls, 0);
    EXPECT_TRUE(acquire.IsContainDelayData(key));
    guard_.beforeComplete_ = {};
    EXPECT_EQ(service.HandleRemoteDelayData(key), UDMF::E_OK);
    EXPECT_EQ(next->calls, 1);
    EXPECT_FALSE(next->delivered.IsEmpty());
    EXPECT_EQ(guard_.requests_, 2);
}

/**
 * @tc.name: HandleRemoteDelayData_AsyncConsume_PreservesValidatedKeyForLifecycle
 * @tc.desc: Accepted remote delivery schedules deletion using the parsed drag key before callback success.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(
    UdmfServiceAuthEntryTest, HandleRemoteDelayData_AsyncConsume_PreservesValidatedKeyForLifecycle, TestSize.Level1)
{
    const std::string key = "udmf://drag/com.test.auth/remoteconsume";
    keys_.push_back({ key, receiverTokenId });
    EXPECT_CALL(*store_, Get(key, _)).WillOnce([&](const auto &, UnifiedData &data) {
        data = Payload();
        return UDMF::E_OK;
    });
    auto removed = std::make_shared<std::promise<void>>();
    auto done = removed->get_future();
    EXPECT_CALL(*store_, Delete(UnifiedKey(key).GetKeyCommonPrefix())).WillOnce([removed](const auto &) {
        removed->set_value();
        return UDMF::E_OK;
    });
    sptr<RecordingAuthDelivery> receiver = new RecordingAuthDelivery();
    DelayGetDataInfo info{ .tokenId = receiverTokenId, .dataCallback = receiver->AsObject() };
    ASSERT_TRUE(DelayDataAcquireContainer::GetInstance().RegisterDelayDataCallback(key, info));
    auto pool = std::make_shared<ExecutorPool>(1, 1);
    UdmfServiceImpl service;
    FeatureSystem::Feature::BindInfo bind;
    bind.executors = pool;
    EXPECT_EQ(service.OnBind(bind), UDMF::E_OK);
    EXPECT_EQ(service.HandleRemoteDelayData(key), UDMF::E_OK);
    EXPECT_EQ(receiver->calls, 1);
    EXPECT_FALSE(receiver->delivered.IsEmpty());
    EXPECT_EQ(done.wait_for(std::chrono::seconds(2)), std::future_status::ready);
    EXPECT_EQ(service.OnBind({}), UDMF::E_OK);
    pool.reset();
}

/**
 * @tc.name: GetDataIfAvailable_IncompleteOrMissingOrigin_NeverReturnsPartialPayload
 * @tc.desc: Waiting and failed replies must stay empty until receiver authorization and full delivery.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(
    UdmfServiceAuthEntryTest, GetDataIfAvailable_IncompleteOrMissingOrigin_NeverReturnsPartialPayload, TestSize.Level1)
{
    UdmfServiceImpl service;
    struct Scenario {
        std::string device;
        int32_t status;
        bool pending;
    };
    const std::vector<Scenario> cases = { { "local-auth-device", UDMF::E_ERROR, false },
        { "remote-auth-device", UDMF::E_OK, true }, { "", UDMF::E_ERROR, false } };
    int index = 0;
    for (const auto &item : cases) {
        const std::string key = "udmf://drag/com.test.auth/incomplete" + std::to_string(index++);
        keys_.push_back({ key, 0 });
        EXPECT_CALL(*store_, Get(key, _)).WillOnce([&](const auto &, UnifiedData &output) {
            if (!item.device.empty()) {
                output = Payload();
                output.GetRuntime()->recordTotalNum = 2;
                output.GetRuntime()->deviceId = item.device;
            }
            return UDMF::E_OK;
        });
        sptr<RecordingAuthDelivery> receiver = new RecordingAuthDelivery();
        auto output = std::make_shared<UnifiedData>();
        EXPECT_EQ(service.GetDataIfAvailable(key, DataLoadInfo(), receiver->AsObject(), output), item.status);
        EXPECT_TRUE(output->IsEmpty());
        EXPECT_EQ(output->GetRuntime(), nullptr);
        EXPECT_EQ(receiver->calls, 0);
        EXPECT_EQ(DelayDataAcquireContainer::GetInstance().IsContainDelayData(key), item.pending);
    }
    EXPECT_EQ(guard_.requests_, 0);
}

/**
 * @tc.name: GetData_IncompleteStoredRecords_ReturnsNotFoundWithoutPartialPayload
 * @tc.desc: A raw IPC caller must not receive partial records before the read authorization gate.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(
    UdmfServiceAuthEntryTest, GetData_IncompleteStoredRecords_ReturnsNotFoundWithoutPartialPayload, TestSize.Level1)
{
    const std::string key = "udmf://drag/com.test.auth/syncincomplete";
    EXPECT_CALL(*store_, Get(key, _)).WillOnce([&](const auto &, UnifiedData &data) {
        data = Payload();
        data.GetRuntime()->recordTotalNum = 2;
        return UDMF::E_OK;
    });
    UdmfServiceImpl service;
    UnifiedData output;
    EXPECT_EQ(service.GetData(Query(key), output), UDMF::E_NOT_FOUND);
    EXPECT_TRUE(output.IsEmpty());
    EXPECT_EQ(output.GetRuntime(), nullptr);
    EXPECT_EQ(guard_.requests_, 0);
}

/**
 * @tc.name: GetDataIfAvailable_ImmediateAuthorizedData_ReturnsBodyWithoutDelayedCallback
 * @tc.desc: Clearing unsuccessful replies must preserve the immediate successful path.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfServiceAuthEntryTest, GetDataIfAvailable_ImmediateAuthorizedData_ReturnsBodyWithoutDelayedCallback,
    TestSize.Level1)
{
    const std::string key = "udmf://drag/com.test.auth/immediateread";
    auto token = static_cast<uint32_t>(IPCSkeleton::GetCallingTokenID());
    EXPECT_CALL(*store_, Get(key, _)).WillOnce([&](const auto &, UnifiedData &data) {
        data = Payload();
        data.GetRuntime()->privileges = { { token, "readAndKeep", "" } };
        return UDMF::E_OK;
    });
    UdmfServiceImpl service;
    sptr<RecordingAuthDelivery> receiver = new RecordingAuthDelivery();
    auto output = std::make_shared<UnifiedData>();
    EXPECT_EQ(service.GetDataIfAvailable(key, DataLoadInfo(), receiver->AsObject(), output), UDMF::E_OK);
    EXPECT_FALSE(output->IsEmpty());
    EXPECT_EQ(receiver->calls, 0);
    EXPECT_FALSE(DelayDataAcquireContainer::GetInstance().IsContainDelayData(key));
    EXPECT_EQ(guard_.requests_, 1);
}

/**
 * @tc.name: GetDataIfAvailable_AnotherReceiverOwnsRegistration_RejectsWithoutSourceDispatch
 * @tc.desc: Failed registration cannot overwrite or consume another token's pending receiver.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfServiceAuthEntryTest, GetDataIfAvailable_AnotherReceiverOwnsRegistration_RejectsWithoutSourceDispatch,
    TestSize.Level1)
{
    const std::string key = "udmf://drag/com.test.auth/otherreceiver";
    keys_.push_back({ key, 0 });
    EXPECT_CALL(*store_, Get(key, _)).WillOnce([&](const auto &, UnifiedData &data) {
        data = Payload();
        data.GetRuntime()->recordTotalNum = 2;
        return UDMF::E_OK;
    });
    sptr<RecordingAuthDelivery> first = new RecordingAuthDelivery();
    auto token = static_cast<uint32_t>(IPCSkeleton::GetCallingTokenID());
    DelayGetDataInfo info{ .tokenId = token + 1, .dataCallback = first->AsObject() };
    auto &acquire = DelayDataAcquireContainer::GetInstance();
    DelayDataAcquireContainer::Request expected;
    ASSERT_TRUE(acquire.RegisterDelayDataCallback(key, info, &expected));
    sptr<RecordingDelayOrigin> origin = new RecordingDelayOrigin();
    ASSERT_TRUE(DelayDataPrepareContainer::GetInstance().RegisterDataLoadCallback(key, origin, sourceTokenId));
    UdmfServiceImpl service;
    sptr<RecordingAuthDelivery> next = new RecordingAuthDelivery();
    auto output = std::make_shared<UnifiedData>();
    EXPECT_EQ(service.GetDataIfAvailable(key, DataLoadInfo(), next->AsObject(), output), UDMF::E_NO_PERMISSION);
    DelayDataAcquireContainer::Request retained;
    ASSERT_TRUE(acquire.QueryDelayDataRequest(key, retained));
    EXPECT_EQ(retained.generation, expected.generation);
    EXPECT_EQ(first->calls, 0);
    EXPECT_EQ(next->calls, 0);
    EXPECT_EQ(origin->calls, 0);
    EXPECT_TRUE(output->IsEmpty());
}

/**
 * @tc.name: SetDelayInfo_UnknownIdentityOrNullNotifier_DoesNotReserveCapacity
 * @tc.desc: Invalid setup fails before storage writes or origin registration.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfServiceAuthEntryTest, SetDelayInfo_UnknownIdentityOrNullNotifier_DoesNotReserveCapacity, TestSize.Level1)
{
    UseNativeDelayIdentity();
    auto token = static_cast<uint32_t>(IPCSkeleton::GetCallingTokenID());
    ON_CALL(*tokens_, GetNativeTokenInfo(token, _)).WillByDefault(Return(-1));
    EXPECT_CALL(*store_, PutDelayData(_, _)).Times(0);
    UdmfServiceImpl service;
    sptr<RecordingDelayOrigin> origin = new RecordingDelayOrigin();
    DataLoadInfo info;
    info.sequenceKey = "invalidsetup";
    std::string key;
    EXPECT_EQ(service.SetDelayInfo(info, origin->AsObject(), key), UDMF::E_ERROR);
    UseNativeDelayIdentity();
    EXPECT_EQ(service.SetDelayInfo(info, nullptr, key), UDMF::E_ERROR);
    EXPECT_EQ(DelayDataPrepareContainer::GetInstance().QueryDataLoadCallbackSize(), 0);
    EXPECT_EQ(origin->calls, 0);
    EXPECT_EQ(guard_.requests_, 0);
}

/**
 * @tc.name: PushDelayData_InvalidKeyOrIdentity_RejectsBeforeReceiverDispatch
 * @tc.desc: Invalid source input never reaches SG or consumes a receiver.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfServiceAuthEntryTest, PushDelayData_InvalidKeyOrIdentity_RejectsBeforeReceiverDispatch, TestSize.Level1)
{
    UseNativeDelayIdentity();
    UdmfServiceImpl service;
    EXPECT_EQ(PushAuthPayload(service, "invalid"), UDMF::E_INVALID_PARAMETERS);
    auto token = static_cast<uint32_t>(IPCSkeleton::GetCallingTokenID());
    ON_CALL(*tokens_, GetNativeTokenInfo(token, _)).WillByDefault(Return(-1));
    EXPECT_EQ(PushAuthPayload(service, "udmf://drag/com.test.auth/invalididentity"), UDMF::E_ERROR);
    EXPECT_EQ(guard_.requests_, 0);
}

/**
 * @tc.name: PushDelayData_ReceiverNotPrivileged_PreservesPendingRegistration
 * @tc.desc: A source push cannot grant an unprivileged different receiver access.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfServiceAuthEntryTest, PushDelayData_ReceiverNotPrivileged_PreservesPendingRegistration, TestSize.Level1)
{
    UseNativeDelayIdentity();
    const std::string key = "udmf://drag/com.test.auth/noprivilege";
    keys_.push_back({ key, 0 });
    auto token = static_cast<uint32_t>(IPCSkeleton::GetCallingTokenID());
    sptr<RecordingAuthDelivery> receiver = new RecordingAuthDelivery();
    DelayGetDataInfo info{ .tokenId = token + 1, .dataCallback = receiver->AsObject() };
    auto &acquire = DelayDataAcquireContainer::GetInstance();
    ASSERT_TRUE(acquire.RegisterDelayDataCallback(key, info));
    UdmfServiceImpl service;
    EXPECT_EQ(PushAuthPayload(service, key), UDMF::E_NO_PERMISSION);
    EXPECT_TRUE(acquire.IsContainDelayData(key));
    EXPECT_EQ(receiver->calls, 0);
    EXPECT_EQ(guard_.requests_, 0);
}

/**
 * @tc.name: PushDelayData_PrefetchStoreUnavailable_ReleasesAttemptForSourceRetry
 * @tc.desc: Persisting without a receiver can fail without consuming the retained origin.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(
    UdmfServiceAuthEntryTest, PushDelayData_PrefetchStoreUnavailable_ReleasesAttemptForSourceRetry, TestSize.Level1)
{
    UseNativeDelayIdentity();
    const std::string key = "udmf://drag/com.test.auth/prefetchfailed";
    keys_.push_back({ key, 0 });
    sptr<RecordingDelayOrigin> origin = new RecordingDelayOrigin();
    auto &prepare = DelayDataPrepareContainer::GetInstance();
    ASSERT_TRUE(prepare.RegisterDataLoadCallback(key, origin, sourceTokenId));
    EXPECT_TRUE(prepare.ExecDataLoadCallback(key, DataLoadInfo()));
    EXPECT_EQ(origin->calls, 1);
    AuthStoreRegistry::current.reset();
    UdmfServiceImpl service;
    EXPECT_EQ(PushAuthPayload(service, key), UDMF::E_DB_ERROR);
    EXPECT_TRUE(prepare.ExecDataLoadCallback(key, DataLoadInfo()));
    EXPECT_EQ(origin->calls, 2);
    EXPECT_EQ(prepare.QueryDataLoadCallbackSize(), 1);
    EXPECT_EQ(guard_.requests_, 0);
}

/**
 * @tc.name: HandleRemoteDelayData_NoPendingReceiver_ReturnsErrorWithoutStoreAccess
 * @tc.desc: Spurious remote data notifications do not consume stored data.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(
    UdmfServiceAuthEntryTest, HandleRemoteDelayData_NoPendingReceiver_ReturnsErrorWithoutStoreAccess, TestSize.Level1)
{
    EXPECT_CALL(*store_, Get(_, _)).Times(0);
    UdmfServiceImpl service;
    EXPECT_EQ(service.HandleRemoteDelayData("udmf://drag/com.test.auth/noreceiver"), UDMF::E_ERROR);
    EXPECT_EQ(guard_.requests_, 0);
}

/**
 * @tc.name: SetDelayInfo_StoreUnavailableOrWriteFails_RollsBackOriginRegistration
 * @tc.desc: Failed setup immediately returns its slot and does not require expiry to recover.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(
    UdmfServiceAuthEntryTest, SetDelayInfo_StoreUnavailableOrWriteFails_RollsBackOriginRegistration, TestSize.Level1)
{
    UseNativeDelayIdentity();
    sptr<RecordingDelayOrigin> origin = new RecordingDelayOrigin();
    auto &prepare = DelayDataPrepareContainer::GetInstance();
    const auto baseline = prepare.QueryDataLoadCallbackSize();
    EXPECT_CALL(*store_, PutDelayData(_, _)).WillOnce(Return(UDMF::E_DB_ERROR));
    UdmfServiceImpl service;
    for (bool available : { true, false }) {
        AuthStoreRegistry::current = available ? store_ : nullptr;
        DataLoadInfo info;
        info.sequenceKey = available ? "write_failed" : "store_unavailable";
        info.recordCount = 1;
        std::string key;
        EXPECT_EQ(service.SetDelayInfo(info, origin->AsObject(), key), UDMF::E_DB_ERROR);
        EXPECT_FALSE(key.empty());
        keys_.push_back({ key, 0 });
        EXPECT_EQ(prepare.QueryDataLoadCallbackSize(), baseline);
        DelayDataPrepareContainer::LoadToken missing;
        EXPECT_FALSE(prepare.QueryDataLoadToken(key, missing));
    }
}

/**
 * @tc.name: SetDelayInfo_FailedWriteReplacesOrigin_RollbackCannotRemoveReplacement
 * @tc.desc: Rollback compares the original registration rather than erasing another same-key source.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(
    UdmfServiceAuthEntryTest, SetDelayInfo_FailedWriteReplacesOrigin_RollbackCannotRemoveReplacement, TestSize.Level1)
{
    UseNativeDelayIdentity();
    sptr<RecordingDelayOrigin> first = new RecordingDelayOrigin();
    sptr<RecordingDelayOrigin> next = new RecordingDelayOrigin();
    auto &prepare = DelayDataPrepareContainer::GetInstance();
    DelayDataPrepareContainer::LoadToken replacement;
    bool registered = false;
    std::string key;
    EXPECT_CALL(*store_, PutDelayData(_, _)).WillOnce([&](const auto &, const auto &) {
        registered = prepare.RegisterDataLoadCallback(key, next, sourceTokenId, &replacement);
        return UDMF::E_DB_ERROR;
    });
    UdmfServiceImpl service;
    DataLoadInfo info;
    info.sequenceKey = "rollback_replaced";
    info.recordCount = 1;
    EXPECT_EQ(service.SetDelayInfo(info, first->AsObject(), key), UDMF::E_DB_ERROR);
    keys_.push_back({ key, sourceTokenId });
    EXPECT_TRUE(registered);
    DelayDataPrepareContainer::LoadToken retained;
    ASSERT_TRUE(prepare.QueryDataLoadToken(key, retained));
    EXPECT_EQ(retained.generation, replacement.generation);
    EXPECT_TRUE(prepare.CompleteDataLoad(key, replacement));
}

/**
 * @tc.name: PushDelayData_AsyncCompletion_PreservesAllowAndEmptiesDeniedDelivery
 * @tc.desc: Verify public behavior, failure propagation and observable state.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(
    UdmfServiceAuthEntryTest, PushDelayData_AsyncCompletion_PreservesAllowAndEmptiesDeniedDelivery, TestSize.Level1)
{
    for (bool deny : { false, true }) {
        const std::string key = deny ? "udmf://drag/com.test.auth/asyncdeny" : "udmf://drag/com.test.auth/asyncallow";
        auto token = static_cast<uint32_t>(IPCSkeleton::GetCallingTokenID());
        ON_CALL(*tokens_, GetTokenTypeFlag(token)).WillByDefault(Return(TOKEN_NATIVE));
        int identityLookups = 0;
        EXPECT_CALL(*tokens_, GetNativeTokenInfo(token, _))
            .Times(AtLeast(2))
            .WillRepeatedly([&](auto, NativeTokenInfo &info) {
                info.processName = deny && ++identityLookups > 1 ? "replaced" : "msdp";
                return 0;
            });
        sptr<RecordingAuthDelivery> delivery = new RecordingAuthDelivery();
        DelayGetDataInfo info;
        info.tokenId = token;
        info.dataCallback = delivery->AsObject();
        auto &acquire = DelayDataAcquireContainer::GetInstance();
        acquire.RegisterDelayDataCallback(key, info);
        UdmfServiceImpl service;
        auto payload = Payload();
        Summary summary;
        guard_.result_ = SecurityGuardDelegate::Strategy::DENY;
        auto requestsBefore = guard_.requests_;
        EXPECT_EQ(service.PushDelayData(key, payload, summary), deny ? UDMF::E_NO_PERMISSION : UDMF::E_OK);
        EXPECT_EQ(delivery->calls, 1);
        EXPECT_EQ(delivery->deliveredKey, key);
        EXPECT_EQ(delivery->delivered.IsEmpty(), deny);
        EXPECT_EQ(guard_.requests_ - requestsBefore, deny ? 1 : 0);
        EXPECT_FALSE(acquire.QueryDelayGetDataInfo(key, info));
        Mock::VerifyAndClearExpectations(tokens_.get());
    }
}

/**
 * @tc.name: OnBind_ReadyUnavailableAndMissingGuard_PreserveServiceBinding
 * @tc.desc: Verify public behavior, failure propagation and observable state.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfServiceAuthEntryTest, OnBind_ReadyUnavailableAndMissingGuard_PreserveServiceBinding, TestSize.Level1)
{
    UdmfServiceImpl service;
    FeatureSystem::Feature::BindInfo bind;
    EXPECT_EQ(service.OnBind(bind), UDMF::E_OK);
    EXPECT_EQ(guard_.starts_, 0);
    guard_.start_ = SecurityGuardDelegate::Status::UNAVAILABLE;
    EXPECT_EQ(service.OnBind(bind), UDMF::E_OK);
    EXPECT_EQ(guard_.starts_, 0);
    SecurityGuardTestRegistry::instance = nullptr;
    EXPECT_EQ(service.OnBind(bind), UDMF::E_OK);
    EXPECT_EQ(guard_.starts_, 0);
    EXPECT_EQ(guard_.requests_, 0);
}
/**
 * @tc.name: GetData_StoredRead_OnlyAllowedDataIsReturned
 * @tc.desc: Verify public behavior, failure propagation and observable state.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfServiceAuthEntryTest, GetData_StoredRead_OnlyAllowedDataIsReturned, TestSize.Level1)
{
    EXPECT_CALL(*store_, Delete(_)).Times(0);
    int index = 0;
    for (auto expected : { UDMF::E_OK, UDMF::E_NO_PERMISSION }) {
        const std::string key = "udmf://drag/com.test.auth/stored" + std::to_string(index++);
        EXPECT_CALL(*store_, Get(key, _)).WillOnce([&](const auto &, UnifiedData &data) {
            data = Payload(expected == UDMF::E_OK ? 100 * 1024 : 8);
            Privilege privilege;
            privilege.tokenId = receiverTokenId;
            privilege.readPermission = "readAndKeep";
            data.GetRuntime()->privileges = { privilege };
            return UDMF::E_OK;
        });
        guard_.result_ = expected == UDMF::E_NO_PERMISSION ? SecurityGuardDelegate::Strategy::DENY
                                                           : SecurityGuardDelegate::Strategy::ALLOW;
        auto requestsBefore = guard_.requests_;
        UdmfServiceImpl service;
        UnifiedData output;
        EXPECT_EQ(service.GetData(Query(key), output), expected);
        EXPECT_EQ(output.IsEmpty(), expected != UDMF::E_OK);
        EXPECT_EQ(guard_.requests_ - requestsBefore, 1);
        if (expected == UDMF::E_OK) {
            ASSERT_EQ(output.GetRecords().size(), 1u);
            EXPECT_EQ(std::get<std::string>(output.GetRecords()[0]->GetOriginValue()).size(), 100 * 1024u);
            EXPECT_LE(guard_.event_.jsonContent.size(), 10 * 1024u);
        }
        if (expected != UDMF::E_OK) {
            EXPECT_EQ(output.GetRuntime(), nullptr);
        }
    }
}
/**
 * @tc.name: GetData_VirtualMarker_ChecksSgBeforeVirtualSessionProcessing
 * @tc.desc: Preserve SG rejection and the upstream virtual-session error after an allowed decision.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfServiceAuthEntryTest, GetData_VirtualMarker_ChecksSgBeforeVirtualSessionProcessing, TestSize.Level1)
{
    EXPECT_CALL(*store_, Delete(_)).Times(0);
    int index = 0;
    for (auto expected : { UDMF::E_NO_PERMISSION, UDMF::E_FS_ERROR }) {
        const std::string key = "udmf://drag/com.test.auth/virtualauth" + std::to_string(index++);
        EXPECT_CALL(*store_, Get(key, _)).WillOnce([&](const auto &, UnifiedData &data) {
            data = Payload(8);
            auto details = std::make_shared<Object>();
            details->value_[VIRTUAL_ENTRY_FLAG] = true;
            auto file = std::make_shared<Object>();
            file->value_[UNIFORM_DATA_TYPE] = std::string(GENERAL_FILE_URI);
            file->value_[ORI_URI] = std::string("file:///virtual-auth.txt");
            file->value_[DETAILS] = details;
            auto record = std::make_shared<UnifiedRecord>(UDMF::FILE, file);
            record->SetUtdId2(GENERAL_FILE_URI);
            record->SetUid("virtual-auth-record");
            data.AddRecord(record);
            data.GetRuntime()->recordTotalNum = 2;
            Privilege privilege;
            privilege.tokenId = receiverTokenId;
            privilege.readPermission = "readAndKeep";
            data.GetRuntime()->privileges = { privilege };
            return UDMF::E_OK;
        });
        guard_.result_ = expected == UDMF::E_NO_PERMISSION ? SecurityGuardDelegate::Strategy::DENY
                                                         : SecurityGuardDelegate::Strategy::ALLOW;
        auto requestsBefore = guard_.requests_;
        UdmfServiceImpl service;
        UnifiedData output;
        EXPECT_EQ(service.GetData(Query(key), output), expected);
        EXPECT_EQ(guard_.requests_ - requestsBefore, 1);
        if (expected != UDMF::E_FS_ERROR) {
            EXPECT_TRUE(output.IsEmpty());
            EXPECT_EQ(output.GetRuntime(), nullptr);
        }
    }
}

/**
 * @tc.name: HandleRemoteDelayData_AsyncRead_PropagatesDecisionBeforeDelivery
 * @tc.desc: Async delivery reports authorization and storage outcomes to the receiver.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfServiceAuthEntryTest, HandleRemoteDelayData_AsyncRead_PropagatesDecisionBeforeDelivery, TestSize.Level1)
{
    EXPECT_CALL(*store_, Delete(_)).Times(0);
    int index = 0;
    for (auto expected : { UDMF::E_OK, UDMF::E_NO_PERMISSION, UDMF::E_ERROR }) {
        const std::string key = "udmf://drag/com.test.auth/remote" + std::to_string(index++);
        EXPECT_CALL(*store_, Get(key, _)).WillOnce([&](const auto &, UnifiedData &data) {
            if (expected == UDMF::E_ERROR) {
                return UDMF::E_ERROR;
            }
            data = Payload(expected == UDMF::E_OK ? 100 * 1024 : 8);
            Privilege privilege;
            privilege.tokenId = receiverTokenId;
            privilege.readPermission = "readAndKeep";
            data.GetRuntime()->privileges = { privilege };
            return UDMF::E_OK;
        });
        sptr<RecordingAuthDelivery> delivery = new RecordingAuthDelivery();
        DelayGetDataInfo info;
        info.tokenId = receiverTokenId;
        info.dataCallback = delivery->AsObject();
        DelayDataAcquireContainer::GetInstance().RegisterDelayDataCallback(key, info);
        guard_.result_ = expected == UDMF::E_NO_PERMISSION ? SecurityGuardDelegate::Strategy::DENY
                                                           : SecurityGuardDelegate::Strategy::ALLOW;
        UdmfServiceImpl service;
        auto requestsBefore = guard_.requests_;
        EXPECT_EQ(service.HandleRemoteDelayData(key), expected);
        EXPECT_EQ(guard_.requests_ - requestsBefore,
            expected == UDMF::E_OK || expected == UDMF::E_NO_PERMISSION ? 1 : 0);
        EXPECT_EQ(delivery->calls, expected == UDMF::E_ERROR ? 0 : 1);
        if (expected != UDMF::E_ERROR) {
            EXPECT_EQ(delivery->delivered.IsEmpty(), expected != UDMF::E_OK);
            EXPECT_FALSE(DelayDataAcquireContainer::GetInstance().QueryDelayGetDataInfo(key, info));
        } else {
            EXPECT_TRUE(DelayDataAcquireContainer::GetInstance().QueryDelayGetDataInfo(key, info));
            DelayDataAcquireContainer::GetInstance().HandleDelayDataCallback(key, UnifiedData());
        }
    }
}

/**
 * @tc.name: HandleRemoteDelayData_BlockedRead_PropagatesDecisionBeforeDelivery
 * @tc.desc: Blocked delivery reports authorization and storage outcomes to the receiver.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfServiceAuthEntryTest, HandleRemoteDelayData_BlockedRead_PropagatesDecisionBeforeDelivery, TestSize.Level1)
{
    EXPECT_CALL(*store_, Delete(_)).Times(0);
    int index = 0;
    for (auto expected : { UDMF::E_OK, UDMF::E_NO_PERMISSION, UDMF::E_ERROR }) {
        const std::string key = "udmf://drag/com.test.auth/remote" + std::to_string(index++);
        EXPECT_CALL(*store_, Get(key, _)).WillOnce([&](const auto &, UnifiedData &data) {
            if (expected == UDMF::E_ERROR) {
                return UDMF::E_ERROR;
            }
            data = Payload(expected == UDMF::E_OK ? 100 * 1024 : 8);
            Privilege privilege;
            privilege.tokenId = receiverTokenId;
            privilege.readPermission = "readAndKeep";
            data.GetRuntime()->privileges = { privilege };
            return UDMF::E_OK;
        });
        auto pending = Prepare(key);
        ASSERT_NE(pending.blockData, nullptr);
        guard_.result_ = expected == UDMF::E_NO_PERMISSION ? SecurityGuardDelegate::Strategy::DENY
                                                           : SecurityGuardDelegate::Strategy::ALLOW;
        UdmfServiceImpl service;
        auto requestsBefore = guard_.requests_;
        EXPECT_EQ(service.HandleRemoteDelayData(key), expected);
        EXPECT_EQ(guard_.requests_ - requestsBefore,
            expected == UDMF::E_OK || expected == UDMF::E_NO_PERMISSION ? 1 : 0);
        auto actual = pending.blockData->GetValue();
        if (expected == UDMF::E_ERROR) {
            EXPECT_FALSE(actual.has_value());
        } else {
            ASSERT_TRUE(actual.has_value());
            EXPECT_EQ(actual->status, expected);
            EXPECT_EQ(actual->prepared, expected == UDMF::E_OK);
            EXPECT_EQ(actual->data.IsEmpty(), expected != UDMF::E_OK);
        }
    }
}

/**
 * @tc.name: GetData_AccessDeniedBeforeBlocking_RetainsPendingWithoutDispatch
 * @tc.desc: Verify public behavior, failure propagation and observable state.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfServiceAuthEntryTest, GetData_AccessDeniedBeforeBlocking_RetainsPendingWithoutDispatch, TestSize.Level1)
{
    const std::string key = "udmf://drag/com.test.auth/accessdenied";
    auto pending = Prepare(key);
    ASSERT_NE(pending.blockData, nullptr);
    pending.blockData->SetValue(DelayDeliveryResult{ Payload(), UDMF::E_OK, false });
    EXPECT_CALL(GetAuthPermissionChecker(), IsValid(_, _)).WillOnce(Return(false));
    UdmfServiceImpl service;
    UnifiedData output;
    EXPECT_EQ(service.GetData(Query(key), output), UDMF::E_NO_PERMISSION);
    EXPECT_TRUE(output.IsEmpty());
    EXPECT_EQ(guard_.requests_, 0);
    EXPECT_FALSE(DelayDataPrepareContainer::GetInstance().QueryBlockDelayData(key, pending));
}
/**
 * @tc.name: PushDelayData_MissingAsyncCallback_ReturnsErrorAndConsumesRegistration
 * @tc.desc: Verify public behavior, failure propagation and observable state.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(
    UdmfServiceAuthEntryTest, PushDelayData_MissingAsyncCallback_ReturnsErrorAndConsumesRegistration, TestSize.Level1)
{
    const std::string key = "udmf://drag/com.test.auth/missingcallback";
    auto token = static_cast<uint32_t>(IPCSkeleton::GetCallingTokenID());
    ON_CALL(*tokens_, GetTokenTypeFlag(token)).WillByDefault(Return(TOKEN_NATIVE));
    EXPECT_CALL(*tokens_, GetNativeTokenInfo(token, _))
        .Times(AtLeast(2))
        .WillRepeatedly([](auto, NativeTokenInfo &info) {
            info.processName = "msdp";
            return 0;
        });
    DelayGetDataInfo info;
    info.tokenId = token;
    auto &acquire = DelayDataAcquireContainer::GetInstance();
    acquire.RegisterDelayDataCallback(key, info);
    UdmfServiceImpl service;
    auto payload = Payload();
    Summary summary;
    EXPECT_EQ(service.PushDelayData(key, payload, summary), UDMF::E_ERROR);
    EXPECT_EQ(guard_.requests_, 0);
    EXPECT_FALSE(acquire.QueryDelayGetDataInfo(key, info));
}
/**
 * @tc.name: GetData_ConsecutiveReads_SharesHealthAcrossTemporaryCoordinators
 * @tc.desc: Four separate public reads retain service-owned health and degrade only the fourth request.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfServiceAuthEntryTest, GetData_ConsecutiveReads_SharesHealthAcrossTemporaryCoordinators, TestSize.Level1)
{
    using Strategy = SecurityGuardDelegate::Strategy;
    guard_.snapshot_.initialized = true;
    guard_.snapshot_.version = 1;
    guard_.snapshot_.policies[0x0F810000] = { { Strategy::ALLOW, 400, "slow" } };
    guard_.clients_ = { { "slow", Strategy::TIMEOUT } };
    UdmfServiceImpl service;
    for (unsigned i = 0; i < 4; ++i) {
        const std::string key = "udmf://drag/com.test.auth/health-" + std::to_string(i);
        auto pending = Prepare(key);
        ASSERT_NE(pending.blockData, nullptr);
        pending.blockData->SetValue(DelayDeliveryResult{ Payload(), UDMF::E_OK, false });
        UnifiedData output;
        EXPECT_EQ(service.GetData(Query(key), output), UDMF::E_OK);
        EXPECT_EQ(output.GetRecords().size(), 1u);
        EXPECT_EQ(guard_.event_.degradedClients.size(), i == 3 ? 1u : 0u);
    }
    EXPECT_EQ(guard_.requests_, 4);
    EXPECT_EQ(guard_.event_.degradedClients, std::vector<std::string>({ "slow" }));
}

/**
 * @tc.name: OnSystemAbilityAdded_OnlyLocalSecurityGuard_StartsThroughExecutor
 * @tc.desc: Use the service's static acts and executor instead of starting SG during OnBind.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfServiceAuthEntryTest, OnSystemAbilityAdded_OnlyLocalSecurityGuard_StartsThroughExecutor, TestSize.Level1)
{
    auto [found, acts] = FeatureSystem::GetInstance().GetStaticActs().Find("udmf");
    ASSERT_TRUE(found);
    ASSERT_NE(acts, nullptr);
    auto pool = std::make_shared<ExecutorPool>(1, 0);
    acts->OnSystemAbilityRemoved(DATA_COLLECT_MANAGER_SA_ID, "");
    UdmfServiceImpl service;
    FeatureSystem::Feature::BindInfo bind;
    bind.executors = pool;
    service.OnBind(bind);
    acts->SetThreadPool(pool);
    EXPECT_EQ(acts->OnSystemAbilityAdded(COMMON_EVENT_SERVICE_ID, ""), UDMF::E_OK);
    EXPECT_EQ(acts->OnSystemAbilityAdded(DATA_COLLECT_MANAGER_SA_ID, "remote-device"), UDMF::E_OK);
    EXPECT_EQ(guard_.starts_, 0);
    EXPECT_EQ(acts->OnSystemAbilityAdded(DATA_COLLECT_MANAGER_SA_ID, ""), UDMF::E_OK);
    auto drained = std::make_shared<std::promise<void>>();
    auto finished = drained->get_future();
    acts->Execute([drained] { drained->set_value(); });
    auto status = finished.wait_for(std::chrono::seconds(3));
    acts->OnSystemAbilityRemoved(DATA_COLLECT_MANAGER_SA_ID, "");
    bind.executors = nullptr;
    service.OnBind(bind);
    acts->SetThreadPool(nullptr);
    pool.reset();
    ASSERT_EQ(status, std::future_status::ready);
    EXPECT_EQ(guard_.starts_, 1);
    EXPECT_EQ(guard_.requests_, 0);
}
/**
 * @tc.name: OnSystemAbilityAdded_FailedRegistration_IsRetriedOnNextReadyEvent
 * @tc.desc: Each local readiness event can retry an unavailable provider without disrupting feature binding.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfServiceAuthEntryTest, OnSystemAbilityAdded_FailedRegistration_IsRetriedOnNextReadyEvent, TestSize.Level1)
{
    auto [found, acts] = FeatureSystem::GetInstance().GetStaticActs().Find("udmf");
    ASSERT_TRUE(found);
    ASSERT_NE(acts, nullptr);
    auto pool = std::make_shared<ExecutorPool>(1, 0);
    acts->OnSystemAbilityRemoved(DATA_COLLECT_MANAGER_SA_ID, "");
    UdmfServiceImpl service;
    FeatureSystem::Feature::BindInfo bind;
    bind.executors = pool;
    service.OnBind(bind);
    acts->SetThreadPool(pool);
    for (auto result : { SecurityGuardDelegate::Status::UNAVAILABLE, SecurityGuardDelegate::Status::READY }) {
        guard_.start_ = result;
        EXPECT_EQ(acts->OnSystemAbilityAdded(DATA_COLLECT_MANAGER_SA_ID, ""), UDMF::E_OK);
        auto drained = std::make_shared<std::promise<void>>();
        auto finished = drained->get_future();
        acts->Execute([drained] { drained->set_value(); });
        EXPECT_EQ(finished.wait_for(std::chrono::seconds(3)), std::future_status::ready);
    }
    acts->OnSystemAbilityRemoved(DATA_COLLECT_MANAGER_SA_ID, "");
    bind.executors = nullptr;
    service.OnBind(bind);
    acts->SetThreadPool(nullptr);
    pool.reset();
    EXPECT_EQ(guard_.starts_, 2);
    EXPECT_EQ(guard_.requests_, 0);
}
/**
 * @tc.name: OnSystemAbilityAdded_MissingGuard_CompletesQueuedNotificationSafely
 * @tc.desc: No registered backend must not crash the service readiness worker.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(
    UdmfServiceAuthEntryTest, OnSystemAbilityAdded_MissingGuard_CompletesQueuedNotificationSafely, TestSize.Level1)
{
    auto [found, acts] = FeatureSystem::GetInstance().GetStaticActs().Find("udmf");
    ASSERT_TRUE(found);
    ASSERT_NE(acts, nullptr);
    auto pool = std::make_shared<ExecutorPool>(1, 0);
    acts->OnSystemAbilityRemoved(DATA_COLLECT_MANAGER_SA_ID, "");
    UdmfServiceImpl service;
    FeatureSystem::Feature::BindInfo bind;
    bind.executors = pool;
    service.OnBind(bind);
    acts->SetThreadPool(pool);
    SecurityGuardTestRegistry::instance = nullptr;
    EXPECT_EQ(acts->OnSystemAbilityAdded(DATA_COLLECT_MANAGER_SA_ID, ""), UDMF::E_OK);
    auto drained = std::make_shared<std::promise<void>>();
    auto finished = drained->get_future();
    acts->Execute([drained] { drained->set_value(); });
    auto status = finished.wait_for(std::chrono::seconds(3));
    acts->OnSystemAbilityRemoved(DATA_COLLECT_MANAGER_SA_ID, "");
    bind.executors = nullptr;
    service.OnBind(bind);
    acts->SetThreadPool(nullptr);
    pool.reset();
    EXPECT_EQ(status, std::future_status::ready);
    EXPECT_EQ(guard_.starts_, 0);
}


} // namespace DistributedDataTest

namespace DistributedDataTest {
/**
 * @tc.name: OnSystemAbilityAdded_BeforeBind_ReplaysAfterExecutorBinding
 * @tc.desc: A ready notification received while UDMF is being loaded must not be lost.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfServiceAuthEntryTest, OnSystemAbilityAdded_BeforeBind_ReplaysAfterExecutorBinding, TestSize.Level1)
{
    auto [found, acts] = FeatureSystem::GetInstance().GetStaticActs().Find("udmf");
    ASSERT_TRUE(found);
    UdmfServiceImpl service;
    FeatureSystem::Feature::BindInfo bind;
    service.OnBind(bind);
    acts->OnSystemAbilityRemoved(DATA_COLLECT_MANAGER_SA_ID, "");
    EXPECT_EQ(acts->OnSystemAbilityAdded(DATA_COLLECT_MANAGER_SA_ID, ""), UDMF::E_OK);
    EXPECT_EQ(guard_.starts_, 0);
    bind.executors = std::make_shared<ExecutorPool>(1, 0);
    service.OnBind(bind);
    auto drained = std::make_shared<std::promise<void>>();
    auto done = drained->get_future();
    bind.executors->Execute([drained] { drained->set_value(); });
    EXPECT_EQ(done.wait_for(std::chrono::seconds(3)), std::future_status::ready);
    EXPECT_EQ(guard_.starts_, 1);
    acts->OnSystemAbilityRemoved(DATA_COLLECT_MANAGER_SA_ID, "");
    bind.executors = nullptr;
    service.OnBind(bind);
}

/**
 * @tc.name: GetData_InvalidUtf8_RejectsWithoutSdkOrRetainedPayload
 * @tc.desc: Malformed UTF-8 from the record is never delivered or silently replaced in the event.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfServiceAuthEntryTest, GetData_InvalidUtf8_RejectsWithoutSdkOrRetainedPayload, TestSize.Level1)
{
    const std::string key = "udmf://drag/com.test.auth/invalid-utf8";
    auto pending = Prepare(key);
    auto payload = Payload();
    payload.GetRecords()[0]->SetValue(std::string(1, static_cast<char>(0xff)));
    pending.blockData->SetValue(DelayDeliveryResult{ payload, UDMF::E_OK, false });
    UdmfServiceImpl service;
    UnifiedData output;
    EXPECT_EQ(service.GetData(Query(key), output), UDMF::E_INVALID_PARAMETERS);
    EXPECT_TRUE(output.IsEmpty());
    EXPECT_EQ(guard_.requests_, 0);
    EXPECT_FALSE(DelayDataPrepareContainer::GetInstance().QueryBlockDelayData(key, pending));
}

} // namespace DistributedDataTest

namespace DistributedDataTest {
/**
 * @tc.name: DragTimeout_RemovesOriginAndReceiverCacheAfterStoreDeletion
 * @tc.desc: Existing drag expiry also releases callback registrations and complete in-process payloads.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfServiceAuthEntryTest, DragTimeout_RemovesOriginAndReceiverCacheAfterStoreDeletion, TestSize.Level1)
{
    UnifiedKey key("drag", "com.test.auth", "01234567890123456789012345678901");
    const auto unifiedKey = key.GetUnifiedKey();
    auto pending = Prepare(unifiedKey);
    ASSERT_TRUE(
        DelayDataPrepareContainer::GetInstance().StoreDelivery(unifiedKey, pending, { Payload(), UDMF::E_OK, false }));
    Runtime runtime;
    runtime.key = key;
    runtime.tokenId = sourceTokenId;
    runtime.createTime = 0;
    EXPECT_CALL(*store_, GetBatchRuntime(_, _)).WillOnce([&](auto &, auto &runtimes) {
        runtimes.push_back(runtime);
        return UDMF::E_OK;
    });
    EXPECT_CALL(*store_, DeleteBatch(_)).WillOnce(Return(UDMF::E_OK));
    EXPECT_EQ(DragLifeCyclePolicy().OnTimeout("drag"), UDMF::E_OK);
    EXPECT_FALSE(DelayDataPrepareContainer::GetInstance().QueryBlockDelayData(unifiedKey, pending));
    EXPECT_FALSE(DelayDataPrepareContainer::GetInstance().ExecDataLoadCallback(unifiedKey, DataLoadInfo()));
}
} // namespace DistributedDataTest

} // namespace OHOS::Test
