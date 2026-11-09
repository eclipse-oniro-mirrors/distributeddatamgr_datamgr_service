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
namespace {
class FuseReadProvider final : public IRemoteStub<IVirtualEntryProvider> {
public:
    bool AddDeathRecipient(const sptr<DeathRecipient> &recipient) override
    {
        return recipient != nullptr;
    }

    bool RemoveDeathRecipient(const sptr<DeathRecipient> &recipient) override
    {
        return recipient != nullptr;
    }

    struct PendingRead {
        std::string id;
        int64_t offset = 0;
        int32_t length = 0;
        sptr<IRemoteObject> callback;
    };

    explicit FuseReadProvider(std::vector<uint8_t> content, size_t maxReadBytes = std::numeric_limits<size_t>::max())
        : content_(std::move(content)), maxReadBytes_(maxReadBytes)
    {
    }

    int32_t Stat(const std::string &id, VirtualEntry &entry) override
    {
        entry.id = id;
        entry.type = VirtualEntryType::FILE;
        entry.size = static_cast<int64_t>(content_.size());
        return 0;
    }

    int32_t Read(const std::string &id, int64_t offset, int32_t length, std::vector<uint8_t> &data) override
    {
        (void)id;
        offsets_.push_back(offset);
        lengths_.push_back(length);
        ++readCount_;
        if (!statuses_.empty()) {
            int32_t status = statuses_.front();
            statuses_.erase(statuses_.begin());
            if (status != 0) {
                return status;
            }
        }
        if (offset < 0 || length < 0 || static_cast<size_t>(offset) >= content_.size()) {
            data.clear();
            return 0;
        }
        size_t available = content_.size() - static_cast<size_t>(offset);
        size_t readSize = std::min({ static_cast<size_t>(length), available, maxReadBytes_ });
        auto begin = content_.begin() + offset;
        data.assign(begin, begin + readSize);
        return 0;
    }

    int32_t Cancel(const std::vector<std::string> &ids) override
    {
        (void)ids;
        return 0;
    }

    int32_t OnRemoteRequest(uint32_t code, MessageParcel &request, MessageParcel &reply, MessageOption &option) override
    {
        if (request.ReadInterfaceToken() != GetDescriptor()) {
            return -EACCES;
        }
        if (code != static_cast<uint32_t>(VirtualEntryProviderCode::READ_ASYNC)) {
            return IRemoteStub<IVirtualEntryProvider>::OnRemoteRequest(code, request, reply, option);
        }
        std::string id;
        int64_t offset = 0;
        int32_t length = 0;
        sptr<IRemoteObject> callback;
        if (!request.ReadString(id) || !request.ReadInt64(offset) || !request.ReadInt32(length) ||
            (callback = request.ReadRemoteObject()) == nullptr) {
            return -EINVAL;
        }
        bool holdCallback = false;
        {
            std::lock_guard<std::mutex> lock(asyncMutex_);
            ++asyncRequestCount_;
            holdCallback = holdCallbacks_;
            if (holdCallback) {
                pendingReads_.push_back({ id, offset, length, callback });
            }
        }
        asyncCondition_.notify_all();
        if (suppressCallback_ || holdCallback) {
            return 0;
        }
        std::vector<uint8_t> data;
        int32_t ret = Read(id, offset, length, data);
        VirtualEntryReadCallbackProxy callbackProxy(callback);
        return callbackProxy.OnResult(ret, data);
    }

    bool CompleteNextRead()
    {
        PendingRead pending;
        {
            std::lock_guard<std::mutex> lock(asyncMutex_);
            if (pendingReads_.empty()) {
                return false;
            }
            pending = std::move(pendingReads_.front());
            pendingReads_.erase(pendingReads_.begin());
        }
        std::vector<uint8_t> data;
        int32_t ret = Read(pending.id, pending.offset, pending.length, data);
        VirtualEntryReadCallbackProxy callbackProxy(pending.callback);
        return callbackProxy.OnResult(ret, data) == 0;
    }

    std::vector<int32_t> statuses_;
    std::vector<int64_t> offsets_;
    std::vector<int32_t> lengths_;
    int32_t readCount_ = 0;
    bool suppressCallback_ = false;
    bool holdCallbacks_ = false;
    size_t asyncRequestCount_ = 0;
    std::vector<PendingRead> pendingReads_;
    std::mutex asyncMutex_;
    std::condition_variable asyncCondition_;

private:
    const std::vector<uint8_t> content_;
    const size_t maxReadBytes_;
};

bool WaitForAsyncRequests(const sptr<FuseReadProvider> &provider, size_t count,
    const std::chrono::steady_clock::time_point &deadline)
{
    std::unique_lock<std::mutex> lock(provider->asyncMutex_);
    return provider->asyncCondition_.wait_until(
        lock, deadline, [&provider, count] { return provider->asyncRequestCount_ == count; });
}
} // namespace

class UdmfServiceImplMockTest : public testing::Test {
public:
    void SetUp();
    void TearDown();
    static void SetUpTestCase(void)
    {
    }
    static void TearDownTestCase(void){};
    static inline std::shared_ptr<MetaDataManagerMock> metaDataManagerMock = nullptr;
    static inline std::shared_ptr<MetaDataMock<StoreMetaData>> metaDataMock = nullptr;
};

void UdmfServiceImplMockTest::SetUp()
{
    metaDataManagerMock = std::make_shared<MetaDataManagerMock>();
    BMetaDataManager::metaDataManager = metaDataManagerMock;
    metaDataMock = std::make_shared<MetaDataMock<StoreMetaData>>();
    BMetaData<StoreMetaData>::metaDataManager = metaDataMock;
}

void UdmfServiceImplMockTest::TearDown()
{
    metaDataManagerMock = nullptr;
    BMetaDataManager::metaDataManager = nullptr;
    metaDataMock = nullptr;
    BMetaData<StoreMetaData>::metaDataManager = nullptr;
}

/**
* @tc.name: IsNeedMetaSyncTest001
* @tc.desc: IsNeedMetaSync test
* @tc.type: FUNC
*/
HWTEST_F(UdmfServiceImplMockTest, IsNeedMetaSyncTest001, TestSize.Level0)
{
    UdmfServiceImpl udmfServiceImpl;
    StoreMetaData meta = StoreMetaData("100", "distributeddata", "drag");
    std::vector<std::string> devices = { "remote_device" };

    EXPECT_CALL(*metaDataManagerMock, LoadMeta(testing::_, testing::_, testing::_)).WillOnce(testing::Return(false));
    auto isNeedSync = udmfServiceImpl.IsNeedMetaSync(meta, devices);
    EXPECT_TRUE(isNeedSync);

    EXPECT_CALL(*metaDataManagerMock, LoadMeta(testing::_, testing::_, testing::_))
        .WillOnce(testing::Return(true))
        .WillOnce(testing::Return(false));
    isNeedSync = udmfServiceImpl.IsNeedMetaSync(meta, devices);
    EXPECT_TRUE(isNeedSync);

    EXPECT_CALL(*metaDataManagerMock, LoadMeta(testing::_, testing::_, testing::_))
        .WillOnce(testing::Return(true))
        .WillOnce(testing::Return(true));
    isNeedSync = udmfServiceImpl.IsNeedMetaSync(meta, devices);
    EXPECT_FALSE(isNeedSync);
}

/**
* @tc.name: IsNeedMetaSyncTest002
* @tc.desc: IsNeedMetaSync test matrix mask
* @tc.type: FUNC
*/
HWTEST_F(UdmfServiceImplMockTest, IsNeedMetaSyncTest002, TestSize.Level0)
{
    QueryOption query;
    query.key = "test_key";
    query.tokenId = 1;
    query.intention = UD_INTENTION_DRAG;
    UdmfServiceImpl udmfServiceImpl;
    StoreMetaData meta = StoreMetaData("100", "distributeddata", "drag");
    std::vector<std::string> devices = { "remote_device" };

    EXPECT_CALL(*metaDataManagerMock, LoadMeta(testing::_, testing::_, testing::_)).WillOnce(testing::Return(false));
    auto isNeedSync = udmfServiceImpl.IsNeedMetaSync(meta, devices);
    EXPECT_TRUE(isNeedSync);
    // mock mask
}

/**
 * @tc.name: ResolveAutoLaunchTest001
 * @tc.desc: ResolveAutoLaunch test.
 * @tc.type: FUNC
 */
HWTEST_F(UdmfServiceImplMockTest, ResolveAutoLaunchTest001, TestSize.Level0)
{
    DistributedDB::AutoLaunchParam param{
        .userId = "100",
        .appId = "distributeddata",
        .storeId = "drag",
    };
    std::string identifier = "identifier";
    std::shared_ptr<UdmfServiceImpl> udmfServiceImpl = std::make_shared<UdmfServiceImpl>();
    EXPECT_CALL(*metaDataMock, LoadMeta(testing::_, testing::_, testing::_)).WillOnce(testing::Return(false));
    auto ret = udmfServiceImpl->ResolveAutoLaunch(identifier, param);
    EXPECT_EQ(ret, UDMF::E_NOT_FOUND);
}

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
    void SetUp() override
    {
        tokens_ = std::make_shared<NiceMock<AccessTokenKitMock>>();
        BAccessTokenKit::accessTokenkit = tokens_;
        ON_CALL(*tokens_, GetTokenTypeFlag(_)).WillByDefault(Return(TOKEN_HAP));
        ON_CALL(*tokens_, GetHapTokenInfo(_, _)).WillByDefault([](auto, HapTokenInfo &info) {
            info.bundleName = "com.test.auth";
            info.instIndex = 0;
            info.userID = 100;
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
    BlockDelayData Prepare(const std::string &key, uint32_t token = 19)
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
        runtime.tokenId = 17;
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
        query.tokenId = 19;
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
            info.processName = ++nativeLookups_ == 2 ? "replaced" : "msdp";
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
    EXPECT_EQ(json["sourceTokenId"], 17);
    EXPECT_EQ(json["targetTokenId"], 19);
    EXPECT_FALSE(json["content"]["entries"].empty());
    EXPECT_FALSE(DelayDataPrepareContainer::GetInstance().QueryBlockDelayData(key, pending));
}
/**
 * @tc.name: GetData_CachedOversize_ReturnsInvalidParametersWithoutDispatchOrConsume
 * @tc.desc: Verify public behavior, failure propagation and observable state.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(
    UdmfServiceAuthEntryTest, GetData_CachedOversize_ReturnsInvalidParametersWithoutDispatchOrConsume, TestSize.Level1)
{
    const std::string key = "udmf://drag/com.test.auth/read-oversize";
    auto pending = Prepare(key);
    ASSERT_NE(pending.blockData, nullptr);
    pending.blockData->SetValue(DelayDeliveryResult{ Payload(10241), UDMF::E_OK, false });
    UdmfServiceImpl service;
    UnifiedData output;
    EXPECT_EQ(service.GetData(Query(key), output), UDMF::E_INVALID_PARAMETERS);
    EXPECT_TRUE(output.IsEmpty());
    EXPECT_EQ(output.GetRuntime(), nullptr);
    EXPECT_EQ(guard_.requests_, 0);
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
    const std::vector<Scenario> cases = { { "local-auth-device", 19, "com.test.auth", true },
        { "remote-auth-device", 19, "com.test.auth", false }, { "local-auth-device", 17, "com.test.auth", false },
        { "local-auth-device", 19, "com.test.replaced", false }, { "", 19, "com.test.auth", false } };
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
    EXPECT_CALL(*tokens_, GetHapTokenInfo(19, _))
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
 * @tc.name: PushDelayData_AsyncDeniedAndOversize_ReloadsThenDeliversAfterAllow
 * @tc.desc: Public read, source push and completion retain retryable origin until accepted delivery.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfServiceAuthEntryTest, PushDelayData_AsyncDeniedAndOversize_ReloadsThenDeliversAfterAllow, TestSize.Level1)
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
    for (auto expected : { UDMF::E_NO_PERMISSION, UDMF::E_INVALID_PARAMETERS, UDMF::E_OK }) {
        sptr<RecordingAuthDelivery> receiver = new RecordingAuthDelivery();
        auto output = std::make_shared<UnifiedData>();
        EXPECT_EQ(service.GetDataIfAvailable(key, DataLoadInfo(), receiver->AsObject(), output), UDMF::E_OK);
        EXPECT_EQ(origin->calls, ++attempts);
        guard_.result_ = expected == UDMF::E_NO_PERMISSION ? SecurityGuardDelegate::Strategy::DENY
                                                           : SecurityGuardDelegate::Strategy::ALLOW;
        EXPECT_EQ(PushAuthPayload(service, key, expected == UDMF::E_INVALID_PARAMETERS ? 10241 : 8), expected);
        EXPECT_EQ(receiver->calls, 1);
        EXPECT_EQ(receiver->delivered.IsEmpty(), expected != UDMF::E_OK);
        EXPECT_EQ(prepare.QueryDataLoadCallbackSize(), expected == UDMF::E_OK ? 0 : 1);
    }
    EXPECT_EQ(guard_.requests_, 2);
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
    keys_.push_back({ key, 19 });
    EXPECT_CALL(*store_, Get(key, _)).WillRepeatedly([&](const auto &, UnifiedData &output) {
        output = Payload();
        output.GetRuntime()->privileges = { { 19, "readAndKeep", "" } };
        return UDMF::E_OK;
    });
    EXPECT_CALL(*store_, Delete(_)).Times(0);
    sptr<RecordingAuthDelivery> first = new RecordingAuthDelivery();
    sptr<RecordingAuthDelivery> next = new RecordingAuthDelivery();
    DelayGetDataInfo info{ .tokenId = 19, .dataCallback = first->AsObject() };
    auto &acquire = DelayDataAcquireContainer::GetInstance();
    ASSERT_TRUE(acquire.RegisterDelayDataCallback(key, info));
    guard_.result_ = SecurityGuardDelegate::Strategy::ALLOW;
    guard_.beforeComplete_ = [&] {
        info.dataCallback = next->AsObject();
        acquire.RegisterDelayDataCallback(key, info);
    };
    UdmfServiceImpl service;
    EXPECT_CALL(*tokens_, GetHapTokenInfo(19, _)).Times(0);
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
    keys_.push_back({ key, 19 });
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
    DelayGetDataInfo info{ .tokenId = 19, .dataCallback = receiver->AsObject() };
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
    ASSERT_TRUE(DelayDataPrepareContainer::GetInstance().RegisterDataLoadCallback(key, origin, 17));
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
    ASSERT_TRUE(prepare.RegisterDataLoadCallback(key, origin, 17));
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
        registered = prepare.RegisterDataLoadCallback(key, next, 17, &replacement);
        return UDMF::E_DB_ERROR;
    });
    UdmfServiceImpl service;
    DataLoadInfo info;
    info.sequenceKey = "rollback_replaced";
    info.recordCount = 1;
    EXPECT_EQ(service.SetDelayInfo(info, first->AsObject(), key), UDMF::E_DB_ERROR);
    keys_.push_back({ key, 17 });
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
    for (auto expected : { UDMF::E_OK, UDMF::E_NO_PERMISSION, UDMF::E_INVALID_PARAMETERS }) {
        const std::string key = "udmf://drag/com.test.auth/stored" + std::to_string(index++);
        EXPECT_CALL(*store_, Get(key, _)).WillOnce([&](const auto &, UnifiedData &data) {
            data = Payload(expected == UDMF::E_INVALID_PARAMETERS ? 10241 : 8);
            Privilege privilege;
            privilege.tokenId = 19;
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
        EXPECT_EQ(guard_.requests_ - requestsBefore, expected == UDMF::E_INVALID_PARAMETERS ? 0 : 1);
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
    for (auto expected : { UDMF::E_NO_PERMISSION, UDMF::E_INVALID_PARAMETERS, UDMF::E_FS_ERROR }) {
        const std::string key = "udmf://drag/com.test.auth/virtualauth" + std::to_string(index++);
        EXPECT_CALL(*store_, Get(key, _)).WillOnce([&](const auto &, UnifiedData &data) {
            data = Payload(expected == UDMF::E_INVALID_PARAMETERS ? 10241 : 8);
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
            privilege.tokenId = 19;
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
        EXPECT_EQ(guard_.requests_ - requestsBefore, expected == UDMF::E_INVALID_PARAMETERS ? 0 : 1);
        if (expected != UDMF::E_FS_ERROR) {
            EXPECT_TRUE(output.IsEmpty());
            EXPECT_EQ(output.GetRuntime(), nullptr);
        }
    }
}

/**
 * @tc.name: HandleRemoteDelayData_AsyncAndBlockedReads_PropagateDecisionBeforeDelivery
 * @tc.desc: Verify public behavior, failure propagation and observable state.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfServiceAuthEntryTest, HandleRemoteDelayData_AsyncAndBlockedReads_PropagateDecisionBeforeDelivery,
    TestSize.Level1)
{
    EXPECT_CALL(*store_, Delete(_)).Times(0);
    int index = 0;
    for (bool asynchronous : { false, true }) {
        for (auto expected : { UDMF::E_OK, UDMF::E_NO_PERMISSION, UDMF::E_INVALID_PARAMETERS, UDMF::E_ERROR }) {
            const std::string key = "udmf://drag/com.test.auth/remote" + std::to_string(index++);
            EXPECT_CALL(*store_, Get(key, _)).WillOnce([&](const auto &, UnifiedData &data) {
                if (expected == UDMF::E_ERROR) {
                    return UDMF::E_ERROR;
                }
                data = Payload(expected == UDMF::E_INVALID_PARAMETERS ? 10241 : 8);
                Privilege privilege;
                privilege.tokenId = 19;
                privilege.readPermission = "readAndKeep";
                data.GetRuntime()->privileges = { privilege };
                return UDMF::E_OK;
            });
            sptr<RecordingAuthDelivery> delivery = new RecordingAuthDelivery();
            DelayGetDataInfo info;
            BlockDelayData pending;
            if (asynchronous) {
                info.tokenId = 19;
                info.dataCallback = delivery->AsObject();
                DelayDataAcquireContainer::GetInstance().RegisterDelayDataCallback(key, info);
            } else {
                pending = Prepare(key);
                ASSERT_NE(pending.blockData, nullptr);
            }
            guard_.result_ = expected == UDMF::E_NO_PERMISSION ? SecurityGuardDelegate::Strategy::DENY
                                                               : SecurityGuardDelegate::Strategy::ALLOW;
            UdmfServiceImpl service;
            auto requestsBefore = guard_.requests_;
            EXPECT_EQ(service.HandleRemoteDelayData(key), expected);
            EXPECT_EQ(guard_.requests_ - requestsBefore,
                expected == UDMF::E_OK || expected == UDMF::E_NO_PERMISSION ? 1 : 0);
            if (asynchronous) {
                EXPECT_EQ(delivery->calls, expected == UDMF::E_ERROR ? 0 : 1);
                if (expected != UDMF::E_ERROR) {
                    EXPECT_EQ(delivery->delivered.IsEmpty(), expected != UDMF::E_OK);
                    EXPECT_FALSE(DelayDataAcquireContainer::GetInstance().QueryDelayGetDataInfo(key, info));
                } else {
                    EXPECT_TRUE(DelayDataAcquireContainer::GetInstance().QueryDelayGetDataInfo(key, info));
                    DelayDataAcquireContainer::GetInstance().HandleDelayDataCallback(key, UnifiedData());
                }
            } else {
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
 * @tc.desc: Use DDMS static acts and its executor instead of starting SG during OnBind.
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
 * @tc.desc: No registered backend must not crash the DDMS SA readiness worker.
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


/**
 * @tc.name: GetUdmfFuseMountPoint_SeparatedPaths_ReturnExpectedPath
 * @tc.desc: Verify the service mount point is mapped to the application sandbox path.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfServiceImplMockTest, GetUdmfFuseMountPoint_SeparatedPaths_ReturnExpectedPath, TestSize.Level0)
{
    EXPECT_EQ(UdmfFuseSessionManager::GetMountPoint(100), "/mnt/data/100/udmf_fuse/files");
    EXPECT_EQ(UdmfFuseSessionManager::GetAppMountPoint(100), "/data/storage/el2/udmf/files");
}

/**
 * @tc.name: IsValidVirtualEntry_InvalidTree_ReturnFalse
 * @tc.desc: Verify invalid file metadata and duplicate directory entries are rejected before registration.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfServiceImplMockTest, IsValidVirtualEntry_InvalidTree_ReturnFalse, TestSize.Level0)
{
    VirtualEntry invalidFile;
    invalidFile.id = "file-id";
    invalidFile.name = "../file.txt";
    invalidFile.type = VirtualEntryType::FILE;
    invalidFile.size = 1;
    EXPECT_FALSE(UdmfFuseSessionManager::IsValid(invalidFile));

    VirtualEntry child = invalidFile;
    child.name = "file.txt";
    VirtualEntry root;
    root.name = "root";
    root.type = VirtualEntryType::DIRECTORY;
    root.subItems = { child, child };
    EXPECT_FALSE(UdmfFuseSessionManager::IsValid(root));
}

/**
 * @tc.name: GetFuseSession_MissingSession_ReturnStale
 * @tc.desc: Verify a missing virtual session cannot be opened or treated as a valid fallback file.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfServiceImplMockTest, GetFuseSession_MissingSession_ReturnStale, TestSize.Level0)
{
    auto &manager = UdmfFuseSessionManager::GetInstance();
    UdmfFuseSessionManager::SessionInfo session;
    const std::string sessionId = "missing-virtual-session";

    EXPECT_FALSE(manager.Get(sessionId, session));
    EXPECT_EQ(manager.AcquireOpen(sessionId, 1000), -ESTALE);
}

/**
 * @tc.name: RegisterFuseSession_SourcePendingQuotaExceeded_ReturnTryAgain
 * @tc.desc: Verify one source cannot retain more than four pending virtual-file sessions.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfServiceImplMockTest, RegisterFuseSession_SourcePendingQuotaExceeded_ReturnTryAgain, TestSize.Level0)
{
    constexpr uint32_t sourceTokenId = 1001;
    constexpr size_t pendingLimit = 4;
    sptr<FuseReadProvider> provider = new FuseReadProvider({ 1 });
    auto &manager = UdmfFuseSessionManager::GetInstance();
    UdmfFuseSessionManager::SessionInfo session;
    session.userId = 100;
    session.sourceTokenId = sourceTokenId;
    session.provider = provider->AsObject();
    session.root.id = "pending-file";
    session.root.name = "pending-file.bin";
    session.root.type = VirtualEntryType::FILE;
    session.root.size = 1;
    std::vector<std::string> sessionIds;
    for (size_t index = 0; index < pendingLimit; ++index) {
        session.generation = index + 1;
        sessionIds.push_back("pending-quota-session-" + std::to_string(index));
        ASSERT_EQ(manager.Register(sessionIds.back(), session), 0);
    }
    session.generation = pendingLimit + 1;

    EXPECT_EQ(manager.Register("pending-quota-overflow", session), -EAGAIN);

    for (const auto &sessionId : sessionIds) {
        manager.Remove(sessionId);
    }
    std::lock_guard<std::mutex> lock(manager.mutex_);
    EXPECT_EQ(manager.pendingSessionCount_, 0u);
    EXPECT_EQ(manager.pendingSourceSessionCounts_.count(sourceTokenId), 0u);
}

/**
 * @tc.name: RegisterFuseSession_GlobalPendingQuotaExceeded_ReturnTryAgain
 * @tc.desc: Verify pending virtual-file sessions are limited globally across source applications.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfServiceImplMockTest, RegisterFuseSession_GlobalPendingQuotaExceeded_ReturnTryAgain, TestSize.Level0)
{
    constexpr size_t pendingLimit = 8;
    sptr<FuseReadProvider> provider = new FuseReadProvider({ 1 });
    auto &manager = UdmfFuseSessionManager::GetInstance();
    UdmfFuseSessionManager::SessionInfo session;
    session.userId = 100;
    session.provider = provider->AsObject();
    session.root.id = "global-pending-file";
    session.root.name = "global-pending-file.bin";
    session.root.type = VirtualEntryType::FILE;
    session.root.size = 1;
    std::vector<std::string> sessionIds;
    for (size_t index = 0; index < pendingLimit; ++index) {
        session.sourceTokenId = 2000 + static_cast<uint32_t>(index / 2);
        session.generation = index + 1;
        sessionIds.push_back("global-pending-quota-session-" + std::to_string(index));
        ASSERT_EQ(manager.Register(sessionIds.back(), session), 0);
    }
    session.sourceTokenId = 3000;
    session.generation = pendingLimit + 1;

    EXPECT_EQ(manager.Register("global-pending-quota-overflow", session), -EAGAIN);

    for (const auto &sessionId : sessionIds) {
        manager.Remove(sessionId);
    }
    std::lock_guard<std::mutex> lock(manager.mutex_);
    EXPECT_EQ(manager.pendingSessionCount_, 0u);
    EXPECT_TRUE(manager.pendingSourceSessionCounts_.empty());
}

/**
 * @tc.name: ActivateFuseSession_GlobalActiveQuotaExceeded_ReturnTryAgain
 * @tc.desc: Verify a fourth active drag is rejected before allocating a FUSE mount.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfServiceImplMockTest, ActivateFuseSession_GlobalActiveQuotaExceeded_ReturnTryAgain, TestSize.Level0)
{
    auto &manager = UdmfFuseSessionManager::GetInstance();
    std::vector<std::string> activeIds;
    const std::string pendingId = "global-active-quota-pending";
    {
        std::lock_guard<std::mutex> lock(manager.mutex_);
        for (uint32_t index = 0; index < 3; ++index) {
            UdmfFuseSessionManager::SessionInfo active;
            active.userId = static_cast<int32_t>(100 + index);
            active.sourceTokenId = 2000 + index;
            active.state = UdmfFuseSessionManager::State::ACTIVE;
            std::string sessionId = "global-active-quota-" + std::to_string(index);
            activeIds.push_back(sessionId);
            manager.sessions_.emplace(sessionId, active);
            ++manager.activeSessionCount_;
            ++manager.activeSourceSessionCounts_[active.sourceTokenId];
            ++manager.activeSessionCounts_[active.userId];
        }
        UdmfFuseSessionManager::SessionInfo pending;
        pending.userId = 100;
        pending.sourceTokenId = 3000;
        manager.sessions_.emplace(pendingId, pending);
        ++manager.pendingSessionCount_;
        ++manager.pendingSourceSessionCounts_[pending.sourceTokenId];
    }
    std::string uri;

    EXPECT_EQ(manager.Activate(pendingId, 4000, 20010001, 20010001, uri), -EAGAIN);
    EXPECT_TRUE(uri.empty());

    manager.Remove(pendingId);
    for (const auto &sessionId : activeIds) {
        manager.Remove(sessionId);
    }
    std::lock_guard<std::mutex> lock(manager.mutex_);
    EXPECT_EQ(manager.activeSessionCount_, 0u);
    EXPECT_TRUE(manager.activeSourceSessionCounts_.empty());
}

/**
 * @tc.name: ActivateFuseSession_SourceActiveQuotaExceeded_ReturnTryAgain
 * @tc.desc: Verify one source cannot occupy all three global active drag slots.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfServiceImplMockTest, ActivateFuseSession_SourceActiveQuotaExceeded_ReturnTryAgain, TestSize.Level0)
{
    constexpr uint32_t sourceTokenId = 3500;
    auto &manager = UdmfFuseSessionManager::GetInstance();
    std::vector<std::string> activeIds;
    const std::string pendingId = "source-active-quota-pending";
    {
        std::lock_guard<std::mutex> lock(manager.mutex_);
        for (uint32_t index = 0; index < 2; ++index) {
            UdmfFuseSessionManager::SessionInfo active;
            active.userId = static_cast<int32_t>(100 + index);
            active.sourceTokenId = sourceTokenId;
            active.state = UdmfFuseSessionManager::State::ACTIVE;
            std::string sessionId = "source-active-quota-" + std::to_string(index);
            activeIds.push_back(sessionId);
            manager.sessions_.emplace(sessionId, active);
            ++manager.activeSessionCount_;
            ++manager.activeSourceSessionCounts_[sourceTokenId];
            ++manager.activeSessionCounts_[active.userId];
        }
        UdmfFuseSessionManager::SessionInfo pending;
        pending.userId = 100;
        pending.sourceTokenId = sourceTokenId;
        manager.sessions_.emplace(pendingId, pending);
        ++manager.pendingSessionCount_;
        ++manager.pendingSourceSessionCounts_[sourceTokenId];
    }
    std::string uri;

    EXPECT_EQ(manager.Activate(pendingId, 4500, 20010001, 20010001, uri), -EAGAIN);
    EXPECT_TRUE(uri.empty());

    manager.Remove(pendingId);
    for (const auto &sessionId : activeIds) {
        manager.Remove(sessionId);
    }
    std::lock_guard<std::mutex> lock(manager.mutex_);
    EXPECT_EQ(manager.activeSessionCount_, 0u);
    EXPECT_EQ(manager.activeSourceSessionCounts_.count(sourceTokenId), 0u);
}

/**
 * @tc.name: RemoveFuseSession_OpenFile_DelayActiveQuotaRelease
 * @tc.desc: Verify a draining drag keeps its global quota until the final open file is released.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfServiceImplMockTest, RemoveFuseSession_OpenFile_DelayActiveQuotaRelease, TestSize.Level0)
{
    constexpr int32_t userId = 100;
    constexpr uint32_t sourceTokenId = 5000;
    const std::string sessionId = "draining-active-quota";
    auto &manager = UdmfFuseSessionManager::GetInstance();
    {
        std::lock_guard<std::mutex> lock(manager.mutex_);
        UdmfFuseSessionManager::SessionInfo active;
        active.userId = userId;
        active.sourceTokenId = sourceTokenId;
        active.state = UdmfFuseSessionManager::State::ACTIVE;
        active.openCount = 1;
        manager.sessions_.emplace(sessionId, active);
        ++manager.activeSessionCount_;
        ++manager.activeSourceSessionCounts_[sourceTokenId];
        ++manager.activeSessionCounts_[userId];
    }

    manager.Remove(sessionId);
    {
        std::lock_guard<std::mutex> lock(manager.mutex_);
        ASSERT_NE(manager.sessions_.find(sessionId), manager.sessions_.end());
        EXPECT_EQ(manager.sessions_.at(sessionId).state, UdmfFuseSessionManager::State::DRAINING);
        EXPECT_EQ(manager.activeSessionCount_, 1u);
    }
    manager.ReleaseOpen(sessionId);
    std::lock_guard<std::mutex> lock(manager.mutex_);
    EXPECT_EQ(manager.sessions_.count(sessionId), 0u);
    EXPECT_EQ(manager.activeSessionCount_, 0u);
    EXPECT_EQ(manager.activeSourceSessionCounts_.count(sourceTokenId), 0u);
}

/**
 * @tc.name: ReleaseFuseSessionOpen_IdleSession_ReleaseActiveQuota
 * @tc.desc: Verify an inactive session is removed after its final FUSE handle is released.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfServiceImplMockTest, ReleaseFuseSessionOpen_IdleSession_ReleaseActiveQuota, TestSize.Level0)
{
    constexpr int32_t userId = 100;
    constexpr uint32_t sourceTokenId = 5100;
    constexpr uint64_t generation = 1;
    const std::string sessionId = "idle-active-quota";
    auto &manager = UdmfFuseSessionManager::GetInstance();
    {
        std::lock_guard<std::mutex> lock(manager.mutex_);
        UdmfFuseSessionManager::SessionInfo active;
        active.userId = userId;
        active.sourceTokenId = sourceTokenId;
        active.generation = generation;
        active.state = UdmfFuseSessionManager::State::ACTIVE;
        active.openCount = 1;
        manager.sessions_.emplace(sessionId, active);
        ++manager.activeSessionCount_;
        ++manager.activeSourceSessionCounts_[sourceTokenId];
        ++manager.activeSessionCounts_[userId];
    }

    manager.ReleaseOpen(sessionId);
    {
        std::lock_guard<std::mutex> lock(manager.mutex_);
        ASSERT_NE(manager.sessions_.find(sessionId), manager.sessions_.end());
        EXPECT_EQ(manager.sessions_.at(sessionId).openCount, 0u);
        EXPECT_EQ(manager.sessions_.at(sessionId).state, UdmfFuseSessionManager::State::ACTIVE);
    }

    manager.CleanupInactive(sessionId, generation);

    std::lock_guard<std::mutex> lock(manager.mutex_);
    EXPECT_EQ(manager.sessions_.count(sessionId), 0u);
    EXPECT_EQ(manager.activeSessionCount_, 0u);
    EXPECT_EQ(manager.activeSourceSessionCounts_.count(sourceTokenId), 0u);
    EXPECT_EQ(manager.activeSessionCounts_.count(userId), 0u);
}

/**
 * @tc.name: AcquireFuseSessionOpen_DifferentAppUid_ReturnNoPermission
 * @tc.desc: Verify another application under the same user cannot open an active virtual-file session.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfServiceImplMockTest, AcquireFuseSessionOpen_DifferentAppUid_ReturnNoPermission, TestSize.Level0)
{
    constexpr int32_t targetUid = 20010001;
    constexpr int32_t otherAppUid = 20010002;
    const std::string sessionId = "uid-restricted-virtual-session";
    auto &manager = UdmfFuseSessionManager::GetInstance();
    UdmfFuseSessionManager::SessionInfo session;
    session.state = UdmfFuseSessionManager::State::ACTIVE;
    session.targetUid = targetUid;
    {
        std::lock_guard<std::mutex> lock(manager.mutex_);
        manager.sessions_.emplace(sessionId, session);
    }

    EXPECT_EQ(manager.AcquireOpen(sessionId, otherAppUid), -EACCES);
    EXPECT_EQ(manager.AcquireOpen(sessionId, targetUid), 0);

    manager.ReleaseOpen(sessionId);
    std::lock_guard<std::mutex> lock(manager.mutex_);
    manager.sessions_.erase(sessionId);
}

/**
 * @tc.name: AcquireFuseSessionOpen_DesktopProxy_AllowFileManagerOnly
 * @tc.desc: Verify a desktop drop session can be opened only by its resolved file-manager proxy UID.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfServiceImplMockTest, AcquireFuseSessionOpen_DesktopProxy_AllowFileManagerOnly, TestSize.Level0)
{
    constexpr int32_t desktopUid = 20010001;
    constexpr int32_t fileManagerUid = 20010002;
    const std::string sessionId = "desktop-proxy-virtual-session";
    auto &manager = UdmfFuseSessionManager::GetInstance();
    UdmfFuseSessionManager::SessionInfo session;
    session.state = UdmfFuseSessionManager::State::ACTIVE;
    session.targetUid = desktopUid;
    session.accessUid = fileManagerUid;
    {
        std::lock_guard<std::mutex> lock(manager.mutex_);
        manager.sessions_.emplace(sessionId, session);
    }

    EXPECT_EQ(manager.AcquireOpen(sessionId, desktopUid), -EACCES);
    EXPECT_EQ(manager.AcquireOpen(sessionId, fileManagerUid), 0);

    manager.ReleaseOpen(sessionId);
    std::lock_guard<std::mutex> lock(manager.mutex_);
    manager.sessions_.erase(sessionId);
}

/**
 * @tc.name: FillFuseAttr_SessionNode_UseOwnerOnlyMode
 * @tc.desc: Verify FUSE session directories and virtual files expose owner-only permissions.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfServiceImplMockTest, FillFuseAttr_SessionNode_UseOwnerOnlyMode, TestSize.Level0)
{
    constexpr uid_t targetUid = 20010001;
    constexpr mode_t permissionMask = S_IRWXU | S_IRWXG | S_IRWXO;
    UdmfFuseController controller(100);
    UdmfFuseController::Node directory;
    directory.inode = FUSE_ROOT_ID + 1;
    directory.targetUid = targetUid;
    directory.entry.type = VirtualEntryType::DIRECTORY;
    struct stat directoryAttr {};
    controller.FillAttr(directory, directoryAttr);

    UdmfFuseController::Node file;
    file.inode = FUSE_ROOT_ID + 2;
    file.targetUid = targetUid;
    file.entry.type = VirtualEntryType::FILE;
    file.entry.size = 0;
    struct stat fileAttr {};
    controller.FillAttr(file, fileAttr);

    EXPECT_EQ(directoryAttr.st_uid, targetUid);
    EXPECT_EQ(directoryAttr.st_mode & permissionMask, 0500);
    EXPECT_EQ(fileAttr.st_uid, targetUid);
    EXPECT_EQ(fileAttr.st_mode & permissionMask, 0400);
}

/**
 * @tc.name: CheckFuseAccess_ReadOnlyNode_EnforceTargetAndMode
 * @tc.desc: Verify access checks allow target reads and directory search while rejecting writes and other UIDs.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfServiceImplMockTest, CheckFuseAccess_ReadOnlyNode_EnforceTargetAndMode, TestSize.Level0)
{
    constexpr uid_t targetUid = 20010001;
    constexpr uid_t otherAppUid = 20010002;
    UdmfFuseController controller(100);
    UdmfFuseController::Node file;
    file.inode = FUSE_ROOT_ID + 1;
    file.targetUid = targetUid;
    file.entry.type = VirtualEntryType::FILE;

    EXPECT_EQ(controller.CheckAccess(targetUid, file, F_OK), 0);
    EXPECT_EQ(controller.CheckAccess(targetUid, file, R_OK), 0);
    EXPECT_EQ(controller.CheckAccess(targetUid, file, W_OK), -EROFS);
    EXPECT_EQ(controller.CheckAccess(targetUid, file, X_OK), -EACCES);
    EXPECT_EQ(controller.CheckAccess(otherAppUid, file, R_OK), -EACCES);
    EXPECT_EQ(controller.CheckAccess(targetUid, file, 0x80), -EINVAL);

    file.entry.type = VirtualEntryType::DIRECTORY;
    EXPECT_EQ(controller.CheckAccess(targetUid, file, R_OK | X_OK), 0);
}

/**
 * @tc.name: GetFuseSeekResult_ContinuousFile_ReturnDataAndHole
 * @tc.desc: Verify virtual files expose one continuous data extent for SEEK_DATA and SEEK_HOLE.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfServiceImplMockTest, GetFuseSeekResult_ContinuousFile_ReturnDataAndHole, TestSize.Level0)
{
    UdmfFuseController::Node file;
    file.entry.type = VirtualEntryType::FILE;
    file.entry.size = 10;
    off_t result = -1;

    EXPECT_EQ(UdmfFuseController::GetSeekResult(file, 3, SEEK_DATA, result), 0);
    EXPECT_EQ(result, 3);
    EXPECT_EQ(UdmfFuseController::GetSeekResult(file, 3, SEEK_HOLE, result), 0);
    EXPECT_EQ(result, 10);
    EXPECT_EQ(UdmfFuseController::GetSeekResult(file, 10, SEEK_DATA, result), -ENXIO);
    EXPECT_EQ(UdmfFuseController::GetSeekResult(file, -1, SEEK_DATA, result), -EINVAL);
    EXPECT_EQ(UdmfFuseController::GetSeekResult(file, 0, SEEK_SET, result), -EINVAL);

    file.entry.size = -1;
    EXPECT_EQ(UdmfFuseController::GetSeekResult(file, 0, SEEK_DATA, result), -EIO);
    file.entry.type = VirtualEntryType::DIRECTORY;
    EXPECT_EQ(UdmfFuseController::GetSeekResult(file, 0, SEEK_DATA, result), -EISDIR);
}

/**
 * @tc.name: FillFuseStatFs_DifferentTargetUid_FilterPrivateNodes
 * @tc.desc: Verify filesystem statistics include only nodes owned by the calling drop target.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfServiceImplMockTest, FillFuseStatFs_DifferentTargetUid_FilterPrivateNodes, TestSize.Level0)
{
    constexpr uid_t targetUid = 20010001;
    constexpr uid_t otherAppUid = 20010002;
    UdmfFuseController controller(100);
    UdmfFuseController::Node root;
    root.inode = FUSE_ROOT_ID;
    root.entry.type = VirtualEntryType::DIRECTORY;
    controller.nodes_.emplace(root.inode, root);

    UdmfFuseController::Node directory;
    directory.inode = FUSE_ROOT_ID + 1;
    directory.targetUid = targetUid;
    directory.entry.type = VirtualEntryType::DIRECTORY;
    controller.nodes_.emplace(directory.inode, directory);

    UdmfFuseController::Node file;
    file.inode = FUSE_ROOT_ID + 2;
    file.targetUid = targetUid;
    file.entry.type = VirtualEntryType::FILE;
    file.entry.size = 4097;
    controller.nodes_.emplace(file.inode, file);

    UdmfFuseController::Node privateFile;
    privateFile.inode = FUSE_ROOT_ID + 3;
    privateFile.targetUid = otherAppUid;
    privateFile.entry.type = VirtualEntryType::FILE;
    privateFile.entry.size = 4096;
    controller.nodes_.emplace(privateFile.inode, privateFile);

    struct statvfs stat {};
    controller.FillStatFs(targetUid, stat);

    EXPECT_EQ(stat.f_bsize, 4096u);
    EXPECT_EQ(stat.f_blocks, 2u);
    EXPECT_EQ(stat.f_files, 3u);
    EXPECT_EQ(stat.f_bfree, 0u);
    EXPECT_NE(stat.f_flag & ST_RDONLY, 0u);
}

/**
 * @tc.name: AddFuseTree_LargeDirectory_BuildNameIndex
 * @tc.desc: Verify a large virtual directory builds a constant-time child lookup index without retaining subtrees.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfServiceImplMockTest, AddFuseTree_LargeDirectory_BuildNameIndex, TestSize.Level0)
{
    constexpr size_t fileCount = 600;
    UdmfFuseController controller(100);
    UdmfFuseController::Node fuseRoot;
    fuseRoot.inode = FUSE_ROOT_ID;
    fuseRoot.parent = FUSE_ROOT_ID;
    fuseRoot.entry.type = VirtualEntryType::DIRECTORY;
    controller.nodes_.emplace(FUSE_ROOT_ID, std::move(fuseRoot));

    VirtualEntry directory;
    directory.name = "virtual-folder";
    directory.type = VirtualEntryType::DIRECTORY;
    directory.subItems.reserve(fileCount);
    for (size_t index = 0; index < fileCount; ++index) {
        VirtualEntry file;
        file.id = "file-id-" + std::to_string(index);
        file.name = "file-" + std::to_string(index) + ".bin";
        file.type = VirtualEntryType::FILE;
        file.size = 1024;
        directory.subItems.push_back(std::move(file));
    }
    UdmfFuseController::Session session;
    session.sessionId = "large-directory-session";
    fuse_ino_t directoryInode = 0;

    ASSERT_EQ(controller.AddTreeLocked(FUSE_ROOT_ID, directory, session, directoryInode), 0);
    auto directoryNode = controller.nodes_.find(directoryInode);
    ASSERT_NE(directoryNode, controller.nodes_.end());
    EXPECT_TRUE(directoryNode->second.entry.subItems.empty());
    EXPECT_EQ(directoryNode->second.children.size(), fileCount);
    EXPECT_EQ(directoryNode->second.childrenByName.size(), fileCount);
    auto indexedChild = directoryNode->second.childrenByName.find("file-599.bin");
    ASSERT_NE(indexedChild, directoryNode->second.childrenByName.end());
    auto fileNode = controller.nodes_.find(indexedChild->second);
    ASSERT_NE(fileNode, controller.nodes_.end());
    EXPECT_EQ(fileNode->second.entry.id, "file-id-599");
}

/**
 * @tc.name: IsFuseUidAllowed_DifferentAppUid_ReturnFalse
 * @tc.desc: Verify only the drop target can access session nodes even when another process runs as root.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfServiceImplMockTest, IsFuseUidAllowed_DifferentAppUid_ReturnFalse, TestSize.Level0)
{
    constexpr uid_t targetUid = 20010001;
    constexpr uid_t otherAppUid = 20010002;
    UdmfFuseController controller(100);
    UdmfFuseController::Node node;
    node.inode = FUSE_ROOT_ID + 1;
    node.sessionId = "short-read-session";
    node.targetUid = targetUid;

    EXPECT_TRUE(controller.IsUidAllowed(targetUid, node));
    EXPECT_FALSE(controller.IsUidAllowed(otherAppUid, node));
    EXPECT_FALSE(controller.IsUidAllowed(0, node));

    node.inode = FUSE_ROOT_ID;
    EXPECT_TRUE(controller.IsUidAllowed(otherAppUid, node));
}

/**
 * @tc.name: LoadFuseBlock_ProviderShortRead_FillExpectedBlock
 * @tc.desc: Verify provider short reads are joined with advancing offsets until the block is complete.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfServiceImplMockTest, LoadFuseBlock_ProviderShortRead_FillExpectedBlock, TestSize.Level0)
{
    std::vector<uint8_t> content{ 0, 1, 2, 3, 4, 5, 6 };
    sptr<FuseReadProvider> provider = new FuseReadProvider(content, 2);
    UdmfFuseController controller(100);
    UdmfFuseController::Node node;
    node.inode = FUSE_ROOT_ID + 1;
    node.entry.id = "short-read-file";
    node.sessionId = "short-read-session";
    node.entry.type = VirtualEntryType::FILE;
    node.entry.size = static_cast<int64_t>(content.size());
    std::shared_ptr<UdmfFuseController::BlockEntry> block;

    EXPECT_EQ(controller.GetOrLoadBlock(node, provider->AsObject(), 0, block), 0);
    ASSERT_NE(block, nullptr);
    EXPECT_EQ(block->data, content);
    EXPECT_EQ(provider->offsets_, (std::vector<int64_t>{ 0, 2, 4, 6 }));
    EXPECT_EQ(provider->lengths_, (std::vector<int32_t>{ 7, 5, 3, 1 }));
}

/**
 * @tc.name: LoadFuseBlock_CacheFull_EvictOldestAndKeepCurrent
 * @tc.desc: Verify a newly downloaded block remains reusable after the controller cache reaches its limit.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfServiceImplMockTest, LoadFuseBlock_CacheFull_EvictOldestAndKeepCurrent, TestSize.Level0)
{
    constexpr size_t blockBytes = 5 * 1024 * 1024;
    constexpr size_t blockCount = 4;
    sptr<FuseReadProvider> provider = new FuseReadProvider(std::vector<uint8_t>(blockBytes * blockCount, 0x5A));
    UdmfFuseController controller(100);
    UdmfFuseController::Node node;
    node.inode = FUSE_ROOT_ID + 1;
    node.sessionId = "cache-eviction-session";
    node.entry.id = "cache-eviction-file";
    node.entry.type = VirtualEntryType::FILE;
    node.entry.size = static_cast<int64_t>(blockBytes * blockCount);
    std::shared_ptr<UdmfFuseController::BlockEntry> block;

    ASSERT_EQ(controller.GetOrLoadBlock(node, provider->AsObject(), 0, block), 0);
    block.reset();
    ASSERT_EQ(controller.GetOrLoadBlock(node, provider->AsObject(), 1, block), 0);
    block.reset();
    ASSERT_EQ(controller.GetOrLoadBlock(node, provider->AsObject(), 2, block), 0);
    block.reset();
    ASSERT_EQ(controller.GetOrLoadBlock(node, provider->AsObject(), 3, block), 0);
    block.reset();

    EXPECT_EQ(controller.cachedBytes_, 3 * blockBytes);
    EXPECT_EQ(controller.blocks_.size(), 3u);
    EXPECT_EQ(controller.blocks_.count({ node.inode, 0 }), 0u);
    EXPECT_EQ(controller.blocks_.count({ node.inode, 3 }), 1u);
    EXPECT_EQ(provider->readCount_, static_cast<int32_t>(blockCount));

    ASSERT_EQ(controller.GetOrLoadBlock(node, provider->AsObject(), 3, block), 0);
    EXPECT_EQ(provider->readCount_, static_cast<int32_t>(blockCount));
}

/**
 * @tc.name: LoadFuseBlock_TransientFailure_RetryAndSucceed
 * @tc.desc: Verify a transient provider failure is retried without poisoning the block cache.
 * @tc.type: FUNC
 */
HWTEST_F(UdmfServiceImplMockTest, LoadFuseBlock_TransientFailure_RetryAndSucceed, TestSize.Level0)
{
    std::vector<uint8_t> content{ 1, 2, 3, 4 };
    sptr<FuseReadProvider> provider = new FuseReadProvider(content);
    provider->statuses_ = { -EAGAIN, 0 };
    UdmfFuseController controller(100);
    UdmfFuseController::Node node;
    node.inode = FUSE_ROOT_ID + 2;
    node.sessionId = "retry-session";
    node.entry.id = "retry-file";
    node.entry.type = VirtualEntryType::FILE;
    node.entry.size = static_cast<int64_t>(content.size());
    std::shared_ptr<UdmfFuseController::BlockEntry> block;

    EXPECT_EQ(controller.GetOrLoadBlock(node, provider->AsObject(), 0, block), 0);
    ASSERT_NE(block, nullptr);
    EXPECT_EQ(block->data, content);
    EXPECT_EQ(provider->readCount_, 2);
}

/**
 * @tc.name: LoadFuseBlock_EmptyReadBeforeEof_ReturnIoError
 * @tc.desc: Verify an empty provider read before the declared file end does not cause an infinite loop.
 * @tc.type: FUNC
 */
HWTEST_F(UdmfServiceImplMockTest, LoadFuseBlock_EmptyReadBeforeEof_ReturnIoError, TestSize.Level0)
{
    sptr<FuseReadProvider> provider = new FuseReadProvider({});
    UdmfFuseController controller(100);
    UdmfFuseController::Node node;
    node.inode = FUSE_ROOT_ID + 3;
    node.sessionId = "empty-read-session";
    node.entry.id = "premature-eof-file";
    node.entry.type = VirtualEntryType::FILE;
    node.entry.size = 4;
    std::shared_ptr<UdmfFuseController::BlockEntry> block;

    EXPECT_EQ(controller.GetOrLoadBlock(node, provider->AsObject(), 0, block), -EIO);
    EXPECT_EQ(provider->readCount_, 1);
}

/**
 * @tc.name: LoadFuseBlock_PreviousTransientFailure_ReloadBlock
 * @tc.desc: Verify a later read creates a new block generation after a transient failure.
 * @tc.type: FUNC
 */
HWTEST_F(UdmfServiceImplMockTest, LoadFuseBlock_PreviousTransientFailure_ReloadBlock, TestSize.Level0)
{
    std::vector<uint8_t> content{ 1, 2, 3, 4 };
    sptr<FuseReadProvider> provider = new FuseReadProvider(content);
    provider->statuses_ = { -ETIMEDOUT, -ETIMEDOUT, -ETIMEDOUT, 0 };
    UdmfFuseController controller(100);
    UdmfFuseController::Node node;
    node.inode = FUSE_ROOT_ID + 4;
    node.sessionId = "reload-session";
    node.entry.id = "reload-file";
    node.entry.type = VirtualEntryType::FILE;
    node.entry.size = static_cast<int64_t>(content.size());
    std::shared_ptr<UdmfFuseController::BlockEntry> failedBlock;
    std::shared_ptr<UdmfFuseController::BlockEntry> loadedBlock;

    EXPECT_EQ(controller.GetOrLoadBlock(node, provider->AsObject(), 0, failedBlock), -ETIMEDOUT);
    EXPECT_EQ(controller.GetOrLoadBlock(node, provider->AsObject(), 0, loadedBlock), 0);
    ASSERT_NE(failedBlock, nullptr);
    ASSERT_NE(loadedBlock, nullptr);
    EXPECT_NE(failedBlock, loadedBlock);
    EXPECT_EQ(loadedBlock->data, content);
    EXPECT_EQ(provider->readCount_, 4);
}

/**
 * @tc.name: LoadFuseBlock_BlockWaitExpired_ReturnTimeout
 * @tc.desc: Verify followers waiting for a loading block stop at the shared absolute deadline.
 * @tc.type: FUNC
 */
HWTEST_F(UdmfServiceImplMockTest, LoadFuseBlock_BlockWaitExpired_ReturnTimeout, TestSize.Level0)
{
    UdmfFuseController controller(100);
    UdmfFuseController::Node node;
    node.inode = FUSE_ROOT_ID + 5;
    node.entry.id = "timeout-file";
    node.entry.type = VirtualEntryType::FILE;
    node.entry.size = 1;
    auto loadingBlock = std::make_shared<UdmfFuseController::BlockEntry>();
    loadingBlock->deadline = std::chrono::steady_clock::now() - std::chrono::milliseconds(1);
    controller.blocks_.emplace(UdmfFuseController::BlockKey{ node.inode, 0 }, loadingBlock);
    std::shared_ptr<UdmfFuseController::BlockEntry> block;

    EXPECT_EQ(controller.GetOrLoadBlock(node, nullptr, 0, block), -ETIMEDOUT);
    EXPECT_EQ(block, loadingBlock);
}

/**
 * @tc.name: RemoveFuseBlock_LoadingBlock_CancelAndErase
 * @tc.desc: Verify session cleanup cancels a loading block and removes it from the shared cache.
 * @tc.type: FUNC
 */
HWTEST_F(UdmfServiceImplMockTest, RemoveFuseBlock_LoadingBlock_CancelAndErase, TestSize.Level0)
{
    UdmfFuseController controller(100);
    constexpr fuse_ino_t inode = FUSE_ROOT_ID + 6;
    UdmfFuseController::BlockKey key{ inode, 0 };
    auto loadingBlock = std::make_shared<UdmfFuseController::BlockEntry>();
    controller.blocks_.emplace(key, loadingBlock);

    controller.RemoveBlocksLocked({ inode });

    EXPECT_TRUE(controller.blocks_.empty());
    EXPECT_EQ(loadingBlock->state, UdmfFuseController::BlockState::CANCELED);
    EXPECT_EQ(loadingBlock->status, -ECANCELED);
}

/**
 * @tc.name: ProviderRead_CallbackMissing_ReturnTimeout
 * @tc.desc: Verify the service stops waiting at the provider call deadline when no callback arrives.
 * @tc.type: FUNC
 */
HWTEST_F(UdmfServiceImplMockTest, ProviderRead_CallbackMissing_ReturnTimeout, TestSize.Level0)
{
    sptr<FuseReadProvider> provider = new FuseReadProvider({ 1 });
    provider->suppressCallback_ = true;
    UdmfFuseController controller(100);
    std::vector<uint8_t> bytes;
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(10);

    EXPECT_EQ(controller.ProviderRead(provider->AsObject(),
                  UdmfFuseController::ProviderReadRequest{ "timeout-session", "timeout-file", 0, 1 }, deadline, bytes),
        -ETIMEDOUT);
    EXPECT_TRUE(bytes.empty());
}

/**
 * @tc.name: ProviderGate_SingleSessionBorrowIdleSlots_ReadConcurrently
 * @tc.desc: Verify one drag session can borrow all idle provider read slots.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfServiceImplMockTest, ProviderGate_SingleSessionBorrowIdleSlots_ReadConcurrently, TestSize.Level0)
{
    sptr<FuseReadProvider> provider = new FuseReadProvider({ 1 });
    provider->holdCallbacks_ = true;
    UdmfFuseController controller(100);
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(1);
    std::vector<std::thread> reads;
    for (size_t index = 0; index < 3; ++index) {
        reads.emplace_back([&controller, &provider, deadline] {
            std::vector<uint8_t> bytes;
            EXPECT_EQ(controller.ProviderRead(provider->AsObject(),
                          UdmfFuseController::ProviderReadRequest{ "single-session", "file", 0, 1 }, deadline, bytes),
                0);
            EXPECT_EQ(bytes, (std::vector<uint8_t>{ 1 }));
        });
    }
    {
        std::unique_lock<std::mutex> lock(provider->asyncMutex_);
        EXPECT_TRUE(provider->asyncCondition_.wait_until(
            lock, deadline, [&provider] { return provider->asyncRequestCount_ == 3; }));
    }
    EXPECT_TRUE(provider->CompleteNextRead());
    EXPECT_TRUE(provider->CompleteNextRead());
    EXPECT_TRUE(provider->CompleteNextRead());
    for (auto &read : reads) {
        read.join();
    }
}

/**
 * @tc.name: ProviderGate_GlobalConcurrencyLimit_QueueUntilSlotAvailable
 * @tc.desc: Verify an excess provider read waits and runs after a global slot becomes available.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfServiceImplMockTest, ProviderGate_GlobalConcurrencyLimit_QueueUntilSlotAvailable, TestSize.Level0)
{
    sptr<FuseReadProvider> firstProvider = new FuseReadProvider({ 1 });
    firstProvider->holdCallbacks_ = true;
    sptr<FuseReadProvider> waitingProvider = new FuseReadProvider({ 2 });
    UdmfFuseController firstController(100);
    UdmfFuseController secondController(101);
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(1);
    std::vector<std::thread> reads;
    for (size_t index = 0; index < 3; ++index) {
        reads.emplace_back([&firstController, &firstProvider, deadline] {
            std::vector<uint8_t> bytes;
            EXPECT_EQ(
                firstController.ProviderRead(firstProvider->AsObject(),
                    UdmfFuseController::ProviderReadRequest{ "active-session", "active-file", 0, 1 }, deadline, bytes),
                0);
        });
    }
    {
        std::unique_lock<std::mutex> lock(firstProvider->asyncMutex_);
        EXPECT_TRUE(firstProvider->asyncCondition_.wait_until(
            lock, deadline, [&firstProvider] { return firstProvider->asyncRequestCount_ == 3; }));
    }
    std::atomic<int32_t> waitingResult = -EIO;
    std::thread waitingRead([&secondController, &waitingProvider, &waitingResult, deadline] {
        std::vector<uint8_t> bytes;
        waitingResult = secondController.ProviderRead(waitingProvider->AsObject(),
            UdmfFuseController::ProviderReadRequest{ "waiting-session", "waiting-file", 0, 1 }, deadline, bytes);
    });
    {
        std::unique_lock<std::mutex> lock(waitingProvider->asyncMutex_);
        auto shortDeadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(50);
        EXPECT_FALSE(waitingProvider->asyncCondition_.wait_until(
            lock, shortDeadline, [&waitingProvider] { return waitingProvider->asyncRequestCount_ != 0; }));
    }
    EXPECT_TRUE(firstProvider->CompleteNextRead());
    {
        std::unique_lock<std::mutex> lock(waitingProvider->asyncMutex_);
        EXPECT_TRUE(waitingProvider->asyncCondition_.wait_until(
            lock, deadline, [&waitingProvider] { return waitingProvider->asyncRequestCount_ == 1; }));
    }
    waitingRead.join();
    EXPECT_EQ(waitingResult.load(), 0);
    EXPECT_TRUE(firstProvider->CompleteNextRead());
    EXPECT_TRUE(firstProvider->CompleteNextRead());
    for (auto &read : reads) {
        read.join();
    }
}

/**
 * @tc.name: ProviderGate_WaitingSessionGetsFairSlot_AvoidStarvation
 * @tc.desc: Verify a waiting drag gets the next slot before an active drag borrows another slot.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfServiceImplMockTest, ProviderGate_WaitingSessionGetsFairSlot_AvoidStarvation, TestSize.Level0)
{
    sptr<FuseReadProvider> activeProvider = new FuseReadProvider({ 1 });
    sptr<FuseReadProvider> borrowedProvider = new FuseReadProvider({ 2 });
    sptr<FuseReadProvider> waitingProvider = new FuseReadProvider({ 3 });
    activeProvider->holdCallbacks_ = true;
    waitingProvider->holdCallbacks_ = true;
    UdmfFuseController controller(100);
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(1);
    std::vector<std::thread> activeReads;
    for (size_t index = 0; index < 3; ++index) {
        activeReads.emplace_back([&controller, &activeProvider, deadline] {
            std::vector<uint8_t> bytes;
            EXPECT_EQ(
                controller.ProviderRead(activeProvider->AsObject(),
                    UdmfFuseController::ProviderReadRequest{ "active-session", "active-file", 0, 1 }, deadline, bytes),
                0);
        });
    }
    EXPECT_TRUE(WaitForAsyncRequests(activeProvider, 3, deadline));
    std::thread borrowedRead([&controller, &borrowedProvider, deadline] {
        std::vector<uint8_t> bytes;
        EXPECT_EQ(
            controller.ProviderRead(borrowedProvider->AsObject(),
                UdmfFuseController::ProviderReadRequest{ "active-session", "borrowed-file", 0, 1 }, deadline, bytes),
            0);
    });
    std::thread waitingRead([&controller, &waitingProvider, deadline] {
        std::vector<uint8_t> bytes;
        EXPECT_EQ(
            controller.ProviderRead(waitingProvider->AsObject(),
                UdmfFuseController::ProviderReadRequest{ "waiting-session", "waiting-file", 0, 1 }, deadline, bytes),
            0);
    });

    EXPECT_TRUE(activeProvider->CompleteNextRead());
    EXPECT_TRUE(WaitForAsyncRequests(waitingProvider, 1, deadline));
    {
        std::lock_guard<std::mutex> lock(borrowedProvider->asyncMutex_);
        EXPECT_EQ(borrowedProvider->asyncRequestCount_, 0u);
    }
    EXPECT_TRUE(waitingProvider->CompleteNextRead());
    EXPECT_TRUE(WaitForAsyncRequests(borrowedProvider, 1, deadline));
    borrowedRead.join();
    waitingRead.join();
    EXPECT_TRUE(activeProvider->CompleteNextRead());
    EXPECT_TRUE(activeProvider->CompleteNextRead());
    for (auto &read : activeReads) {
        read.join();
    }
}

/**
 * @tc.name: ProviderGate_ConsecutiveTimeouts_OpenCircuit
 * @tc.desc: Verify consecutive provider timeouts open the circuit and subsequent reads fail fast.
 * @tc.type: FUNC
 */
HWTEST_F(UdmfServiceImplMockTest, ProviderGate_ConsecutiveTimeouts_OpenCircuit, TestSize.Level0)
{
    sptr<FuseReadProvider> provider = new FuseReadProvider({ 1 });
    provider->suppressCallback_ = true;
    UdmfFuseController controller(100);
    std::vector<uint8_t> bytes;

    for (size_t index = 0; index < 3; ++index) {
        auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(5);
        EXPECT_EQ(
            controller.ProviderRead(provider->AsObject(),
                UdmfFuseController::ProviderReadRequest{ "circuit-session", "timeout-file", 0, 1 }, deadline, bytes),
            -ETIMEDOUT);
    }
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(50);
    EXPECT_EQ(controller.ProviderRead(provider->AsObject(),
                  UdmfFuseController::ProviderReadRequest{ "circuit-session", "timeout-file", 0, 1 }, deadline, bytes),
        -ETIMEDOUT);
    EXPECT_EQ(provider->asyncRequestCount_, 3);
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
    runtime.tokenId = 17;
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
