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

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <future>
#include <map>

#include "access_token_mock.h"
#include "account_delegate_mock.h"
#include "file.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "ipc_skeleton.h"
#include "iremote_stub.h"
#include "lifecycle_manager.h"
#include "preprocess_utils.h"
#include "store_cache.h"
#include "text.h"
#include "udmf_fuse_lowlevel_mock.h"
#include "udmf_fuse_mount_adapter_mock.h"
#include "udmf_fuse_session_manager.h"
#include "udmf_service_impl.h"
#include "virtual_entry_provider.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
namespace {
uint32_t g_virtualEntryCallingToken = 0;
}

// This replacement is linked only into the dedicated virtual-entry unit-test executable.
uint32_t IPCSkeleton::GetCallingTokenID()
{
    return g_virtualEntryCallingToken;
}
} // namespace OHOS

namespace OHOS::UDMF {
namespace {
constexpr uint32_t SOURCE_TOKEN = 8001;
constexpr uint32_t TARGET_TOKEN = 9001;
constexpr uint32_t DESKTOP_TOKEN = 9002;
constexpr int32_t TEST_USER = 100;
constexpr int64_t FILE_BYTES = 7;
constexpr const char *SOURCE_BUNDLE = "com.example.virtual.source";
constexpr const char *TARGET_BUNDLE = "com.example.virtual.target";
constexpr const char *DESKTOP_BUNDLE = "com.ohos.sceneboard";
constexpr const char *STORE_KEY = "drag100";

std::string FileManagerBundle()
{
    constexpr char brand[] = { 'h', 'u', 'a', 'w', 'e', 'i', '\0' };
    return "com." + std::string(brand) + ".hmos.filemanager";
}

class VirtualEntryStoreMock : public Store {
public:
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

class VirtualEntryPrivilegeMock : public CheckerManager::Checker {
public:
    MOCK_METHOD(bool, IsValid, (const std::vector<Privilege> &, const CheckerManager::CheckInfo &), (override));
};

class ServiceEntryProvider final : public IRemoteStub<IVirtualEntryProvider> {
public:
    bool AddDeathRecipient(const sptr<DeathRecipient> &recipient) override
    {
        return acceptDeathRecipient && recipient != nullptr;
    }

    bool RemoveDeathRecipient(const sptr<DeathRecipient> &recipient) override
    {
        return recipient != nullptr;
    }

    int32_t Stat(const std::string &, VirtualEntry &) override
    {
        return -ENOSYS;
    }

    int32_t Read(const std::string &, int64_t, int32_t, std::vector<uint8_t> &) override
    {
        return -ENOSYS;
    }

    int32_t Cancel(const std::vector<std::string> &) override
    {
        return 0;
    }

    int32_t OnRemoteRequest(uint32_t, MessageParcel &, MessageParcel &, MessageOption &) override
    {
        ++remoteRequests;
        return -ENOSYS;
    }

    bool acceptDeathRecipient = true;
    std::atomic<uint32_t> remoteRequests{ 0 };
};

VirtualEntry MakeServiceEntry()
{
    VirtualEntry entry;
    entry.id = "virtual-file";
    entry.name = "example.bin";
    entry.type = VirtualEntryType::FILE;
    entry.size = FILE_BYTES;
    entry.modifyTime = 123456;
    return entry;
}

std::shared_ptr<UnifiedRecord> MakeMarkedRecord(bool marker = true)
{
    auto details = std::make_shared<Object>();
    details->value_[VIRTUAL_ENTRY_FLAG] = marker;
    details->value_["business-detail"] = std::string("preserved");
    auto object = std::make_shared<Object>();
    object->value_[UNIFORM_DATA_TYPE] = std::string(GENERAL_FILE_URI);
    object->value_[ORI_URI] = std::string("file:///virtual/example.bin");
    object->value_[FILE_TYPE] = std::string("general.file");
    object->value_[DETAILS] = details;
    return std::make_shared<File>(FILE, object);
}
} // namespace

class UdmfVirtualEntryServiceTest : public testing::Test {
public:
    void SetUp() override
    {
        savedCallingToken_ = g_virtualEntryCallingToken;
        g_virtualEntryCallingToken = SOURCE_TOKEN;
        savedAccount_ = DistributedData::AccountDelegate::GetInstance();
        DistributedData::AccountDelegate::instance_ = &account_;
        savedAccessToken_ = BAccessTokenKit::accessTokenkit;
        BAccessTokenKit::accessTokenkit = token_;
        savedCheckers_ = CheckerManager::GetInstance().checkers_;
        CheckerManager::GetInstance().checkers_["DataChecker"] = &privilege_;
        savedExecutor_ = manager_.executor_;
        manager_.SetExecutor(nullptr);
        savedLifecycleExecutor_ = LifeCycleManager::GetInstance().executors_;
        LifeCycleManager::GetInstance().SetThreadPool(nullptr);
        savedStoreExecutor_ = StoreCache::GetInstance().executorPool_;
        savedStoreTask_ = StoreCache::GetInstance().taskId_;
        const auto cachedStore = StoreCache::GetInstance().stores_.Find(STORE_KEY);
        hadStore_ = cachedStore.first;
        savedStore_ = cachedStore.second;
        StoreCache::GetInstance().stores_.InsertOrAssign(STORE_KEY, store_);
        UdmfFuseMountAdapterMock::Reset();
        UdmfFuseMountAdapterMock::mountStatus = 0;
        ConfigureMocks();
        InitializeData();
    }

    void TearDown() override
    {
        UdmfFuseMountAdapterMock::unmountStatus = 0;
        for (const auto &key : ownedKeys_) {
            manager_.Remove(key);
        }
        if (boundExecutor_ != nullptr) {
            DistributedData::FeatureSystem::Feature::BindInfo bindInfo{};
            (void)service_.OnBind(bindInfo);
            boundExecutor_.reset();
        }
        manager_.SetExecutor(savedExecutor_);
        LifeCycleManager::GetInstance().SetThreadPool(savedLifecycleExecutor_);
        StoreCache::GetInstance().SetThreadPool(savedStoreExecutor_);
        StoreCache::GetInstance().taskId_ = savedStoreTask_;
        if (hadStore_) {
            StoreCache::GetInstance().stores_.InsertOrAssign(STORE_KEY, savedStore_);
        } else {
            StoreCache::GetInstance().stores_.Erase(STORE_KEY);
        }
        CheckerManager::GetInstance().checkers_ = savedCheckers_;
        BAccessTokenKit::accessTokenkit = savedAccessToken_;
        DistributedData::AccountDelegate::instance_ = savedAccount_;
        g_virtualEntryCallingToken = savedCallingToken_;
        UdmfFuseMountAdapterMock::Reset();
    }

protected:
    void ConfigureMocks()
    {
        ON_CALL(account_, QueryForegroundUserId(_)).WillByDefault(DoAll(SetArgReferee<0>(TEST_USER), Return(true)));
        ON_CALL(account_, GetUserByToken(_)).WillByDefault(Return(TEST_USER));
        ON_CALL(*token_, GetTokenTypeFlag(_)).WillByDefault(Return(TOKEN_HAP));
        ON_CALL(*token_, GetTokenType(_)).WillByDefault(Return(TOKEN_HAP));
        ON_CALL(*token_, GetHapTokenInfo(_, _)).WillByDefault(Invoke([](AccessTokenID token, HapTokenInfo &info) {
            info = HapTokenInfo{};
            info.bundleName = token == SOURCE_TOKEN ? SOURCE_BUNDLE : TARGET_BUNDLE;
            info.userID = TEST_USER;
            info.instIndex = 0;
            return RET_SUCCESS;
        }));
        ON_CALL(*store_, Get(_, _)).WillByDefault(Invoke([this](const std::string &, UnifiedData &data) {
            data = storedData_;
            return E_OK;
        }));
        ON_CALL(privilege_, IsValid(_, _))
            .WillByDefault(Invoke([](const std::vector<Privilege> &privileges, const CheckerManager::CheckInfo &info) {
                return std::any_of(privileges.begin(), privileges.end(),
                    [&info](const auto &privilege) { return privilege.tokenId == info.tokenId; });
            }));
    }

    void InitializeData()
    {
        UnifiedKey key("drag", SOURCE_BUNDLE, "0123456789abcdef0123456789abcdef");
        query_.key = key.GetUnifiedKey();
        query_.intention = UD_INTENTION_DRAG;
        query_.tokenId = SOURCE_TOKEN;
        ownedKeys_.push_back(query_.key);
        Runtime runtime;
        runtime.key = key;
        runtime.tokenId = SOURCE_TOKEN;
        runtime.sourcePackage = SOURCE_BUNDLE;
        runtime.createPackage = SOURCE_BUNDLE;
        runtime.deviceId = PreProcessUtils::GetLocalDeviceId();
        runtime.recordTotalNum = 1;
        runtime.privileges = { { SOURCE_TOKEN, "readAndKeep", "" } };
        storedData_.SetRuntime(runtime);
        storedData_.SetRecords({ MakeMarkedRecord() });
    }

    void SetRecords(std::vector<std::shared_ptr<UnifiedRecord>> records)
    {
        storedData_.SetRecords(std::move(records));
        storedData_.GetRuntime()->recordTotalNum = static_cast<uint32_t>(storedData_.GetRecords().size());
    }

    int32_t RegisterSession(uint32_t recordIndex = 0, uint32_t sourceToken = SOURCE_TOKEN, int32_t user = TEST_USER)
    {
        UdmfFuseSessionManager::SessionInfo info;
        info.userId = user;
        info.sourceTokenId = sourceToken;
        info.generation = 1;
        info.recordIndex = recordIndex;
        info.root = MakeServiceEntry();
        info.provider = provider_->AsObject();
        return manager_.Register(query_.key, info);
    }

    void ConfigureProxyTokens(int32_t desktopUser = TEST_USER)
    {
        query_.tokenId = TARGET_TOKEN;
        storedData_.GetRuntime()->privileges = { { DESKTOP_TOKEN, "readAndKeep", "" } };
        ON_CALL(*token_, GetHapTokenInfo(TARGET_TOKEN, _)).WillByDefault(Invoke([](AccessTokenID, HapTokenInfo &info) {
            info = HapTokenInfo{};
            info.bundleName = FileManagerBundle();
            info.userID = TEST_USER;
            info.instIndex = 0;
            return RET_SUCCESS;
        }));
        ON_CALL(*token_, GetHapTokenInfo(DESKTOP_TOKEN, _))
            .WillByDefault(Invoke([desktopUser](AccessTokenID, HapTokenInfo &info) {
                info = HapTokenInfo{};
                info.bundleName = DESKTOP_BUNDLE;
                info.userID = desktopUser;
                return RET_SUCCESS;
            }));
    }

    UdmfServiceImpl service_;
    UdmfFuseSessionManager &manager_ = UdmfFuseSessionManager::GetInstance();
    FuseLowlevelMock fuse_;
    NiceMock<DistributedData::AccountDelegateMock> account_;
    NiceMock<VirtualEntryPrivilegeMock> privilege_;
    std::shared_ptr<NiceMock<AccessTokenKitMock>> token_ = std::make_shared<NiceMock<AccessTokenKitMock>>();
    std::shared_ptr<NiceMock<VirtualEntryStoreMock>> store_ = std::make_shared<NiceMock<VirtualEntryStoreMock>>();
    sptr<ServiceEntryProvider> provider_ = new ServiceEntryProvider();
    UnifiedData storedData_;
    QueryOption query_;
    std::vector<std::string> ownedKeys_;
    uint32_t savedCallingToken_ = 0;
    DistributedData::AccountDelegate *savedAccount_ = nullptr;
    std::shared_ptr<BAccessTokenKit> savedAccessToken_;
    std::map<std::string, CheckerManager::Checker *> savedCheckers_;
    std::shared_ptr<Store> savedStore_;
    bool hadStore_ = false;
    std::shared_ptr<ExecutorPool> savedExecutor_;
    std::shared_ptr<ExecutorPool> savedLifecycleExecutor_;
    std::shared_ptr<ExecutorPool> savedStoreExecutor_;
    std::shared_ptr<ExecutorPool> boundExecutor_;
    ExecutorPool::TaskId savedStoreTask_ = ExecutorPool::INVALID_TASK_ID;
};

/**
 * @tc.name: RegisterVirtualEntry_InvalidKeyOrIntention_RejectBeforeStoreAccess
 * @tc.desc: Only a valid drag key can register a virtual file provider.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(
    UdmfVirtualEntryServiceTest, RegisterVirtualEntry_InvalidKeyOrIntention_RejectBeforeStoreAccess, TestSize.Level0)
{
    UnifiedKey dataHub("DataHub", SOURCE_BUNDLE, "0123456789abcdef0123456789abcdef");
    EXPECT_CALL(*store_, Get(_, _)).Times(0);
    for (const auto &key : { std::string(), std::string("invalid-key"), dataHub.GetUnifiedKey() }) {
        SCOPED_TRACE(key);
        EXPECT_EQ(
            service_.RegisterVirtualEntry(key, 0, MakeServiceEntry(), provider_->AsObject()), E_INVALID_PARAMETERS);
    }
}

/**
 * @tc.name: RegisterVirtualEntry_NullProviderOrInvalidTree_RejectBeforeStoreAccess
 * @tc.desc: File metadata must be valid and a live provider reference must be supplied.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfVirtualEntryServiceTest, RegisterVirtualEntry_NullProviderOrInvalidTree_RejectBeforeStoreAccess,
    TestSize.Level0)
{
    EXPECT_CALL(*store_, Get(_, _)).Times(0);
    EXPECT_EQ(service_.RegisterVirtualEntry(query_.key, 0, MakeServiceEntry(), nullptr), E_INVALID_PARAMETERS);
    auto entry = MakeServiceEntry();
    entry.size = -1;
    EXPECT_EQ(service_.RegisterVirtualEntry(query_.key, 0, entry, provider_->AsObject()), E_INVALID_PARAMETERS);
    entry.size = FILE_BYTES;
    entry.name = "../escape";
    EXPECT_EQ(service_.RegisterVirtualEntry(query_.key, 0, entry, provider_->AsObject()), E_INVALID_PARAMETERS);
}

/**
 * @tc.name: RegisterVirtualEntry_StoreUnavailable_ReturnNotFound
 * @tc.desc: Failure to obtain the source store cannot create a pending session.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfVirtualEntryServiceTest, RegisterVirtualEntry_StoreUnavailable_ReturnNotFound, TestSize.Level0)
{
    EXPECT_CALL(account_, QueryForegroundUserId(_)).WillOnce(Return(false));
    EXPECT_CALL(*store_, Get(_, _)).Times(0);
    EXPECT_EQ(service_.RegisterVirtualEntry(query_.key, 0, MakeServiceEntry(), provider_->AsObject()), E_NOT_FOUND);
    UdmfFuseSessionManager::SessionInfo info;
    EXPECT_FALSE(manager_.Get(query_.key, info));
}

/**
 * @tc.name: RegisterVirtualEntry_StoredDataMissing_ReturnNotFound
 * @tc.desc: Store errors and absent runtime metadata both reject provider registration.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfVirtualEntryServiceTest, RegisterVirtualEntry_StoredDataMissing_ReturnNotFound, TestSize.Level0)
{
    EXPECT_CALL(*store_, Get(query_.key, _)).WillOnce(Return(E_DB_ERROR));
    EXPECT_EQ(service_.RegisterVirtualEntry(query_.key, 0, MakeServiceEntry(), provider_->AsObject()), E_NOT_FOUND);
    storedData_ = UnifiedData();
    EXPECT_CALL(*store_, Get(query_.key, _)).WillOnce(DoAll(SetArgReferee<1>(storedData_), Return(E_OK)));
    EXPECT_EQ(service_.RegisterVirtualEntry(query_.key, 0, MakeServiceEntry(), provider_->AsObject()), E_NOT_FOUND);
}

/**
 * @tc.name: RegisterVirtualEntry_ZeroOrDifferentCallingToken_DenySourceImpersonation
 * @tc.desc: The IPC caller must be the token that originally stored the drag record.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfVirtualEntryServiceTest, RegisterVirtualEntry_ZeroOrDifferentCallingToken_DenySourceImpersonation,
    TestSize.Level0)
{
    for (uint32_t token : { uint32_t(0), TARGET_TOKEN }) {
        SCOPED_TRACE(token);
        g_virtualEntryCallingToken = token;
        ASSERT_EQ(IPCSkeleton::GetCallingTokenID(), token);
        EXPECT_EQ(
            service_.RegisterVirtualEntry(query_.key, 0, MakeServiceEntry(), provider_->AsObject()), E_NO_PERMISSION);
    }
}

/**
 * @tc.name: RegisterVirtualEntry_SavedSourceIdentityChanged_DenyStaleToken
 * @tc.desc: A changed package identity must not reuse a drag record written by the previous source.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfVirtualEntryServiceTest, RegisterVirtualEntry_SavedSourceIdentityChanged_DenyStaleToken, TestSize.Level0)
{
    ASSERT_EQ(IPCSkeleton::GetCallingTokenID(), SOURCE_TOKEN);
    storedData_.GetRuntime()->sourcePackage = "com.example.different.source";
    EXPECT_EQ(service_.RegisterVirtualEntry(query_.key, 0, MakeServiceEntry(), provider_->AsObject()), E_NO_PERMISSION);
}

/**
 * @tc.name: RegisterVirtualEntry_SourceTokenLookupFailed_DenyRegistration
 * @tc.desc: Inability to verify the saved source token must not be treated as authorization.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfVirtualEntryServiceTest, RegisterVirtualEntry_SourceTokenLookupFailed_DenyRegistration, TestSize.Level0)
{
    EXPECT_CALL(*token_, GetHapTokenInfo(SOURCE_TOKEN, _)).WillOnce(Return(-1));
    EXPECT_EQ(service_.RegisterVirtualEntry(query_.key, 0, MakeServiceEntry(), provider_->AsObject()), E_NO_PERMISSION);
}

/**
 * @tc.name: RegisterVirtualEntry_RecordIndexInvalid_DenyOutOfRangeAndNullRecord
 * @tc.desc: The registered index must identify an existing non-null source record.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(
    UdmfVirtualEntryServiceTest, RegisterVirtualEntry_RecordIndexInvalid_DenyOutOfRangeAndNullRecord, TestSize.Level0)
{
    EXPECT_EQ(service_.RegisterVirtualEntry(query_.key, 1, MakeServiceEntry(), provider_->AsObject()), E_NO_PERMISSION);
    SetRecords({ nullptr });
    EXPECT_EQ(service_.RegisterVirtualEntry(query_.key, 0, MakeServiceEntry(), provider_->AsObject()), E_NO_PERMISSION);
}

/**
 * @tc.name: RegisterVirtualEntry_RecordHasNoFileUri_RejectUnrelatedRecord
 * @tc.desc: A plain-text record cannot be registered as a virtual file by supplying an index.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfVirtualEntryServiceTest, RegisterVirtualEntry_RecordHasNoFileUri_RejectUnrelatedRecord, TestSize.Level0)
{
    SetRecords({ std::make_shared<Text>() });
    EXPECT_EQ(
        service_.RegisterVirtualEntry(query_.key, 0, MakeServiceEntry(), provider_->AsObject()), E_INVALID_PARAMETERS);
}

/**
 * @tc.name: RegisterVirtualEntry_MarkerMissingFalseOrWrongType_RejectForgedMetadata
 * @tc.desc: Only a boolean true marker in a valid details object identifies virtual source data.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfVirtualEntryServiceTest, RegisterVirtualEntry_MarkerMissingFalseOrWrongType_RejectForgedMetadata,
    TestSize.Level0)
{
    for (int32_t shape = 0; shape < 6; ++shape) {
        SCOPED_TRACE(shape);
        auto record = MakeMarkedRecord(false);
        auto object = std::get<std::shared_ptr<Object>>(record->GetEntry(GENERAL_FILE_URI));
        auto details = std::get<std::shared_ptr<Object>>(object->value_.at(DETAILS));
        if (shape == 0) {
            object->value_.erase(DETAILS);
        } else if (shape == 1) {
            object->value_[DETAILS] = std::shared_ptr<Object>();
        } else if (shape == 2) {
            object->value_[DETAILS] = std::string("invalid-details");
        } else if (shape == 3) {
            details->value_.erase(VIRTUAL_ENTRY_FLAG);
        } else if (shape == 4) {
            details->value_[VIRTUAL_ENTRY_FLAG] = int32_t(1);
        }
        SetRecords({ record });
        EXPECT_EQ(service_.RegisterVirtualEntry(query_.key, 0, MakeServiceEntry(), provider_->AsObject()),
            E_INVALID_PARAMETERS);
    }
}

/**
 * @tc.name: RegisterVirtualEntry_SourceUserLookupFailed_ReturnError
 * @tc.desc: A valid source identity without a resolvable HAP user cannot create a session.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfVirtualEntryServiceTest, RegisterVirtualEntry_SourceUserLookupFailed_ReturnError, TestSize.Level0)
{
    HapTokenInfo validInfo{};
    validInfo.bundleName = SOURCE_BUNDLE;
    validInfo.userID = TEST_USER;
    EXPECT_CALL(*token_, GetHapTokenInfo(SOURCE_TOKEN, _))
        .WillOnce(DoAll(SetArgReferee<1>(validInfo), Return(RET_SUCCESS)))
        .WillOnce(Return(-1));
    EXPECT_EQ(service_.RegisterVirtualEntry(query_.key, 0, MakeServiceEntry(), provider_->AsObject()), E_ERROR);
}

/**
 * @tc.name: RegisterVirtualEntry_ProviderDeathRegistrationFailed_ReturnErrorAndRollback
 * @tc.desc: A provider without death tracking must not leave an unusable pending session.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfVirtualEntryServiceTest, RegisterVirtualEntry_ProviderDeathRegistrationFailed_ReturnErrorAndRollback,
    TestSize.Level0)
{
    provider_->acceptDeathRecipient = false;
    EXPECT_EQ(service_.RegisterVirtualEntry(query_.key, 0, MakeServiceEntry(), provider_->AsObject()), E_ERROR);
    UdmfFuseSessionManager::SessionInfo info;
    EXPECT_FALSE(manager_.Get(query_.key, info));
    EXPECT_EQ(UdmfFuseMountAdapterMock::mounts, 0u);
}

/**
 * @tc.name: RegisterVirtualEntry_ValidSource_CreatePendingSessionWithoutMount
 * @tc.desc: Persist source token, user, record index and metadata without starting FUSE before drop.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(
    UdmfVirtualEntryServiceTest, RegisterVirtualEntry_ValidSource_CreatePendingSessionWithoutMount, TestSize.Level0)
{
    ASSERT_EQ(IPCSkeleton::GetCallingTokenID(), SOURCE_TOKEN);
    ASSERT_EQ(service_.RegisterVirtualEntry(query_.key, 0, MakeServiceEntry(), provider_->AsObject()), E_OK);
    UdmfFuseSessionManager::SessionInfo info;
    ASSERT_TRUE(manager_.Get(query_.key, info));
    EXPECT_EQ(info.userId, TEST_USER);
    EXPECT_EQ(info.sourceTokenId, SOURCE_TOKEN);
    EXPECT_EQ(info.recordIndex, 0u);
    EXPECT_GT(info.generation, 0u);
    EXPECT_EQ(info.root.id, "virtual-file");
    EXPECT_EQ(info.root.size, FILE_BYTES);
    EXPECT_EQ(info.provider, provider_->AsObject());
    EXPECT_EQ(info.state, UdmfFuseSessionManager::State::PENDING_DROP);
    EXPECT_EQ(UdmfFuseMountAdapterMock::mounts, 0u);
}

/**
 * @tc.name: RegisterVirtualEntry_DuplicateRegistration_PreserveExistingSession
 * @tc.desc: A second registration fails without replacing the original provider session.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(
    UdmfVirtualEntryServiceTest, RegisterVirtualEntry_DuplicateRegistration_PreserveExistingSession, TestSize.Level0)
{
    ASSERT_EQ(service_.RegisterVirtualEntry(query_.key, 0, MakeServiceEntry(), provider_->AsObject()), E_OK);
    UdmfFuseSessionManager::SessionInfo original;
    ASSERT_TRUE(manager_.Get(query_.key, original));
    EXPECT_EQ(service_.RegisterVirtualEntry(query_.key, 0, MakeServiceEntry(), provider_->AsObject()), E_ERROR);
    UdmfFuseSessionManager::SessionInfo current;
    ASSERT_TRUE(manager_.Get(query_.key, current));
    EXPECT_EQ(current.generation, original.generation);
    EXPECT_EQ(current.provider, original.provider);
}

/**
 * @tc.name: GetData_TwoVirtualMarkers_RejectAmbiguousRoot
 * @tc.desc: A drag with multiple persisted virtual root markers must fail before activation.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfVirtualEntryServiceTest, GetData_TwoVirtualMarkers_RejectAmbiguousRoot, TestSize.Level0)
{
    SetRecords({ MakeMarkedRecord(), MakeMarkedRecord() });
    ASSERT_EQ(RegisterSession(), 0);
    UnifiedData result;
    EXPECT_EQ(service_.GetData(query_, result), E_INVALID_PARAMETERS);
    EXPECT_EQ(UdmfFuseMountAdapterMock::mounts, 0u);
}

/**
 * @tc.name: GetData_SessionWithoutMarker_RemoveOrphanSession
 * @tc.desc: A pending session cannot turn an ordinary persisted record into a virtual file.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfVirtualEntryServiceTest, GetData_SessionWithoutMarker_RemoveOrphanSession, TestSize.Level0)
{
    SetRecords({ MakeMarkedRecord(false) });
    ASSERT_EQ(RegisterSession(), 0);
    UnifiedData result;
    EXPECT_EQ(service_.GetData(query_, result), E_INVALID_PARAMETERS);
    UdmfFuseSessionManager::SessionInfo info;
    EXPECT_FALSE(manager_.Get(query_.key, info));
    EXPECT_EQ(UdmfFuseMountAdapterMock::mounts, 0u);
}

/**
 * @tc.name: GetData_MarkerWithoutSession_ReturnFileSystemError
 * @tc.desc: Lost in-memory provider state must not expose the source placeholder URI.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfVirtualEntryServiceTest, GetData_MarkerWithoutSession_ReturnFileSystemError, TestSize.Level0)
{
    UnifiedData result;
    EXPECT_EQ(service_.GetData(query_, result), E_FS_ERROR);
    EXPECT_EQ(UdmfFuseMountAdapterMock::mounts, 0u);
    storedData_.GetRuntime()->privileges.front().readPermission.clear();
    EXPECT_EQ(service_.GetData(query_, result), E_FS_ERROR);
}

/**
 * @tc.name: GetData_SessionSourceOrRecordMismatch_DenyActivation
 * @tc.desc: The session must match both the persisted source token and the marked record index.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfVirtualEntryServiceTest, GetData_SessionSourceOrRecordMismatch_DenyActivation, TestSize.Level0)
{
    ASSERT_EQ(RegisterSession(0, TARGET_TOKEN), 0);
    UnifiedData result;
    EXPECT_EQ(service_.GetData(query_, result), E_NO_PERMISSION);
    manager_.Remove(query_.key);
    SetRecords({ MakeMarkedRecord(), std::make_shared<Text>() });
    ASSERT_EQ(RegisterSession(1), 0);
    EXPECT_EQ(service_.GetData(query_, result), E_NO_PERMISSION);
    EXPECT_EQ(UdmfFuseMountAdapterMock::mounts, 0u);
}

/**
 * @tc.name: GetData_TargetUserMismatch_DenyCrossUserVirtualFile
 * @tc.desc: Ordinary URI processing must not permit activation for another account's mount.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfVirtualEntryServiceTest, GetData_TargetUserMismatch_DenyCrossUserVirtualFile, TestSize.Level0)
{
    ASSERT_EQ(RegisterSession(0, SOURCE_TOKEN, TEST_USER + 1), 0);
    UnifiedData result;
    EXPECT_EQ(service_.GetData(query_, result), E_NO_PERMISSION);
    EXPECT_EQ(UdmfFuseMountAdapterMock::mounts, 0u);
}

/**
 * @tc.name: GetData_TargetUserLookupFailed_DenyActivation
 * @tc.desc: The target must remain a valid HAP account after URI authorization succeeds.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfVirtualEntryServiceTest, GetData_TargetUserLookupFailed_DenyActivation, TestSize.Level0)
{
    ASSERT_EQ(RegisterSession(), 0);
    ON_CALL(*token_, GetTokenTypeFlag(SOURCE_TOKEN)).WillByDefault(Return(TOKEN_NATIVE));
    NativeTokenInfo nativeInfo{};
    nativeInfo.processName = SOURCE_BUNDLE;
    ON_CALL(*token_, GetNativeTokenInfo(SOURCE_TOKEN, _))
        .WillByDefault(DoAll(SetArgReferee<1>(nativeInfo), Return(RET_SUCCESS)));
    UnifiedData result;
    EXPECT_EQ(service_.GetData(query_, result), E_NO_PERMISSION);
    EXPECT_EQ(UdmfFuseMountAdapterMock::mounts, 0u);
}

/**
 * @tc.name: GetData_UriAuthorizationMetadataFailed_KeepSessionPending
 * @tc.desc: Failure before FUSE activation must not consume or mount the pending session.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfVirtualEntryServiceTest, GetData_UriAuthorizationMetadataFailed_KeepSessionPending, TestSize.Level0)
{
    ASSERT_EQ(RegisterSession(), 0);
    HapTokenInfo validInfo{};
    validInfo.bundleName = SOURCE_BUNDLE;
    validInfo.userID = TEST_USER;
    EXPECT_CALL(*token_, GetHapTokenInfo(SOURCE_TOKEN, _))
        .WillOnce(DoAll(SetArgReferee<1>(validInfo), Return(RET_SUCCESS)))
        .WillOnce(Return(-1));
    UnifiedData result;
    EXPECT_EQ(service_.GetData(query_, result), E_ERROR);
    UdmfFuseSessionManager::SessionInfo info;
    ASSERT_TRUE(manager_.Get(query_.key, info));
    EXPECT_EQ(info.state, UdmfFuseSessionManager::State::PENDING_DROP);
    EXPECT_EQ(UdmfFuseMountAdapterMock::mounts, 0u);
}

/**
 * @tc.name: GetData_MountFailed_RetainPendingSessionAndAllowRetry
 * @tc.desc: A failed storage mount must preserve the pending session so a later retrieval can succeed.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfVirtualEntryServiceTest, GetData_MountFailed_RetainPendingSessionAndAllowRetry, TestSize.Level0)
{
    ASSERT_EQ(RegisterSession(), 0);
    UdmfFuseMountAdapterMock::mountStatus = -EIO;
    UnifiedData result;
    EXPECT_EQ(service_.GetData(query_, result), E_FS_ERROR);
    UdmfFuseSessionManager::SessionInfo info;
    ASSERT_TRUE(manager_.Get(query_.key, info));
    EXPECT_EQ(info.state, UdmfFuseSessionManager::State::PENDING_DROP);
    EXPECT_EQ(UdmfFuseMountAdapterMock::mounts, 1u);

    UdmfFuseMountAdapterMock::mountStatus = 0;
    EXPECT_EQ(service_.GetData(query_, result), E_OK);
    ASSERT_TRUE(manager_.Get(query_.key, info));
    EXPECT_EQ(info.state, UdmfFuseSessionManager::State::ACTIVE);
    EXPECT_EQ(UdmfFuseMountAdapterMock::mounts, 2u);
}

/**
 * @tc.name: GetData_ValidVirtualFile_ReplaceUriAndRemoveOnlyInternalMarker
 * @tc.desc: Successful drop returns the sandbox FUSE URI while preserving unrelated details.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfVirtualEntryServiceTest, GetData_ValidVirtualFile_ReplaceUriAndRemoveOnlyInternalMarker, TestSize.Level0)
{
    ASSERT_EQ(RegisterSession(), 0);
    UnifiedData result;
    ASSERT_EQ(service_.GetData(query_, result), E_OK);
    UdmfFuseSessionManager::SessionInfo info;
    ASSERT_TRUE(manager_.Get(query_.key, info));
    EXPECT_EQ(info.state, UdmfFuseSessionManager::State::ACTIVE);
    EXPECT_EQ(info.targetTokenId, SOURCE_TOKEN);
    EXPECT_EQ(info.targetUid, IPCSkeleton::GetCallingUid());
    ASSERT_EQ(result.GetRecords().size(), 1u);
    auto value = result.GetRecords()[0]->GetEntry(GENERAL_FILE_URI);
    ASSERT_TRUE(std::holds_alternative<std::shared_ptr<Object>>(value));
    auto object = std::get<std::shared_ptr<Object>>(value);
    ASSERT_NE(object, nullptr);
    std::string uri;
    ASSERT_TRUE(object->GetValue(ORI_URI, uri));
    EXPECT_NE(uri.find(UdmfFuseSessionManager::GetAppMountPoint(TEST_USER)), std::string::npos);
    EXPECT_NE(uri.find(info.alias), std::string::npos);
    EXPECT_NE(uri.find("example.bin"), std::string::npos);
    std::shared_ptr<Object> details;
    ASSERT_TRUE(object->GetValue(DETAILS, details));
    ASSERT_NE(details, nullptr);
    EXPECT_EQ(details->value_.count(VIRTUAL_ENTRY_FLAG), 0u);
    std::string preserved;
    EXPECT_TRUE(details->GetValue("business-detail", preserved));
    EXPECT_EQ(preserved, "preserved");
    EXPECT_EQ(provider_->remoteRequests.load(), 0u);
}

/**
 * @tc.name: GetData_VirtualRecordAfterText_PreserveOtherRecordsAndSelectCorrectIndex
 * @tc.desc: Activation must exclude only the virtual record from ordinary URI authorization.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfVirtualEntryServiceTest, GetData_VirtualRecordAfterText_PreserveOtherRecordsAndSelectCorrectIndex,
    TestSize.Level0)
{
    auto text = std::make_shared<Text>();
    SetRecords({ text, MakeMarkedRecord() });
    ASSERT_EQ(RegisterSession(1), 0);
    UnifiedData result;
    ASSERT_EQ(service_.GetData(query_, result), E_OK);
    ASSERT_EQ(result.GetRecords().size(), 2u);
    EXPECT_EQ(result.GetRecords()[0], text);
    EXPECT_EQ(result.GetRecords()[0]->GetType(), TEXT);
    auto object = std::get<std::shared_ptr<Object>>(result.GetRecords()[1]->GetEntry(GENERAL_FILE_URI));
    std::string uri;
    ASSERT_NE(object, nullptr);
    EXPECT_TRUE(object->GetValue(ORI_URI, uri));
    EXPECT_NE(uri.find("example.bin"), std::string::npos);
}

/**
 * @tc.name: GetData_LifecycleRemovalFailed_RollbackActivatedSession
 * @tc.desc: A consume-on-read failure after activation must release its FUSE session.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfVirtualEntryServiceTest, GetData_LifecycleRemovalFailed_RollbackActivatedSession, TestSize.Level0)
{
    storedData_.GetRuntime()->privileges.front().readPermission.clear();
    ASSERT_EQ(RegisterSession(), 0);
    UnifiedData result;
    EXPECT_EQ(service_.GetData(query_, result), E_DB_ERROR);
    UdmfFuseSessionManager::SessionInfo info;
    EXPECT_FALSE(manager_.Get(query_.key, info));
    EXPECT_EQ(UdmfFuseMountAdapterMock::mounts, 1u);
    EXPECT_EQ(UdmfFuseMountAdapterMock::unmounts, 1u);
}

/**
 * @tc.name: GetData_UnauthorizedRequester_DenyBeforeMount
 * @tc.desc: Knowing a key is insufficient to obtain another application's virtual file.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfVirtualEntryServiceTest, GetData_UnauthorizedRequester_DenyBeforeMount, TestSize.Level0)
{
    query_.tokenId = TARGET_TOKEN;
    ASSERT_EQ(RegisterSession(), 0);
    UnifiedData result;
    EXPECT_EQ(service_.GetData(query_, result), E_NO_PERMISSION);
    EXPECT_EQ(UdmfFuseMountAdapterMock::mounts, 0u);
    UdmfFuseSessionManager::SessionInfo info;
    ASSERT_TRUE(manager_.Get(query_.key, info));
    EXPECT_EQ(info.state, UdmfFuseSessionManager::State::PENDING_DROP);
}

/**
 * @tc.name: GetData_FileManagerWithDesktopPrivilege_ReachActivationAfterProxyAuthorization
 * @tc.desc: The desktop-to-file-manager exception is evaluated when direct token validation fails.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfVirtualEntryServiceTest, GetData_FileManagerWithDesktopPrivilege_ReachActivationAfterProxyAuthorization,
    TestSize.Level0)
{
    ConfigureProxyTokens();
    ASSERT_EQ(RegisterSession(), 0);
    UdmfFuseMountAdapterMock::mountStatus = -EIO;
    UnifiedData result;
    EXPECT_EQ(service_.GetData(query_, result), E_FS_ERROR);
    EXPECT_EQ(UdmfFuseMountAdapterMock::mounts, 1u);
}

/**
 * @tc.name: GetData_CachedDesktopPrivilege_IncludeCachedTokensInProxyAuthorization
 * @tc.desc: A desktop privilege cached before data arrives must participate in virtual proxy validation.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfVirtualEntryServiceTest, GetData_CachedDesktopPrivilege_IncludeCachedTokensInProxyAuthorization,
    TestSize.Level0)
{
    ConfigureProxyTokens();
    storedData_.GetRuntime()->privileges.clear();
    service_.privilegeCache_[query_.key] = { { DESKTOP_TOKEN, "readAndKeep", "" } };
    ASSERT_EQ(RegisterSession(), 0);
    UdmfFuseMountAdapterMock::mountStatus = -EIO;
    UnifiedData result;
    EXPECT_EQ(service_.GetData(query_, result), E_FS_ERROR);
    EXPECT_EQ(UdmfFuseMountAdapterMock::mounts, 1u);
}

/**
 * @tc.name: GetData_DesktopFromDifferentUser_DenyProxyAuthorization
 * @tc.desc: A desktop privilege belonging to another account must not authorize a virtual file.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfVirtualEntryServiceTest, GetData_DesktopFromDifferentUser_DenyProxyAuthorization, TestSize.Level0)
{
    ConfigureProxyTokens(TEST_USER + 1);
    ASSERT_EQ(RegisterSession(), 0);
    UnifiedData result;
    EXPECT_EQ(service_.GetData(query_, result), E_NO_PERMISSION);
    EXPECT_EQ(UdmfFuseMountAdapterMock::mounts, 0u);
}

/**
 * @tc.name: GetData_ProxyWithoutVirtualMarker_DenyExceptionForOrdinaryData
 * @tc.desc: The desktop exception must not expand authorization for an ordinary file record.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfVirtualEntryServiceTest, GetData_ProxyWithoutVirtualMarker_DenyExceptionForOrdinaryData, TestSize.Level0)
{
    ConfigureProxyTokens();
    SetRecords({ MakeMarkedRecord(false) });
    UnifiedData result;
    EXPECT_EQ(service_.GetData(query_, result), E_NO_PERMISSION);
    EXPECT_EQ(UdmfFuseMountAdapterMock::mounts, 0u);
}

/**
 * @tc.name: GetData_ProxyWithNonDragIntention_DenyExceptionOutsideDrag
 * @tc.desc: A virtual marker must not enable desktop proxy access outside the drag intention.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfVirtualEntryServiceTest, GetData_ProxyWithNonDragIntention_DenyExceptionOutsideDrag, TestSize.Level0)
{
    ConfigureProxyTokens();
    query_.intention = UD_INTENTION_DATA_HUB;
    UnifiedData result;
    EXPECT_EQ(service_.GetData(query_, result), E_NO_PERMISSION);
    EXPECT_EQ(UdmfFuseMountAdapterMock::mounts, 0u);
}

/**
 * @tc.name: RegisterVirtualEntry_NullFileObject_RejectAbsentVirtualMetadata
 * @tc.desc: A file entry containing a null object must not be accepted as a marked virtual record.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfVirtualEntryServiceTest, RegisterVirtualEntry_NullFileObject_RejectAbsentVirtualMetadata, TestSize.Level0)
{
    auto record = MakeMarkedRecord();
    record->SetValue(std::shared_ptr<Object>());
    SetRecords({ record });
    EXPECT_EQ(
        service_.RegisterVirtualEntry(query_.key, 0, MakeServiceEntry(), provider_->AsObject()), E_INVALID_PARAMETERS);
}

/**
 * @tc.name: RegisterVirtualEntry_NonFileRecordWithMarker_RejectMisleadingEntry
 * @tc.desc: A record's file-URI entry cannot override the required FILE record type.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(
    UdmfVirtualEntryServiceTest, RegisterVirtualEntry_NonFileRecordWithMarker_RejectMisleadingEntry, TestSize.Level0)
{
    auto record = MakeMarkedRecord();
    record->SetType(TEXT);
    record->SetUtdId2(GENERAL_FILE_URI);
    SetRecords({ record });
    EXPECT_EQ(
        service_.RegisterVirtualEntry(query_.key, 0, MakeServiceEntry(), provider_->AsObject()), E_INVALID_PARAMETERS);
}

/**
 * @tc.name: RegisterVirtualEntry_NativeSourceCannotResolveHapUser_ReturnError
 * @tc.desc: A verified native process identity cannot substitute for a HAP user's FUSE mount.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(
    UdmfVirtualEntryServiceTest, RegisterVirtualEntry_NativeSourceCannotResolveHapUser_ReturnError, TestSize.Level0)
{
    ON_CALL(*token_, GetTokenTypeFlag(SOURCE_TOKEN)).WillByDefault(Return(TOKEN_NATIVE));
    NativeTokenInfo nativeInfo{};
    nativeInfo.processName = SOURCE_BUNDLE;
    ON_CALL(*token_, GetNativeTokenInfo(SOURCE_TOKEN, _))
        .WillByDefault(DoAll(SetArgReferee<1>(nativeInfo), Return(RET_SUCCESS)));
    EXPECT_EQ(service_.RegisterVirtualEntry(query_.key, 0, MakeServiceEntry(), provider_->AsObject()), E_ERROR);
}

/**
 * @tc.name: RegisterVirtualEntry_NewRegistrationAfterRemoval_AdvanceGeneration
 * @tc.desc: A new drag session must have a fresh generation after the previous registration is removed.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(
    UdmfVirtualEntryServiceTest, RegisterVirtualEntry_NewRegistrationAfterRemoval_AdvanceGeneration, TestSize.Level0)
{
    ASSERT_EQ(service_.RegisterVirtualEntry(query_.key, 0, MakeServiceEntry(), provider_->AsObject()), E_OK);
    UdmfFuseSessionManager::SessionInfo original;
    ASSERT_TRUE(manager_.Get(query_.key, original));
    manager_.Remove(query_.key);
    ASSERT_EQ(service_.RegisterVirtualEntry(query_.key, 0, MakeServiceEntry(), provider_->AsObject()), E_OK);
    UdmfFuseSessionManager::SessionInfo current;
    ASSERT_TRUE(manager_.Get(query_.key, current));
    EXPECT_GT(current.generation, original.generation);
    EXPECT_EQ(current.state, UdmfFuseSessionManager::State::PENDING_DROP);
}

/**
 * @tc.name: GetData_NoVirtualMarkerOrSession_BypassFuseActivation
 * @tc.desc: The new virtual-data path must leave unmarked ordinary file reads on their original path.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfVirtualEntryServiceTest, GetData_NoVirtualMarkerOrSession_BypassFuseActivation, TestSize.Level0)
{
    SetRecords({ MakeMarkedRecord(false) });
    UnifiedData result;
    ASSERT_EQ(service_.GetData(query_, result), E_OK);
    EXPECT_EQ(UdmfFuseMountAdapterMock::mounts, 0u);
    ASSERT_EQ(result.GetRecords().size(), 1u);
    auto value = result.GetRecords()[0]->GetEntry(GENERAL_FILE_URI);
    ASSERT_TRUE(std::holds_alternative<std::shared_ptr<Object>>(value));
    auto object = std::get<std::shared_ptr<Object>>(value);
    ASSERT_NE(object, nullptr);
    std::string uri;
    EXPECT_TRUE(object->GetValue(ORI_URI, uri));
    EXPECT_EQ(uri, "file:///virtual/example.bin");
}

/**
 * @tc.name: GetData_UnmarkedConsumeFails_DoNotMountFuse
 * @tc.desc: The no-marker branch preserves lifecycle errors without allocating virtual-file resources.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfVirtualEntryServiceTest, GetData_UnmarkedConsumeFails_DoNotMountFuse, TestSize.Level0)
{
    SetRecords({ MakeMarkedRecord(false) });
    storedData_.GetRuntime()->privileges.front().readPermission.clear();
    UnifiedData result;
    EXPECT_EQ(service_.GetData(query_, result), E_DB_ERROR);
    EXPECT_EQ(UdmfFuseMountAdapterMock::mounts, 0u);
}

/**
 * @tc.name: GetData_CachedTargetPrivilege_ActivateAndConsumeCachedAuthorization
 * @tc.desc: The cache authorizes the initial drop but must not grant a subsequent unprivileged retrieval.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(
    UdmfVirtualEntryServiceTest, GetData_CachedTargetPrivilege_ActivateAndConsumeCachedAuthorization, TestSize.Level0)
{
    query_.tokenId = TARGET_TOKEN;
    service_.privilegeCache_[query_.key] = { { TARGET_TOKEN, "readAndKeep", "" } };
    ASSERT_EQ(RegisterSession(), 0);
    UnifiedData result;
    ASSERT_EQ(service_.GetData(query_, result), E_OK);
    UdmfFuseSessionManager::SessionInfo info;
    ASSERT_TRUE(manager_.Get(query_.key, info));
    EXPECT_EQ(info.targetTokenId, TARGET_TOKEN);
    EXPECT_EQ(service_.GetData(query_, result), E_NO_PERMISSION);
}

/**
 * @tc.name: GetData_FileManagerWithoutDesktopGrant_DenyProxyException
 * @tc.desc: A file-manager identity alone must not bypass the source's drag authorization.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfVirtualEntryServiceTest, GetData_FileManagerWithoutDesktopGrant_DenyProxyException, TestSize.Level0)
{
    ConfigureProxyTokens();
    storedData_.GetRuntime()->privileges = { { SOURCE_TOKEN, "readAndKeep", "" } };
    ASSERT_EQ(RegisterSession(), 0);
    UnifiedData result;
    EXPECT_EQ(service_.GetData(query_, result), E_NO_PERMISSION);
    EXPECT_EQ(UdmfFuseMountAdapterMock::mounts, 0u);
}

/**
 * @tc.name: GetData_ActiveSessionWithAnotherTarget_RejectRetargeting
 * @tc.desc: Even an otherwise authorized reader cannot retarget an already activated virtual session.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfVirtualEntryServiceTest, GetData_ActiveSessionWithAnotherTarget_RejectRetargeting, TestSize.Level0)
{
    ASSERT_EQ(RegisterSession(), 0);
    UnifiedData result;
    ASSERT_EQ(service_.GetData(query_, result), E_OK);
    SetRecords({ MakeMarkedRecord() });
    storedData_.GetRuntime()->privileges = { { TARGET_TOKEN, "readAndKeep", "" } };
    query_.tokenId = TARGET_TOKEN;
    EXPECT_EQ(service_.GetData(query_, result), E_FS_ERROR);
    UdmfFuseSessionManager::SessionInfo info;
    ASSERT_TRUE(manager_.Get(query_.key, info));
    EXPECT_EQ(info.targetTokenId, SOURCE_TOKEN);
}

/**
 * @tc.name: RegisterVirtualEntry_DirectoryRoot_PreserveChildMetadata
 * @tc.desc: Directory roots pass through the same public registration path with explicit child sizes.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfVirtualEntryServiceTest, RegisterVirtualEntry_DirectoryRoot_PreserveChildMetadata, TestSize.Level0)
{
    VirtualEntry directory;
    directory.type = VirtualEntryType::DIRECTORY;
    directory.name = "documents";
    directory.subItems = { MakeServiceEntry() };
    ASSERT_EQ(service_.RegisterVirtualEntry(query_.key, 0, directory, provider_->AsObject()), E_OK);
    UdmfFuseSessionManager::SessionInfo info;
    ASSERT_TRUE(manager_.Get(query_.key, info));
    EXPECT_EQ(info.root.type, VirtualEntryType::DIRECTORY);
    ASSERT_EQ(info.root.subItems.size(), 1u);
    EXPECT_EQ(info.root.subItems[0].id, "virtual-file");
    EXPECT_EQ(info.root.subItems[0].size, FILE_BYTES);
    EXPECT_EQ(UdmfFuseMountAdapterMock::mounts, 0u);
}

/**
 * @tc.name: GetData_ExplicitZeroSizeFile_ActivateWithoutDownloading
 * @tc.desc: Size zero is a valid empty file and activation must not request provider data or metadata.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfVirtualEntryServiceTest, GetData_ExplicitZeroSizeFile_ActivateWithoutDownloading, TestSize.Level0)
{
    auto entry = MakeServiceEntry();
    entry.size = 0;
    ASSERT_EQ(service_.RegisterVirtualEntry(query_.key, 0, entry, provider_->AsObject()), E_OK);
    UnifiedData result;
    ASSERT_EQ(service_.GetData(query_, result), E_OK);
    UdmfFuseSessionManager::SessionInfo info;
    ASSERT_TRUE(manager_.Get(query_.key, info));
    EXPECT_EQ(info.root.size, 0);
    EXPECT_EQ(info.state, UdmfFuseSessionManager::State::ACTIVE);
    EXPECT_EQ(provider_->remoteRequests.load(), 0u);
}

/**
 * @tc.name: GetData_DirectoryRoot_ReturnDirectoryUriWithoutProviderReads
 * @tc.desc: The registration and drop path supports directory roots with known-size children.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfVirtualEntryServiceTest, GetData_DirectoryRoot_ReturnDirectoryUriWithoutProviderReads, TestSize.Level0)
{
    VirtualEntry directory;
    directory.type = VirtualEntryType::DIRECTORY;
    directory.name = "documents";
    directory.subItems = { MakeServiceEntry() };
    ASSERT_EQ(service_.RegisterVirtualEntry(query_.key, 0, directory, provider_->AsObject()), E_OK);
    UnifiedData result;
    ASSERT_EQ(service_.GetData(query_, result), E_OK);
    ASSERT_EQ(result.GetRecords().size(), 1u);
    auto value = result.GetRecords()[0]->GetEntry(GENERAL_FILE_URI);
    ASSERT_TRUE(std::holds_alternative<std::shared_ptr<Object>>(value));
    auto object = std::get<std::shared_ptr<Object>>(value);
    ASSERT_NE(object, nullptr);
    std::string uri;
    EXPECT_TRUE(object->GetValue(ORI_URI, uri));
    EXPECT_NE(uri.find("/documents"), std::string::npos);
    EXPECT_EQ(provider_->remoteRequests.load(), 0u);
}

/**
 * @tc.name: OnBind_NoExecutor_KeepVirtualDropAvailableWithoutBackgroundTasks
 * @tc.desc: The new FUSE executor binding permits activation with no executor and preserves read-and-keep behavior.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfVirtualEntryServiceTest, OnBind_NoExecutor_KeepVirtualDropAvailableWithoutBackgroundTasks, TestSize.Level0)
{
    DistributedData::FeatureSystem::Feature::BindInfo bindInfo{};
    ASSERT_EQ(service_.OnBind(bindInfo), 0);
    ASSERT_EQ(service_.RegisterVirtualEntry(query_.key, 0, MakeServiceEntry(), provider_->AsObject()), E_OK);
    UnifiedData result;
    EXPECT_EQ(service_.GetData(query_, result), E_OK);
    UdmfFuseSessionManager::SessionInfo info;
    ASSERT_TRUE(manager_.Get(query_.key, info));
    EXPECT_EQ(info.state, UdmfFuseSessionManager::State::ACTIVE);
    EXPECT_EQ(info.expiryTask, ExecutorPool::INVALID_TASK_ID);
    EXPECT_EQ(info.cleanupTask, ExecutorPool::INVALID_TASK_ID);
}

/**
 * @tc.name: GetData_ConsumeVirtualFile_LifecycleAcceptedAndSessionRemainsReadable
 * @tc.desc: Successful consume-on-read schedules metadata removal while retaining the activated FUSE file.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfVirtualEntryServiceTest, GetData_ConsumeVirtualFile_LifecycleAcceptedAndSessionRemainsReadable,
    TestSize.Level0)
{
    boundExecutor_ = std::make_shared<ExecutorPool>(1, 1);
    DistributedData::FeatureSystem::Feature::BindInfo bindInfo{};
    bindInfo.executors = boundExecutor_;
    ASSERT_EQ(service_.OnBind(bindInfo), 0);
    storedData_.GetRuntime()->privileges.front().readPermission.clear();
    ASSERT_EQ(RegisterSession(), 0);
    auto deletion = std::make_shared<std::promise<void>>();
    auto completed = deletion->get_future();
    EXPECT_CALL(*store_, Delete(_)).WillOnce(Invoke([deletion](const std::string &) {
        deletion->set_value();
        return E_OK;
    }));

    UnifiedData result;
    EXPECT_EQ(service_.GetData(query_, result), E_OK);
    EXPECT_EQ(completed.wait_for(std::chrono::seconds(2)), std::future_status::ready);
    UdmfFuseSessionManager::SessionInfo info;
    ASSERT_TRUE(manager_.Get(query_.key, info));
    EXPECT_EQ(info.state, UdmfFuseSessionManager::State::ACTIVE);
    EXPECT_NE(info.expiryTask, ExecutorPool::INVALID_TASK_ID);
    EXPECT_NE(info.cleanupTask, ExecutorPool::INVALID_TASK_ID);
    EXPECT_EQ(UdmfFuseMountAdapterMock::mounts, 1u);
}

/**
 * @tc.name: GetData_ConsumeUnmarkedFile_LifecycleAcceptedWithoutFuse
 * @tc.desc: The no-marker branch may consume ordinary data without activating a FUSE controller.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfVirtualEntryServiceTest, GetData_ConsumeUnmarkedFile_LifecycleAcceptedWithoutFuse, TestSize.Level0)
{
    boundExecutor_ = std::make_shared<ExecutorPool>(1, 1);
    DistributedData::FeatureSystem::Feature::BindInfo bindInfo{};
    bindInfo.executors = boundExecutor_;
    ASSERT_EQ(service_.OnBind(bindInfo), 0);
    SetRecords({ MakeMarkedRecord(false) });
    storedData_.GetRuntime()->privileges.front().readPermission.clear();
    auto deletion = std::make_shared<std::promise<void>>();
    auto completed = deletion->get_future();
    EXPECT_CALL(*store_, Delete(_)).WillOnce(Invoke([deletion](const std::string &) {
        deletion->set_value();
        return E_OK;
    }));

    UnifiedData result;
    EXPECT_EQ(service_.GetData(query_, result), E_OK);
    EXPECT_EQ(completed.wait_for(std::chrono::seconds(2)), std::future_status::ready);
    EXPECT_EQ(UdmfFuseMountAdapterMock::mounts, 0u);
}
} // namespace OHOS::UDMF
