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
#include <limits>
#include <mutex>
#include <thread>

#include "accesstoken_kit.h"
#include "bootstrap.h"
#include "error_code.h"
#include "executor_pool.h"
#include "gtest/gtest.h"
#include "ipc_skeleton.h"
#include "iremote_stub.h"
#include "kvstore_meta_manager.h"
#include "mock/access_token_mock.h"
#include "mock/meta_data_manager_mock.h"
#include "nativetoken_kit.h"
#include "text.h"
#include "token_setproc.h"
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

/**
 * @tc.name: GetUdmfFuseMountPoint_SeparatedPaths_ReturnExpectedPath
 * @tc.desc: Verify the service mount point is mapped to the application sandbox path.
 * @tc.type: FUNC
 */
HWTEST_F(UdmfServiceImplMockTest, GetUdmfFuseMountPoint_SeparatedPaths_ReturnExpectedPath, TestSize.Level0)
{
    EXPECT_EQ(UdmfFuseSessionManager::GetMountPoint(100), "/mnt/data/100/udmf_fuse");
    EXPECT_EQ(UdmfFuseSessionManager::GetAppMountPoint(100), "/data/storage/el2/udmf");
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
 */
HWTEST_F(UdmfServiceImplMockTest, LoadFuseBlock_ProviderShortRead_FillExpectedBlock, TestSize.Level0)
{
    std::vector<uint8_t> content{ 0, 1, 2, 3, 4, 5, 6 };
    sptr<FuseReadProvider> provider = new FuseReadProvider(content, 2);
    UdmfFuseController controller(100);
    UdmfFuseController::Node node;
    node.inode = FUSE_ROOT_ID + 1;
    node.entry.id = "short-read-file";
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

    EXPECT_EQ(controller.ProviderRead(provider->AsObject(), "timeout-session", "timeout-file", 0, 1, deadline, bytes),
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
            EXPECT_EQ(
                controller.ProviderRead(provider->AsObject(), "single-session", "file", 0, 1, deadline, bytes), 0);
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
            EXPECT_EQ(firstController.ProviderRead(
                          firstProvider->AsObject(), "active-session", "active-file", 0, 1, deadline, bytes),
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
        waitingResult = secondController.ProviderRead(
            waitingProvider->AsObject(), "waiting-session", "waiting-file", 0, 1, deadline, bytes);
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
            EXPECT_EQ(controller.ProviderRead(
                          activeProvider->AsObject(), "active-session", "active-file", 0, 1, deadline, bytes),
                0);
        });
    }
    EXPECT_TRUE(WaitForAsyncRequests(activeProvider, 3, deadline));
    std::thread borrowedRead([&controller, &borrowedProvider, deadline] {
        std::vector<uint8_t> bytes;
        EXPECT_EQ(controller.ProviderRead(
                      borrowedProvider->AsObject(), "active-session", "borrowed-file", 0, 1, deadline, bytes),
            0);
    });
    std::thread waitingRead([&controller, &waitingProvider, deadline] {
        std::vector<uint8_t> bytes;
        EXPECT_EQ(controller.ProviderRead(
                      waitingProvider->AsObject(), "waiting-session", "waiting-file", 0, 1, deadline, bytes),
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
            controller.ProviderRead(provider->AsObject(), "circuit-session", "timeout-file", 0, 1, deadline, bytes),
            -ETIMEDOUT);
    }
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(50);
    EXPECT_EQ(controller.ProviderRead(provider->AsObject(), "circuit-session", "timeout-file", 0, 1, deadline, bytes),
        -ETIMEDOUT);
    EXPECT_EQ(provider->asyncRequestCount_, 3);
}
} // namespace DistributedDataTest
} // namespace OHOS::Test
