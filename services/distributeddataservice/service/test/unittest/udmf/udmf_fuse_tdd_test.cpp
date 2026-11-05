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
#include <fcntl.h>
#include <limits>
#include <mutex>
#include <string>
#include <sys/eventfd.h>
#include <thread>
#include <unistd.h>
#include <vector>

#include "gtest/gtest.h"
#include "iremote_stub.h"
#include "udmf_fuse_controller.h"
#include "udmf_fuse_lowlevel_mock.h"
#include "udmf_fuse_mount_adapter_mock.h"
#include "udmf_fuse_session_manager.h"
#include "virtual_entry_provider.h"
#include "virtual_entry_read_callback_proxy.h"

using namespace testing::ext;

namespace OHOS::UDMF {
namespace {
constexpr uid_t TARGET_UID = 20010001;
constexpr uid_t OTHER_UID = 20010002;
constexpr int32_t TEST_USER = 100;
constexpr uint32_t SOURCE_TOKEN = 8001;
constexpr uint32_t TARGET_TOKEN = 9001;
constexpr size_t BLOCK_BYTES = 5 * 1024 * 1024;
constexpr int64_t PROVIDER_MODIFY_TIME = 2345;
constexpr int64_t ENTRY_MODIFY_TIME = 1234;
constexpr int64_t DEFAULT_FILE_SIZE = 7;

class TddProvider final : public IRemoteStub<IVirtualEntryProvider> {
public:
    bool AddDeathRecipient(const sptr<DeathRecipient> &recipient) override
    {
        if (!acceptDeathRecipient) {
            return false;
        }
        deathRecipient = recipient;
        return true;
    }

    bool RemoveDeathRecipient(const sptr<DeathRecipient> &recipient) override
    {
        if (recipient == deathRecipient) {
            deathRecipient = nullptr;
        }
        return true;
    }

    bool IsObjectDead() const override
    {
        return dead;
    }

    int32_t Stat(const std::string &id, VirtualEntry &entry) override
    {
        ++statCalls;
        entry.id = mismatchId ? "wrong-id" : id;
        entry.type = VirtualEntryType::FILE;
        entry.modifyTime = PROVIDER_MODIFY_TIME;
        entry.size = unknownStatSize ? -1 : static_cast<int64_t>(content.size());
        return statStatus;
    }

    int32_t Read(const std::string &id, int64_t offset, int32_t length, std::vector<uint8_t> &data) override
    {
        (void)id;
        std::lock_guard<std::mutex> lock(mutex);
        ++readCalls;
        offsets.push_back(offset);
        lengths.push_back(length);
        int32_t status = readStatus;
        if (!statuses.empty()) {
            status = statuses.front();
            statuses.erase(statuses.begin());
        }
        if (status != 0) {
            return status;
        }
        if (static_cast<size_t>(offset) >= content.size()) {
            return 0;
        }
        size_t size = std::min({ static_cast<size_t>(length), maxReadBytes,
            content.size() - static_cast<size_t>(offset) });
        data.assign(content.begin() + offset, content.begin() + offset + size);
        if (oversizedResult) {
            data.push_back(0xFF);
        }
        return 0;
    }

    int32_t Cancel(const std::vector<std::string> &ids) override
    {
        canceledIds = ids;
        ++cancelCalls;
        return 0;
    }

    int32_t OnRemoteRequest(uint32_t code, MessageParcel &request, MessageParcel &reply, MessageOption &option) override
    {
        (void)reply;
        (void)option;
        if (request.ReadInterfaceToken() != GetDescriptor()) {
            return -EACCES;
        }
        if (transportStatus != 0) {
            return transportStatus;
        }
        if (code != static_cast<uint32_t>(VirtualEntryProviderCode::READ_ASYNC)) {
            return -EINVAL;
        }
        std::string id;
        int64_t offset = 0;
        int32_t length = 0;
        if (!request.ReadString(id) || !request.ReadInt64(offset) || !request.ReadInt32(length)) {
            return -EINVAL;
        }
        auto callback = request.ReadRemoteObject();
        if (callback == nullptr) {
            return -EINVAL;
        }
        if (suppressCallback) {
            pendingCallback = callback;
            return 0;
        }
        std::vector<uint8_t> bytes;
        int32_t status = Read(id, offset, length, bytes);
        VirtualEntryReadCallbackProxy proxy(callback);
        int32_t ret = proxy.OnResult(status, bytes);
        if (repeatCallback && ret == 0) {
            ret = proxy.OnResult(0, { 0xAA });
        }
        return ret;
    }

    std::vector<uint8_t> content{ 0, 1, 2, 3, 4, 5, 6 };
    size_t maxReadBytes = std::numeric_limits<size_t>::max();
    std::vector<int32_t> statuses;
    std::vector<int64_t> offsets;
    std::vector<int32_t> lengths;
    std::vector<std::string> canceledIds;
    int32_t readStatus = 0;
    int32_t statStatus = 0;
    int32_t transportStatus = 0;
    bool unknownStatSize = false;
    bool mismatchId = false;
    bool oversizedResult = false;
    bool suppressCallback = false;
    bool repeatCallback = false;
    bool acceptDeathRecipient = true;
    bool dead = false;
    std::atomic<size_t> statCalls{ 0 };
    std::atomic<size_t> readCalls{ 0 };
    size_t cancelCalls = 0;
    sptr<DeathRecipient> deathRecipient;
    sptr<IRemoteObject> pendingCallback;
    std::mutex mutex;
};

VirtualEntry MakeFile(int64_t size = DEFAULT_FILE_SIZE, const std::string &name = "example.bin")
{
    VirtualEntry entry;
    entry.id = name;
    entry.name = name;
    entry.size = size;
    entry.modifyTime = ENTRY_MODIFY_TIME;
    return entry;
}

VirtualEntry MakeDirectory(size_t count)
{
    VirtualEntry entry;
    entry.name = "directory";
    entry.type = VirtualEntryType::DIRECTORY;
    for (size_t index = 0; index < count; ++index) {
        entry.subItems.push_back(MakeFile(DEFAULT_FILE_SIZE, "file-" + std::to_string(index)));
    }
    return entry;
}
} // namespace

class UdmfFuseTddTest : public testing::Test {
public:
    void SetUp() override
    {
        UdmfFuseMountAdapterMock::Reset();
        UdmfFuseMountAdapterMock::mountStatus = 0;
        manager_.SetExecutor(nullptr);
        provider_ = new TddProvider();
    }

    void TearDown() override
    {
        provider_->pendingCallback = nullptr;
        UdmfFuseMountAdapterMock::unmountStatus = 0;
        for (const auto &id : ownedSessions_) {
            manager_.Remove(id);
            UdmfFuseSessionManager::SessionInfo info;
            while (manager_.Get(id, info) && info.openCount != 0) {
                manager_.ReleaseOpen(id);
            }
            manager_.Remove(id);
        }
        // Release a retained controller after a draining session closed without an executor.
        UdmfFuseSessionManager::SessionInfo cleanup;
        cleanup.userId = TEST_USER;
        cleanup.sourceTokenId = SOURCE_TOKEN;
        cleanup.generation = 1;
        cleanup.root = MakeFile(0);
        cleanup.provider = provider_->AsObject();
        (void)manager_.Register("tdd-cleanup-probe", cleanup);
        manager_.Remove("tdd-cleanup-probe");
        UdmfFuseMountAdapterMock::Reset();
    }

protected:
    int32_t Register(const VirtualEntry &root, const std::string &id = "tdd-session",
        uint32_t source = SOURCE_TOKEN, int32_t user = TEST_USER)
    {
        UdmfFuseSessionManager::SessionInfo info;
        info.userId = user;
        info.sourceTokenId = source;
        info.generation = 1;
        info.root = root;
        info.provider = provider_->AsObject();
        ownedSessions_.push_back(id);
        return manager_.Register(id, info);
    }

    int32_t ActivateFile(int64_t size = 7)
    {
        int32_t ret = Register(MakeFile(size));
        return ret == 0 ? manager_.Activate("tdd-session", TARGET_TOKEN, TARGET_UID, TARGET_UID, uri_) : ret;
    }

    fuse_ino_t Lookup(fuse_ino_t parent, const char *name, uid_t uid = TARGET_UID)
    {
        auto request = mock_.MakeRequest(uid);
        mock_.operations.lookup(request.Handle(), parent, name);
        return request.error == 0 ? request.entry.ino : 0;
    }

    fuse_ino_t RootInode(const std::string &id = "tdd-session")
    {
        UdmfFuseSessionManager::SessionInfo info;
        if (!manager_.Get(id, info)) {
            return 0;
        }
        auto alias = Lookup(FUSE_ROOT_ID, info.alias.c_str());
        return alias == 0 ? 0 : Lookup(alias, info.root.name.c_str());
    }

    FuseLowlevelMock mock_;
    UdmfFuseSessionManager &manager_ = UdmfFuseSessionManager::GetInstance();
    sptr<TddProvider> provider_;
    std::vector<std::string> ownedSessions_;
    std::string uri_;
};

/**
 * @tc.name: ValidateEntry_InvalidNames_RejectEveryUnsafeForm
 * @tc.desc: Verify empty, traversal-like, path-like, embedded-NUL and oversized names are rejected.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfFuseTddTest, ValidateEntry_InvalidNames_RejectEveryUnsafeForm, TestSize.Level0)
{
    for (const auto &name : { std::string(), std::string("."), std::string(".."), std::string("a/b"),
        std::string("a\\b"), std::string("a\0b", 3), std::string(256, 'n') }) {
        SCOPED_TRACE(name);
        EXPECT_FALSE(UdmfFuseSessionManager::IsValid(MakeFile(0, name)));
    }
    EXPECT_TRUE(UdmfFuseSessionManager::IsValid(MakeFile(0, std::string(255, 'n'))));
}

/**
 * @tc.name: ValidateEntry_FileAndDirectoryMetadata_EnforceShape
 * @tc.desc: Verify file IDs, sizes, descendants and directory-only metadata are validated.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfFuseTddTest, ValidateEntry_FileAndDirectoryMetadata_EnforceShape, TestSize.Level0)
{
    auto file = MakeFile();
    EXPECT_TRUE(UdmfFuseSessionManager::IsValid(file));
    file.id.clear();
    EXPECT_FALSE(UdmfFuseSessionManager::IsValid(file));
    file.id.assign(1024, 'i');
    file.size = 0;
    EXPECT_TRUE(UdmfFuseSessionManager::IsValid(file));
    file.id.push_back('i');
    EXPECT_FALSE(UdmfFuseSessionManager::IsValid(file));
    file = MakeFile(-2);
    EXPECT_FALSE(UdmfFuseSessionManager::IsValid(file));
    file = MakeFile();
    file.subItems.push_back(MakeFile());
    EXPECT_FALSE(UdmfFuseSessionManager::IsValid(file));
    auto directory = MakeDirectory(0);
    EXPECT_TRUE(UdmfFuseSessionManager::IsValid(directory));
    directory.id = "invalid-directory-id";
    EXPECT_FALSE(UdmfFuseSessionManager::IsValid(directory));
    directory.id.clear();
    directory.size = 0;
    EXPECT_FALSE(UdmfFuseSessionManager::IsValid(directory));
    directory.size = -1;
    directory.type = static_cast<VirtualEntryType>(99);
    EXPECT_FALSE(UdmfFuseSessionManager::IsValid(directory));
}

/**
 * @tc.name: ValidateEntry_DuplicateNamesAndInvalidDescendants_RejectTree
 * @tc.desc: Verify each sibling name is unique and descendant validation is recursive.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfFuseTddTest, ValidateEntry_DuplicateNamesAndInvalidDescendants_RejectTree, TestSize.Level0)
{
    auto tree = MakeDirectory(2);
    EXPECT_TRUE(UdmfFuseSessionManager::IsValid(tree));
    tree.subItems[1].name = tree.subItems[0].name;
    EXPECT_FALSE(UdmfFuseSessionManager::IsValid(tree));
    tree = MakeDirectory(1);
    tree.subItems[0].id.clear();
    EXPECT_FALSE(UdmfFuseSessionManager::IsValid(tree));
}

/**
 * @tc.name: ValidateEntry_DepthBoundary_IncludeRootAtDepthZero
 * @tc.desc: Verify exactly 64 nesting levels are accepted and level 65 is rejected.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfFuseTddTest, ValidateEntry_DepthBoundary_IncludeRootAtDepthZero, TestSize.Level0)
{
    auto tree = MakeFile();
    for (size_t index = 0; index < 64; ++index) {
        auto parent = MakeDirectory(0);
        parent.subItems.push_back(std::move(tree));
        tree = std::move(parent);
    }
    EXPECT_TRUE(UdmfFuseSessionManager::IsValid(tree));
    auto overflow = MakeDirectory(0);
    overflow.subItems.push_back(std::move(tree));
    EXPECT_FALSE(UdmfFuseSessionManager::IsValid(overflow));
}

/**
 * @tc.name: ValidateEntry_NodeBoundary_IncludeRootIn4096Limit
 * @tc.desc: Verify node counting includes the directory root and rejects node 4097.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfFuseTddTest, ValidateEntry_NodeBoundary_IncludeRootIn4096Limit, TestSize.Level1)
{
    auto tree = MakeDirectory(4095);
    EXPECT_TRUE(UdmfFuseSessionManager::IsValid(tree));
    tree.subItems.push_back(MakeFile(0, "overflow"));
    EXPECT_FALSE(UdmfFuseSessionManager::IsValid(tree));
}

/**
 * @tc.name: Register_InvalidFields_RejectWithoutCreatingSession
 * @tc.desc: Verify every mandatory registration field is checked before retaining a session.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfFuseTddTest, Register_InvalidFields_RejectWithoutCreatingSession, TestSize.Level0)
{
    UdmfFuseSessionManager::SessionInfo valid;
    valid.userId = TEST_USER;
    valid.sourceTokenId = SOURCE_TOKEN;
    valid.generation = 1;
    valid.root = MakeFile();
    valid.provider = provider_->AsObject();
    EXPECT_EQ(manager_.Register("", valid), -EINVAL);
    auto invalid = valid;
    invalid.userId = -1;
    EXPECT_EQ(manager_.Register("invalid", invalid), -EINVAL);
    invalid = valid;
    invalid.sourceTokenId = 0;
    EXPECT_EQ(manager_.Register("invalid", invalid), -EINVAL);
    invalid = valid;
    invalid.generation = 0;
    EXPECT_EQ(manager_.Register("invalid", invalid), -EINVAL);
    invalid = valid;
    invalid.provider = nullptr;
    EXPECT_EQ(manager_.Register("invalid", invalid), -EINVAL);
    invalid = valid;
    invalid.root.name.clear();
    EXPECT_EQ(manager_.Register("invalid", invalid), -EINVAL);
    EXPECT_FALSE(manager_.Get("invalid", invalid));
}

/**
 * @tc.name: Register_DuplicateId_KeepOriginalSession
 * @tc.desc: Verify a duplicate registration cannot replace the retained file tree.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfFuseTddTest, Register_DuplicateId_KeepOriginalSession, TestSize.Level0)
{
    ASSERT_EQ(Register(MakeFile()), 0);
    EXPECT_EQ(Register(MakeFile(2, "replacement")), -EEXIST);
    UdmfFuseSessionManager::SessionInfo info;
    ASSERT_TRUE(manager_.Get("tdd-session", info));
    EXPECT_EQ(info.root.name, "example.bin");
    EXPECT_EQ(info.state, UdmfFuseSessionManager::State::PENDING_DROP);
    EXPECT_EQ(UdmfFuseMountAdapterMock::mounts, 0u);
}

/**
 * @tc.name: Register_DeathRecipientFailure_RollBackPendingQuota
 * @tc.desc: Verify failed death-recipient setup releases pending quota and permits re-registration.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfFuseTddTest, Register_DeathRecipientFailure_RollBackPendingQuota, TestSize.Level0)
{
    provider_->acceptDeathRecipient = false;
    for (size_t index = 0; index < 6; ++index) {
        EXPECT_EQ(Register(MakeFile()), -EPIPE);
        UdmfFuseSessionManager::SessionInfo info;
        EXPECT_FALSE(manager_.Get("tdd-session", info));
    }
    provider_->acceptDeathRecipient = true;
    EXPECT_EQ(Register(MakeFile()), 0);
}

/**
 * @tc.name: Register_AlreadyDeadProvider_RollBackSession
 * @tc.desc: Verify a provider dying during registration cannot leave a live pending entry.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfFuseTddTest, Register_AlreadyDeadProvider_RollBackSession, TestSize.Level0)
{
    provider_->dead = true;
    EXPECT_EQ(Register(MakeFile()), -EPIPE);
    UdmfFuseSessionManager::SessionInfo info;
    EXPECT_FALSE(manager_.Get("tdd-session", info));
    provider_->dead = false;
    EXPECT_EQ(Register(MakeFile()), 0);
}

/**
 * @tc.name: Activate_InvalidTargetOrMissingSession_RejectBeforeMount
 * @tc.desc: Verify invalid target identities and stale keys cannot allocate a mount.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfFuseTddTest, Activate_InvalidTargetOrMissingSession_RejectBeforeMount, TestSize.Level0)
{
    EXPECT_EQ(manager_.Activate("missing", 0, TARGET_UID, TARGET_UID, uri_), -EINVAL);
    EXPECT_EQ(manager_.Activate("missing", TARGET_TOKEN, -1, TARGET_UID, uri_), -EINVAL);
    EXPECT_EQ(manager_.Activate("missing", TARGET_TOKEN, TARGET_UID, -1, uri_), -EINVAL);
    EXPECT_EQ(manager_.Activate("missing", TARGET_TOKEN, TARGET_UID, TARGET_UID, uri_), -ESTALE);
    EXPECT_EQ(UdmfFuseMountAdapterMock::mounts, 0u);
}

/**
 * @tc.name: Activate_MountFailure_KeepPendingAndAllowRetry
 * @tc.desc: Verify mount failure does not consume active quota or lose the pending session.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfFuseTddTest, Activate_MountFailure_KeepPendingAndAllowRetry, TestSize.Level0)
{
    ASSERT_EQ(Register(MakeFile()), 0);
    UdmfFuseMountAdapterMock::mountStatus = -EACCES;
    EXPECT_EQ(manager_.Activate("tdd-session", TARGET_TOKEN, TARGET_UID, TARGET_UID, uri_), -EACCES);
    UdmfFuseSessionManager::SessionInfo info;
    ASSERT_TRUE(manager_.Get("tdd-session", info));
    EXPECT_EQ(info.state, UdmfFuseSessionManager::State::PENDING_DROP);
    UdmfFuseMountAdapterMock::mountStatus = 0;
    EXPECT_EQ(manager_.Activate("tdd-session", TARGET_TOKEN, TARGET_UID, TARGET_UID, uri_), 0);
    EXPECT_EQ(UdmfFuseMountAdapterMock::mounts, 2u);
}

/**
 * @tc.name: Activate_ControllerFailure_UnmountAndAllowRetry
 * @tc.desc: Verify failed FUSE initialization rolls back its mount and remains retryable.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfFuseTddTest, Activate_ControllerFailure_UnmountAndAllowRetry, TestSize.Level0)
{
    ASSERT_EQ(Register(MakeFile()), 0);
    mock_.customIoStatus = -EIO;
    EXPECT_EQ(manager_.Activate("tdd-session", TARGET_TOKEN, TARGET_UID, TARGET_UID, uri_), -EIO);
    EXPECT_EQ(UdmfFuseMountAdapterMock::unmounts, 1u);
    EXPECT_EQ(UdmfFuseMountAdapterMock::lastMountPoint, "/mnt/data/100/udmf_fuse/files");
    EXPECT_EQ(UdmfFuseMountAdapterMock::lastUnmountPoint, UdmfFuseMountAdapterMock::lastMountPoint);
    mock_.customIoStatus = 0;
    EXPECT_EQ(manager_.Activate("tdd-session", TARGET_TOKEN, TARGET_UID, TARGET_UID, uri_), 0);
}

/**
 * @tc.name: Activate_RepeatForSameTarget_ReuseUriAndMount
 * @tc.desc: Verify repeat activation is idempotent and another application cannot take over the session.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfFuseTddTest, Activate_RepeatForSameTarget_ReuseUriAndMount, TestSize.Level0)
{
    ASSERT_EQ(ActivateFile(), 0);
    EXPECT_EQ(UdmfFuseMountAdapterMock::lastMountPoint, "/mnt/data/100/udmf_fuse/files");
    EXPECT_EQ(uri_.find("file:///data/storage/el2/udmf/files/"), 0u);
    std::string repeated;
    EXPECT_EQ(manager_.Activate("tdd-session", TARGET_TOKEN, TARGET_UID, TARGET_UID, repeated), 0);
    EXPECT_EQ(repeated, uri_);
    EXPECT_EQ(UdmfFuseMountAdapterMock::mounts, 1u);
    EXPECT_EQ(manager_.Activate("tdd-session", TARGET_TOKEN + 1, TARGET_UID, TARGET_UID, repeated), -EACCES);
    EXPECT_EQ(manager_.Activate("tdd-session", TARGET_TOKEN, OTHER_UID, OTHER_UID, repeated), -EACCES);
}

/**
 * @tc.name: OpenSession_PendingMissingAndWrongUid_RejectAccess
 * @tc.desc: Verify only the target UID can open an active session.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfFuseTddTest, OpenSession_PendingMissingAndWrongUid_RejectAccess, TestSize.Level0)
{
    ASSERT_EQ(Register(MakeFile()), 0);
    EXPECT_EQ(manager_.AcquireOpen("missing", TARGET_UID), -ESTALE);
    EXPECT_EQ(manager_.AcquireOpen("tdd-session", TARGET_UID), -ESTALE);
    ASSERT_EQ(manager_.Activate("tdd-session", TARGET_TOKEN, TARGET_UID, TARGET_UID, uri_), 0);
    EXPECT_EQ(manager_.AcquireOpen("tdd-session", -1), -EACCES);
    EXPECT_EQ(manager_.AcquireOpen("tdd-session", OTHER_UID), -EACCES);
    EXPECT_EQ(manager_.AcquireOpen("tdd-session", TARGET_UID), 0);
    UdmfFuseSessionManager::SessionInfo info;
    ASSERT_TRUE(manager_.Get("tdd-session", info));
    EXPECT_EQ(info.openCount, 1u);
    manager_.ReleaseOpen("tdd-session");
    manager_.ReleaseOpen("tdd-session");
    manager_.ReleaseOpen("missing");
    ASSERT_TRUE(manager_.Get("tdd-session", info));
    EXPECT_EQ(info.openCount, 0u);
}

/**
 * @tc.name: Remove_OpenSession_DrainUntilLastClose
 * @tc.desc: Verify removal rejects new opens while preserving existing handles until the last close.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfFuseTddTest, Remove_OpenSession_DrainUntilLastClose, TestSize.Level0)
{
    ASSERT_EQ(ActivateFile(), 0);
    ASSERT_EQ(manager_.AcquireOpen("tdd-session", TARGET_UID), 0);
    ASSERT_EQ(manager_.AcquireOpen("tdd-session", TARGET_UID), 0);
    manager_.Remove("tdd-session");
    UdmfFuseSessionManager::SessionInfo info;
    ASSERT_TRUE(manager_.Get("tdd-session", info));
    EXPECT_EQ(info.state, UdmfFuseSessionManager::State::DRAINING);
    EXPECT_EQ(manager_.AcquireOpen("tdd-session", TARGET_UID), -ESTALE);
    EXPECT_EQ(manager_.Activate("tdd-session", TARGET_TOKEN, TARGET_UID, TARGET_UID, uri_), -ESTALE);
    manager_.ReleaseOpen("tdd-session");
    EXPECT_TRUE(manager_.Get("tdd-session", info));
    manager_.ReleaseOpen("tdd-session");
    EXPECT_FALSE(manager_.Get("tdd-session", info));
    EXPECT_EQ(provider_->cancelCalls, 1u);
}

/**
 * @tc.name: Remove_PendingAndRepeatedRemoval_ReleaseQuotaWithoutMount
 * @tc.desc: Verify pending removal is idempotent and releases per-source capacity.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfFuseTddTest, Remove_PendingAndRepeatedRemoval_ReleaseQuotaWithoutMount, TestSize.Level0)
{
    ASSERT_EQ(Register(MakeFile()), 0);
    manager_.Remove("tdd-session");
    manager_.Remove("tdd-session");
    UdmfFuseSessionManager::SessionInfo info;
    EXPECT_FALSE(manager_.Get("tdd-session", info));
    EXPECT_EQ(Register(MakeFile()), 0);
    EXPECT_EQ(UdmfFuseMountAdapterMock::mounts, 0u);
}

/**
 * @tc.name: ProviderDeath_ActiveSession_RemoveAndUnmount
 * @tc.desc: Verify provider death invalidates the session and tears down its idle mount.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfFuseTddTest, ProviderDeath_ActiveSession_RemoveAndUnmount, TestSize.Level0)
{
    ASSERT_EQ(ActivateFile(), 0);
    auto recipient = provider_->deathRecipient;
    ASSERT_NE(recipient, nullptr);
    provider_->dead = true;
    recipient->OnRemoteDied(wptr<IRemoteObject>(provider_->AsObject()));
    UdmfFuseSessionManager::SessionInfo info;
    EXPECT_FALSE(manager_.Get("tdd-session", info));
    EXPECT_EQ(UdmfFuseMountAdapterMock::unmounts, 1u);
    EXPECT_EQ(UdmfFuseMountAdapterMock::lastUnmountPoint, UdmfFuseMountAdapterMock::lastMountPoint);
}

/**
 * @tc.name: Start_InvalidDescriptor_ReturnBadFd
 * @tc.desc: Verify invalid input does not create a FUSE session.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfFuseTddTest, Start_InvalidDescriptor_ReturnBadFd, TestSize.Level0)
{
    UdmfFuseController controller(TEST_USER);
    EXPECT_EQ(controller.Start(-1), -EBADF);
    EXPECT_EQ(mock_.created.load(), 0u);
}

/**
 * @tc.name: Start_SessionCreationFailure_CloseTransferredFd
 * @tc.desc: Verify FUSE session allocation failure closes the supplied descriptor.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfFuseTddTest, Start_SessionCreationFailure_CloseTransferredFd, TestSize.Level0)
{
    UdmfFuseController controller(TEST_USER);
    int fd = eventfd(0, EFD_CLOEXEC);
    ASSERT_GE(fd, 0);
    mock_.failSession = true;
    EXPECT_EQ(controller.Start(fd), -ENOMEM);
    EXPECT_EQ(fcntl(fd, F_GETFD), -1);
    EXPECT_EQ(errno, EBADF);
}

/**
 * @tc.name: Start_CustomIoFailure_DestroySessionAndCloseFd
 * @tc.desc: Verify custom-I/O setup failure cannot leak the descriptor or session.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfFuseTddTest, Start_CustomIoFailure_DestroySessionAndCloseFd, TestSize.Level0)
{
    UdmfFuseController controller(TEST_USER);
    int fd = eventfd(0, EFD_CLOEXEC);
    ASSERT_GE(fd, 0);
    mock_.customIoStatus = -EIO;
    EXPECT_EQ(controller.Start(fd), -EIO);
    EXPECT_EQ(mock_.created.load(), 1u);
    EXPECT_EQ(mock_.destroyed.load(), 1u);
    EXPECT_EQ(fcntl(fd, F_GETFD), -1);
}

/**
 * @tc.name: Start_LoopConfigurationFailure_ReturnNoMemory
 * @tc.desc: Verify failure before FUSE_INIT wakes the starter and cleans the session.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfFuseTddTest, Start_LoopConfigurationFailure_ReturnNoMemory, TestSize.Level0)
{
    UdmfFuseController controller(TEST_USER);
    int fd = eventfd(0, EFD_CLOEXEC);
    ASSERT_GE(fd, 0);
    mock_.failLoopConfig = true;
    EXPECT_EQ(controller.Start(fd), -ENOMEM);
    EXPECT_EQ(mock_.created.load(), mock_.destroyed.load());
}

/**
 * @tc.name: Start_LoopFailure_ReturnOriginalError
 * @tc.desc: Verify loop failure before initialization is reported without waiting for the deadline.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfFuseTddTest, Start_LoopFailure_ReturnOriginalError, TestSize.Level0)
{
    UdmfFuseController controller(TEST_USER);
    int fd = eventfd(0, EFD_CLOEXEC);
    ASSERT_GE(fd, 0);
    mock_.loopStatus = -EIO;
    EXPECT_EQ(controller.Start(fd), -EIO);
    EXPECT_EQ(mock_.created.load(), mock_.destroyed.load());
}

/**
 * @tc.name: Start_InitializationTimeout_StopLoopAndCloseSession
 * @tc.desc: Verify missing FUSE_INIT cannot leave a live background loop.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfFuseTddTest, Start_InitializationTimeout_StopLoopAndCloseSession, TestSize.Level1)
{
    UdmfFuseController controller(TEST_USER);
    int fd = eventfd(0, EFD_CLOEXEC);
    ASSERT_GE(fd, 0);
    mock_.initialize = false;
    EXPECT_EQ(controller.Start(fd), -ETIMEDOUT);
    EXPECT_EQ(mock_.created.load(), mock_.destroyed.load());
}

/**
 * @tc.name: Start_AlreadyRunning_RejectAndReleaseNewResources
 * @tc.desc: Verify repeated start preserves the original session and closes only the new descriptor.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfFuseTddTest, Start_AlreadyRunning_RejectAndReleaseNewResources, TestSize.Level0)
{
    UdmfFuseController controller(TEST_USER);
    int first = eventfd(0, EFD_CLOEXEC);
    ASSERT_GE(first, 0);
    ASSERT_EQ(controller.Start(first), 0);
    int second = eventfd(0, EFD_CLOEXEC);
    ASSERT_GE(second, 0);
    EXPECT_EQ(controller.Start(second), -EALREADY);
    EXPECT_EQ(fcntl(second, F_GETFD), -1);
    EXPECT_GE(fcntl(first, F_GETFD), 0);
    controller.Stop();
    controller.Stop();
    EXPECT_EQ(mock_.created.load(), mock_.destroyed.load());
}

/**
 * @tc.name: AddSession_InvalidOptionsAndStoppedController_Reject
 * @tc.desc: Verify required session fields and controller readiness are enforced.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfFuseTddTest, AddSession_InvalidOptionsAndStoppedController_Reject, TestSize.Level0)
{
    UdmfFuseController controller(TEST_USER);
    UdmfFuseController::SessionOptions options;
    std::string path;
    EXPECT_EQ(controller.AddSession(options, path), -EINVAL);
    options.sessionId = "id";
    EXPECT_EQ(controller.AddSession(options, path), -EINVAL);
    options.alias = "alias";
    EXPECT_EQ(controller.AddSession(options, path), -EINVAL);
    options.provider = provider_->AsObject();
    options.root = MakeFile();
    EXPECT_EQ(controller.AddSession(options, path), -ENODEV);
    EXPECT_TRUE(path.empty());
}

/**
 * @tc.name: Lookup_TargetOnlyAlias_ConcealOtherApplicationsFiles
 * @tc.desc: Verify an alias is visible only to its authorized target, including when the caller UID is zero.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfFuseTddTest, Lookup_TargetOnlyAlias_ConcealOtherApplicationsFiles, TestSize.Level0)
{
    ASSERT_EQ(ActivateFile(), 0);
    UdmfFuseSessionManager::SessionInfo info;
    ASSERT_TRUE(manager_.Get("tdd-session", info));
    EXPECT_NE(Lookup(FUSE_ROOT_ID, info.alias.c_str()), 0u);
    EXPECT_EQ(Lookup(FUSE_ROOT_ID, info.alias.c_str(), OTHER_UID), 0u);
    EXPECT_EQ(Lookup(FUSE_ROOT_ID, info.alias.c_str(), 0), 0u);
    EXPECT_EQ(Lookup(FUSE_ROOT_ID, "missing"), 0u);
    auto request = mock_.MakeRequest(TARGET_UID);
    mock_.operations.lookup(request.Handle(), FUSE_ROOT_ID, "");
    EXPECT_EQ(request.error, EINVAL);
    mock_.operations.lookup(request.Handle(), FUSE_ROOT_ID, nullptr);
    EXPECT_EQ(request.error, EINVAL);
    mock_.operations.lookup(request.Handle(), 999999, "file");
    EXPECT_EQ(request.error, EACCES);
}

/**
 * @tc.name: GetAttr_KnownFileAndRoot_ReportModesAndMetadata
 * @tc.desc: Verify known metadata requires no provider stat and uses owner-only file permissions.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfFuseTddTest, GetAttr_KnownFileAndRoot_ReportModesAndMetadata, TestSize.Level0)
{
    ASSERT_EQ(ActivateFile(), 0);
    auto inode = RootInode();
    ASSERT_NE(inode, 0u);
    auto request = mock_.MakeRequest(TARGET_UID);
    mock_.operations.getattr(request.Handle(), inode, nullptr);
    EXPECT_EQ(request.error, 0);
    EXPECT_EQ(request.attr.st_size, 7);
    EXPECT_EQ(request.attr.st_mode & 0777, 0400);
    EXPECT_EQ(request.attr.st_uid, TARGET_UID);
    EXPECT_EQ(request.attr.st_blocks, 1);
    EXPECT_EQ(provider_->statCalls.load(), 0u);
    mock_.operations.getattr(request.Handle(), FUSE_ROOT_ID, nullptr);
    EXPECT_EQ(request.attr.st_mode & 0777, 0555);
    EXPECT_EQ(request.attr.st_nlink, 2u);
}

/**
 * @tc.name: GetAttr_DeclaredSize_ReturnMetadataWithoutCallback
 * @tc.desc: Verify attributes use the declared size and never depend on a stat callback.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfFuseTddTest, GetAttr_DeclaredSize_ReturnMetadataWithoutCallback, TestSize.Level0)
{
    ASSERT_EQ(ActivateFile(), 0);
    auto inode = RootInode();
    ASSERT_NE(inode, 0u);
    auto request = mock_.MakeRequest(TARGET_UID);
    mock_.operations.getattr(request.Handle(), inode, nullptr);
    EXPECT_EQ(request.error, 0);
    EXPECT_EQ(request.attr.st_size, 7);
    EXPECT_EQ(request.attr.st_mtim.tv_sec, 1);
    EXPECT_EQ(request.attr.st_mtim.tv_nsec, 234000000);
    mock_.operations.getattr(request.Handle(), inode, nullptr);
    EXPECT_EQ(provider_->statCalls.load(), 0u);
}

/**
 * @tc.name: Register_MissingFileSize_RejectWithNoStatFallback
 * @tc.desc: Verify missing size cannot register even if the provider could supply stat metadata.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfFuseTddTest, Register_MissingFileSize_RejectWithNoStatFallback, TestSize.Level0)
{
    EXPECT_EQ(Register(MakeFile(-1)), -EINVAL);
    EXPECT_EQ(Register(MakeFile(-2)), -EINVAL);
    UdmfFuseSessionManager::SessionInfo info;
    EXPECT_FALSE(manager_.Get("tdd-session", info));
    EXPECT_EQ(provider_->statCalls.load(), 0u);
    EXPECT_EQ(UdmfFuseMountAdapterMock::mounts, 0u);
}

/**
 * @tc.name: GetAttr_StatProviderUnresponsive_UseDeclaredSize
 * @tc.desc: Verify a metadata callback failure cannot block attributes for a sized file.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfFuseTddTest, GetAttr_StatProviderUnresponsive_UseDeclaredSize, TestSize.Level0)
{
    ASSERT_EQ(ActivateFile(), 0);
    provider_->statStatus = -ETIMEDOUT;
    auto request = mock_.MakeRequest(TARGET_UID);
    mock_.operations.getattr(request.Handle(), RootInode(), nullptr);
    EXPECT_EQ(request.error, 0);
    EXPECT_EQ(request.attr.st_size, 7);
    EXPECT_EQ(provider_->statCalls.load(), 0u);
}

/**
 * @tc.name: Callbacks_UnauthorizedUid_RejectAllFileOperations
 * @tc.desc: Verify a URI or inode alone grants no read, stat, access, open, flush or seek authority.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfFuseTddTest, Callbacks_UnauthorizedUid_RejectAllFileOperations, TestSize.Level0)
{
    ASSERT_EQ(ActivateFile(), 0);
    auto inode = RootInode();
    auto request = mock_.MakeRequest(OTHER_UID);
    struct fuse_file_info info {};
    info.fh = inode;
    mock_.operations.getattr(request.Handle(), inode, &info);
    EXPECT_EQ(request.error, EACCES);
    mock_.operations.access(request.Handle(), inode, R_OK);
    EXPECT_EQ(request.error, EACCES);
    mock_.operations.open(request.Handle(), inode, &info);
    EXPECT_EQ(request.error, EACCES);
    mock_.operations.read(request.Handle(), inode, 1, 0, &info);
    EXPECT_EQ(request.error, EACCES);
    mock_.operations.flush(request.Handle(), inode, &info);
    EXPECT_EQ(request.error, EACCES);
    mock_.operations.lseek(request.Handle(), inode, 0, SEEK_DATA, &info);
    EXPECT_EQ(request.error, EACCES);
    EXPECT_EQ(provider_->readCalls.load(), 0u);
}

/**
 * @tc.name: Callbacks_MissingContext_RejectWithoutProviderAccess
 * @tc.desc: Verify missing FUSE caller identity is rejected throughout read and metadata operations.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfFuseTddTest, Callbacks_MissingContext_RejectWithoutProviderAccess, TestSize.Level0)
{
    ASSERT_EQ(ActivateFile(), 0);
    auto inode = RootInode();
    auto request = mock_.MakeRequest(TARGET_UID);
    request.contextAvailable = false;
    struct fuse_file_info info {};
    mock_.operations.read(request.Handle(), inode, 1, 0, &info);
    EXPECT_EQ(request.error, EACCES);
    mock_.operations.access(request.Handle(), inode, R_OK);
    EXPECT_EQ(request.error, EACCES);
    mock_.operations.statfs(request.Handle(), inode);
    EXPECT_EQ(request.error, EACCES);
    mock_.operations.getattr(request.Handle(), inode, &info);
    EXPECT_EQ(request.error, EACCES);
    EXPECT_EQ(provider_->readCalls.load(), 0u);
}

/**
 * @tc.name: Callbacks_MissingController_ReplyWithOperationSpecificError
 * @tc.desc: Verify null userdata cannot crash filesystem callbacks.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfFuseTddTest, Callbacks_MissingController_ReplyWithOperationSpecificError, TestSize.Level0)
{
    ASSERT_EQ(ActivateFile(), 0);
    auto request = mock_.MakeRequest(TARGET_UID);
    request.userdata = nullptr;
    struct fuse_file_info info {};
    mock_.operations.lookup(request.Handle(), FUSE_ROOT_ID, "file");
    EXPECT_EQ(request.error, EINVAL);
    mock_.operations.getattr(request.Handle(), 9, &info);
    EXPECT_EQ(request.error, ENOENT);
    mock_.operations.open(request.Handle(), 9, &info);
    EXPECT_EQ(request.error, ENOENT);
    mock_.operations.read(request.Handle(), 9, 1, 0, &info);
    EXPECT_EQ(request.error, ENOENT);
    mock_.operations.opendir(request.Handle(), 9, &info);
    EXPECT_EQ(request.error, ENOTDIR);
    mock_.operations.readdir(request.Handle(), 9, 10, 0, &info);
    EXPECT_EQ(request.error, ENOTDIR);
    mock_.operations.statfs(request.Handle(), 9);
    EXPECT_EQ(request.error, EACCES);
    mock_.operations.flush(request.Handle(), 9, &info);
    EXPECT_EQ(request.error, ENOENT);
    mock_.operations.lseek(request.Handle(), 9, 0, SEEK_DATA, &info);
    EXPECT_EQ(request.error, ENOENT);
    mock_.operations.release(request.Handle(), 9, &info);
    EXPECT_EQ(request.error, 0);
}

/**
 * @tc.name: Access_ReadOnlyFile_ValidateMaskAndDenyWrites
 * @tc.desc: Verify supported access masks and file execute/write rejection.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfFuseTddTest, Access_ReadOnlyFile_ValidateMaskAndDenyWrites, TestSize.Level0)
{
    ASSERT_EQ(ActivateFile(), 0);
    auto inode = RootInode();
    auto request = mock_.MakeRequest(TARGET_UID);
    mock_.operations.access(request.Handle(), inode, F_OK);
    EXPECT_EQ(request.error, 0);
    mock_.operations.access(request.Handle(), inode, R_OK);
    EXPECT_EQ(request.error, 0);
    mock_.operations.access(request.Handle(), inode, W_OK);
    EXPECT_EQ(request.error, EROFS);
    mock_.operations.access(request.Handle(), inode, X_OK);
    EXPECT_EQ(request.error, EACCES);
    mock_.operations.access(request.Handle(), inode, 0x80);
    EXPECT_EQ(request.error, EINVAL);
}

/**
 * @tc.name: Open_ReadOnlyAndRelease_MaintainSessionOpenCount
 * @tc.desc: Verify open rejects write flags and successful release balances the open count.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfFuseTddTest, Open_ReadOnlyAndRelease_MaintainSessionOpenCount, TestSize.Level0)
{
    ASSERT_EQ(ActivateFile(), 0);
    auto inode = RootInode();
    auto request = mock_.MakeRequest(TARGET_UID);
    struct fuse_file_info info {};
    info.flags = O_WRONLY;
    mock_.operations.open(request.Handle(), inode, &info);
    EXPECT_EQ(request.error, EROFS);
    info.flags = O_RDONLY;
    mock_.operations.open(request.Handle(), inode, &info);
    EXPECT_EQ(request.error, 0);
    EXPECT_EQ(info.fh, inode);
    EXPECT_EQ(info.direct_io, 1u);
    UdmfFuseSessionManager::SessionInfo session;
    ASSERT_TRUE(manager_.Get("tdd-session", session));
    EXPECT_EQ(session.openCount, 1u);
    mock_.operations.release(request.Handle(), inode, &info);
    EXPECT_EQ(request.error, 0);
    ASSERT_TRUE(manager_.Get("tdd-session", session));
    EXPECT_EQ(session.openCount, 0u);
}

/**
 * @tc.name: Read_NegativeOffsetZeroLengthAndEof_AvoidDownload
 * @tc.desc: Verify invalid and empty read ranges never trigger a provider download.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfFuseTddTest, Read_NegativeOffsetZeroLengthAndEof_AvoidDownload, TestSize.Level0)
{
    ASSERT_EQ(ActivateFile(), 0);
    auto inode = RootInode();
    auto request = mock_.MakeRequest(TARGET_UID);
    mock_.operations.read(request.Handle(), inode, 1, -1, nullptr);
    EXPECT_EQ(request.error, EINVAL);
    mock_.operations.read(request.Handle(), inode, 0, 0, nullptr);
    EXPECT_EQ(request.error, 0);
    EXPECT_TRUE(request.bytes.empty());
    mock_.operations.read(request.Handle(), inode, 10, 7, nullptr);
    EXPECT_EQ(request.error, 0);
    EXPECT_TRUE(request.bytes.empty());
    EXPECT_EQ(provider_->readCalls.load(), 0u);
}

/**
 * @tc.name: Read_ProviderShortReads_JoinBlockAndReuseCache
 * @tc.desc: Verify short reads advance offsets, fill the declared block and serve later reads from cache.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfFuseTddTest, Read_ProviderShortReads_JoinBlockAndReuseCache, TestSize.Level0)
{
    ASSERT_EQ(ActivateFile(), 0);
    provider_->maxReadBytes = 2;
    auto inode = RootInode();
    auto request = mock_.MakeRequest(TARGET_UID);
    mock_.operations.read(request.Handle(), inode, 3, 2, nullptr);
    EXPECT_EQ(request.error, 0);
    EXPECT_EQ(request.bytes, (std::vector<uint8_t>{ 2, 3, 4 }));
    EXPECT_EQ(provider_->offsets, (std::vector<int64_t>{ 0, 2, 4, 6 }));
    EXPECT_EQ(provider_->lengths, (std::vector<int32_t>{ 7, 5, 3, 1 }));
    mock_.operations.read(request.Handle(), inode, 7, 0, nullptr);
    EXPECT_EQ(request.bytes, provider_->content);
    EXPECT_EQ(provider_->readCalls.load(), 4u);
}

/**
 * @tc.name: Lookup_DeclaredSize_ReturnRealSizeBeforeRead
 * @tc.desc: Verify the first file lookup returns real size so a normal copy never caches a false empty file.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfFuseTddTest, Lookup_DeclaredSize_ReturnRealSizeBeforeRead, TestSize.Level0)
{
    ASSERT_EQ(ActivateFile(), 0);
    UdmfFuseSessionManager::SessionInfo session;
    ASSERT_TRUE(manager_.Get("tdd-session", session));
    auto alias = Lookup(FUSE_ROOT_ID, session.alias.c_str());
    auto request = mock_.MakeRequest(TARGET_UID);
    mock_.operations.lookup(request.Handle(), alias, session.root.name.c_str());
    ASSERT_EQ(request.error, 0);
    EXPECT_EQ(request.entry.attr.st_size, 7);
    EXPECT_EQ(provider_->statCalls.load(), 0u);
    mock_.operations.read(request.Handle(), request.entry.ino, 9, 0, nullptr);
    EXPECT_EQ(request.error, 0);
    EXPECT_EQ(request.bytes, provider_->content);
    EXPECT_EQ(provider_->statCalls.load(), 0u);
}

/**
 * @tc.name: Register_NestedMissingSize_RejectTreeBeforeMount
 * @tc.desc: Verify every nested file must declare a size before the session can activate.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfFuseTddTest, Register_NestedMissingSize_RejectTreeBeforeMount, TestSize.Level0)
{
    auto root = MakeDirectory(2);
    root.subItems[1].size = -1;
    EXPECT_FALSE(UdmfFuseSessionManager::IsValid(root));
    EXPECT_EQ(Register(root), -EINVAL);
    EXPECT_EQ(provider_->readCalls.load(), 0u);
    EXPECT_EQ(provider_->statCalls.load(), 0u);
    EXPECT_EQ(UdmfFuseMountAdapterMock::mounts, 0u);
}

/**
 * @tc.name: Read_EmptyDataBeforeDeclaredEof_ReturnIoError
 * @tc.desc: Verify premature EOF cannot silently create a truncated copy.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfFuseTddTest, Read_EmptyDataBeforeDeclaredEof_ReturnIoError, TestSize.Level0)
{
    ASSERT_EQ(ActivateFile(), 0);
    provider_->content.clear();
    auto request = mock_.MakeRequest(TARGET_UID);
    mock_.operations.read(request.Handle(), RootInode(), 7, 0, nullptr);
    EXPECT_EQ(request.error, EIO);
    EXPECT_TRUE(request.bytes.empty());
    EXPECT_EQ(provider_->readCalls.load(), 1u);
}

/**
 * @tc.name: Read_TransientFailure_RetryAndReloadNextAttempt
 * @tc.desc: Verify exhausted transient reads do not poison the next copy attempt.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfFuseTddTest, Read_TransientFailure_RetryAndReloadNextAttempt, TestSize.Level0)
{
    ASSERT_EQ(ActivateFile(), 0);
    provider_->statuses = { -EAGAIN, -EAGAIN, -EAGAIN, 0 };
    auto inode = RootInode();
    auto request = mock_.MakeRequest(TARGET_UID);
    mock_.operations.read(request.Handle(), inode, 1, 0, nullptr);
    EXPECT_EQ(request.error, EAGAIN);
    EXPECT_EQ(provider_->readCalls.load(), 3u);
    mock_.operations.read(request.Handle(), inode, 1, 0, nullptr);
    EXPECT_EQ(request.error, 0);
    EXPECT_EQ(request.bytes, (std::vector<uint8_t>{ 0 }));
    EXPECT_EQ(provider_->readCalls.load(), 4u);
}

/**
 * @tc.name: Read_NonTransientFailure_DoNotRetryFailedBlock
 * @tc.desc: Verify permanent errors are not retried on every kernel read.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfFuseTddTest, Read_NonTransientFailure_DoNotRetryFailedBlock, TestSize.Level0)
{
    ASSERT_EQ(ActivateFile(), 0);
    auto inode = RootInode();
    provider_->readStatus = -EIO;
    auto request = mock_.MakeRequest(TARGET_UID);
    mock_.operations.read(request.Handle(), inode, 1, 0, nullptr);
    EXPECT_EQ(request.error, EIO);
    provider_->readStatus = 0;
    mock_.operations.read(request.Handle(), inode, 1, 0, nullptr);
    EXPECT_EQ(request.error, EIO);
    EXPECT_EQ(provider_->readCalls.load(), 1u);
}

/**
 * @tc.name: Read_CrossBlockRange_UseBottomLayerFiveMiBRequests
 * @tc.desc: Verify caller read size does not replace the fixed provider block size.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfFuseTddTest, Read_CrossBlockRange_UseBottomLayerFiveMiBRequests, TestSize.Level1)
{
    provider_->content.assign(BLOCK_BYTES * 2, 0x5A);
    provider_->content[BLOCK_BYTES] = 0x31;
    ASSERT_EQ(ActivateFile(static_cast<int64_t>(provider_->content.size())), 0);
    auto request = mock_.MakeRequest(TARGET_UID);
    mock_.operations.read(request.Handle(), RootInode(), 2, BLOCK_BYTES - 1, nullptr);
    EXPECT_EQ(request.error, 0);
    EXPECT_EQ(request.bytes, (std::vector<uint8_t>{ 0x5A, 0x31 }));
    EXPECT_EQ(provider_->offsets, (std::vector<int64_t>{ 0, BLOCK_BYTES }));
    EXPECT_EQ(provider_->lengths, (std::vector<int32_t>{ BLOCK_BYTES, BLOCK_BYTES }));
}

/**
 * @tc.name: Read_ControllerCacheFull_EvictLeastRecentlyUsedBlock
 * @tc.desc: Verify a fourth block evicts an old cached block and later reads reload it.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfFuseTddTest, Read_ControllerCacheFull_EvictLeastRecentlyUsedBlock, TestSize.Level1)
{
    provider_->content.assign(BLOCK_BYTES * 4, 0x5A);
    ASSERT_EQ(ActivateFile(static_cast<int64_t>(provider_->content.size())), 0);
    auto inode = RootInode();
    for (size_t index = 0; index < 4; ++index) {
        auto request = mock_.MakeRequest(TARGET_UID);
        mock_.operations.read(request.Handle(), inode, 1, index * BLOCK_BYTES, nullptr);
        ASSERT_EQ(request.error, 0);
        EXPECT_EQ(request.bytes, (std::vector<uint8_t>{ 0x5A }));
    }
    EXPECT_EQ(provider_->readCalls.load(), 4u);
    auto request = mock_.MakeRequest(TARGET_UID);
    mock_.operations.read(request.Handle(), inode, 1, BLOCK_BYTES * 3, nullptr);
    EXPECT_EQ(provider_->readCalls.load(), 4u);
    mock_.operations.read(request.Handle(), inode, 1, 0, nullptr);
    EXPECT_EQ(request.error, 0);
    EXPECT_EQ(provider_->readCalls.load(), 5u);
}

/**
 * @tc.name: Read_TransportFailure_ReturnIoErrorWithoutCopy
 * @tc.desc: Verify failed provider IPC cannot create content in the destination buffer.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfFuseTddTest, Read_TransportFailure_ReturnIoErrorWithoutCopy, TestSize.Level0)
{
    ASSERT_EQ(ActivateFile(), 0);
    provider_->transportStatus = -EPIPE;
    auto request = mock_.MakeRequest(TARGET_UID);
    mock_.operations.read(request.Handle(), RootInode(), 1, 0, nullptr);
    EXPECT_EQ(request.error, EIO);
    EXPECT_TRUE(request.bytes.empty());
    EXPECT_EQ(provider_->readCalls.load(), 0u);
}

/**
 * @tc.name: Directory_EnumerateAndSearch_KeepMetadataLocal
 * @tc.desc: Verify ordinary and plus directory reads enumerate the same authorized children without stat downloads.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfFuseTddTest, Directory_EnumerateAndSearch_KeepMetadataLocal, TestSize.Level0)
{
    ASSERT_EQ(Register(MakeDirectory(2)), 0);
    ASSERT_EQ(manager_.Activate("tdd-session", TARGET_TOKEN, TARGET_UID, TARGET_UID, uri_), 0);
    auto inode = RootInode();
    ASSERT_NE(inode, 0u);
    auto request = mock_.MakeRequest(TARGET_UID);
    mock_.operations.readdir(request.Handle(), inode, 1024, 0, nullptr);
    EXPECT_EQ(request.error, 0);
    EXPECT_EQ(request.names, (std::vector<std::string>{ ".", "..", "file-0", "file-1" }));
    auto plus = mock_.MakeRequest(TARGET_UID);
    mock_.operations.readdirplus(plus.Handle(), inode, 1024, 0, nullptr);
    EXPECT_EQ(plus.names, request.names);
    EXPECT_NE(Lookup(inode, "file-1"), 0u);
    EXPECT_EQ(provider_->statCalls.load(), 0u);
    EXPECT_EQ(provider_->readCalls.load(), 0u);
}

/**
 * @tc.name: Directory_OffsetsAndSmallBuffers_RespectEnumerationCursor
 * @tc.desc: Verify small buffers, continuation offsets and EOF do not overrun the requested directory response.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfFuseTddTest, Directory_OffsetsAndSmallBuffers_RespectEnumerationCursor, TestSize.Level0)
{
    ASSERT_EQ(Register(MakeDirectory(2)), 0);
    ASSERT_EQ(manager_.Activate("tdd-session", TARGET_TOKEN, TARGET_UID, TARGET_UID, uri_), 0);
    auto inode = RootInode();
    auto small = mock_.MakeRequest(TARGET_UID);
    mock_.operations.readdir(small.Handle(), inode, 1, 0, nullptr);
    EXPECT_TRUE(small.bytes.empty());
    EXPECT_TRUE(small.names.empty());
    auto continuation = mock_.MakeRequest(TARGET_UID);
    mock_.operations.readdir(continuation.Handle(), inode, 1024, 2, nullptr);
    EXPECT_EQ(continuation.names, (std::vector<std::string>{ "file-0", "file-1" }));
    auto eof = mock_.MakeRequest(TARGET_UID);
    mock_.operations.readdir(eof.Handle(), inode, 1024, 4, nullptr);
    EXPECT_TRUE(eof.bytes.empty());
    mock_.operations.readdir(eof.Handle(), inode, 1024, -1, nullptr);
    EXPECT_EQ(eof.error, EACCES);
}

/**
 * @tc.name: Directory_OtherUidOrNonDirectory_RejectEnumeration
 * @tc.desc: Verify directories remain private and regular files are not traversable.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfFuseTddTest, Directory_OtherUidOrNonDirectory_RejectEnumeration, TestSize.Level0)
{
    ASSERT_EQ(Register(MakeDirectory(1)), 0);
    ASSERT_EQ(manager_.Activate("tdd-session", TARGET_TOKEN, TARGET_UID, TARGET_UID, uri_), 0);
    auto inode = RootInode();
    auto request = mock_.MakeRequest(OTHER_UID);
    struct fuse_file_info info {};
    mock_.operations.opendir(request.Handle(), inode, &info);
    EXPECT_EQ(request.error, EACCES);
    mock_.operations.readdir(request.Handle(), inode, 1024, 0, &info);
    EXPECT_EQ(request.error, EACCES);
    auto file = Lookup(inode, "file-0");
    request.context.uid = TARGET_UID;
    mock_.operations.opendir(request.Handle(), file, &info);
    EXPECT_EQ(request.error, ENOTDIR);
    mock_.operations.readdir(request.Handle(), file, 1024, 0, &info);
    EXPECT_EQ(request.error, ENOTDIR);
}

/**
 * @tc.name: Directory_OpenCloseAndFileOperations_EnforceKind
 * @tc.desc: Verify directory handles balance session counts while file-only operations reject directories.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfFuseTddTest, Directory_OpenCloseAndFileOperations_EnforceKind, TestSize.Level0)
{
    ASSERT_EQ(Register(MakeDirectory(0)), 0);
    ASSERT_EQ(manager_.Activate("tdd-session", TARGET_TOKEN, TARGET_UID, TARGET_UID, uri_), 0);
    auto inode = RootInode();
    auto request = mock_.MakeRequest(TARGET_UID);
    struct fuse_file_info info {};
    mock_.operations.opendir(request.Handle(), inode, &info);
    EXPECT_EQ(request.error, 0);
    EXPECT_EQ(info.fh, inode);
    mock_.operations.open(request.Handle(), inode, &info);
    EXPECT_EQ(request.error, EISDIR);
    mock_.operations.read(request.Handle(), inode, 1, 0, &info);
    EXPECT_EQ(request.error, EINVAL);
    mock_.operations.flush(request.Handle(), inode, &info);
    EXPECT_EQ(request.error, EISDIR);
    mock_.operations.lseek(request.Handle(), inode, 0, SEEK_DATA, &info);
    EXPECT_EQ(request.error, EISDIR);
    mock_.operations.releasedir(request.Handle(), inode, &info);
    EXPECT_EQ(request.error, 0);
    UdmfFuseSessionManager::SessionInfo session;
    ASSERT_TRUE(manager_.Get("tdd-session", session));
    EXPECT_EQ(session.openCount, 0u);
}

/**
 * @tc.name: Directory_SharedRoot_DoNotListPrivateAliases
 * @tc.desc: Verify applications cannot enumerate another drag alias through the shared mount root.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfFuseTddTest, Directory_SharedRoot_DoNotListPrivateAliases, TestSize.Level0)
{
    ASSERT_EQ(ActivateFile(), 0);
    auto request = mock_.MakeRequest(OTHER_UID);
    struct fuse_file_info info {};
    mock_.operations.opendir(request.Handle(), FUSE_ROOT_ID, &info);
    EXPECT_EQ(request.error, 0);
    mock_.operations.readdir(request.Handle(), FUSE_ROOT_ID, 1024, 0, &info);
    EXPECT_EQ(request.names, (std::vector<std::string>{ ".", ".." }));
    mock_.operations.releasedir(request.Handle(), FUSE_ROOT_ID, &info);
    EXPECT_EQ(request.error, 0);
}

/**
 * @tc.name: FlushAndFsync_InvalidHandles_RejectWithoutDataMutation
 * @tc.desc: Verify supported no-op flush and sync calls validate the file handle.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfFuseTddTest, FlushAndFsync_InvalidHandles_RejectWithoutDataMutation, TestSize.Level0)
{
    ASSERT_EQ(ActivateFile(), 0);
    auto inode = RootInode();
    auto request = mock_.MakeRequest(TARGET_UID);
    struct fuse_file_info info {};
    mock_.operations.flush(request.Handle(), inode, nullptr);
    EXPECT_EQ(request.error, EBADF);
    mock_.operations.flush(request.Handle(), inode, &info);
    EXPECT_EQ(request.error, EBADF);
    info.fh = inode;
    mock_.operations.flush(request.Handle(), inode, &info);
    EXPECT_EQ(request.error, 0);
    mock_.operations.fsync(request.Handle(), inode, 1, &info);
    EXPECT_EQ(request.error, 0);
    EXPECT_EQ(provider_->readCalls.load(), 0u);
}

/**
 * @tc.name: Lseek_DataHoleAndInvalidArguments_ReturnDefinedResults
 * @tc.desc: Verify supported sparse-file queries and rejection of invalid offsets, flags and handles.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfFuseTddTest, Lseek_DataHoleAndInvalidArguments_ReturnDefinedResults, TestSize.Level0)
{
    ASSERT_EQ(ActivateFile(), 0);
    auto inode = RootInode();
    auto request = mock_.MakeRequest(TARGET_UID);
    struct fuse_file_info info {};
    mock_.operations.lseek(request.Handle(), inode, 0, SEEK_DATA, nullptr);
    EXPECT_EQ(request.error, EBADF);
    mock_.operations.lseek(request.Handle(), inode, 0, SEEK_DATA, &info);
    EXPECT_EQ(request.error, EBADF);
    info.fh = inode;
    mock_.operations.lseek(request.Handle(), inode, 2, SEEK_DATA, &info);
    EXPECT_EQ(request.error, 0);
    EXPECT_EQ(request.seekOffset, 2);
    mock_.operations.lseek(request.Handle(), inode, 2, SEEK_HOLE, &info);
    EXPECT_EQ(request.seekOffset, 7);
    mock_.operations.lseek(request.Handle(), inode, -1, SEEK_DATA, &info);
    EXPECT_EQ(request.error, EINVAL);
    mock_.operations.lseek(request.Handle(), inode, 7, SEEK_DATA, &info);
    EXPECT_EQ(request.error, ENXIO);
    mock_.operations.lseek(request.Handle(), inode, 0, SEEK_SET, &info);
    EXPECT_EQ(request.error, EINVAL);
}

/**
 * @tc.name: Lseek_DeclaredSize_UseMetadataWithoutStat
 * @tc.desc: Verify seek uses the declared file size and does not request provider metadata.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfFuseTddTest, Lseek_DeclaredSize_UseMetadataWithoutStat, TestSize.Level0)
{
    ASSERT_EQ(ActivateFile(), 0);
    auto inode = RootInode();
    auto request = mock_.MakeRequest(TARGET_UID);
    struct fuse_file_info info {};
    info.fh = inode;
    provider_->mismatchId = true;
    mock_.operations.lseek(request.Handle(), inode, 0, SEEK_DATA, &info);
    EXPECT_EQ(request.error, 0);
    EXPECT_EQ(request.seekOffset, 0);
    mock_.operations.lseek(request.Handle(), inode, 0, SEEK_HOLE, &info);
    EXPECT_EQ(request.error, 0);
    EXPECT_EQ(request.seekOffset, 7);
    EXPECT_EQ(provider_->statCalls.load(), 0u);
}

/**
 * @tc.name: StatFs_TargetFiltering_ReportReadOnlyUsage
 * @tc.desc: Verify only the target sees private nodes in filesystem statistics.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfFuseTddTest, StatFs_TargetFiltering_ReportReadOnlyUsage, TestSize.Level0)
{
    ASSERT_EQ(ActivateFile(), 0);
    auto target = mock_.MakeRequest(TARGET_UID);
    mock_.operations.statfs(target.Handle(), 0);
    EXPECT_EQ(target.error, 0);
    EXPECT_EQ(target.statFs.f_bsize, 4096u);
    EXPECT_EQ(target.statFs.f_blocks, 1u);
    EXPECT_EQ(target.statFs.f_files, 3u);
    EXPECT_EQ(target.statFs.f_bfree, 0u);
    EXPECT_NE(target.statFs.f_flag & ST_RDONLY, 0u);
    auto other = mock_.MakeRequest(OTHER_UID);
    mock_.operations.statfs(other.Handle(), 0);
    EXPECT_EQ(other.statFs.f_blocks, 0u);
    EXPECT_EQ(other.statFs.f_files, 1u);
    mock_.operations.statfs(other.Handle(), RootInode());
    EXPECT_EQ(other.error, EACCES);
}

/**
 * @tc.name: RemoveSession_InvalidateOldInodesAndCancelFiles
 * @tc.desc: Verify old inodes disappear after deletion and cancellation is sent only once.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfFuseTddTest, RemoveSession_InvalidateOldInodesAndCancelFiles, TestSize.Level0)
{
    ASSERT_EQ(ActivateFile(), 0);
    auto inode = RootInode();
    auto *controller = static_cast<UdmfFuseController *>(mock_.userdata);
    controller->RemoveSession("tdd-session");
    controller->RemoveSession("tdd-session");
    EXPECT_EQ(provider_->cancelCalls, 1u);
    EXPECT_EQ(provider_->canceledIds, (std::vector<std::string>{ "example.bin" }));
    auto request = mock_.MakeRequest(TARGET_UID);
    mock_.operations.getattr(request.Handle(), inode, nullptr);
    EXPECT_EQ(request.error, ENOENT);
    mock_.operations.forget(request.Handle(), inode, 1);
    EXPECT_EQ(request.error, 0);
}

/**
 * @tc.name: CustomIo_NullControllerAndInvalidFd_ReturnError
 * @tc.desc: Verify custom reads reject null userdata and invalid descriptors without hanging.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfFuseTddTest, CustomIo_NullControllerAndInvalidFd_ReturnError, TestSize.Level0)
{
    ASSERT_EQ(ActivateFile(), 0);
    char buffer[8]{};
    EXPECT_EQ(mock_.customIo.read(-1, buffer, sizeof(buffer), nullptr), -1);
    EXPECT_EQ(errno, EINVAL);
    int fd = eventfd(0, EFD_CLOEXEC);
    ASSERT_GE(fd, 0);
    ASSERT_EQ(close(fd), 0);
    EXPECT_EQ(mock_.customIo.read(fd, buffer, sizeof(buffer), mock_.userdata), -1);
    EXPECT_EQ(errno, EIO);
}

/**
 * @tc.name: CustomIo_PipeDataAndRepeatedEmptyReads_PreserveRetryBound
 * @tc.desc: Verify real descriptor reads copy data and repeated zero-byte reads stop after the configured retries.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfFuseTddTest, CustomIo_PipeDataAndRepeatedEmptyReads_PreserveRetryBound, TestSize.Level0)
{
    ASSERT_EQ(ActivateFile(), 0);
    int descriptors[2]{};
    ASSERT_EQ(pipe(descriptors), 0);
    const char sent[] = "abc";
    EXPECT_EQ(write(descriptors[1], sent, 3), 3);
    char received[3]{};
    EXPECT_EQ(mock_.customIo.read(descriptors[0], received, sizeof(received), mock_.userdata), 3);
    EXPECT_EQ(std::string(received, sizeof(received)), "abc");
    EXPECT_EQ(write(descriptors[1], sent, 3), 3);
    EXPECT_EQ(mock_.customIo.read(descriptors[0], received, 0, mock_.userdata), -1);
    EXPECT_EQ(errno, EIO);
    (void)close(descriptors[0]);
    (void)close(descriptors[1]);
}

/**
 * @tc.name: CustomIo_WriteVectors_PropagateDataAndErrors
 * @tc.desc: Verify custom writev preserves buffers and reports invalid descriptor failures.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfFuseTddTest, CustomIo_WriteVectors_PropagateDataAndErrors, TestSize.Level0)
{
    ASSERT_EQ(ActivateFile(), 0);
    int descriptors[2]{};
    ASSERT_EQ(pipe(descriptors), 0);
    char first[] = "ab";
    char second[] = "cd";
    struct iovec vectors[2] = { { first, 2 }, { second, 2 } };
    EXPECT_EQ(mock_.customIo.writev(descriptors[1], vectors, 2, mock_.userdata), 4);
    char received[4]{};
    EXPECT_EQ(read(descriptors[0], received, sizeof(received)), 4);
    EXPECT_EQ(std::string(received, sizeof(received)), "abcd");
    EXPECT_EQ(mock_.customIo.writev(-1, vectors, 2, mock_.userdata), -1);
    EXPECT_EQ(mock_.customIo.writev(-1, vectors, 2, nullptr), -1);
    (void)close(descriptors[0]);
    (void)close(descriptors[1]);
}

/**
 * @tc.name: Register_SourceQuota_ReleasePendingCapacity
 * @tc.desc: Verify source pending quota includes all registered trees and is restored by removal.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfFuseTddTest, Register_SourceQuota_ReleasePendingCapacity, TestSize.Level0)
{
    for (size_t index = 0; index < 4; ++index) {
        ASSERT_EQ(Register(MakeFile(), "pending-" + std::to_string(index)), 0);
    }
    EXPECT_EQ(Register(MakeFile(), "pending-overflow"), -EAGAIN);
    manager_.Remove("pending-0");
    EXPECT_EQ(Register(MakeFile(), "pending-overflow"), 0);
}

/**
 * @tc.name: Register_GlobalQuota_RejectNinthPendingDrag
 * @tc.desc: Verify pending quota is enforced across source applications.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfFuseTddTest, Register_GlobalQuota_RejectNinthPendingDrag, TestSize.Level0)
{
    for (size_t index = 0; index < 8; ++index) {
        ASSERT_EQ(Register(MakeFile(), "global-" + std::to_string(index),
            SOURCE_TOKEN + static_cast<uint32_t>(index / 2)), 0);
    }
    EXPECT_EQ(Register(MakeFile(), "global-overflow", SOURCE_TOKEN + 10), -EAGAIN);
    manager_.Remove("global-0");
    EXPECT_EQ(Register(MakeFile(), "global-overflow", SOURCE_TOKEN + 10), 0);
}

/**
 * @tc.name: Activate_GlobalQuota_AllowNewDragAfterRemoval
 * @tc.desc: Verify a fourth active drag is rejected and removal restores global active capacity.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfFuseTddTest, Activate_GlobalQuota_AllowNewDragAfterRemoval, TestSize.Level0)
{
    for (size_t index = 0; index < 3; ++index) {
        std::string id = "active-" + std::to_string(index);
        ASSERT_EQ(Register(MakeFile(), id, SOURCE_TOKEN + static_cast<uint32_t>(index)), 0);
        ASSERT_EQ(manager_.Activate(id, TARGET_TOKEN, TARGET_UID, TARGET_UID, uri_), 0);
    }
    ASSERT_EQ(Register(MakeFile(), "active-overflow", SOURCE_TOKEN + 10), 0);
    EXPECT_EQ(manager_.Activate("active-overflow", TARGET_TOKEN, TARGET_UID, TARGET_UID, uri_), -EAGAIN);
    manager_.Remove("active-0");
    EXPECT_EQ(manager_.Activate("active-overflow", TARGET_TOKEN, TARGET_UID, TARGET_UID, uri_), 0);
    EXPECT_EQ(UdmfFuseMountAdapterMock::mounts, 1u);
}

/**
 * @tc.name: Activate_SourceQuota_AllowSecondButRejectThird
 * @tc.desc: Verify source active quota is independent of global free slots.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfFuseTddTest, Activate_SourceQuota_AllowSecondButRejectThird, TestSize.Level0)
{
    for (size_t index = 0; index < 2; ++index) {
        std::string id = "source-active-" + std::to_string(index);
        ASSERT_EQ(Register(MakeFile(), id), 0);
        ASSERT_EQ(manager_.Activate(id, TARGET_TOKEN, TARGET_UID, TARGET_UID, uri_), 0);
    }
    ASSERT_EQ(Register(MakeFile(), "source-overflow"), 0);
    EXPECT_EQ(manager_.Activate("source-overflow", TARGET_TOKEN, TARGET_UID, TARGET_UID, uri_), -EAGAIN);
    manager_.Remove("source-active-0");
    EXPECT_EQ(manager_.Activate("source-overflow", TARGET_TOKEN, TARGET_UID, TARGET_UID, uri_), 0);
}

/**
 * @tc.name: AddSession_DuplicateIdOrAlias_KeepExistingTree
 * @tc.desc: Verify failed direct session insertion cannot erase an existing authorized alias.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfFuseTddTest, AddSession_DuplicateIdOrAlias_KeepExistingTree, TestSize.Level0)
{
    ASSERT_EQ(ActivateFile(), 0);
    UdmfFuseSessionManager::SessionInfo session;
    ASSERT_TRUE(manager_.Get("tdd-session", session));
    UdmfFuseController::SessionOptions options{ "tdd-session", session.alias, MakeFile(),
        provider_->AsObject(), TARGET_UID, TARGET_UID };
    auto *controller = static_cast<UdmfFuseController *>(mock_.userdata);
    std::string path;
    EXPECT_EQ(controller->AddSession(options, path), -EEXIST);
    options.sessionId = "collision";
    EXPECT_EQ(controller->AddSession(options, path), -EEXIST);
    EXPECT_NE(RootInode(), 0u);
    EXPECT_TRUE(path.empty());
}

/**
 * @tc.name: AddSession_DuplicateChild_RollBackPartialTree
 * @tc.desc: Verify failed recursive insertion removes the partial alias and permits a corrected retry.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfFuseTddTest, AddSession_DuplicateChild_RollBackPartialTree, TestSize.Level0)
{
    ASSERT_EQ(ActivateFile(), 0);
    auto root = MakeDirectory(2);
    root.subItems[1].name = root.subItems[0].name;
    UdmfFuseController::SessionOptions options{ "partial", "partial-alias", root,
        provider_->AsObject(), TARGET_UID, TARGET_UID };
    auto *controller = static_cast<UdmfFuseController *>(mock_.userdata);
    std::string path;
    EXPECT_EQ(controller->AddSession(options, path), -EEXIST);
    EXPECT_EQ(Lookup(FUSE_ROOT_ID, "partial-alias"), 0u);
    EXPECT_NE(RootInode(), 0u);
    options.root = MakeDirectory(2);
    EXPECT_EQ(controller->AddSession(options, path), 0);
    EXPECT_EQ(path, "partial-alias/directory");
    controller->RemoveSession("partial");
}

/**
 * @tc.name: Callbacks_MissingInode_UseDefinedErrors
 * @tc.desc: Verify metadata, open, read, flush and seek cannot use a nonexistent inode.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfFuseTddTest, Callbacks_MissingInode_UseDefinedErrors, TestSize.Level0)
{
    ASSERT_EQ(ActivateFile(), 0);
    auto request = mock_.MakeRequest(TARGET_UID);
    struct fuse_file_info info {};
    constexpr fuse_ino_t missing = 999999;
    mock_.operations.getattr(request.Handle(), missing, &info);
    EXPECT_EQ(request.error, ENOENT);
    mock_.operations.access(request.Handle(), missing, R_OK);
    EXPECT_EQ(request.error, ENOENT);
    mock_.operations.open(request.Handle(), missing, &info);
    EXPECT_EQ(request.error, ENOENT);
    mock_.operations.read(request.Handle(), missing, 1, 0, &info);
    EXPECT_EQ(request.error, ENOENT);
    mock_.operations.flush(request.Handle(), missing, &info);
    EXPECT_EQ(request.error, ENOENT);
    mock_.operations.lseek(request.Handle(), missing, 0, SEEK_DATA, &info);
    EXPECT_EQ(request.error, ENOENT);
    mock_.operations.statfs(request.Handle(), missing);
    EXPECT_EQ(request.error, ENOENT);
    mock_.operations.releasedir(request.Handle(), missing, &info);
    EXPECT_EQ(request.error, 0);
}

/**
 * @tc.name: Directory_LargeTree_Enumerate600FilesWithoutRemoteStat
 * @tc.desc: Verify the large-directory regression path stays local during pre-scan.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfFuseTddTest, Directory_LargeTree_Enumerate600FilesWithoutRemoteStat, TestSize.Level1)
{
    ASSERT_EQ(Register(MakeDirectory(600)), 0);
    ASSERT_EQ(manager_.Activate("tdd-session", TARGET_TOKEN, TARGET_UID, TARGET_UID, uri_), 0);
    auto inode = RootInode();
    auto request = mock_.MakeRequest(TARGET_UID);
    mock_.operations.readdirplus(request.Handle(), inode, 65536, 0, nullptr);
    EXPECT_EQ(request.error, 0);
    EXPECT_EQ(request.names.size(), 602u);
    ASSERT_FALSE(request.names.empty());
    EXPECT_EQ(request.names.back(), "file-599");
    EXPECT_NE(Lookup(inode, "file-599"), 0u);
    EXPECT_EQ(provider_->statCalls.load(), 0u);
    EXPECT_EQ(provider_->readCalls.load(), 0u);
}

/**
 * @tc.name: Read_EmptyFile_ReturnEofWithoutProvider
 * @tc.desc: Verify a declared empty file is readable and does not trigger download or metadata callbacks.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfFuseTddTest, Read_EmptyFile_ReturnEofWithoutProvider, TestSize.Level0)
{
    ASSERT_EQ(ActivateFile(0), 0);
    auto inode = RootInode();
    auto request = mock_.MakeRequest(TARGET_UID);
    mock_.operations.read(request.Handle(), inode, 1024, 0, nullptr);
    EXPECT_EQ(request.error, 0);
    EXPECT_TRUE(request.bytes.empty());
    mock_.operations.getattr(request.Handle(), inode, nullptr);
    EXPECT_EQ(request.attr.st_size, 0);
    EXPECT_EQ(request.attr.st_blocks, 0);
    EXPECT_EQ(provider_->readCalls.load(), 0u);
    EXPECT_EQ(provider_->statCalls.load(), 0u);
}

/**
 * @tc.name: Read_ProviderErrors_MapExpectedFuseErrors
 * @tc.desc: Verify documented provider failures map to the corresponding FUSE error response.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfFuseTddTest, Read_ProviderErrors_MapExpectedFuseErrors, TestSize.Level1)
{
    for (int32_t status : { -ETIMEDOUT, -ECANCELED, -EAGAIN, -ENOENT, -EINVAL, -EACCES, -ESTALE, -EPIPE }) {
        SCOPED_TRACE(status);
        ASSERT_EQ(ActivateFile(), 0);
        provider_->statuses = { status, status, status };
        auto request = mock_.MakeRequest(TARGET_UID);
        mock_.operations.read(request.Handle(), RootInode(), 1, 0, nullptr);
        EXPECT_EQ(request.error, status == -EPIPE ? EIO : -status);
        EXPECT_TRUE(request.bytes.empty());
        manager_.Remove("tdd-session");
    }
}

/**
 * @tc.name: Remove_ThenNewDrag_ReadFreshData
 * @tc.desc: Verify a canceled session does not prevent a subsequent drag from downloading.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfFuseTddTest, Remove_ThenNewDrag_ReadFreshData, TestSize.Level0)
{
    ASSERT_EQ(ActivateFile(), 0);
    auto request = mock_.MakeRequest(TARGET_UID);
    mock_.operations.read(request.Handle(), RootInode(), 1, 0, nullptr);
    ASSERT_EQ(request.error, 0);
    manager_.Remove("tdd-session");
    provider_->content[0] = 0x42;
    ASSERT_EQ(ActivateFile(), 0);
    auto next = mock_.MakeRequest(TARGET_UID);
    mock_.operations.read(next.Handle(), RootInode(), 1, 0, nullptr);
    EXPECT_EQ(next.error, 0);
    EXPECT_EQ(next.bytes, (std::vector<uint8_t>{ 0x42 }));
    EXPECT_EQ(provider_->readCalls.load(), 2u);
}

/**
 * @tc.name: Unmount_Failure_RetryThroughLaterCleanup
 * @tc.desc: Verify a failed unmount can be retried without mounting a duplicate controller.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfFuseTddTest, Unmount_Failure_RetryThroughLaterCleanup, TestSize.Level0)
{
    ASSERT_EQ(ActivateFile(), 0);
    UdmfFuseMountAdapterMock::unmountStatus = -EIO;
    manager_.Remove("tdd-session");
    EXPECT_EQ(UdmfFuseMountAdapterMock::unmounts, 1u);
    UdmfFuseMountAdapterMock::unmountStatus = 0;
    ASSERT_EQ(Register(MakeFile(), "unmount-retry"), 0);
    manager_.Remove("unmount-retry");
    EXPECT_EQ(UdmfFuseMountAdapterMock::unmounts, 2u);
    EXPECT_EQ(ActivateFile(), 0);
    EXPECT_EQ(UdmfFuseMountAdapterMock::mounts, 2u);
}

/**
 * @tc.name: Read_OversizedProviderResult_RejectBeforeCopy
 * @tc.desc: Verify an asynchronous callback cannot exceed the requested block remainder.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfFuseTddTest, Read_OversizedProviderResult_RejectBeforeCopy, TestSize.Level0)
{
    ASSERT_EQ(ActivateFile(), 0);
    provider_->oversizedResult = true;
    auto request = mock_.MakeRequest(TARGET_UID);
    mock_.operations.read(request.Handle(), RootInode(), 1, 0, nullptr);
    EXPECT_EQ(request.error, EIO);
    EXPECT_TRUE(request.bytes.empty());
    EXPECT_EQ(provider_->readCalls.load(), 1u);
}

/**
 * @tc.name: Read_RepeatedCallback_KeepFirstCompletion
 * @tc.desc: Verify repeated callback delivery does not overwrite data or release a provider slot twice.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfFuseTddTest, Read_RepeatedCallback_KeepFirstCompletion, TestSize.Level0)
{
    ASSERT_EQ(ActivateFile(), 0);
    provider_->repeatCallback = true;
    auto inode = RootInode();
    auto request = mock_.MakeRequest(TARGET_UID);
    mock_.operations.read(request.Handle(), inode, 7, 0, nullptr);
    EXPECT_EQ(request.error, 0);
    EXPECT_EQ(request.bytes, provider_->content);
    mock_.operations.read(request.Handle(), inode, 1, 1, nullptr);
    EXPECT_EQ(request.bytes, (std::vector<uint8_t>{ 1 }));
    EXPECT_EQ(provider_->readCalls.load(), 1u);
}

/**
 * @tc.name: Read_MissingCallback_TimeoutAndRecoverNextRead
 * @tc.desc: Verify the public FUSE read deadline bounds an unresponsive provider and permits the next read.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfFuseTddTest, Read_MissingCallback_TimeoutAndRecoverNextRead, TestSize.Level2)
{
    ASSERT_EQ(ActivateFile(), 0);
    provider_->suppressCallback = true;
    auto inode = RootInode();
    auto request = mock_.MakeRequest(TARGET_UID);
    // This Level2 case intentionally waits for the production 30-second deadline.
    mock_.operations.read(request.Handle(), inode, 1, 0, nullptr);
    EXPECT_EQ(request.error, ETIMEDOUT);
    EXPECT_TRUE(request.bytes.empty());
    ASSERT_NE(provider_->pendingCallback, nullptr);
    VirtualEntryReadCallbackProxy late(provider_->pendingCallback);
    EXPECT_EQ(late.OnResult(0, { 0xAA }), 0);
    provider_->pendingCallback = nullptr;
    EXPECT_TRUE(request.bytes.empty());
    provider_->suppressCallback = false;
    auto retry = mock_.MakeRequest(TARGET_UID);
    mock_.operations.read(retry.Handle(), inode, 1, 0, nullptr);
    EXPECT_EQ(retry.error, 0);
    EXPECT_EQ(retry.bytes, (std::vector<uint8_t>{ 0 }));
}
} // namespace OHOS::UDMF
