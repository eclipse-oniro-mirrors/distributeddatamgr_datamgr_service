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
#define LOG_TAG "KvdbServiceImplDumpStackTest"
#include <fcntl.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <functional>
#include <limits>
#include <string>
#include <vector>

#include "account_delegate_mock.h"
#include "bootstrap.h"
#include "changeevent/remote_change_event.h"
#include "checker/checker_manager.h"
#include "cloud/cloud_event.h"
#include "cloud/cloud_server.h"
#include "device_manager_adapter.h"
#include "directory/directory_manager.h"
#include "distributed_kv_data_manager.h"
#include "eventcenter/event_center.h"
#include "ipc_skeleton.h"
#include "kvdb_query.h"
#include "kvdb_service_impl.h"
#include "kvdb_service_stub.h"
#include "kvstore_death_recipient.h"
#include "kvstore_meta_manager.h"
#include "kvstore_sync_manager.h"
#include "log_print.h"
#include "metadata/auto_launch_meta_data.h"
#include "mock/access_token_mock.h"
#include "mock/meta_data_manager_mock.h"
#include "nativetoken_kit.h"
#include "network/network_delegate.h"
#include "network_delegate_mock.h"
#include "sync_mgr/sync_mgr.h"
#include "token_setproc.h"
#include "types.h"
#include "utils/anonymous.h"
#include "utils/constant.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::DistributedData;
using namespace OHOS::Security::AccessToken;
using MetaAction = OHOS::DistributedData::MetaDataManager::Action;
using AppId = OHOS::DistributedKv::AppId;
using ChangeType = OHOS::DistributedData::DeviceMatrix::ChangeType;
using DistributedKvDataManager = OHOS::DistributedKv::DistributedKvDataManager;
using DBStatus = DistributedDB::DBStatus;
using DBMode = DistributedDB::SyncMode;
using Options = OHOS::DistributedKv::Options;
using Status = OHOS::DistributedKv::Status;
using SingleKvStore = OHOS::DistributedKv::SingleKvStore;
using StoreId = OHOS::DistributedKv::StoreId;
using SyncInfo = OHOS::DistributedKv::KVDBService::SyncInfo;
using SyncMode = OHOS::DistributedKv::SyncMode;
using SyncAction = OHOS::DistributedKv::KVDBServiceImpl::SyncAction;
using SwitchState = OHOS::DistributedKv::SwitchState;
using UserId = OHOS::DistributedKv::UserId;
using StoreMetaData = OHOS::DistributedData::StoreMetaData;
using SyncEnd = OHOS::DistributedKv::KvStoreSyncManager::SyncEnd;
using DBResult = std::map<std::string, DistributedDB::DBStatus>;
using DmAdapter = OHOS::DistributedData::DeviceManagerAdapter;
using DBLaunchParam = OHOS::DistributedKv::KVDBServiceImpl::DBLaunchParam;
using BackupInfo = OHOS::DistributedKv::BackupInfo;
static OHOS::DistributedKv::StoreId storeId = { "kvdb_test_storeid" };
static constexpr const char *TEST_USER = "0";
namespace {
constexpr unsigned long HMFS_IOCTL_MAGIC = 0xF5;

struct HmfsKeyFileArgs {
    char filename[256];
    uint32_t flags;
};

constexpr unsigned long HMFS_IOC_KEY_FILE_SETFLAGS = _IOW(HMFS_IOCTL_MAGIC, 72, HmfsKeyFileArgs);
constexpr unsigned long HMFS_IOC_KEY_FILE_GETFLAGS = _IOWR(HMFS_IOCTL_MAGIC, 73, HmfsKeyFileArgs);

using IoctlHandler = std::function<int(int, unsigned long, void *)>;
IoctlHandler g_ioctlHandler;

struct IoctlPlan {
    int getRet = 0;
    int getErr = 0;
    int setRet = 0;
    int setErr = 0;
    uint32_t getFlags = 0;
    std::string taggedName;
    std::string failSetName;
    int getCalls = 0;
    int setCalls = 0;
};

IoctlHandler MakeIoctlHandler(std::shared_ptr<IoctlPlan> plan)
{
    return [plan](int fd, unsigned long request, void *arg) {
        auto *args = static_cast<HmfsKeyFileArgs *>(arg);
        std::string name = (args != nullptr) ? std::string(args->filename) : std::string();
        if (request == HMFS_IOC_KEY_FILE_GETFLAGS) {
            ++plan->getCalls;
            if (plan->getRet != 0) {
                errno = plan->getErr;
                return plan->getRet;
            }
            if (args != nullptr) {
                bool tagged = !plan->taggedName.empty() && name.find(plan->taggedName) != std::string::npos;
                args->flags = tagged ? 1u : plan->getFlags;
            }
            return 0;
        }
        if (request == HMFS_IOC_KEY_FILE_SETFLAGS) {
            ++plan->setCalls;
            if (plan->setRet != 0) {
                errno = plan->setErr;
                return plan->setRet;
            }
            if (!plan->failSetName.empty() && name.find(plan->failSetName) != std::string::npos) {
                errno = EACCES;
                return -1;
            }
            return 0;
        }
        return static_cast<int>(syscall(SYS_ioctl, fd, request, arg));
    };
}

class IoctlHookGuard {
public:
    explicit IoctlHookGuard(const IoctlHandler &handler)
    {
        g_ioctlHandler = handler;
    }

    ~IoctlHookGuard()
    {
        g_ioctlHandler = nullptr;
    }
};

bool MakeDir(const std::string &path)
{
    return mkdir(path.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH) == 0 || errno == EEXIST;
}

bool MakeDirs(const std::string &path, std::vector<std::string> &newDirs)
{
    for (size_t pos = 0; pos != std::string::npos;) {
        pos = path.find('/', pos + 1);
        std::string dir = path.substr(0, pos);
        if (dir.empty() || access(dir.c_str(), F_OK) == 0) {
            continue;
        }
        if (!MakeDir(dir)) {
            return false;
        }
        newDirs.push_back(dir);
    }
    return true;
}

void RemoveDirs(const std::vector<std::string> &dirs)
{
    for (auto it = dirs.rbegin(); it != dirs.rend(); ++it) {
        (void)rmdir(it->c_str());
    }
}

bool MakeFile(const std::string &path)
{
    int fd = open(path.c_str(), O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        return false;
    }
    close(fd);
    return true;
}

std::string GetDbStoreDir(const std::string &storeId)
{
    std::string storeDir;
    if (DistributedDB::KvStoreDelegateManager::GetDatabaseDir(storeId, storeDir) != DistributedDB::DBStatus::OK) {
        return "";
    }
    return storeDir;
}

std::string GetDbBase(const std::string &dbRoot, const std::string &storeId)
{
    std::string storeDir = GetDbStoreDir(storeId);
    if (storeDir.empty()) {
        return "";
    }
    return dbRoot + "/" + storeDir + "/single_ver/";
}

bool CreateDbLayout(const std::string &dbRoot, const std::string &storeId)
{
    std::string storeDir = GetDbStoreDir(storeId);
    if (storeDir.empty()) {
        return false;
    }
    std::string base = dbRoot + "/" + storeDir + "/single_ver/";
    if (!MakeDir(dbRoot) || !MakeDir(dbRoot + "/" + storeDir) || !MakeDir(base)) {
        return false;
    }
    return MakeDir(base + "main") && MakeDir(base + "meta");
}

void RemoveDbLayout(const std::string &dbRoot, const std::string &storeId)
{
    std::string storeDir = GetDbStoreDir(storeId);
    if (storeDir.empty()) {
        return;
    }
    std::string base = dbRoot + "/" + storeDir + "/single_ver/";
    const std::string files[] = { "main/gen_natural_store.db", "main/gen_natural_store.db-wal",
        "main/gen_natural_store.db-shm", "meta/meta.db", "meta/meta.db-wal", "meta/meta.db-shm" };
    for (const auto &file : files) {
        (void)unlink((base + file).c_str());
    }
    (void)rmdir((base + "main").c_str());
    (void)rmdir((base + "meta").c_str());
    (void)rmdir(base.c_str());
    (void)rmdir((dbRoot + "/" + storeDir).c_str());
    (void)rmdir(dbRoot.c_str());
}
} // namespace

extern "C" int __wrap_ioctl(int fd, unsigned long request, void *arg) /* NOLINT */
{
    if (g_ioctlHandler != nullptr) {
        return g_ioctlHandler(fd, request, arg);
    }
    return static_cast<int>(syscall(SYS_ioctl, fd, request, arg));
}

namespace OHOS::Test {
namespace DistributedDataTest {
constexpr size_t EXECUTOR_MIN_SIZE = 5;
constexpr size_t EXECUTOR_MAX_SIZE = 12;

class KvdbServiceImplDumpStackTest : public testing::Test {
public:
    static inline std::shared_ptr<AccessTokenKitMock> accTokenMock = nullptr;
    static inline std::shared_ptr<AccountDelegateMock> accountDelegateMock = nullptr;
    static inline std::shared_ptr<MetaDataManagerMock> metaDataManagerMock = nullptr;
    static inline std::shared_ptr<MetaDataMock<StoreMetaData>> metaDataMock = nullptr;
    static DistributedKvDataManager manager;
    static Options create;
    static UserId userId;
    static AppId appId;

    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    static void RemoveAllStore(OHOS::DistributedKv::DistributedKvDataManager &manager);
    void SetUp();
    void TearDown();

protected:
    std::shared_ptr<DistributedKv::KVDBServiceImpl> kvdbServiceImpl_;
    static NetworkDelegateMock delegate_;
    StoreMetaData metaData_;
    Options options_;
};

DistributedKvDataManager KvdbServiceImplDumpStackTest::manager;
Options KvdbServiceImplDumpStackTest::create;
UserId KvdbServiceImplDumpStackTest::userId;
AppId KvdbServiceImplDumpStackTest::appId;
NetworkDelegateMock KvdbServiceImplDumpStackTest::delegate_;

void KvdbServiceImplDumpStackTest::RemoveAllStore(DistributedKvDataManager &manager)
{
    manager.CloseAllKvStore(appId);
    manager.DeleteAllKvStore(appId, create.baseDir);
}

void KvdbServiceImplDumpStackTest::SetUpTestCase(void)
{
    auto executors = std::make_shared<ExecutorPool>(EXECUTOR_MAX_SIZE, EXECUTOR_MIN_SIZE);
    manager.SetExecutors(executors);
    userId.userId = "kvdbserviceimpltest1";
    appId.appId = "ohos.kvdbserviceimpl.test";
    create.createIfMissing = true;
    create.encrypt = false;
    create.securityLevel = OHOS::DistributedKv::S1;
    create.autoSync = true;
    create.kvStoreType = OHOS::DistributedKv::SINGLE_VERSION;
    create.area = OHOS::DistributedKv::EL1;
    create.baseDir = std::string("/data/service/el1/public/database/") + appId.appId;
    mkdir(create.baseDir.c_str(), (S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH));
    RemoveAllStore(manager);

    accTokenMock = std::make_shared<AccessTokenKitMock>();
    BAccessTokenKit::accessTokenkit = accTokenMock;
    accountDelegateMock = std::make_shared<AccountDelegateMock>();
    AccountDelegate::instance_ = nullptr;
    AccountDelegate::RegisterAccountInstance(accountDelegateMock.get());
    metaDataManagerMock = std::make_shared<MetaDataManagerMock>();
    BMetaDataManager::metaDataManager = metaDataManagerMock;
    metaDataMock = std::make_shared<MetaDataMock<StoreMetaData>>();
    BMetaData<StoreMetaData>::metaDataManager = metaDataMock;
    NetworkDelegate::RegisterNetworkInstance(&delegate_);
    std::vector<DirectoryManager::Strategy> strategies = {
        { true, 0, "/data/local/tmp/dump_stack_ut/{bundleName}/kvdb", "/data/local/tmp/dump_stack_ut/meta", "" },
    };
    std::vector<DirectoryManager::StoreType> storeTypes;
    DirectoryManager::GetInstance().Initialize(strategies, storeTypes);
}

void KvdbServiceImplDumpStackTest::TearDownTestCase()
{
    RemoveAllStore(manager);
    (void)remove((create.baseDir + "/kvdb").c_str());
    (void)remove(create.baseDir.c_str());

    accTokenMock = nullptr;
    BAccessTokenKit::accessTokenkit = nullptr;
    accountDelegateMock = nullptr;
    AccountDelegate::RegisterAccountInstance(nullptr);
    metaDataManagerMock = nullptr;
    BMetaDataManager::metaDataManager = nullptr;
    metaDataMock = nullptr;
    BMetaData<StoreMetaData>::metaDataManager = nullptr;
    std::vector<DirectoryManager::Strategy> resetStrategies;
    std::vector<DirectoryManager::StoreType> resetStoreTypes;
    DirectoryManager::GetInstance().Initialize(resetStrategies, resetStoreTypes);
}

void KvdbServiceImplDumpStackTest::SetUp(void)
{
    kvdbServiceImpl_ = std::make_shared<DistributedKv::KVDBServiceImpl>();

    EXPECT_CALL(*accountDelegateMock, GetCurrentAccountId()).WillRepeatedly(testing::Return("testAccount"));
    options_.isNeedCompress = true;
    metaData_.deviceId = DmAdapter::GetInstance().GetLocalDevice().uuid;
    metaData_.bundleName = appId.appId;
    metaData_.storeId = storeId.storeId;
    metaData_.user = TEST_USER;
    metaData_.tokenId = OHOS::IPCSkeleton::GetCallingTokenID();
    metaData_.version = 1;
    MetaDataManager::GetInstance().DelMeta(metaData_.GetKey());
}

void KvdbServiceImplDumpStackTest::TearDown(void)
{
    RemoveAllStore(manager);
}

/**
 * @tc.name: DumpStack_AfterCreate_FlagEnabled_Native_ReturnOk
 * @tc.desc: AC-1.1 - AfterCreate with dumpStackOnFileDeletion keeps the legacy return code and tags the default dir
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(KvdbServiceImplDumpStackTest, DumpStack_AfterCreate_FlagEnabled_Native_ReturnOk, TestSize.Level0)
{
    auto tokenMock = std::make_shared<AccessTokenKitMock>();
    ON_CALL(*tokenMock, GetTokenTypeFlag(_)).WillByDefault(Return(TOKEN_NATIVE));
    BAccessTokenKit::accessTokenkit = tokenMock;

    StoreMetaData dirMeta;
    dirMeta.bundleName = appId.appId;
    std::string dataDir = DirectoryManager::GetInstance().GetStorePath(dirMeta);
    ASSERT_FALSE(dataDir.empty());
    ASSERT_TRUE(CreateDbLayout(dataDir, storeId.storeId));
    std::string base = GetDbBase(dataDir, storeId.storeId);
    ASSERT_FALSE(base.empty());
    ASSERT_TRUE(MakeFile(base + "meta/meta.db"));

    Options opts = create;
    opts.dumpStackOnFileDeletion = true;
    auto plan = std::make_shared<IoctlPlan>();
    IoctlHookGuard guard(MakeIoctlHandler(plan));
    std::vector<uint8_t> password;
    auto status = kvdbServiceImpl_->AfterCreate(appId, storeId, opts, password);

    EXPECT_EQ(status, Status::SUCCESS);
    EXPECT_EQ(plan->getCalls, 1);
    EXPECT_EQ(plan->setCalls, 1);
    BAccessTokenKit::accessTokenkit = accTokenMock;
    RemoveDbLayout(dataDir, storeId.storeId);
}

/**
 * @tc.name: DumpStack_AfterCreate_FlagDisabled_ReturnOk
 * @tc.desc: AC-1.1 - AfterCreate without the flag keeps the legacy behavior
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(KvdbServiceImplDumpStackTest, DumpStack_AfterCreate_FlagDisabled_ReturnOk, TestSize.Level0)
{
    Options opts = create;
    opts.dumpStackOnFileDeletion = false;
    std::vector<uint8_t> password;
    auto status = kvdbServiceImpl_->AfterCreate(appId, storeId, opts, password);

    EXPECT_EQ(status, Status::SUCCESS);
}

/**
 * @tc.name: DumpStack_AfterCreate_NonSystemApp_ReturnOk
 * @tc.desc: AC-3.1 - A non system application caller skips tagging without changing the return code
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(KvdbServiceImplDumpStackTest, DumpStack_AfterCreate_NonSystemApp_ReturnOk, TestSize.Level0)
{
    auto tokenMock = std::make_shared<AccessTokenKitMock>();
    ON_CALL(*tokenMock, GetTokenTypeFlag(_)).WillByDefault(Return(TOKEN_HAP));
    auto tokenIdKitMock = std::make_shared<TokenIdKitMock>();
    ON_CALL(*tokenIdKitMock, IsSystemAppByFullTokenID(_)).WillByDefault(Return(false));
    BAccessTokenKit::accessTokenkit = tokenMock;
    BTokenIdKit::tokenkIdKit = tokenIdKitMock;

    Options opts = create;
    opts.dumpStackOnFileDeletion = true;
    std::vector<uint8_t> password;
    auto status = kvdbServiceImpl_->AfterCreate(appId, storeId, opts, password);

    EXPECT_EQ(status, Status::SUCCESS);
    BAccessTokenKit::accessTokenkit = accTokenMock;
    BTokenIdKit::tokenkIdKit = nullptr;
}

/**
 * @tc.name: DumpStack_AfterCreate_LocalOnlyType_ReturnOk
 * @tc.desc: AC-1.3 - A LOCAL_ONLY store has no db/wal/shm layout and skips tagging
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(KvdbServiceImplDumpStackTest, DumpStack_AfterCreate_LocalOnlyType_ReturnOk, TestSize.Level0)
{
    auto tokenMock = std::make_shared<AccessTokenKitMock>();
    ON_CALL(*tokenMock, GetTokenTypeFlag(_)).WillByDefault(Return(TOKEN_NATIVE));
    BAccessTokenKit::accessTokenkit = tokenMock;

    Options opts = create;
    opts.dumpStackOnFileDeletion = true;
    opts.kvStoreType = OHOS::DistributedKv::LOCAL_ONLY;
    std::vector<uint8_t> password;
    auto status = kvdbServiceImpl_->AfterCreate(appId, storeId, opts, password);

    EXPECT_EQ(status, Status::SUCCESS);
    BAccessTokenKit::accessTokenkit = accTokenMock;
}

/**
 * @tc.name: DumpStack_AfterCreate_SystemAppFlagEnabled_ReturnOk
 * @tc.desc: AC-3.1 - A system application caller reaches the tagging flow and keeps the return code
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(KvdbServiceImplDumpStackTest, DumpStack_AfterCreate_SystemAppFlagEnabled_ReturnOk, TestSize.Level0)
{
    auto tokenMock = std::make_shared<AccessTokenKitMock>();
    ON_CALL(*tokenMock, GetTokenTypeFlag(_)).WillByDefault(Return(TOKEN_HAP));
    ON_CALL(*tokenMock, GetHapTokenInfo(_, _)).WillByDefault(Return(0));
    auto tokenIdMock = std::make_shared<TokenIdKitMock>();
    ON_CALL(*tokenIdMock, IsSystemAppByFullTokenID(_)).WillByDefault(Return(true));
    BAccessTokenKit::accessTokenkit = tokenMock;
    BTokenIdKit::tokenkIdKit = tokenIdMock;

    Options opts = create;
    opts.dumpStackOnFileDeletion = true;
    std::vector<uint8_t> password;
    auto status = kvdbServiceImpl_->AfterCreate(appId, storeId, opts, password);

    EXPECT_EQ(status, Status::SUCCESS);
    BAccessTokenKit::accessTokenkit = accTokenMock;
    BTokenIdKit::tokenkIdKit = nullptr;
}

/**
 * @tc.name: DumpStack_AfterCreate_CustomDirWithoutWhitelist_TagAssembledDir
 * @tc.desc: AC-1.2 - AfterCreate assembles a HAP custom dir without auto-sync whitelist metadata
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(KvdbServiceImplDumpStackTest, DumpStack_AfterCreate_CustomDirWithoutWhitelist_TagAssembledDir, TestSize.Level0)
{
    auto tokenMock = std::make_shared<AccessTokenKitMock>();
    ON_CALL(*tokenMock, GetTokenTypeFlag(_)).WillByDefault(Return(TOKEN_HAP));
    HapTokenInfo hapInfo{};
    hapInfo.instIndex = 0;
    ON_CALL(*tokenMock, GetHapTokenInfo(_, _)).WillByDefault(DoAll(SetArgReferee<1>(hapInfo), Return(0)));
    auto tokenIdKitMock = std::make_shared<TokenIdKitMock>();
    ON_CALL(*tokenIdKitMock, IsSystemAppByFullTokenID(_)).WillByDefault(Return(true));
    BAccessTokenKit::accessTokenkit = tokenMock;
    BTokenIdKit::tokenkIdKit = tokenIdKitMock;
    SyncManager::AutoSyncInfo empty;
    SyncManager::GetInstance().SetAutoSyncAppInfo(empty);

    Options opts = create;
    opts.dumpStackOnFileDeletion = true;
    opts.isCustomDir = true;
    std::string customLeaf = "dump_stack_ut_after_create_custom";
    opts.baseDir = std::string(create.baseDir) + "/" + customLeaf;

    StoreMetaData meta;
    meta.storeId = storeId.storeId;
    meta.dataDir = opts.baseDir;
    meta.storeType = static_cast<int32_t>(opts.kvStoreType);
    meta.securityLevel = opts.securityLevel;
    meta.area = opts.area;
    meta.bundleName = appId.appId;
    meta.appId = appId.appId;
    meta.appType = "harmony";
    meta.hapName = opts.hapName;
    meta.user = TEST_USER;
    meta.instanceId = hapInfo.instIndex;
    std::string customDir = kvdbServiceImpl_->AssembleCustomDir(meta, customLeaf);
    ASSERT_FALSE(customDir.empty());
    std::vector<std::string> newDirs;
    ASSERT_TRUE(MakeDirs(customDir, newDirs));
    ASSERT_TRUE(CreateDbLayout(customDir, storeId.storeId));
    std::string base = GetDbBase(customDir, storeId.storeId);
    ASSERT_FALSE(base.empty());
    ASSERT_TRUE(MakeFile(base + "meta/meta.db"));

    auto plan = std::make_shared<IoctlPlan>();
    IoctlHookGuard guard(MakeIoctlHandler(plan));
    std::vector<uint8_t> password;
    auto status = kvdbServiceImpl_->AfterCreate(appId, storeId, opts, password);

    EXPECT_EQ(status, Status::SUCCESS);
    EXPECT_EQ(plan->getCalls, 1);
    EXPECT_EQ(plan->setCalls, 1);

    BAccessTokenKit::accessTokenkit = accTokenMock;
    BTokenIdKit::tokenkIdKit = nullptr;
    RemoveDbLayout(customDir, storeId.storeId);
    RemoveDirs(newDirs);
}

/**
 * @tc.name: DumpStack_AfterCreate_UpgradeFailed_StillTags
 * @tc.desc: AC-1.1 - A failed store upgrade still tags files and keeps the upgrade failure code
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(KvdbServiceImplDumpStackTest, DumpStack_AfterCreate_UpgradeFailed_StillTags, TestSize.Level0)
{
    auto tokenMock = std::make_shared<AccessTokenKitMock>();
    ON_CALL(*tokenMock, GetTokenTypeFlag(_)).WillByDefault(Return(TOKEN_NATIVE));
    BAccessTokenKit::accessTokenkit = tokenMock;

    EXPECT_CALL(*metaDataManagerMock, LoadMeta(testing::_, testing::_, testing::_))
        .WillOnce(testing::DoAll(testing::Invoke([](const std::string &, Serializable &meta, bool) {
            auto &oldMeta = static_cast<StoreMetaMapping &>(meta);
            oldMeta.dataDir = "/data/service/el1/public/database/old_dump_stack_dir";
        }),
            testing::Return(true)))
        .WillRepeatedly(testing::Return(true));

    StoreMetaData dirMeta;
    dirMeta.bundleName = appId.appId;
    std::string dataDir = DirectoryManager::GetInstance().GetStorePath(dirMeta);
    ASSERT_FALSE(dataDir.empty());
    ASSERT_TRUE(CreateDbLayout(dataDir, storeId.storeId));
    std::string base = GetDbBase(dataDir, storeId.storeId);
    ASSERT_FALSE(base.empty());
    ASSERT_TRUE(MakeFile(base + "meta/meta.db"));

    auto plan = std::make_shared<IoctlPlan>();
    IoctlHookGuard guard(MakeIoctlHandler(plan));

    Options opts = create;
    opts.dumpStackOnFileDeletion = true;
    std::vector<uint8_t> password;
    auto status = kvdbServiceImpl_->AfterCreate(appId, storeId, opts, password);

    EXPECT_EQ(status, Status::STORE_UPGRADE_FAILED);
    EXPECT_EQ(plan->getCalls, 1);
    EXPECT_EQ(plan->setCalls, 1);
    BAccessTokenKit::accessTokenkit = accTokenMock;
    RemoveDbLayout(dataDir, storeId.storeId);
}

/**
 * @tc.name: DumpStack_SetDumpStackTags_DefaultDir_001
 * @tc.desc: AC-1.1 - Existing db and meta files are tagged once, an already tagged file is skipped
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(KvdbServiceImplDumpStackTest, DumpStack_SetDumpStackTags_DefaultDir_001, TestSize.Level0)
{
    std::string storeIdStr = "dumpStackTagDefault";
    std::string root = std::string(create.baseDir) + "/dump_stack_ut_default";
    std::string dataDir = root + "/data";
    ASSERT_TRUE(MakeDir(root));
    ASSERT_TRUE(CreateDbLayout(dataDir, storeIdStr));
    std::string base = GetDbBase(dataDir, storeIdStr);
    ASSERT_FALSE(base.empty());
    ASSERT_TRUE(MakeFile(base + "main/gen_natural_store.db"));
    ASSERT_TRUE(MakeFile(base + "meta/meta.db"));

    auto tokenMock = std::make_shared<AccessTokenKitMock>();
    ON_CALL(*tokenMock, GetTokenTypeFlag(_)).WillByDefault(Return(TOKEN_NATIVE));
    BAccessTokenKit::accessTokenkit = tokenMock;

    StoreMetaData meta;
    meta.storeId = storeIdStr;
    meta.dataDir = dataDir;
    meta.storeType = static_cast<int32_t>(OHOS::DistributedKv::SINGLE_VERSION);
    auto plan = std::make_shared<IoctlPlan>();
    plan->taggedName = "gen_natural_store.db";
    IoctlHookGuard guard(MakeIoctlHandler(plan));

    kvdbServiceImpl_->SetDumpStackTags(meta, false);

    EXPECT_EQ(plan->getCalls, 2);
    EXPECT_EQ(plan->setCalls, 1);

    BAccessTokenKit::accessTokenkit = accTokenMock;
    RemoveDbLayout(dataDir, storeIdStr);
    (void)rmdir(root.c_str());
}

/**
 * @tc.name: DumpStack_SetDumpStackTags_SetFail_001
 * @tc.desc: AC-1.5 - A failed tag set degrades silently and the remaining files are still processed
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(KvdbServiceImplDumpStackTest, DumpStack_SetDumpStackTags_SetFail_001, TestSize.Level0)
{
    std::string storeIdStr = "dumpStackTagSetFail";
    std::string root = std::string(create.baseDir) + "/dump_stack_ut_set_fail";
    std::string dataDir = root + "/data";
    ASSERT_TRUE(MakeDir(root));
    ASSERT_TRUE(CreateDbLayout(dataDir, storeIdStr));
    std::string base = GetDbBase(dataDir, storeIdStr);
    ASSERT_FALSE(base.empty());
    ASSERT_TRUE(MakeFile(base + "main/gen_natural_store.db"));
    ASSERT_TRUE(MakeFile(base + "meta/meta.db"));

    auto tokenMock = std::make_shared<AccessTokenKitMock>();
    ON_CALL(*tokenMock, GetTokenTypeFlag(_)).WillByDefault(Return(TOKEN_NATIVE));
    BAccessTokenKit::accessTokenkit = tokenMock;

    StoreMetaData meta;
    meta.storeId = storeIdStr;
    meta.dataDir = dataDir;
    meta.storeType = static_cast<int32_t>(OHOS::DistributedKv::SINGLE_VERSION);
    auto plan = std::make_shared<IoctlPlan>();
    plan->failSetName = "gen_natural_store.db";
    IoctlHookGuard guard(MakeIoctlHandler(plan));

    kvdbServiceImpl_->SetDumpStackTags(meta, false);

    EXPECT_EQ(plan->getCalls, 2);
    EXPECT_EQ(plan->setCalls, 2);

    BAccessTokenKit::accessTokenkit = accTokenMock;
    RemoveDbLayout(dataDir, storeIdStr);
    (void)rmdir(root.c_str());
}

/**
 * @tc.name: DumpStack_SetDumpStackTags_CustomDir_001
 * @tc.desc: AC-1.2 - A native custom dir store uses dataDir when customDir is empty
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(KvdbServiceImplDumpStackTest, DumpStack_SetDumpStackTags_CustomDir_001, TestSize.Level0)
{
    std::string storeIdStr = "dumpStackTagCustom";
    std::string root = std::string(create.baseDir) + "/dump_stack_ut_custom";
    std::string dataDir = root;
    ASSERT_TRUE(MakeDir(root));
    ASSERT_TRUE(CreateDbLayout(dataDir, storeIdStr));
    std::string base = GetDbBase(dataDir, storeIdStr);
    ASSERT_FALSE(base.empty());
    ASSERT_TRUE(MakeFile(base + "meta/meta.db"));

    auto tokenMock = std::make_shared<AccessTokenKitMock>();
    ON_CALL(*tokenMock, GetTokenTypeFlag(_)).WillByDefault(Return(TOKEN_NATIVE));
    BAccessTokenKit::accessTokenkit = tokenMock;

    StoreMetaData meta;
    meta.storeId = storeIdStr;
    meta.dataDir = root;
    meta.storeType = static_cast<int32_t>(OHOS::DistributedKv::SINGLE_VERSION);
    auto plan = std::make_shared<IoctlPlan>();
    IoctlHookGuard guard(MakeIoctlHandler(plan));

    kvdbServiceImpl_->SetDumpStackTags(meta, true);

    EXPECT_EQ(plan->getCalls, 1);
    EXPECT_EQ(plan->setCalls, 1);

    BAccessTokenKit::accessTokenkit = accTokenMock;
    RemoveDbLayout(dataDir, storeIdStr);
    (void)rmdir(root.c_str());
}

/**
 * @tc.name: DumpStack_SetDumpStackTags_CustomDirSyncMeta_001
 * @tc.desc: AC-1.2 - A store prefers existing meta.customDir with either custom-dir flag
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(KvdbServiceImplDumpStackTest, DumpStack_SetDumpStackTags_CustomDirSyncMeta_001, TestSize.Level0)
{
    std::string storeIdStr = "dumpStackTagCustomSyncMeta";
    std::string root = std::string(create.baseDir) + "/dump_stack_ut_custom_sync_meta";
    std::string customDir = root + "/sync/kvdb";
    ASSERT_TRUE(MakeDir(root));
    ASSERT_TRUE(MakeDir(root + "/sync"));
    ASSERT_TRUE(CreateDbLayout(customDir, storeIdStr));
    std::string base = GetDbBase(customDir, storeIdStr);
    ASSERT_FALSE(base.empty());
    ASSERT_TRUE(MakeFile(base + "meta/meta.db"));

    auto tokenMock = std::make_shared<AccessTokenKitMock>();
    ON_CALL(*tokenMock, GetTokenTypeFlag(_)).WillByDefault(Return(TOKEN_HAP));
    BAccessTokenKit::accessTokenkit = tokenMock;
    auto tokenIdKitMock = std::make_shared<TokenIdKitMock>();
    ON_CALL(*tokenIdKitMock, IsSystemAppByFullTokenID(_)).WillByDefault(Return(true));
    BTokenIdKit::tokenkIdKit = tokenIdKitMock;

    StoreMetaData meta;
    meta.storeId = storeIdStr;
    meta.dataDir = root;
    meta.customDir = customDir;
    meta.storeType = static_cast<int32_t>(OHOS::DistributedKv::SINGLE_VERSION);
    auto plan = std::make_shared<IoctlPlan>();
    IoctlHookGuard guard(MakeIoctlHandler(plan));

    kvdbServiceImpl_->SetDumpStackTags(meta, true);
    kvdbServiceImpl_->SetDumpStackTags(meta, false);

    EXPECT_EQ(plan->getCalls, 2);
    EXPECT_EQ(plan->setCalls, 2);

    BAccessTokenKit::accessTokenkit = accTokenMock;
    BTokenIdKit::tokenkIdKit = nullptr;
    RemoveDbLayout(customDir, storeIdStr);
    (void)rmdir((root + "/sync").c_str());
    (void)rmdir(root.c_str());
}

/**
 * @tc.name: DumpStack_SetDumpStackTags_DefaultEmptyDir_001
 * @tc.desc: AC-1.1 - A non-custom store with an empty dataDir uses the DirectoryManager path
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(KvdbServiceImplDumpStackTest, DumpStack_SetDumpStackTags_DefaultEmptyDir_001, TestSize.Level0)
{
    std::string storeIdStr = "dumpStackTagDefaultEmpty";
    auto tokenMock = std::make_shared<AccessTokenKitMock>();
    ON_CALL(*tokenMock, GetTokenTypeFlag(_)).WillByDefault(Return(TOKEN_NATIVE));
    BAccessTokenKit::accessTokenkit = tokenMock;

    StoreMetaData meta;
    meta.storeId = storeIdStr;
    meta.bundleName = appId.appId;
    meta.user = TEST_USER;
    Options options;
    options.kvStoreType = OHOS::DistributedKv::SINGLE_VERSION;
    options.area = OHOS::DistributedKv::EL1;
    options.securityLevel = OHOS::DistributedKv::S1;
    kvdbServiceImpl_->AddOptions(options, meta);
    std::string dataDir = meta.dataDir;
    ASSERT_FALSE(dataDir.empty());
    std::vector<std::string> newDirs;
    ASSERT_TRUE(MakeDirs(dataDir, newDirs));
    ASSERT_TRUE(CreateDbLayout(dataDir, storeIdStr));
    std::string base = GetDbBase(dataDir, storeIdStr);
    ASSERT_FALSE(base.empty());
    ASSERT_TRUE(MakeFile(base + "meta/meta.db"));

    meta.dataDir.clear();
    auto plan = std::make_shared<IoctlPlan>();
    IoctlHookGuard guard(MakeIoctlHandler(plan));
    kvdbServiceImpl_->SetDumpStackTags(meta, false);

    EXPECT_EQ(plan->getCalls, 1);
    EXPECT_EQ(plan->setCalls, 1);

    BAccessTokenKit::accessTokenkit = accTokenMock;
    RemoveDbLayout(dataDir, storeIdStr);
    RemoveDirs(newDirs);
}

/**
 * @tc.name: DumpStack_SetDumpStackTags_CustomDirNoSeparator_001
 * @tc.desc: AC-1.2 - A HAP custom dataDir without a separator assembles an empty custom leaf
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(KvdbServiceImplDumpStackTest, DumpStack_SetDumpStackTags_CustomDirNoSeparator_001, TestSize.Level0)
{
    std::string storeIdStr = "dumpStackTagCustomNoSeparator";
    auto tokenMock = std::make_shared<AccessTokenKitMock>();
    ON_CALL(*tokenMock, GetTokenTypeFlag(_)).WillByDefault(Return(TOKEN_HAP));
    BAccessTokenKit::accessTokenkit = tokenMock;
    auto tokenIdKitMock = std::make_shared<TokenIdKitMock>();
    ON_CALL(*tokenIdKitMock, IsSystemAppByFullTokenID(_)).WillByDefault(Return(true));
    BTokenIdKit::tokenkIdKit = tokenIdKitMock;

    StoreMetaData meta;
    meta.storeId = storeIdStr;
    meta.dataDir = "customdir";
    meta.storeType = static_cast<int32_t>(OHOS::DistributedKv::SINGLE_VERSION);
    meta.securityLevel = OHOS::DistributedKv::S1;
    meta.area = OHOS::DistributedKv::EL1;
    meta.bundleName = appId.appId;
    meta.appId = appId.appId;
    meta.appType = "harmony";
    meta.user = TEST_USER;
    std::string customDir = kvdbServiceImpl_->AssembleCustomDir(meta, "");
    ASSERT_FALSE(customDir.empty());
    std::vector<std::string> newDirs;
    ASSERT_TRUE(MakeDirs(customDir, newDirs));
    ASSERT_TRUE(CreateDbLayout(customDir, storeIdStr));
    std::string base = GetDbBase(customDir, storeIdStr);
    ASSERT_FALSE(base.empty());
    ASSERT_TRUE(MakeFile(base + "meta/meta.db"));

    auto plan = std::make_shared<IoctlPlan>();
    IoctlHookGuard guard(MakeIoctlHandler(plan));
    kvdbServiceImpl_->SetDumpStackTags(meta, true);

    EXPECT_EQ(plan->getCalls, 1);
    EXPECT_EQ(plan->setCalls, 1);

    BAccessTokenKit::accessTokenkit = accTokenMock;
    BTokenIdKit::tokenkIdKit = nullptr;
    RemoveDbLayout(customDir, storeIdStr);
    RemoveDirs(newDirs);
}

/**
 * @tc.name: DumpStack_SetDumpStackTags_CustomDirTrailingSeparator_001
 * @tc.desc: AC-1.2 - A HAP custom dataDir with a trailing separator assembles an empty custom leaf
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(KvdbServiceImplDumpStackTest, DumpStack_SetDumpStackTags_CustomDirTrailingSeparator_001, TestSize.Level0)
{
    std::string storeIdStr = "dumpStackTagCustomTrailingSeparator";
    auto tokenMock = std::make_shared<AccessTokenKitMock>();
    ON_CALL(*tokenMock, GetTokenTypeFlag(_)).WillByDefault(Return(TOKEN_HAP));
    BAccessTokenKit::accessTokenkit = tokenMock;
    auto tokenIdKitMock = std::make_shared<TokenIdKitMock>();
    ON_CALL(*tokenIdKitMock, IsSystemAppByFullTokenID(_)).WillByDefault(Return(true));
    BTokenIdKit::tokenkIdKit = tokenIdKitMock;

    StoreMetaData meta;
    meta.storeId = storeIdStr;
    meta.dataDir = std::string(create.baseDir) + "/dump_stack_ut_trailing/";
    meta.storeType = static_cast<int32_t>(OHOS::DistributedKv::SINGLE_VERSION);
    meta.securityLevel = OHOS::DistributedKv::S1;
    meta.area = OHOS::DistributedKv::EL1;
    meta.bundleName = appId.appId;
    meta.appId = appId.appId;
    meta.appType = "harmony";
    meta.user = TEST_USER;
    std::string customDir = kvdbServiceImpl_->AssembleCustomDir(meta, "");
    ASSERT_FALSE(customDir.empty());
    std::vector<std::string> newDirs;
    ASSERT_TRUE(MakeDirs(customDir, newDirs));
    ASSERT_TRUE(CreateDbLayout(customDir, storeIdStr));
    std::string base = GetDbBase(customDir, storeIdStr);
    ASSERT_FALSE(base.empty());
    ASSERT_TRUE(MakeFile(base + "meta/meta.db"));

    auto plan = std::make_shared<IoctlPlan>();
    IoctlHookGuard guard(MakeIoctlHandler(plan));
    kvdbServiceImpl_->SetDumpStackTags(meta, true);

    EXPECT_EQ(plan->getCalls, 1);
    EXPECT_EQ(plan->setCalls, 1);

    BAccessTokenKit::accessTokenkit = accTokenMock;
    BTokenIdKit::tokenkIdKit = nullptr;
    RemoveDbLayout(customDir, storeIdStr);
    RemoveDirs(newDirs);
}

/**
 * @tc.name: DumpStack_SetDumpStackTags_InvalidStoreId_001
 * @tc.desc: AC-1.6 - An unsafe store id skips tagging without touching the file system
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(KvdbServiceImplDumpStackTest, DumpStack_SetDumpStackTags_InvalidStoreId_001, TestSize.Level0)
{
    auto tokenMock = std::make_shared<AccessTokenKitMock>();
    ON_CALL(*tokenMock, GetTokenTypeFlag(_)).WillByDefault(Return(TOKEN_NATIVE));
    BAccessTokenKit::accessTokenkit = tokenMock;

    StoreMetaData meta;
    meta.storeId = "bad/store";
    meta.dataDir = std::string(create.baseDir) + "/dump_stack_ut_invalid";
    meta.storeType = static_cast<int32_t>(OHOS::DistributedKv::SINGLE_VERSION);
    ASSERT_TRUE(GetDbStoreDir(meta.storeId).empty());
    auto plan = std::make_shared<IoctlPlan>();
    IoctlHookGuard guard(MakeIoctlHandler(plan));

    kvdbServiceImpl_->SetDumpStackTags(meta, false);

    EXPECT_EQ(plan->getCalls, 0);
    EXPECT_EQ(plan->setCalls, 0);
    BAccessTokenKit::accessTokenkit = accTokenMock;
}

/**
 * @tc.name: DumpStack_SetDumpStackTags_EmptyDataDirResolved_001
 * @tc.desc: AC-1.1 - A non-custom store with an empty dataDir resolves the DirectoryManager path and tags files
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(KvdbServiceImplDumpStackTest, DumpStack_SetDumpStackTags_EmptyDataDirResolved_001, TestSize.Level0)
{
    std::string storeIdStr = "dumpStackTagEmptyDataDir";
    StoreMetaData meta;
    meta.storeId = storeIdStr;
    meta.bundleName = appId.appId;
    meta.storeType = static_cast<int32_t>(OHOS::DistributedKv::SINGLE_VERSION);
    std::string dataDir = DirectoryManager::GetInstance().GetStorePath(meta);
    ASSERT_FALSE(dataDir.empty());
    std::vector<std::string> newDirs;
    ASSERT_TRUE(MakeDirs(dataDir, newDirs));
    ASSERT_TRUE(CreateDbLayout(dataDir, storeIdStr));
    std::string base = GetDbBase(dataDir, storeIdStr);
    ASSERT_FALSE(base.empty());
    ASSERT_TRUE(MakeFile(base + "meta/meta.db"));

    auto tokenMock = std::make_shared<AccessTokenKitMock>();
    ON_CALL(*tokenMock, GetTokenTypeFlag(_)).WillByDefault(Return(TOKEN_NATIVE));
    BAccessTokenKit::accessTokenkit = tokenMock;

    meta.dataDir.clear();
    auto plan = std::make_shared<IoctlPlan>();
    IoctlHookGuard guard(MakeIoctlHandler(plan));
    kvdbServiceImpl_->SetDumpStackTags(meta, false);

    EXPECT_EQ(plan->getCalls, 1);
    EXPECT_EQ(plan->setCalls, 1);
    BAccessTokenKit::accessTokenkit = accTokenMock;
    RemoveDbLayout(dataDir, storeIdStr);
    RemoveDirs(newDirs);
}

/**
 * @tc.name: DumpStack_SetDumpStackTags_CustomDirTokenIdNotHap_001
 * @tc.desc: AC-1.2 - A HAP caller keeps an empty customDir when the store token is not HAP and tags dataDir
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(KvdbServiceImplDumpStackTest, DumpStack_SetDumpStackTags_CustomDirTokenIdNotHap_001, TestSize.Level0)
{
    constexpr uint32_t STORE_TOKEN_ID = 0x5A5A;
    std::string storeIdStr = "dumpStackTagCustomTokenId";
    std::string dataDir = std::string(create.baseDir) + "/dump_stack_ut_custom_token_id";
    ASSERT_TRUE(MakeDir(dataDir));
    ASSERT_TRUE(CreateDbLayout(dataDir, storeIdStr));
    std::string base = GetDbBase(dataDir, storeIdStr);
    ASSERT_FALSE(base.empty());
    ASSERT_TRUE(MakeFile(base + "meta/meta.db"));

    auto tokenMock = std::make_shared<AccessTokenKitMock>();
    ON_CALL(*tokenMock, GetTokenTypeFlag(_)).WillByDefault(Return(TOKEN_HAP));
    ON_CALL(*tokenMock, GetTokenTypeFlag(STORE_TOKEN_ID)).WillByDefault(Return(TOKEN_NATIVE));
    BAccessTokenKit::accessTokenkit = tokenMock;
    auto tokenIdKitMock = std::make_shared<TokenIdKitMock>();
    ON_CALL(*tokenIdKitMock, IsSystemAppByFullTokenID(_)).WillByDefault(Return(true));
    BTokenIdKit::tokenkIdKit = tokenIdKitMock;

    StoreMetaData meta;
    meta.storeId = storeIdStr;
    meta.dataDir = dataDir;
    meta.tokenId = STORE_TOKEN_ID;
    meta.storeType = static_cast<int32_t>(OHOS::DistributedKv::SINGLE_VERSION);
    auto plan = std::make_shared<IoctlPlan>();
    IoctlHookGuard guard(MakeIoctlHandler(plan));
    kvdbServiceImpl_->SetDumpStackTags(meta, true);

    EXPECT_EQ(plan->getCalls, 1);
    EXPECT_EQ(plan->setCalls, 1);
    BAccessTokenKit::accessTokenkit = accTokenMock;
    BTokenIdKit::tokenkIdKit = nullptr;
    RemoveDbLayout(dataDir, storeIdStr);
}

/**
 * @tc.name: DumpStack_SetDumpStackTags_CustomDirLeafAssembled_001
 * @tc.desc: AC-1.2 - A native caller with HAP store metadata assembles and tags the custom dir
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(KvdbServiceImplDumpStackTest, DumpStack_SetDumpStackTags_CustomDirLeafAssembled_001, TestSize.Level0)
{
    constexpr const char *CUSTOM_LEAF = "dump_stack_ut_custom_leaf";
    constexpr uint32_t STORE_TOKEN_ID = 0x5A5A;
    std::string storeIdStr = "dumpStackTagCustomLeaf";
    auto tokenMock = std::make_shared<AccessTokenKitMock>();
    ON_CALL(*tokenMock, GetTokenTypeFlag(_)).WillByDefault(Return(TOKEN_NATIVE));
    ON_CALL(*tokenMock, GetTokenTypeFlag(STORE_TOKEN_ID)).WillByDefault(Return(TOKEN_HAP));
    BAccessTokenKit::accessTokenkit = tokenMock;
    auto tokenIdKitMock = std::make_shared<TokenIdKitMock>();
    ON_CALL(*tokenIdKitMock, IsSystemAppByFullTokenID(_)).WillByDefault(Return(true));
    BTokenIdKit::tokenkIdKit = tokenIdKitMock;

    StoreMetaData meta;
    meta.storeId = storeIdStr;
    meta.bundleName = appId.appId;
    meta.dataDir = std::string(create.baseDir) + "/" + CUSTOM_LEAF;
    meta.securityLevel = OHOS::DistributedKv::S1;
    meta.area = OHOS::DistributedKv::EL1;
    meta.user = TEST_USER;
    meta.tokenId = STORE_TOKEN_ID;
    meta.storeType = static_cast<int32_t>(OHOS::DistributedKv::SINGLE_VERSION);
    std::string customDir = kvdbServiceImpl_->AssembleCustomDir(meta, CUSTOM_LEAF);
    ASSERT_FALSE(customDir.empty());
    std::vector<std::string> newDirs;
    ASSERT_TRUE(MakeDirs(customDir, newDirs));
    ASSERT_TRUE(CreateDbLayout(customDir, storeIdStr));
    std::string base = GetDbBase(customDir, storeIdStr);
    ASSERT_FALSE(base.empty());
    ASSERT_TRUE(MakeFile(base + "meta/meta.db"));

    auto plan = std::make_shared<IoctlPlan>();
    IoctlHookGuard guard(MakeIoctlHandler(plan));
    kvdbServiceImpl_->SetDumpStackTags(meta, true);

    EXPECT_EQ(plan->getCalls, 1);
    EXPECT_EQ(plan->setCalls, 1);
    BAccessTokenKit::accessTokenkit = accTokenMock;
    BTokenIdKit::tokenkIdKit = nullptr;
    RemoveDbLayout(customDir, storeIdStr);
    RemoveDirs(newDirs);
}

/**
 * @tc.name: DumpStack_SetDumpStackTags_AllFilesTaggedAndSetFail_001
 * @tc.desc: AC-1.5 - Every db file is inspected, tagged files are skipped and set failures degrade silently
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(KvdbServiceImplDumpStackTest, DumpStack_SetDumpStackTags_AllFilesTaggedAndSetFail_001, TestSize.Level0)
{
    constexpr int NUM_DB_FILES = 6;
    constexpr int NUM_SET_FAILED_FILES = 3;
    std::string storeIdStr = "dumpStackTagAllFiles";
    std::string dataDir = std::string(create.baseDir) + "/dump_stack_ut_all_files";
    ASSERT_TRUE(MakeDir(dataDir));
    ASSERT_TRUE(CreateDbLayout(dataDir, storeIdStr));
    std::string base = GetDbBase(dataDir, storeIdStr);
    ASSERT_FALSE(base.empty());
    const std::string files[NUM_DB_FILES] = { "main/gen_natural_store.db", "main/gen_natural_store.db-wal",
        "main/gen_natural_store.db-shm", "meta/meta.db", "meta/meta.db-wal", "meta/meta.db-shm" };
    for (const auto &file : files) {
        ASSERT_TRUE(MakeFile(base + file));
    }

    auto tokenMock = std::make_shared<AccessTokenKitMock>();
    ON_CALL(*tokenMock, GetTokenTypeFlag(_)).WillByDefault(Return(TOKEN_NATIVE));
    BAccessTokenKit::accessTokenkit = tokenMock;

    StoreMetaData meta;
    meta.storeId = storeIdStr;
    meta.dataDir = dataDir;
    meta.storeType = static_cast<int32_t>(OHOS::DistributedKv::SINGLE_VERSION);
    auto plan = std::make_shared<IoctlPlan>();
    plan->taggedName = "gen_natural_store.db";
    plan->failSetName = "meta.db";
    IoctlHookGuard guard(MakeIoctlHandler(plan));
    kvdbServiceImpl_->SetDumpStackTags(meta, false);

    EXPECT_EQ(plan->getCalls, NUM_DB_FILES);
    EXPECT_EQ(plan->setCalls, NUM_SET_FAILED_FILES);
    BAccessTokenKit::accessTokenkit = accTokenMock;
    RemoveDbLayout(dataDir, storeIdStr);
}

} // namespace DistributedDataTest
} // namespace OHOS::Test
