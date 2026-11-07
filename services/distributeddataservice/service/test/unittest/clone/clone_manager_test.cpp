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

#include <gtest/gtest.h>
#include <fcntl.h>
#include <unistd.h>
#include <dlfcn.h>
#include <fstream>

#include "iremote_object.h"
#include "iremote_broker.h"
#include "message_parcel.h"

#include "auth_delegate.h"
#include "bootstrap.h"
#include "crypto/crypto_manager.h"
#include "device_manager_adapter.h"
#include "directory/directory_manager.h"
#include "directory/directory_manager.h"
#include "clone_manager.h"
#include "db_store_mock.h"
#include "hks_api.h"
#include "hks_param.h"
#include "metadata/meta_data_manager.h"
#include "metadata/secret_key_meta_data.h"
#include "metadata/store_meta_data.h"
#include "message_parcel.h"
#include "serializable/serializable.h"
#include "utils/base64_utils.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::DistributedKv;
using namespace OHOS::DistributedData;
using StoreMetaData = DistributedData::StoreMetaData;

namespace OHOS::Test {
const std::string SECRETKEY_BACKUP_PATH = "/data/service/el1/public/database/backup_test/";
const std::string SECRETKEY_BACKUP_FILE = SECRETKEY_BACKUP_PATH + "secret_key_backup.conf";
const std::string NORMAL_BACKUP_DATA =
    "{\"infos\":[{\"bundleName\":\"com.myapp.example\",\"dbName\":"
    "\"storeId\",\"instanceId\":0,\"storeType\":\"1\",\"user\":\"100\","
    "\"sKey\":\"9aJQwx3XD3EN7To2j/I9E9MCzn2+6f/bBqFjOPcY+1pRgx/"
    "XI6jXedyuzEEVdwrc\",\"time\":[50,180,137,103,0,0,0,0]},{"
    "\"bundleName\":\"sa1\",\"dbName\":\"storeId1\",\"instanceId\":\"0\","
    "\"dbType\":\"1\",\"user\":\"0\",\"sKey\":\"9aJQwx3XD3EN7To2j/"
    "I9E9MCzn2+6f/bBqFjOPcY+1pRgx/"
    "XI6jXedyuzEEVdwrc\",\"time\":[50,180,137,103,0,0,0,0]}]}";

class CloneManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static std::shared_ptr<DBStoreMock> dbStoreMock_;
};

std::shared_ptr<DBStoreMock> CloneManagerTest::dbStoreMock_ = std::make_shared<DBStoreMock>();

// PrepareRootKey skips generation for DE-level keys (the service creates the root key during
// provisioning), and HUKS scopes keys by caller uid, so the test process (uid 0) has no
// distributed_db_root_key until we generate one here.
static void GenerateTestRootKey()
{
    const std::string keyAliasStr = "distributed_db_root_key";
    std::vector<uint8_t> keyAlias(keyAliasStr.begin(), keyAliasStr.end());
    struct HksBlob rootKeyName = { static_cast<uint32_t>(keyAlias.size()), keyAlias.data() };
    struct HksParam rootKeyParams[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_256 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
        { .tag = HKS_TAG_DIGEST, .uint32Param = 0 },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
        { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_GCM },
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE },
    };
    struct HksParamSet *params = nullptr;
    if (HksInitParamSet(&params) != HKS_SUCCESS || HksAddParams(params, rootKeyParams,
        sizeof(rootKeyParams) / sizeof(rootKeyParams[0])) != HKS_SUCCESS ||
        HksBuildParamSet(&params) != HKS_SUCCESS) {
        return;
    }
    if (HksKeyExist(&rootKeyName, params) == HKS_SUCCESS) {
        HksFreeParamSet(&params);
        return;
    }
    (void)HksGenerateKey(&rootKeyName, params, nullptr);
    HksFreeParamSet(&params);
}

void CloneManagerTest::SetUpTestCase(void)
{
    mode_t mode = S_IRWXU | S_IRWXG | S_IXOTH; // 0771
    mkdir(SECRETKEY_BACKUP_PATH.c_str(), mode);
    auto executors = std::make_shared<ExecutorPool>(12, 5);
    GenerateTestRootKey();
    MetaDataManager::GetInstance().Initialize(dbStoreMock_, nullptr, "");
    Bootstrap::GetInstance().LoadComponents();
    Bootstrap::GetInstance().LoadDirectory();
    Bootstrap::GetInstance().LoadCheckers();
    Bootstrap::GetInstance().LoadDoubleSyncConfig();
}

void CloneManagerTest::TearDownTestCase(void)
{
    (void)remove(SECRETKEY_BACKUP_FILE.c_str());
    (void)rmdir(SECRETKEY_BACKUP_PATH.c_str());
}

void CloneManagerTest::SetUp(void)
{}

void CloneManagerTest::TearDown(void)
{}

static int32_t WriteContentToFile(const std::string &path, const std::string &content)
{
    std::fstream file(path, std::ios::out | std::ios::trunc);
    if (!file.is_open()) {
        return -1;
    }
    file << content;
    file.close();
    return 0;
}

static const std::string VALID_SYMKEY =
    "27,145,118,212,62,156,133,135,50,68,188,239,20,170,227,190,37,142,218,158,177,32,5,"
    "160,13,114,186,141,59,91,44,200";
static const std::string VALID_IV =
    "97,160,201,177,46,37,129,18,112,220,107,106,25,231,15,15,58,85,31,83,123,216,211,2,"
    "222,49,122,72,21,251,83,16";
static const std::string SHORT_IV =
    "97,160,201,177,46,37,129,18,112,220,107,106,25,231,15,15,58,85,31,83,123,216,211,2,"
    "222,49,122,72,21,251,83";

static bool SaveEncryptedStoreMeta(const std::string &localDeviceId, const std::string &bundleName,
    const std::string &storeId, const std::string &userId, const std::vector<uint8_t> &password,
    const std::vector<uint8_t> &sKeyOverride = std::vector<uint8_t>())
{
    StoreMetaData storeMeta;
    storeMeta.deviceId = localDeviceId;
    storeMeta.user = userId;
    storeMeta.bundleName = bundleName;
    storeMeta.storeId = storeId;
    storeMeta.dataDir = "";
    storeMeta.isEncrypt = true;
    storeMeta.area = 1;
    storeMeta.storeType = 1;
    if (!MetaDataManager::GetInstance().SaveMeta(storeMeta.GetKey(), storeMeta, true)) {
        return false;
    }
    SecretKeyMetaData secretKeyMeta;
    if (sKeyOverride.empty()) {
        CryptoManager::CryptoParams params = { .area = 1, .userId = userId };
        secretKeyMeta.sKey = CryptoManager::GetInstance().Encrypt(password, params);
        if (secretKeyMeta.sKey.empty()) {
            return false;
        }
        secretKeyMeta.nonce = params.nonce;
    } else {
        secretKeyMeta.sKey = sKeyOverride;
    }
    secretKeyMeta.area = 1;
    secretKeyMeta.storeType = 1;
    secretKeyMeta.time = {50, 180, 137, 103, 0, 0, 0, 0};
    return MetaDataManager::GetInstance().SaveMeta(storeMeta.GetSecretKey(), secretKeyMeta, true);
}

static void CleanupStoreMeta(const std::string &localDeviceId, const std::string &bundleName,
    const std::string &storeId, const std::string &userId)
{
    StoreMetaData storeMeta;
    storeMeta.deviceId = localDeviceId;
    storeMeta.user = userId;
    storeMeta.bundleName = bundleName;
    storeMeta.storeId = storeId;
    storeMeta.dataDir = "";
    MetaDataManager::GetInstance().DelMeta(storeMeta.GetKey(), true);
    MetaDataManager::GetInstance().DelMeta(storeMeta.GetSecretKey(), true);
}

// The framework's real input is a flat array of typed entries; the peer OS version is a
// sibling entry in the same type/detail shape, e.g. {"type": "OSVersion", "detail": "7.0.0.115"}.
static std::string BuildCloneInfo(const std::string &bundleName, const std::string &userId,
    const std::string &osVersion, const std::string &iv)
{
    std::string info = "[{\"type\":\"encryption_info\",\"detail\":{\"encryption_symkey\":\"" + VALID_SYMKEY +
        "\",\"encryption_algname\":\"AES256\",\"gcmParams_iv\":\"" + iv +
        "\"}},{\"type\":\"application_selection\",\"detail\":[{\"bundleName\":\"" + bundleName +
        "\",\"accessTokenId\":100}]},{\"type\":\"userId\",\"detail\":\"" + userId + "\"}";
    if (!osVersion.empty()) {
        info += ",{\"type\":\"OSVersion\",\"detail\":\"" + osVersion + "\"}";
    }
    return info + "]";
}

static std::string ReadBackupFileFromReply(MessageParcel &reply)
{
    int32_t fd = reply.ReadFileDescriptor();
    if (fd < 0) {
        return "";
    }
    std::string content;
    char buffer[4096] = {0};
    ssize_t size = 0;
    while ((size = read(fd, buffer, sizeof(buffer))) > 0) {
        content.append(buffer, static_cast<size_t>(size));
    }
    close(fd);
    return content;
}

/**
 * @tc.name: OnRestore_ImportCloneKeyFailed
 * @tc.desc: Test OnRestore returns -1 when ImportCloneKey fails
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: zhaojh
 */
HWTEST_F(CloneManagerTest, OnRestore_ImportCloneKeyFailed, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;

    // Prepare a valid backup file (content doesn't matter, as ImportCloneKey will fail first)
    EXPECT_EQ(WriteContentToFile(SECRETKEY_BACKUP_FILE, NORMAL_BACKUP_DATA), 0);
    int32_t fd = open(SECRETKEY_BACKUP_FILE.c_str(), O_RDONLY);
    ASSERT_GE(fd, 0);
    data.WriteFileDescriptor(fd);

    // Prepare cloneInfoStr with invalid encryption_symkey (too short, so ImportCloneKey fails)
    std::string cloneInfoStr =
        "[{\"type\":\"encryption_info\",\"detail\":{\"encryption_symkey\":\"1,2,3\",\"encryption_algname\":\"AES256\","
        "\"gcmParams_iv\":\"97,160,201,177,46,37,129,18,112,220,107,106,25,231,15,15,""58,85,31,83,123,216,211,2,222,"
        "49,122,72,21,251,83,16\"}},{\"type\":\"userId\",\"detail\":\"100\"}]";
    data.WriteString(cloneInfoStr);

    // Should return -1 due to ImportCloneKey failure
    EXPECT_EQ(OnRestore(data, reply), -1);
    close(fd);
}

/**
 * @tc.name: ImportCloneKey_EmptyString
 * @tc.desc: Test ImportCloneKey with empty string
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: zhaojh
 */
HWTEST_F(CloneManagerTest, ImportCloneKey_EmptyString, TestSize.Level0)
{
    std::string emptyStr = "";
    EXPECT_FALSE(ImportCloneKey(emptyStr));
}

/**
 * @tc.name: isNumber_EmptyString
 * @tc.desc: Test IsNumber with empty string returns false
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: Claude
 */
HWTEST_F(CloneManagerTest, isNumber_EmptyString, TestSize.Level0)
{
    EXPECT_FALSE(IsNumber(""));
    EXPECT_TRUE(IsNumber("100"));
    EXPECT_TRUE(IsNumber("0"));
    EXPECT_TRUE(IsNumber("1234567890"));
    EXPECT_FALSE(IsNumber("abc"));
    EXPECT_FALSE(IsNumber("100abc"));
    EXPECT_FALSE(IsNumber("100.5"));
    EXPECT_FALSE(IsNumber("-100"));
    EXPECT_FALSE(IsNumber(" "));
}

/**
 * @tc.name: GetSecretKeyBackup_LoadMetaFail
 * @tc.desc: Test GetSecretKeyBackup when LoadMeta fails (continue branch)
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: Claude
 */
HWTEST_F(CloneManagerTest, GetSecretKeyBackup_LoadMetaFail, TestSize.Level0)
{
    std::vector<DistributedData::CloneBundleInfo> bundleInfos;
    DistributedData::CloneBundleInfo bundleInfo;
    bundleInfo.bundleName = "nonexistent.bundle";
    bundleInfo.accessTokenId = 100;
    bundleInfos.push_back(bundleInfo);

    std::vector<uint8_t> iv(32, 0);
    std::string userId = "100";
    std::string localDeviceId = "local_device_id";

    std::string result = GetSecretKeyBackup(bundleInfos, userId, iv, localDeviceId);
    // Should return serialized empty backup
    EXPECT_FALSE(result.empty());
}

/**
 * @tc.name: OnRestore_EmptyBackupData
 * @tc.desc: Test OnRestore when backupData.infos is empty (returns -1)
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: Claude
 */
HWTEST_F(CloneManagerTest, OnRestore_EmptyBackupData, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;

    // Create a backup file with empty infos
    std::string backupData = "{\"infos\":[]}";
    EXPECT_EQ(WriteContentToFile(SECRETKEY_BACKUP_FILE, backupData), 0);

    int32_t fd = open(SECRETKEY_BACKUP_FILE.c_str(), O_RDONLY);
    ASSERT_GE(fd, 0);
    data.WriteFileDescriptor(fd);

    std::string cloneInfoStr =
        "[{\"type\":\"encryption_info\",\"detail\":{\"encryption_symkey\":\"27,"
        "145,118,212,62,156,133,135,50,68,188,239,20,170,227,190,37,142,218,"
        "158,177,32,5,160,13,114,186,141,59,91,44,200\",\"encryption_algname\":"
        "\"AES256\",\"gcmParams_iv\":\"97,160,201,177,46,37,129,18,112,220,107,"
        "106,25,231,15,15,58,85,31,83,123,216,211,2,222,49,122,72,21,251,83,"
        "16\"}},{\"type\":\"userId\",\"detail\":\"100\"}]";
    data.WriteString(cloneInfoStr);

    auto result = OnRestore(data, reply);
    EXPECT_EQ(result, -1);

    close(fd);
    ASSERT_EQ(remove(SECRETKEY_BACKUP_FILE.c_str()), 0);
}

/**
 * @tc.name: OnRestore_ParseFailure
 * @tc.desc: Test OnRestore when ParseSecretKeyFile fails
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: Claude
 */
HWTEST_F(CloneManagerTest, OnRestore_ParseFailure, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;

    // Write invalid file descriptor
    data.WriteFileDescriptor(-1);
    data.WriteString("");

    auto result = OnRestore(data, reply);
    EXPECT_EQ(result, -1);
}

/**
 * @tc.name: OnRestore_InvalidCloneInfo
 * @tc.desc: Test OnRestore when CloneInfo Unmarshal fails
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: Claude
 */
HWTEST_F(CloneManagerTest, OnRestore_InvalidCloneInfo, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;

    // Create a valid backup file
    std::string backupData = "{\"infos\":[{\"bundleName\":\"test\",\"dbName\":\"test\","
        "\"user\":\"100\",\"sKey\":\"test\",\"instanceId\":0,\"storeType\":1}]}";
    EXPECT_EQ(WriteContentToFile(SECRETKEY_BACKUP_FILE, backupData), 0);

    int32_t fd = open(SECRETKEY_BACKUP_FILE.c_str(), O_RDONLY);
    ASSERT_GE(fd, 0);
    data.WriteFileDescriptor(fd);

    // Write invalid clone info
    data.WriteString("InvalidJson");

    auto result = OnRestore(data, reply);
    EXPECT_EQ(result, -1);

    close(fd);
    ASSERT_EQ(remove(SECRETKEY_BACKUP_FILE.c_str()), 0);
}

/**
 * @tc.name: OnRestore_BackupItemInvalid
 * @tc.desc: Test OnRestore when BackupItem is invalid (continue loop)
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: Claude
 */
HWTEST_F(CloneManagerTest, OnRestore_BackupItemInvalid, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;

    // Create a backup file with invalid items
    std::string backupData = "{\"infos\":[{\"bundleName\":\"\",\"dbName\":\"\","
        "\"user\":\"\",\"sKey\":\"\",\"instanceId\":0,\"storeType\":1}]}";
    EXPECT_EQ(WriteContentToFile(SECRETKEY_BACKUP_FILE, backupData), 0);

    int32_t fd = open(SECRETKEY_BACKUP_FILE.c_str(), O_RDONLY);
    ASSERT_GE(fd, 0);
    data.WriteFileDescriptor(fd);

    std::string cloneInfoStr =
        "[{\"type\":\"encryption_info\",\"detail\":{\"encryption_symkey\":\"27,"
        "145,118,212,62,156,133,135,50,68,188,239,20,170,227,190,37,142,218,"
        "158,177,32,5,160,13,114,186,141,59,91,44,200\",\"encryption_algname\":"
        "\"AES256\",\"gcmParams_iv\":\"97,160,201,177,46,37,129,18,112,220,107,"
        "106,25,231,15,15,58,85,31,83,123,216,211,2,222,49,122,72,21,251,83,"
        "16\"}},{\"type\":\"userId\",\"detail\":\"100\"}]";
    data.WriteString(cloneInfoStr);

    auto result = OnRestore(data, reply);
    // Should return 0 as invalid items are skipped
    EXPECT_EQ(result, 0);

    close(fd);
    ASSERT_EQ(remove(SECRETKEY_BACKUP_FILE.c_str()), 0);
}

/**
 * @tc.name: OnRestore_RestoreSecretKeyFailed
 * @tc.desc: Test OnRestore when RestoreSecretKey fails for some items (continue loop)
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: Claude
 */
HWTEST_F(CloneManagerTest, OnRestore_RestoreSecretKeyFailed, TestSize.Level0)
{
    MessageParcel data;
    MessageParcel reply;

    // Create a backup file with one valid and one invalid item
    std::string backupData = "{\"infos\":[""{\"bundleName\":\"test1\",\"dbName\":\"store1\","
        "\"user\":\"100\",\"sKey\":\"invalid\",\"instanceId\":0,\"storeType\":1},"
        "{\"bundleName\":\"test2\",\"dbName\":\"store2\","
        "\"user\":\"100\",\"sKey\":\"invalid\",\"instanceId\":0,\"storeType\":1}]}";
    EXPECT_EQ(WriteContentToFile(SECRETKEY_BACKUP_FILE, backupData), 0);

    int32_t fd = open(SECRETKEY_BACKUP_FILE.c_str(), O_RDONLY);
    ASSERT_GE(fd, 0);
    data.WriteFileDescriptor(fd);

    std::string cloneInfoStr =
        "[{\"type\":\"encryption_info\",\"detail\":{\"encryption_symkey\":\"27,"
        "145,118,212,62,156,133,135,50,68,188,239,20,170,227,190,37,142,218,"
        "158,177,32,5,160,13,114,186,141,59,91,44,200\",\"encryption_algname\":"
        "\"AES256\",\"gcmParams_iv\":\"97,160,201,177,46,37,129,18,112,220,107,"
        "106,25,231,15,15,58,85,31,83,123,216,211,2,222,49,122,72,21,251,83,"
        "16\"}},{\"type\":\"userId\",\"detail\":\"100\"}]";
    data.WriteString(cloneInfoStr);

    auto result = OnRestore(data, reply);
    // Should return 0 as failed items are skipped
    EXPECT_EQ(result, 0);

    close(fd);
    ASSERT_EQ(remove(SECRETKEY_BACKUP_FILE.c_str()), 0);
}
/**
 * @tc.name: BackupItemUnmarshal_OldFormatSample_KeepsNonceEmpty
 * @tc.desc: Old-format backup sample without nonce field parses and leaves nonce empty
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: htt1997
 */
HWTEST_F(CloneManagerTest, BackupItemUnmarshal_OldFormatSample_KeepsNonceEmpty, TestSize.Level0)
{
    const std::string oldFormatSample =
        "{\"infos\":[{\"area\":1,\"bundleName\":\"com.example.app\",\"dbName\":\"storeId\","
        "\"instanceId\":0,\"sKey\":\"9aJQwx3XD3EN7To2j/I9E9MCzn2+6f/bqFjOPcY+1pRgx/XI6jXedyuzEEVdwrc\","
        "\"storeType\":1,\"time\":[50,180,137,103,0,0,0,0],\"user\":\"100\"}]}";
    SecretKeyBackupData backupData;
    EXPECT_TRUE(Serializable::Unmarshall(oldFormatSample, backupData));
    ASSERT_EQ(backupData.infos.size(), 1u);
    const auto &item = backupData.infos[0];
    EXPECT_EQ(item.bundleName, "com.example.app");
    EXPECT_EQ(item.dbName, "storeId");
    EXPECT_EQ(item.user, "100");
    EXPECT_EQ(item.instanceId, 0);
    EXPECT_EQ(item.storeType, 1);
    EXPECT_EQ(item.area, 1);
    EXPECT_FALSE(item.sKey.empty());
    EXPECT_TRUE(item.nonce.empty());
}

/**
 * @tc.name: BackupItemMarshalUnmarshal_NewFormatSample_RoundTrip
 * @tc.desc: New-format item with nonce round-trips; empty nonce emits no nonce key (old-format identical)
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: htt1997
 */
HWTEST_F(CloneManagerTest, BackupItemMarshalUnmarshal_NewFormatSample_RoundTrip, TestSize.Level0)
{
    SecretKeyBackupData::BackupItem item;
    item.bundleName = "com.example.app";
    item.dbName = "storeId";
    item.user = "100";
    item.instanceId = 0;
    item.storeType = 1;
    item.area = 1;
    item.sKey = "cipher-text-base64";
    item.time = {50, 180, 137, 103, 0, 0, 0, 0};
    item.nonce = "AAECAwQFBgcICQoL";

    std::string marshaled = Serializable::Marshall(item);
    EXPECT_NE(marshaled.find("\"nonce\":\"AAECAwQFBgcICQoL\""), std::string::npos);

    SecretKeyBackupData::BackupItem parsed;
    EXPECT_TRUE(Serializable::Unmarshall(marshaled, parsed));
    EXPECT_EQ(parsed.nonce, "AAECAwQFBgcICQoL");
    EXPECT_EQ(parsed.sKey, "cipher-text-base64");
    EXPECT_EQ(parsed.bundleName, "com.example.app");

    SecretKeyBackupData::BackupItem oldItem = item;
    oldItem.nonce.clear();
    std::string oldMarshaled = Serializable::Marshall(oldItem);
    EXPECT_EQ(oldMarshaled.find("nonce"), std::string::npos);
}

/**
 * @tc.name: BackupItemUnmarshal_MissingNonce_DoesNotFailChain
 * @tc.desc: Missing nonce field does not fail the BackupItem unmarshal required-field chain
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: htt1997
 */
HWTEST_F(CloneManagerTest, BackupItemUnmarshal_MissingNonce_DoesNotFailChain, TestSize.Level0)
{
    const std::string itemWithoutNonce =
        "{\"area\":1,\"bundleName\":\"com.example.app\",\"dbName\":\"storeId\","
        "\"instanceId\":0,\"sKey\":\"cipher\",\"storeType\":1,\"time\":[1,2,3,4,5,6,7,8],\"user\":\"100\"}";
    auto node = Serializable::ToJson(itemWithoutNonce);
    ASSERT_FALSE(node.is_null());
    SecretKeyBackupData::BackupItem item;
    EXPECT_TRUE(item.Unmarshal(node));
    EXPECT_TRUE(item.nonce.empty());
}

/**
 * @tc.name: CloneBackupInfoUnmarshal_WithAndWithoutOSVersion
 * @tc.desc: CloneBackupInfo parses the flat entry array with and without the OSVersion entry
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: htt1997
 */
HWTEST_F(CloneManagerTest, CloneBackupInfoUnmarshal_WithAndWithoutOSVersion, TestSize.Level0)
{
    const std::string encryptionDetail =
        "{\"encryption_symkey\":\"1,2,3\",\"encryption_algname\":\"AES256\","
        "\"gcmParams_iv\":\"97,160,201,177,46,37,129,18,112,220,107,106,25,231,15,15,"
        "58,85,31,83,123,216,211,2,222,49,122,72,21,251,83,16\"}";
    const std::string withoutVersion = "[{\"type\":\"encryption_info\",\"detail\":" + encryptionDetail +
        "},{\"type\":\"application_selection\",\"detail\":[{\"bundleName\":\"com.example.app\","
        "\"accessTokenId\":100}]},{\"type\":\"userId\",\"detail\":\"100\"}]";
    CloneBackupInfo backupInfo;
    EXPECT_TRUE(backupInfo.Unmarshal(withoutVersion));
    EXPECT_TRUE(backupInfo.osVersion.empty());
    EXPECT_EQ(backupInfo.userId, "100");
    ASSERT_EQ(backupInfo.bundleInfos.size(), 1u);
    EXPECT_EQ(backupInfo.bundleInfos[0].bundleName, "com.example.app");
    EXPECT_EQ(backupInfo.encryptionInfo.algName, "AES256");

    const std::string withVersion = "[{\"type\":\"encryption_info\",\"detail\":" + encryptionDetail +
        "},{\"type\":\"userId\",\"detail\":\"100\"},{\"type\":\"OSVersion\",\"detail\":\"7.0.0.115\"}]";
    CloneBackupInfo versioned;
    EXPECT_TRUE(versioned.Unmarshal(withVersion));
    EXPECT_EQ(versioned.osVersion, "7.0.0.115");
    EXPECT_EQ(versioned.userId, "100");
}


/**
 * @tc.name: IsOldOsVersion_Matrix
 * @tc.desc: IsOldOsVersion returns true for pre-7.1, empty or unparseable forms, false for "major.minor" >= 7.1
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: htt1997
 */
HWTEST_F(CloneManagerTest, IsOldOsVersion_Matrix, TestSize.Level0)
{
    EXPECT_FALSE(IsOldOsVersion("7.1"));
    EXPECT_FALSE(IsOldOsVersion("7.1.0"));
    EXPECT_FALSE(IsOldOsVersion("7.1.0.115"));
    EXPECT_FALSE(IsOldOsVersion("7.2.1"));
    EXPECT_TRUE(IsOldOsVersion("7.0.0.115"));
    EXPECT_FALSE(IsOldOsVersion("8.0"));
    EXPECT_TRUE(IsOldOsVersion("7.0"));
    EXPECT_TRUE(IsOldOsVersion("6.10"));
    EXPECT_TRUE(IsOldOsVersion("71"));
    EXPECT_TRUE(IsOldOsVersion("7"));
    EXPECT_TRUE(IsOldOsVersion("abc"));
    EXPECT_TRUE(IsOldOsVersion(""));
}
/**
 * @tc.name: CloneManagerPerItemNonceUniqueTest
 * @tc.desc: Same password in two BackupItems produces different ciphertexts and unique per-item nonces
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: htt1997
 */
HWTEST_F(CloneManagerTest, CloneManagerPerItemNonceUniqueTest, TestSize.Level0)
{
    const std::string localDeviceId = "local_device_id";
    const std::string userId = "100";
    const std::string bundleName = "com.nonce.unique";
    const std::vector<uint8_t> password = {'p', 'a', 's', 's', 'w', '0', 'r', 'd'};
    ASSERT_TRUE(SaveEncryptedStoreMeta(localDeviceId, bundleName, "store1", userId, password));
    ASSERT_TRUE(SaveEncryptedStoreMeta(localDeviceId, bundleName, "store2", userId, password));

    ASSERT_TRUE(ImportCloneKey(VALID_SYMKEY));
    std::vector<uint8_t> iv(32, 7);
    std::vector<DistributedData::CloneBundleInfo> bundleInfos;
    DistributedData::CloneBundleInfo bundleInfo;
    bundleInfo.bundleName = bundleName;
    bundleInfo.accessTokenId = 100;
    bundleInfos.push_back(bundleInfo);
    std::string content = GetSecretKeyBackup(bundleInfos, userId, iv, localDeviceId, "7.1");
    DeleteCloneKey();
    ASSERT_FALSE(content.empty());

    SecretKeyBackupData backupData;
    ASSERT_TRUE(Serializable::Unmarshall(content, backupData));
    ASSERT_EQ(backupData.infos.size(), 2u);
    EXPECT_NE(backupData.infos[0].sKey, backupData.infos[1].sKey);
    EXPECT_FALSE(backupData.infos[0].nonce.empty());
    EXPECT_FALSE(backupData.infos[1].nonce.empty());
    EXPECT_NE(backupData.infos[0].nonce, backupData.infos[1].nonce);
    EXPECT_EQ(Base64::Decode(backupData.infos[0].nonce).size(), 12u);
    EXPECT_EQ(Base64::Decode(backupData.infos[1].nonce).size(), 12u);

    CleanupStoreMeta(localDeviceId, bundleName, "store1", userId);
    CleanupStoreMeta(localDeviceId, bundleName, "store2", userId);
}

/**
 * @tc.name: CloneManagerBackupOldFormatForOldPeerTest
 * @tc.desc: Peer version below 7.1 produces an old-format backup without per-item nonce
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: htt1997
 */
HWTEST_F(CloneManagerTest, CloneManagerBackupOldFormatForOldPeerTest, TestSize.Level0)
{
    const std::string localDeviceId = "local_device_id";
    const std::string userId = "100";
    const std::string bundleName = "com.oldpeer.fmt";
    const std::vector<uint8_t> password = {'s', 'e', 'c', 'r', 'e', 't'};
    ASSERT_TRUE(SaveEncryptedStoreMeta(localDeviceId, bundleName, "store1", userId, password));

    MessageParcel data;
    MessageParcel reply;
    data.WriteString(BuildCloneInfo(bundleName, userId, "7.0", VALID_IV));
    EXPECT_EQ(OnBackup(data, reply, localDeviceId), 0);
    std::string content = ReadBackupFileFromReply(reply);
    ASSERT_FALSE(content.empty());
    EXPECT_EQ(content.find("nonce"), std::string::npos);

    SecretKeyBackupData backupData;
    EXPECT_TRUE(Serializable::Unmarshall(content, backupData));
    ASSERT_EQ(backupData.infos.size(), 1u);
    EXPECT_TRUE(backupData.infos[0].nonce.empty());
    CleanupStoreMeta(localDeviceId, bundleName, "store1", userId);
}

/**
 * @tc.name: CloneManagerBackupNoVersionFallbackTest
 * @tc.desc: Missing peer device version falls back to the old backup format
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: htt1997
 */
HWTEST_F(CloneManagerTest, CloneManagerBackupNoVersionFallbackTest, TestSize.Level0)
{
    const std::string localDeviceId = "local_device_id";
    const std::string userId = "100";
    const std::string bundleName = "com.noversion.fmt";
    const std::vector<uint8_t> password = {'s', 'e', 'c', 'r', 'e', 't'};
    ASSERT_TRUE(SaveEncryptedStoreMeta(localDeviceId, bundleName, "store1", userId, password));

    MessageParcel data;
    MessageParcel reply;
    data.WriteString(BuildCloneInfo(bundleName, userId, "", VALID_IV));
    EXPECT_EQ(OnBackup(data, reply, localDeviceId), 0);
    std::string content = ReadBackupFileFromReply(reply);
    ASSERT_FALSE(content.empty());
    EXPECT_EQ(content.find("nonce"), std::string::npos);

    CleanupStoreMeta(localDeviceId, bundleName, "store1", userId);
}

/**
 * @tc.name: CloneManagerBackupVersionFormMatrixTest
 * @tc.desc: Backup format selection follows IsOldOsVersion across version form variants
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: htt1997
 */
HWTEST_F(CloneManagerTest, CloneManagerBackupVersionFormMatrixTest, TestSize.Level0)
{
    const std::string localDeviceId = "local_device_id";
    const std::string userId = "100";
    const std::string bundleName = "com.version.matrix";
    const std::vector<uint8_t> password = {'m', 'a', 't', 'r', 'i', 'x'};
    ASSERT_TRUE(SaveEncryptedStoreMeta(localDeviceId, bundleName, "store1", userId, password));

    const std::vector<std::pair<std::string, bool>> cases = {
        {"7.1", true}, {"7.1.0", true}, {"8.0", true},
        {"7.0", false}, {"", false}, {"71", false}, {"7", false}, {"abc", false},
    };
    for (const auto &testCase : cases) {
        MessageParcel data;
        MessageParcel reply;
        data.WriteString(BuildCloneInfo(bundleName, userId, testCase.first, VALID_IV));
        EXPECT_EQ(OnBackup(data, reply, localDeviceId), 0) << "version: " << testCase.first;
        std::string content = ReadBackupFileFromReply(reply);
        ASSERT_FALSE(content.empty()) << "version: " << testCase.first;
        if (testCase.second) {
            EXPECT_NE(content.find("nonce"), std::string::npos) << "version: " << testCase.first;
        } else {
            EXPECT_EQ(content.find("nonce"), std::string::npos) << "version: " << testCase.first;
        }
    }
    CleanupStoreMeta(localDeviceId, bundleName, "store1", userId);
}

/**
 * @tc.name: CloneManagerBackupSkipFailedItemTest
 * @tc.desc: A store whose secret key cannot be re-encrypted is skipped; other items remain
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: htt1997
 */
HWTEST_F(CloneManagerTest, CloneManagerBackupSkipFailedItemTest, TestSize.Level0)
{
    const std::string localDeviceId = "local_device_id";
    const std::string userId = "100";
    const std::string bundleName = "com.skip.failed";
    const std::vector<uint8_t> password = {'v', 'a', 'l', 'i', 'd'};
    ASSERT_TRUE(SaveEncryptedStoreMeta(localDeviceId, bundleName, "store1", userId, password));
    ASSERT_TRUE(SaveEncryptedStoreMeta(localDeviceId, bundleName, "store2", userId, password,
        {0x01, 0x02, 0x03}));

    ASSERT_TRUE(ImportCloneKey(VALID_SYMKEY));
    std::vector<uint8_t> iv(32, 7);
    std::vector<DistributedData::CloneBundleInfo> bundleInfos;
    DistributedData::CloneBundleInfo bundleInfo;
    bundleInfo.bundleName = bundleName;
    bundleInfo.accessTokenId = 100;
    bundleInfos.push_back(bundleInfo);
    std::string content = GetSecretKeyBackup(bundleInfos, userId, iv, localDeviceId, "7.1");
    DeleteCloneKey();
    ASSERT_FALSE(content.empty());

    SecretKeyBackupData backupData;
    ASSERT_TRUE(Serializable::Unmarshall(content, backupData));
    ASSERT_EQ(backupData.infos.size(), 1u);
    EXPECT_EQ(backupData.infos[0].dbName, "store1");
    EXPECT_FALSE(backupData.infos[0].nonce.empty());

    CleanupStoreMeta(localDeviceId, bundleName, "store1", userId);
    CleanupStoreMeta(localDeviceId, bundleName, "store2", userId);
}

/**
 * @tc.name: CloneManagerBackupEarlyExitNoKeyResidueTest
 * @tc.desc: OnBackup failing on an invalid IV must not leave the clone key imported in HKS
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: htt1997
 */
HWTEST_F(CloneManagerTest, CloneManagerBackupEarlyExitNoKeyResidueTest, TestSize.Level0)
{
    DeleteCloneKey();
    MessageParcel data;
    MessageParcel reply;
    data.WriteString(BuildCloneInfo("com.residue.check", "100", "7.1", SHORT_IV));
    EXPECT_EQ(OnBackup(data, reply, "local_device_id"), -1);

    const std::string keyAliasStr = "distributed_db_backup_key";
    std::vector<uint8_t> keyAlias(keyAliasStr.begin(), keyAliasStr.end());
    struct HksBlob keyBlob = { static_cast<uint32_t>(keyAlias.size()), keyAlias.data() };
    EXPECT_NE(HksKeyExist(&keyBlob, nullptr), 0);
}
// Loads the secret restored by OnRestore under the clone key and decrypts it back; returns
// true and fills restoredPassword only when the round trip succeeds.
static bool LoadRestoredSecret(const std::string &userId, const std::string &bundleName,
    const std::string &storeId, std::vector<uint8_t> &restoredPassword)
{
    auto cloneKey = SecretKeyMetaData::GetCloneKey({ userId, "default", bundleName, storeId, "0" });
    SecretKeyMetaData restored;
    if (!MetaDataManager::GetInstance().LoadMeta(cloneKey, restored, true)) {
        return false;
    }
    CryptoManager::CryptoParams params = { .area = 1, .userId = userId, .nonce = restored.nonce };
    restoredPassword = CryptoManager::GetInstance().Decrypt(restored.sKey, params);
    return !restoredPassword.empty();
}

// Writes the backup content to the test file and runs OnRestore over it; returns the result.
static int32_t RestoreBackupContent(const std::string &bundleName, const std::string &userId,
    const std::string &content)
{
    MessageParcel data;
    MessageParcel reply;
    if (WriteContentToFile(SECRETKEY_BACKUP_FILE, content) != 0) {
        return -1;
    }
    int32_t fd = open(SECRETKEY_BACKUP_FILE.c_str(), O_RDONLY);
    if (fd < 0) {
        return -1;
    }
    data.WriteFileDescriptor(fd);
    data.WriteString(BuildCloneInfo(bundleName, userId, "", VALID_IV));
    int32_t result = OnRestore(data, reply);
    close(fd);
    return result;
}

/**
 * @tc.name: CloneManagerOldFormatRestoreTest
 * @tc.desc: An old-format backup restores with the shared iv and the password round-trips
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: htt1997
 */
HWTEST_F(CloneManagerTest, CloneManagerOldFormatRestoreTest, TestSize.Level0)
{
    const std::string localDeviceId = "local_device_id";
    const std::string userId = "100";
    const std::string bundleName = "com.oldrestore.app";
    const std::string storeId = "store1";
    const std::vector<uint8_t> password = {'o', 'l', 'd', 'p', 'a', 's', 's'};
    ASSERT_TRUE(SaveEncryptedStoreMeta(localDeviceId, bundleName, storeId, userId, password));

    ASSERT_TRUE(ImportCloneKey(VALID_SYMKEY));
    std::vector<uint8_t> iv = ConvertDecStrToVec(VALID_IV);
    std::vector<DistributedData::CloneBundleInfo> bundleInfos;
    DistributedData::CloneBundleInfo bundleInfo;
    bundleInfo.bundleName = bundleName;
    bundleInfo.accessTokenId = 100;
    bundleInfos.push_back(bundleInfo);
    std::string content = GetSecretKeyBackup(bundleInfos, userId, iv, localDeviceId, "7.0");
    DeleteCloneKey();
    ASSERT_FALSE(content.empty());
    EXPECT_EQ(content.find("nonce"), std::string::npos);

    EXPECT_EQ(RestoreBackupContent(bundleName, userId, content), 0);

    std::vector<uint8_t> restoredPassword;
    EXPECT_TRUE(LoadRestoredSecret(userId, bundleName, storeId, restoredPassword));
    EXPECT_EQ(restoredPassword, password);

    CleanupStoreMeta(localDeviceId, bundleName, storeId, userId);
    MetaDataManager::GetInstance().DelMeta(
        SecretKeyMetaData::GetCloneKey({ userId, "default", bundleName, storeId, "0" }), true);
}

/**
 * @tc.name: CloneManagerNewFormatRestoreTest
 * @tc.desc: A new-format backup restores each item with its own per-item nonce
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: htt1997
 */
HWTEST_F(CloneManagerTest, CloneManagerNewFormatRestoreTest, TestSize.Level0)
{
    const std::string localDeviceId = "local_device_id";
    const std::string userId = "100";
    const std::string bundleName = "com.newrestore.app";
    const std::vector<uint8_t> password = {'n', 'e', 'w', 'p', 'a', 's', 's'};
    ASSERT_TRUE(SaveEncryptedStoreMeta(localDeviceId, bundleName, "store1", userId, password));
    ASSERT_TRUE(SaveEncryptedStoreMeta(localDeviceId, bundleName, "store2", userId, password));

    ASSERT_TRUE(ImportCloneKey(VALID_SYMKEY));
    std::vector<uint8_t> iv = ConvertDecStrToVec(VALID_IV);
    std::vector<DistributedData::CloneBundleInfo> bundleInfos;
    DistributedData::CloneBundleInfo bundleInfo;
    bundleInfo.bundleName = bundleName;
    bundleInfo.accessTokenId = 100;
    bundleInfos.push_back(bundleInfo);
    std::string content = GetSecretKeyBackup(bundleInfos, userId, iv, localDeviceId, "7.1");
    DeleteCloneKey();
    ASSERT_FALSE(content.empty());
    EXPECT_NE(content.find("nonce"), std::string::npos);

    MessageParcel data;
    MessageParcel reply;
    EXPECT_EQ(WriteContentToFile(SECRETKEY_BACKUP_FILE, content), 0);
    int32_t fd = open(SECRETKEY_BACKUP_FILE.c_str(), O_RDONLY);
    ASSERT_GE(fd, 0);
    data.WriteFileDescriptor(fd);
    data.WriteString(BuildCloneInfo(bundleName, userId, "", VALID_IV));
    EXPECT_EQ(OnRestore(data, reply), 0);
    close(fd);

    std::vector<uint8_t> restoredPassword;
    EXPECT_TRUE(LoadRestoredSecret(userId, bundleName, "store1", restoredPassword));
    EXPECT_EQ(restoredPassword, password);
    restoredPassword.clear();
    EXPECT_TRUE(LoadRestoredSecret(userId, bundleName, "store2", restoredPassword));
    EXPECT_EQ(restoredPassword, password);

    CleanupStoreMeta(localDeviceId, bundleName, "store1", userId);
    CleanupStoreMeta(localDeviceId, bundleName, "store2", userId);
    MetaDataManager::GetInstance().DelMeta(
        SecretKeyMetaData::GetCloneKey({ userId, "default", bundleName, "store1", "0" }), true);
    MetaDataManager::GetInstance().DelMeta(
        SecretKeyMetaData::GetCloneKey({ userId, "default", bundleName, "store2", "0" }), true);
}

/**
 * @tc.name: CloneManagerRestoreSkipInvalidItemTest
 * @tc.desc: A corrupted item is skipped while the intact item still restores and OnRestore returns 0
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: htt1997
 */
HWTEST_F(CloneManagerTest, CloneManagerRestoreSkipInvalidItemTest, TestSize.Level0)
{
    const std::string localDeviceId = "local_device_id";
    const std::string userId = "100";
    const std::string bundleName = "com.skipinvalid.app";
    const std::vector<uint8_t> password = {'s', 'k', 'i', 'p', 'm', 'e'};
    ASSERT_TRUE(SaveEncryptedStoreMeta(localDeviceId, bundleName, "store1", userId, password));
    ASSERT_TRUE(SaveEncryptedStoreMeta(localDeviceId, bundleName, "store2", userId, password));

    ASSERT_TRUE(ImportCloneKey(VALID_SYMKEY));
    std::vector<uint8_t> iv = ConvertDecStrToVec(VALID_IV);
    std::vector<DistributedData::CloneBundleInfo> bundleInfos;
    DistributedData::CloneBundleInfo bundleInfo;
    bundleInfo.bundleName = bundleName;
    bundleInfo.accessTokenId = 100;
    bundleInfos.push_back(bundleInfo);
    std::string content = GetSecretKeyBackup(bundleInfos, userId, iv, localDeviceId, "7.0");
    DeleteCloneKey();
    ASSERT_FALSE(content.empty());

    SecretKeyBackupData backupData;
    ASSERT_TRUE(Serializable::Unmarshall(content, backupData));
    ASSERT_EQ(backupData.infos.size(), 2u);
    backupData.infos[1].sKey = "corrupted-not-base64-cipher!!";
    content = Serializable::Marshall(backupData);

    MessageParcel data;
    MessageParcel reply;
    EXPECT_EQ(WriteContentToFile(SECRETKEY_BACKUP_FILE, content), 0);
    int32_t fd = open(SECRETKEY_BACKUP_FILE.c_str(), O_RDONLY);
    ASSERT_GE(fd, 0);
    data.WriteFileDescriptor(fd);
    data.WriteString(BuildCloneInfo(bundleName, userId, "", VALID_IV));
    EXPECT_EQ(OnRestore(data, reply), 0);
    close(fd);

    std::vector<uint8_t> restoredPassword;
    EXPECT_TRUE(LoadRestoredSecret(userId, bundleName, "store1", restoredPassword));
    EXPECT_EQ(restoredPassword, password);
    restoredPassword.clear();
    EXPECT_FALSE(LoadRestoredSecret(userId, bundleName, "store2", restoredPassword));

    CleanupStoreMeta(localDeviceId, bundleName, "store1", userId);
    CleanupStoreMeta(localDeviceId, bundleName, "store2", userId);
    MetaDataManager::GetInstance().DelMeta(
        SecretKeyMetaData::GetCloneKey({ userId, "default", bundleName, "store1", "0" }), true);
}

/**
 * @tc.name: CloneManagerRestoreNonceTriStateTest
 * @tc.desc: Item nonce tri-state: absent or empty-decoding falls back to the shared iv; wrong length fails the item
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: htt1997
 */
HWTEST_F(CloneManagerTest, CloneManagerRestoreNonceTriStateTest, TestSize.Level0)
{
    const std::string localDeviceId = "local_device_id";
    const std::string userId = "100";
    const std::string bundleName = "com.tristate.app";
    const std::vector<uint8_t> password = {'t', 'r', 'i', 's', 't', 'a', 't', 'e'};
    ASSERT_TRUE(SaveEncryptedStoreMeta(localDeviceId, bundleName, "store1", userId, password));
    ASSERT_TRUE(SaveEncryptedStoreMeta(localDeviceId, bundleName, "store2", userId, password));
    ASSERT_TRUE(SaveEncryptedStoreMeta(localDeviceId, bundleName, "store3", userId, password));

    ASSERT_TRUE(ImportCloneKey(VALID_SYMKEY));
    std::vector<uint8_t> iv = ConvertDecStrToVec(VALID_IV);
    std::vector<DistributedData::CloneBundleInfo> bundleInfos;
    DistributedData::CloneBundleInfo bundleInfo;
    bundleInfo.bundleName = bundleName;
    bundleInfo.accessTokenId = 100;
    bundleInfos.push_back(bundleInfo);
    std::string content = GetSecretKeyBackup(bundleInfos, userId, iv, localDeviceId, "7.0");
    DeleteCloneKey();
    ASSERT_FALSE(content.empty());

    SecretKeyBackupData backupData;
    ASSERT_TRUE(Serializable::Unmarshall(content, backupData));
    ASSERT_EQ(backupData.infos.size(), 3u);
    // All three items are old-format ciphertexts; only the nonce field varies.
    backupData.infos[0].nonce = "";
    backupData.infos[1].nonce = "!!!";
    std::vector<uint8_t> shortNonce = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    backupData.infos[2].nonce = DistributedData::Base64::Encode(shortNonce);
    content = Serializable::Marshall(backupData);

    MessageParcel data;
    MessageParcel reply;
    EXPECT_EQ(WriteContentToFile(SECRETKEY_BACKUP_FILE, content), 0);
    int32_t fd = open(SECRETKEY_BACKUP_FILE.c_str(), O_RDONLY);
    ASSERT_GE(fd, 0);
    data.WriteFileDescriptor(fd);
    data.WriteString(BuildCloneInfo(bundleName, userId, "", VALID_IV));
    EXPECT_EQ(OnRestore(data, reply), 0);
    close(fd);

    std::vector<uint8_t> restoredPassword;
    // Absent nonce and a nonce decoding to empty both fall back to the shared iv.
    EXPECT_TRUE(LoadRestoredSecret(userId, bundleName, "store1", restoredPassword));
    EXPECT_EQ(restoredPassword, password);
    restoredPassword.clear();
    EXPECT_TRUE(LoadRestoredSecret(userId, bundleName, "store2", restoredPassword));
    EXPECT_EQ(restoredPassword, password);
    // A nonce that decodes to a non-12-byte value fails the item.
    restoredPassword.clear();
    EXPECT_FALSE(LoadRestoredSecret(userId, bundleName, "store3", restoredPassword));

    CleanupStoreMeta(localDeviceId, bundleName, "store1", userId);
    CleanupStoreMeta(localDeviceId, bundleName, "store2", userId);
    CleanupStoreMeta(localDeviceId, bundleName, "store3", userId);
    MetaDataManager::GetInstance().DelMeta(
        SecretKeyMetaData::GetCloneKey({ userId, "default", bundleName, "store1", "0" }), true);
    MetaDataManager::GetInstance().DelMeta(
        SecretKeyMetaData::GetCloneKey({ userId, "default", bundleName, "store2", "0" }), true);
}
/**
 * @tc.name: CloneManagerItemFailureSummaryTest
 * @tc.desc: Item-level failures keep backup/restore flows returning normally with intact items
 *           handled; the summary log and HiSysEvent output are verified via hilog at runtime
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: htt1997
 */
HWTEST_F(CloneManagerTest, CloneManagerItemFailureSummaryTest, TestSize.Level0)
{
    const std::string localDeviceId = "local_device_id";
    const std::string userId = "100";
    const std::string bundleName = "com.summary.app";
    const std::vector<uint8_t> password = {'s', 'u', 'm', 'm', 'a', 'r', 'y'};
    ASSERT_TRUE(SaveEncryptedStoreMeta(localDeviceId, bundleName, "store1", userId, password));
    ASSERT_TRUE(SaveEncryptedStoreMeta(localDeviceId, bundleName, "store2", userId, password,
        {0x01, 0x02, 0x03}));

    ASSERT_TRUE(ImportCloneKey(VALID_SYMKEY));
    std::vector<uint8_t> iv = ConvertDecStrToVec(VALID_IV);
    std::vector<DistributedData::CloneBundleInfo> bundleInfos;
    DistributedData::CloneBundleInfo bundleInfo;
    bundleInfo.bundleName = bundleName;
    bundleInfo.accessTokenId = 100;
    bundleInfos.push_back(bundleInfo);
    std::string content = GetSecretKeyBackup(bundleInfos, userId, iv, localDeviceId, "7.1");
    DeleteCloneKey();
    ASSERT_FALSE(content.empty());
    SecretKeyBackupData backupData;
    ASSERT_TRUE(Serializable::Unmarshall(content, backupData));
    ASSERT_EQ(backupData.infos.size(), 1u);
    EXPECT_EQ(backupData.infos[0].dbName, "store1");

    backupData.infos[0].sKey = "corrupted-not-base64-cipher!!";
    content = Serializable::Marshall(backupData);

    MessageParcel data;
    MessageParcel reply;
    EXPECT_EQ(WriteContentToFile(SECRETKEY_BACKUP_FILE, content), 0);
    int32_t fd = open(SECRETKEY_BACKUP_FILE.c_str(), O_RDONLY);
    ASSERT_GE(fd, 0);
    data.WriteFileDescriptor(fd);
    data.WriteString(BuildCloneInfo(bundleName, userId, "", VALID_IV));
    EXPECT_EQ(OnRestore(data, reply), 0);
    close(fd);

    std::vector<uint8_t> restoredPassword;
    EXPECT_FALSE(LoadRestoredSecret(userId, bundleName, "store1", restoredPassword));
    EXPECT_FALSE(LoadRestoredSecret(userId, bundleName, "store2", restoredPassword));

    CleanupStoreMeta(localDeviceId, bundleName, "store1", userId);
    CleanupStoreMeta(localDeviceId, bundleName, "store2", userId);
}
/**
 * @tc.name: CompatMatrix_OldToNew
 * @tc.desc: Quadrant 1: an old-format backup made for a pre-7.1 peer restores on this version
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: htt1997
 */
HWTEST_F(CloneManagerTest, CompatMatrix_OldToNew, TestSize.Level0)
{
    const std::string localDeviceId = "local_device_id";
    const std::string userId = "100";
    const std::string bundleName = "compat.old2new";
    const std::string storeId = "store1";
    const std::vector<uint8_t> password = {'c', 'o', 'm', 'p', 'a', 't'};
    ASSERT_TRUE(SaveEncryptedStoreMeta(localDeviceId, bundleName, storeId, userId, password));

    MessageParcel data;
    MessageParcel reply;
    data.WriteString(BuildCloneInfo(bundleName, userId, "7.0", VALID_IV));
    EXPECT_EQ(OnBackup(data, reply, localDeviceId), 0);
    std::string content = ReadBackupFileFromReply(reply);
    ASSERT_FALSE(content.empty());
    EXPECT_EQ(content.find("nonce"), std::string::npos);

    EXPECT_EQ(WriteContentToFile(SECRETKEY_BACKUP_FILE, content), 0);
    int32_t fd = open(SECRETKEY_BACKUP_FILE.c_str(), O_RDONLY);
    ASSERT_GE(fd, 0);
    MessageParcel restoreData;
    MessageParcel restoreReply;
    restoreData.WriteFileDescriptor(fd);
    restoreData.WriteString(BuildCloneInfo(bundleName, userId, "", VALID_IV));
    EXPECT_EQ(OnRestore(restoreData, restoreReply), 0);
    close(fd);

    std::vector<uint8_t> restoredPassword;
    EXPECT_TRUE(LoadRestoredSecret(userId, bundleName, storeId, restoredPassword));
    EXPECT_EQ(restoredPassword, password);

    CleanupStoreMeta(localDeviceId, bundleName, storeId, userId);
    MetaDataManager::GetInstance().DelMeta(
        SecretKeyMetaData::GetCloneKey({ userId, "default", bundleName, storeId, "0" }), true);
}

/**
 * @tc.name: CompatMatrix_NewToOld
 * @tc.desc: Quadrant 2: a backup made for a pre-7.1 peer parses as pure old format and restores
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: htt1997
 */
HWTEST_F(CloneManagerTest, CompatMatrix_NewToOld, TestSize.Level0)
{
    const std::string localDeviceId = "local_device_id";
    const std::string userId = "100";
    const std::string bundleName = "compat.new2old";
    const std::string storeId = "store1";
    const std::vector<uint8_t> password = {'c', 'o', 'm', 'p', 'a', 't'};
    ASSERT_TRUE(SaveEncryptedStoreMeta(localDeviceId, bundleName, storeId, userId, password));

    MessageParcel data;
    MessageParcel reply;
    data.WriteString(BuildCloneInfo(bundleName, userId, "7.0", VALID_IV));
    EXPECT_EQ(OnBackup(data, reply, localDeviceId), 0);
    std::string content = ReadBackupFileFromReply(reply);
    ASSERT_FALSE(content.empty());
    EXPECT_EQ(content.find("nonce"), std::string::npos);

    // The pre-7.1 peer pulls only the fields it knows, so the file must parse cleanly.
    SecretKeyBackupData parsedByOldPeer;
    EXPECT_TRUE(Serializable::Unmarshall(content, parsedByOldPeer));
    ASSERT_EQ(parsedByOldPeer.infos.size(), 1u);
    EXPECT_TRUE(parsedByOldPeer.infos[0].nonce.empty());

    EXPECT_EQ(WriteContentToFile(SECRETKEY_BACKUP_FILE, content), 0);
    int32_t fd = open(SECRETKEY_BACKUP_FILE.c_str(), O_RDONLY);
    ASSERT_GE(fd, 0);
    MessageParcel restoreData;
    MessageParcel restoreReply;
    restoreData.WriteFileDescriptor(fd);
    restoreData.WriteString(BuildCloneInfo(bundleName, userId, "", VALID_IV));
    EXPECT_EQ(OnRestore(restoreData, restoreReply), 0);
    close(fd);

    std::vector<uint8_t> restoredPassword;
    EXPECT_TRUE(LoadRestoredSecret(userId, bundleName, storeId, restoredPassword));
    EXPECT_EQ(restoredPassword, password);

    CleanupStoreMeta(localDeviceId, bundleName, storeId, userId);
    MetaDataManager::GetInstance().DelMeta(
        SecretKeyMetaData::GetCloneKey({ userId, "default", bundleName, storeId, "0" }), true);
}

/**
 * @tc.name: CompatMatrix_NewToNew
 * @tc.desc: Quadrant 3: a new-format backup round-trips between 7.1 devices with per-item nonces
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: htt1997
 */
HWTEST_F(CloneManagerTest, CompatMatrix_NewToNew, TestSize.Level0)
{
    const std::string localDeviceId = "local_device_id";
    const std::string userId = "100";
    const std::string bundleName = "compat.new2new";
    const std::vector<uint8_t> password = {'c', 'o', 'm', 'p', 'a', 't'};
    ASSERT_TRUE(SaveEncryptedStoreMeta(localDeviceId, bundleName, "store1", userId, password));
    ASSERT_TRUE(SaveEncryptedStoreMeta(localDeviceId, bundleName, "store2", userId, password));

    MessageParcel data;
    MessageParcel reply;
    data.WriteString(BuildCloneInfo(bundleName, userId, "7.1", VALID_IV));
    EXPECT_EQ(OnBackup(data, reply, localDeviceId), 0);
    std::string content = ReadBackupFileFromReply(reply);
    ASSERT_FALSE(content.empty());
    EXPECT_NE(content.find("nonce"), std::string::npos);

    EXPECT_EQ(WriteContentToFile(SECRETKEY_BACKUP_FILE, content), 0);
    int32_t fd = open(SECRETKEY_BACKUP_FILE.c_str(), O_RDONLY);
    ASSERT_GE(fd, 0);
    MessageParcel restoreData;
    MessageParcel restoreReply;
    restoreData.WriteFileDescriptor(fd);
    restoreData.WriteString(BuildCloneInfo(bundleName, userId, "", VALID_IV));
    EXPECT_EQ(OnRestore(restoreData, restoreReply), 0);
    close(fd);

    std::vector<uint8_t> restoredPassword;
    EXPECT_TRUE(LoadRestoredSecret(userId, bundleName, "store1", restoredPassword));
    EXPECT_EQ(restoredPassword, password);
    restoredPassword.clear();
    EXPECT_TRUE(LoadRestoredSecret(userId, bundleName, "store2", restoredPassword));
    EXPECT_EQ(restoredPassword, password);

    CleanupStoreMeta(localDeviceId, bundleName, "store1", userId);
    CleanupStoreMeta(localDeviceId, bundleName, "store2", userId);
    MetaDataManager::GetInstance().DelMeta(
        SecretKeyMetaData::GetCloneKey({ userId, "default", bundleName, "store1", "0" }), true);
    MetaDataManager::GetInstance().DelMeta(
        SecretKeyMetaData::GetCloneKey({ userId, "default", bundleName, "store2", "0" }), true);
}

/**
 * @tc.name: CompatMatrix_VersionMisjudgeInjection
 * @tc.desc: Quadrant 4 (fault injection): a new-format file that reaches a pre-7.1 peer parses
 *           without crash, its items are skipped by the shared-iv-only decrypt, and the same
 *           file still restores on a 7.1 device
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: htt1997
 */
HWTEST_F(CloneManagerTest, CompatMatrix_VersionMisjudgeInjection, TestSize.Level0)
{
    const std::string localDeviceId = "local_device_id";
    const std::string userId = "100";
    const std::string bundleName = "compat.misjudge";
    const std::string storeId = "store1";
    const std::vector<uint8_t> password = {'c', 'o', 'm', 'p', 'a', 't'};
    ASSERT_TRUE(SaveEncryptedStoreMeta(localDeviceId, bundleName, storeId, userId, password));

    // The framework misjudges the peer as >= 7.1, so the file carries per-item nonces.
    MessageParcel data;
    MessageParcel reply;
    data.WriteString(BuildCloneInfo(bundleName, userId, "7.1", VALID_IV));
    EXPECT_EQ(OnBackup(data, reply, localDeviceId), 0);
    std::string content = ReadBackupFileFromReply(reply);
    ASSERT_FALSE(content.empty());
    EXPECT_NE(content.find("nonce"), std::string::npos);

    // The pre-7.1 peer parses the file with its pull-based parser without crash.
    SecretKeyBackupData parsedByOldPeer;
    EXPECT_TRUE(Serializable::Unmarshall(content, parsedByOldPeer));
    ASSERT_EQ(parsedByOldPeer.infos.size(), 1u);
    EXPECT_FALSE(parsedByOldPeer.infos[0].nonce.empty());

    // Simulate the old peer's shared-iv-only restore: strip the nonces it ignores and run the
    // restore; the item fails to decrypt and is skipped, while the flow still returns 0.
    std::string oldPeerContent = content;
    SecretKeyBackupData oldSideData;
    ASSERT_TRUE(Serializable::Unmarshall(oldPeerContent, oldSideData));
    oldSideData.infos[0].nonce.clear();
    oldPeerContent = Serializable::Marshall(oldSideData);
    EXPECT_EQ(WriteContentToFile(SECRETKEY_BACKUP_FILE, oldPeerContent), 0);
    int32_t fd = open(SECRETKEY_BACKUP_FILE.c_str(), O_RDONLY);
    ASSERT_GE(fd, 0);
    MessageParcel oldPeerData;
    MessageParcel oldPeerReply;
    oldPeerData.WriteFileDescriptor(fd);
    oldPeerData.WriteString(BuildCloneInfo(bundleName, userId, "", VALID_IV));
    EXPECT_EQ(OnRestore(oldPeerData, oldPeerReply), 0);
    close(fd);
    std::vector<uint8_t> restoredPassword;
    EXPECT_FALSE(LoadRestoredSecret(userId, bundleName, storeId, restoredPassword));

    // The same intact file still restores on a 7.1 device through the per-item nonce path.
    EXPECT_EQ(WriteContentToFile(SECRETKEY_BACKUP_FILE, content), 0);
    fd = open(SECRETKEY_BACKUP_FILE.c_str(), O_RDONLY);
    ASSERT_GE(fd, 0);
    MessageParcel newData;
    MessageParcel newReply;
    newData.WriteFileDescriptor(fd);
    newData.WriteString(BuildCloneInfo(bundleName, userId, "", VALID_IV));
    EXPECT_EQ(OnRestore(newData, newReply), 0);
    close(fd);
    restoredPassword.clear();
    EXPECT_TRUE(LoadRestoredSecret(userId, bundleName, storeId, restoredPassword));
    EXPECT_EQ(restoredPassword, password);

    CleanupStoreMeta(localDeviceId, bundleName, storeId, userId);
    MetaDataManager::GetInstance().DelMeta(
        SecretKeyMetaData::GetCloneKey({ userId, "default", bundleName, storeId, "0" }), true);
}
/**
 * @tc.name: DeployedCloneSoLoadTest
 * @tc.desc: Integration probe: the deployed clone .so on this device loads and exports both
 *           extension entry symbols (the service dlopens it per EXTENSION_BACKUP/RESTORE call)
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: htt1997
 */
HWTEST_F(CloneManagerTest, DeployedCloneSoLoadTest, TestSize.Level0)
{
    const char *deployedSoPath = "/system/lib64/libdistributeddata_clone.z.so";
    void *handle = dlopen(deployedSoPath, RTLD_LAZY);
    ASSERT_NE(handle, nullptr) << "dlopen failed: " << dlerror();
    EXPECT_NE(dlsym(handle, "DistributedDataOnBackup"), nullptr);
    EXPECT_NE(dlsym(handle, "DistributedDataOnRestore"), nullptr);
    dlclose(handle);
}

/**
 * @tc.name: CloneManagerBackupFdDemoTest
 * @tc.desc: Demo: capture the backup file returned as fd by the real OnBackup flow for both
 *           formats (mocked inputs: two stores sharing one password, old/new peer versions)
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: htt1997
 */
HWTEST_F(CloneManagerTest, CloneManagerBackupFdDemoTest, TestSize.Level0)
{
    const std::string localDeviceId = "local_device_id";
    const std::string userId = "100";
    const std::string bundleName = "com.fd.demo";
    const std::string passwordStr = "demo-pass";
    const std::vector<uint8_t> password(passwordStr.begin(), passwordStr.end());
    // Mock input metadata: two encrypted stores holding the SAME password.
    ASSERT_TRUE(SaveEncryptedStoreMeta(localDeviceId, bundleName, "store1", userId, password));
    ASSERT_TRUE(SaveEncryptedStoreMeta(localDeviceId, bundleName, "store2", userId, password));
    printf("[demo] mock input: 2 encrypted stores, same password \"%s\", peer shared iv = \"%s...\"\n",
        passwordStr.c_str(), VALID_IV.substr(0, 12).c_str());

    auto backupPath = DirectoryManager::GetInstance().GetClonePath(userId);
    printf("[demo] OnBackup writes to (DirectoryManager::GetClonePath): %s\n", backupPath.c_str());

    const std::vector<std::pair<std::string, std::string>> rounds = {
        {"7.0", "OLD format (shared iv)"},
        {"7.1", "NEW format (per-item nonce)"},
    };
    for (const auto &round : rounds) {
        MessageParcel data;
        MessageParcel reply;
        data.WriteString(BuildCloneInfo(bundleName, userId, round.first, VALID_IV));
        ASSERT_EQ(OnBackup(data, reply, localDeviceId), 0);

        int32_t fd = reply.ReadFileDescriptor();
        ASSERT_GE(fd, 0);
        std::string content;
        char buffer[4096] = {0};
        ssize_t size = 0;
        while ((size = read(fd, buffer, sizeof(buffer))) > 0) {
            content.append(buffer, static_cast<size_t>(size));
        }
        printf("[demo] ===== peerDeviceVersion=\"%s\" -> %s =====\n", round.first.c_str(), round.second.c_str());
        printf("[demo] fd from reply = %d, backup file size = %zu bytes\n", fd, content.size());
        printf("[demo] raw file content:\n%s\n", content.c_str());

        SecretKeyBackupData backupData;
        ASSERT_TRUE(Serializable::Unmarshall(content, backupData));
        for (size_t i = 0; i < backupData.infos.size(); ++i) {
            const auto &item = backupData.infos[i];
            printf("[demo] item[%zu] dbName=%s nonce=\"%s\" (decoded %zu bytes) sKey=%s\n",
                i, item.dbName.c_str(), item.nonce.c_str(), Base64::Decode(item.nonce).size(),
                item.sKey.c_str());
        }
        close(fd);
    }

    CleanupStoreMeta(localDeviceId, bundleName, "store1", userId);
    CleanupStoreMeta(localDeviceId, bundleName, "store2", userId);
}
} // namespace OHOS::Test