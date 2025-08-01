/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "bootstrap.h"
#include "kvstore_meta_manager.h"

#include "metadata/appid_meta_data.h"
#include "metadata/auto_launch_meta_data.h"
#include "metadata/appid_meta_data.h"
#include "metadata/capability_meta_data.h"
#include "metadata/capability_range.h"
#include "metadata/corrupted_meta_data.h"
#include "metadata/matrix_meta_data.h"
#include "metadata/meta_data.h"
#include "metadata/meta_data_manager.h"
#include "metadata/object_user_meta_data.h"
#include "metadata/secret_key_meta_data.h"
#include "metadata/store_meta_data.h"
#include "metadata/store_meta_data_local.h"
#include "metadata/strategy_meta_data.h"
#include "metadata/switches_meta_data.h"
#include "metadata/user_meta_data.h"
#include "metadata/device_meta_data.h"
#include "utils/constant.h"
#include "gtest/gtest.h"
#include "serializable/serializable.h"
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::DistributedKv;
using namespace OHOS::DistributedData;
namespace OHOS::Test {
class ServiceMetaDataTest : public testing::Test {
public:
    static constexpr size_t NUM_MIN = 1;
    static constexpr size_t NUM_MAX = 2;
    static constexpr uint32_t USER_ID1 = 101;
    static constexpr uint32_t USER_ID2 = 100;
    static constexpr uint32_t TEST_CURRENT_VERSION = 0x03000002;
    static void SetUpTestCase()
    {
        std::shared_ptr<ExecutorPool> executors = std::make_shared<ExecutorPool>(NUM_MAX, NUM_MIN);
        Bootstrap::GetInstance().LoadDirectory();
        Bootstrap::GetInstance().LoadCheckers();
        KvStoreMetaManager::GetInstance().BindExecutor(executors);
        KvStoreMetaManager::GetInstance().InitMetaParameter();
        KvStoreMetaManager::GetInstance().InitMetaListener();
    }
    static void TearDownTestCase(void) {};
    void SetUp() {};
    void TearDown() {};
};

/**
 * @tc.name: AppIDMetaData
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: SQL
 */
HWTEST_F(ServiceMetaDataTest, AppIDMetaData, TestSize.Level1)
{
    AppIDMetaData appIdMetaData("appid", "ohos.test.demo");
    AppIDMetaData appIdMeta;

    std::string key = appIdMetaData.GetKey();
    EXPECT_EQ(key, "appid");
    auto result = MetaDataManager::GetInstance().SaveMeta(key, appIdMetaData, true);
    EXPECT_TRUE(result);
    result = MetaDataManager::GetInstance().LoadMeta(key, appIdMeta, true);
    EXPECT_TRUE(result);
    EXPECT_EQ(appIdMetaData.appId, appIdMeta.appId);
    EXPECT_EQ(appIdMetaData.bundleName, appIdMeta.bundleName);
    EXPECT_EQ(appIdMetaData.GetKey(), appIdMeta.GetKey());
    result = MetaDataManager::GetInstance().DelMeta(key, true);
    EXPECT_TRUE(result);

    result = MetaDataManager::GetInstance().SaveMeta(key, appIdMetaData);
    EXPECT_TRUE(result);
    result = MetaDataManager::GetInstance().LoadMeta(key, appIdMeta);
    EXPECT_TRUE(result);
    EXPECT_EQ(appIdMetaData.appId, appIdMeta.appId);
    EXPECT_EQ(appIdMetaData.bundleName, appIdMeta.bundleName);
    EXPECT_EQ(appIdMetaData.GetKey(), appIdMeta.GetKey());
    result = MetaDataManager::GetInstance().DelMeta(key);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: corruptedMeta
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: SQL
 */
HWTEST_F(ServiceMetaDataTest, corruptedMeta, TestSize.Level1)
{
    CorruptedMetaData corruptedMeta("appid", "ohos.test.demo", "test_store");
    CorruptedMetaData corruptedMetaData;
    corruptedMeta.isCorrupted = true;
    std::string key = corruptedMeta.GetKey();
    EXPECT_EQ(key, "CorruptedMetaData###appid###ohos.test.demo###test_store");

    auto result = MetaDataManager::GetInstance().SaveMeta(key, corruptedMeta, true);
    EXPECT_TRUE(result);
    result = MetaDataManager::GetInstance().LoadMeta(key, corruptedMetaData, true);
    EXPECT_TRUE(result);
    EXPECT_EQ(corruptedMeta.appId, corruptedMetaData.appId);
    EXPECT_EQ(corruptedMeta.bundleName, corruptedMetaData.bundleName);
    EXPECT_EQ(corruptedMeta.storeId, corruptedMetaData.storeId);
    EXPECT_EQ(corruptedMeta.GetKey(), corruptedMetaData.GetKey());
    result = MetaDataManager::GetInstance().DelMeta(key, true);
    EXPECT_TRUE(result);

    result = MetaDataManager::GetInstance().SaveMeta(key, corruptedMeta);
    EXPECT_TRUE(result);
    result = MetaDataManager::GetInstance().LoadMeta(key, corruptedMetaData);
    EXPECT_TRUE(result);
    EXPECT_EQ(corruptedMeta.appId, corruptedMetaData.appId);
    EXPECT_EQ(corruptedMeta.bundleName, corruptedMetaData.bundleName);
    EXPECT_EQ(corruptedMeta.storeId, corruptedMetaData.storeId);
    EXPECT_EQ(corruptedMeta.GetKey(), corruptedMetaData.GetKey());
    result = MetaDataManager::GetInstance().DelMeta(key);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: SecretKeyMetaData
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: SQL
 */
HWTEST_F(ServiceMetaDataTest, SecretKeyMetaData001, TestSize.Level1)
{
    SecretKeyMetaData secretKeyMeta;
    SecretKeyMetaData secretKeyMetaData;
    secretKeyMeta.storeType = 1;
    std::initializer_list<std::string> fields = { "time", "skey" };

    std::string key = secretKeyMeta.GetKey(fields);
    EXPECT_EQ(key, "SecretKey###time###skey###SINGLE_KEY");
    std::string backupkey = secretKeyMeta.GetBackupKey(fields);
    EXPECT_EQ(backupkey, "BackupSecretKey###time###skey###");

    auto result = MetaDataManager::GetInstance().SaveMeta(key, secretKeyMeta, true);
    EXPECT_TRUE(result);
    result = MetaDataManager::GetInstance().LoadMeta(key, secretKeyMetaData, true);
    EXPECT_TRUE(result);
    EXPECT_EQ(secretKeyMeta.GetKey(fields), secretKeyMetaData.GetKey(fields));
    EXPECT_EQ(secretKeyMeta.GetBackupKey(fields), secretKeyMetaData.GetBackupKey(fields));

    result = MetaDataManager::GetInstance().DelMeta(key, true);
    EXPECT_TRUE(result);

    result = MetaDataManager::GetInstance().SaveMeta(key, secretKeyMeta);
    EXPECT_TRUE(result);
    result = MetaDataManager::GetInstance().LoadMeta(key, secretKeyMetaData);
    EXPECT_TRUE(result);
    EXPECT_EQ(secretKeyMeta.GetKey(fields), secretKeyMetaData.GetKey(fields));
    EXPECT_EQ(secretKeyMeta.GetBackupKey(fields), secretKeyMetaData.GetBackupKey(fields));

    result = MetaDataManager::GetInstance().DelMeta(key);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: SecretKeyMetaData
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: SQL
 */
HWTEST_F(ServiceMetaDataTest, SecretKeyMetaData002, TestSize.Level1)
{
    SecretKeyMetaData secretKeyMeta;
    SecretKeyMetaData secretKeyMetaData;
    secretKeyMeta.storeType = 1;
    std::initializer_list<std::string> fields = { "time", "skey" };

    std::string prefix = secretKeyMeta.GetPrefix(fields);
    EXPECT_EQ(prefix, "SecretKey###time###skey###");
    std::string backupprefix = secretKeyMeta.GetBackupPrefix(fields);
    EXPECT_EQ(backupprefix, "BackupSecretKey###time###skey###");

    auto result = MetaDataManager::GetInstance().SaveMeta(prefix, secretKeyMeta, true);
    EXPECT_TRUE(result);
    result = MetaDataManager::GetInstance().LoadMeta(prefix, secretKeyMetaData, true);
    EXPECT_TRUE(result);
    EXPECT_EQ(secretKeyMeta.GetPrefix(fields), secretKeyMetaData.GetPrefix(fields));
    EXPECT_EQ(secretKeyMeta.GetBackupPrefix(fields), secretKeyMetaData.GetBackupPrefix(fields));

    result = MetaDataManager::GetInstance().DelMeta(prefix, true);
    EXPECT_TRUE(result);

    result = MetaDataManager::GetInstance().SaveMeta(prefix, secretKeyMeta);
    EXPECT_TRUE(result);
    result = MetaDataManager::GetInstance().LoadMeta(prefix, secretKeyMetaData);
    EXPECT_TRUE(result);
    EXPECT_EQ(secretKeyMeta.GetPrefix(fields), secretKeyMetaData.GetPrefix(fields));
    EXPECT_EQ(secretKeyMeta.GetBackupPrefix(fields), secretKeyMetaData.GetBackupPrefix(fields));

    result = MetaDataManager::GetInstance().DelMeta(prefix);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: StoreMetaData
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: SQL
 */
HWTEST_F(ServiceMetaDataTest, StoreMetaData001, TestSize.Level1)
{
    StoreMetaData storeMetaData("100", "appid", "test_store");
    storeMetaData.dataDir = "testDir";
    StoreMetaData storeMeta;

    std::string key = storeMetaData.GetKey();
    EXPECT_EQ(key, "KvStoreMetaData######100###default######test_store###testDir");
    std::string keylocal = storeMetaData.GetKeyLocal();
    EXPECT_EQ(keylocal, "KvStoreMetaDataLocal######100###default######test_store###testDir");
    std::initializer_list<std::string> fields = { "100", "appid", "test_store" };
    std::string keyfields = storeMetaData.GetKey(fields);
    EXPECT_EQ(keyfields, "KvStoreMetaData###100###appid###test_store");

    auto result = MetaDataManager::GetInstance().SaveMeta(key, storeMetaData, true);
    EXPECT_TRUE(result);
    result = MetaDataManager::GetInstance().LoadMeta(key, storeMeta, true);
    EXPECT_TRUE(result);
    EXPECT_EQ(storeMetaData.GetKey(), storeMeta.GetKey());
    EXPECT_EQ(storeMetaData.GetKeyLocal(), storeMeta.GetKeyLocal());
    EXPECT_EQ(storeMetaData.GetKey(fields), storeMeta.GetKey(fields));

    result = MetaDataManager::GetInstance().DelMeta(key, true);
    EXPECT_TRUE(result);

    std::string syncKey = storeMetaData.GetKeyWithoutPath();
    result = MetaDataManager::GetInstance().SaveMeta(syncKey, storeMetaData);
    EXPECT_TRUE(result);
    result = MetaDataManager::GetInstance().LoadMeta(syncKey, storeMeta);
    EXPECT_TRUE(result);
    EXPECT_EQ(storeMetaData.GetKey(), storeMeta.GetKey());
    EXPECT_EQ(storeMetaData.GetKeyLocal(), storeMeta.GetKeyLocal());
    EXPECT_EQ(storeMetaData.GetKey(fields), storeMeta.GetKey(fields));

    result = MetaDataManager::GetInstance().DelMeta(syncKey);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: StoreMetaData
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: SQL
 */
HWTEST_F(ServiceMetaDataTest, StoreMetaData002, TestSize.Level1)
{
    StoreMetaData storeMetaData("100", "appid", "test_store");
    storeMetaData.dataDir = "testDir";
    StoreMetaData storeMeta;

    std::string secretkey = storeMetaData.GetSecretKey();
    EXPECT_EQ(secretkey, "SecretKey###100###default######test_store###0###testDir###SINGLE_KEY");
    std::string backupsecretkey = storeMetaData.GetBackupSecretKey();
    EXPECT_EQ(backupsecretkey, "BackupSecretKey###100###default######test_store###0###");

    auto result = MetaDataManager::GetInstance().SaveMeta(secretkey, storeMetaData, true);
    EXPECT_TRUE(result);
    result = MetaDataManager::GetInstance().LoadMeta(secretkey, storeMeta, true);
    EXPECT_TRUE(result);
    EXPECT_EQ(storeMetaData.GetSecretKey(), storeMeta.GetSecretKey());
    EXPECT_EQ(storeMetaData.GetBackupSecretKey(), storeMeta.GetBackupSecretKey());

    result = MetaDataManager::GetInstance().DelMeta(secretkey, true);
    EXPECT_TRUE(result);

    result = MetaDataManager::GetInstance().SaveMeta(secretkey, storeMetaData);
    EXPECT_TRUE(result);
    result = MetaDataManager::GetInstance().LoadMeta(secretkey, storeMeta);
    EXPECT_TRUE(result);
    EXPECT_EQ(storeMetaData.GetSecretKey(), storeMeta.GetSecretKey());
    EXPECT_EQ(storeMetaData.GetBackupSecretKey(), storeMeta.GetBackupSecretKey());

    result = MetaDataManager::GetInstance().DelMeta(secretkey);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: StoreMetaData
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: SQL
 */
HWTEST_F(ServiceMetaDataTest, StoreMetaData003, TestSize.Level1)
{
    StoreMetaData storeMetaData("100", "appid", "test_store");
    StoreMetaData storeMeta;

    auto storealias = storeMetaData.GetStoreAlias();
    EXPECT_EQ(storealias, "test_store");
    std::string strategykey = storeMetaData.GetStrategyKey();
    EXPECT_EQ(strategykey, "StrategyMetaData######100###default######test_store");
    std::initializer_list<std::string> fields = { "100", "appid", "test_store" };
    std::string prefix = storeMetaData.GetPrefix(fields);
    EXPECT_EQ(prefix, "KvStoreMetaData###100###appid###test_store###");

    auto result = MetaDataManager::GetInstance().SaveMeta(strategykey, storeMetaData, true);
    EXPECT_TRUE(result);
    result = MetaDataManager::GetInstance().LoadMeta(strategykey, storeMeta, true);
    EXPECT_TRUE(result);
    EXPECT_EQ(storeMetaData.GetStrategyKey(), storeMeta.GetStrategyKey());
    EXPECT_EQ(storeMetaData.GetStoreAlias(), storeMeta.GetStoreAlias());
    EXPECT_EQ(storeMetaData.GetPrefix(fields), storeMeta.GetPrefix(fields));

    result = MetaDataManager::GetInstance().DelMeta(strategykey, true);
    EXPECT_TRUE(result);

    result = MetaDataManager::GetInstance().SaveMeta(strategykey, storeMetaData);
    EXPECT_TRUE(result);
    result = MetaDataManager::GetInstance().LoadMeta(strategykey, storeMeta);
    EXPECT_TRUE(result);
    EXPECT_EQ(storeMetaData.GetStrategyKey(), storeMeta.GetStrategyKey());
    EXPECT_EQ(storeMetaData.GetStoreAlias(), storeMeta.GetStoreAlias());
    EXPECT_EQ(storeMetaData.GetPrefix(fields), storeMeta.GetPrefix(fields));

    result = MetaDataManager::GetInstance().DelMeta(strategykey);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: StoreMetaData
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: SQL
 */
HWTEST_F(ServiceMetaDataTest, StoreMetaData004, TestSize.Level1)
{
    StoreMetaData storeMetaData("100", "appid", "test_store");
    storeMetaData.version = TEST_CURRENT_VERSION;
    storeMetaData.instanceId = 1;
    storeMetaData.dataDir = "testDir";
    StoreMetaData storeMeta;

    std::string key = storeMetaData.GetKey();
    EXPECT_EQ(key, "KvStoreMetaData######100###default######test_store###1###testDir");
    std::string keylocal = storeMetaData.GetKeyLocal();
    EXPECT_EQ(keylocal, "KvStoreMetaDataLocal######100###default######test_store###1###testDir");

    auto result = MetaDataManager::GetInstance().SaveMeta(key, storeMetaData, true);
    EXPECT_TRUE(result);
    result = MetaDataManager::GetInstance().LoadMeta(key, storeMeta, true);
    EXPECT_TRUE(result);
    EXPECT_EQ(storeMetaData.GetKey(), storeMeta.GetKey());
    EXPECT_EQ(storeMetaData.GetKeyLocal(), storeMeta.GetKeyLocal());

    result = MetaDataManager::GetInstance().DelMeta(key, true);
    EXPECT_TRUE(result);

    std::string syncKey = storeMetaData.GetKeyWithoutPath();
    result = MetaDataManager::GetInstance().SaveMeta(syncKey, storeMetaData);
    EXPECT_TRUE(result);
    result = MetaDataManager::GetInstance().LoadMeta(syncKey, storeMeta);
    EXPECT_TRUE(result);
    EXPECT_EQ(storeMetaData.GetKey(), storeMeta.GetKey());
    EXPECT_EQ(storeMetaData.GetKeyLocal(), storeMeta.GetKeyLocal());

    result = MetaDataManager::GetInstance().DelMeta(syncKey);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: StoreMetaData
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: SQL
 */
HWTEST_F(ServiceMetaDataTest, StoreMetaData005, TestSize.Level1)
{
    StoreMetaData storeMetaData("100", "appid", "test_store");
    storeMetaData.version = TEST_CURRENT_VERSION;
    storeMetaData.instanceId = 1;
    storeMetaData.dataDir = "testDir";
    StoreMetaData storeMeta;

    std::string secretkey = storeMetaData.GetSecretKey();
    EXPECT_EQ(secretkey, "SecretKey###100###default######test_store###testDir###SINGLE_KEY");
    std::string backupsecretkey = storeMetaData.GetBackupSecretKey();
    EXPECT_EQ(backupsecretkey, "BackupSecretKey###100###default######test_store###");
    std::string strategykey = storeMetaData.GetStrategyKey();
    EXPECT_EQ(strategykey, "StrategyMetaData######100###default######test_store###1");

    auto result = MetaDataManager::GetInstance().SaveMeta(secretkey, storeMetaData, true);
    EXPECT_TRUE(result);
    result = MetaDataManager::GetInstance().LoadMeta(secretkey, storeMeta, true);
    EXPECT_TRUE(result);
    EXPECT_EQ(storeMetaData.GetSecretKey(), storeMeta.GetSecretKey());
    EXPECT_EQ(storeMetaData.GetBackupSecretKey(), storeMeta.GetBackupSecretKey());
    EXPECT_EQ(storeMetaData.GetStrategyKey(), storeMeta.GetStrategyKey());

    result = MetaDataManager::GetInstance().DelMeta(secretkey, true);
    EXPECT_TRUE(result);

    result = MetaDataManager::GetInstance().SaveMeta(secretkey, storeMetaData);
    EXPECT_TRUE(result);
    result = MetaDataManager::GetInstance().LoadMeta(secretkey, storeMeta);
    EXPECT_TRUE(result);
    EXPECT_EQ(storeMetaData.GetSecretKey(), storeMeta.GetSecretKey());
    EXPECT_EQ(storeMetaData.GetBackupSecretKey(), storeMeta.GetBackupSecretKey());
    EXPECT_EQ(storeMetaData.GetStrategyKey(), storeMeta.GetStrategyKey());

    result = MetaDataManager::GetInstance().DelMeta(secretkey);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: StoreMetaData
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: SQL
 */
HWTEST_F(ServiceMetaDataTest, StoreMetaData006, TestSize.Level1)
{
    StoreMetaData storemetaData1("100", "appid", "test_store");
    StoreMetaData storemetaData2("100", "appid", "test_store");
    StoreMetaData storemetaData3("10", "appid1", "storeid");
    EXPECT_TRUE(storemetaData1 == storemetaData2);
    EXPECT_FALSE(storemetaData1 == storemetaData3);

    storemetaData1.isAutoSync = true;
    EXPECT_FALSE(storemetaData1 == storemetaData2);
    storemetaData2.isAutoSync = true;
    EXPECT_TRUE(storemetaData1 == storemetaData2);

    storemetaData1.isBackup = true;
    EXPECT_FALSE(storemetaData1 == storemetaData2);
    storemetaData2.isBackup = true;
    EXPECT_TRUE(storemetaData1 == storemetaData2);

    storemetaData1.isDirty = true;
    EXPECT_FALSE(storemetaData1 == storemetaData2);
    storemetaData2.isDirty = true;
    EXPECT_TRUE(storemetaData1 == storemetaData2);

    storemetaData1.isEncrypt = true;
    EXPECT_FALSE(storemetaData1 == storemetaData2);
    storemetaData2.isEncrypt = true;
    EXPECT_TRUE(storemetaData1 == storemetaData2);

    storemetaData1.isSearchable = true;
    EXPECT_FALSE(storemetaData1 == storemetaData2);
    storemetaData2.isSearchable = true;
    EXPECT_TRUE(storemetaData1 == storemetaData2);

    storemetaData1.isNeedCompress = true;
    EXPECT_FALSE(storemetaData1 == storemetaData2);
    storemetaData2.isNeedCompress = true;
    EXPECT_TRUE(storemetaData1 == storemetaData2);

    storemetaData1.enableCloud = true;
    EXPECT_FALSE(storemetaData1 == storemetaData2);
    storemetaData2.enableCloud = true;
    EXPECT_TRUE(storemetaData1 == storemetaData2);

    storemetaData1.cloudAutoSync = true;
    EXPECT_FALSE(storemetaData1 == storemetaData2);
    storemetaData2.cloudAutoSync = true;
    EXPECT_TRUE(storemetaData1 == storemetaData2);
}

/**
 * @tc.name: StoreMetaData
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: SQL
 */
HWTEST_F(ServiceMetaDataTest, StoreMetaData007, TestSize.Level1)
{
    StoreMetaData storemetaData1("100", "appid", "test_store");
    StoreMetaData storemetaData2("100", "appid", "test_store");
    StoreMetaData storemetaData3("10", "appid1", "storeid");
    EXPECT_TRUE(storemetaData1 != storemetaData3);
    EXPECT_FALSE(storemetaData1 != storemetaData2);

    storemetaData1.isAutoSync = true;
    EXPECT_TRUE(storemetaData1 != storemetaData2);
    storemetaData2.isAutoSync = true;
    EXPECT_FALSE(storemetaData1 != storemetaData2);

    storemetaData1.isBackup = true;
    EXPECT_TRUE(storemetaData1 != storemetaData2);
    storemetaData2.isBackup = true;
    EXPECT_FALSE(storemetaData1 != storemetaData2);

    storemetaData1.isDirty = true;
    EXPECT_TRUE(storemetaData1 != storemetaData2);
    storemetaData2.isDirty = true;
    EXPECT_FALSE(storemetaData1 != storemetaData2);

    storemetaData1.isEncrypt = true;
    EXPECT_TRUE(storemetaData1 != storemetaData2);
    storemetaData2.isEncrypt = true;
    EXPECT_FALSE(storemetaData1 != storemetaData2);

    storemetaData1.isSearchable = true;
    EXPECT_TRUE(storemetaData1 != storemetaData2);
    storemetaData2.isSearchable = true;
    EXPECT_FALSE(storemetaData1 != storemetaData2);

    storemetaData1.isNeedCompress = true;
    EXPECT_TRUE(storemetaData1 != storemetaData2);
    storemetaData2.isNeedCompress = true;
    EXPECT_FALSE(storemetaData1 != storemetaData2);

    storemetaData1.enableCloud = true;
    EXPECT_TRUE(storemetaData1 != storemetaData2);
    storemetaData2.enableCloud = true;
    EXPECT_FALSE(storemetaData1 != storemetaData2);

    storemetaData1.cloudAutoSync = true;
    EXPECT_TRUE(storemetaData1 != storemetaData2);
    storemetaData2.cloudAutoSync = true;
    EXPECT_FALSE(storemetaData1 != storemetaData2);
}

/**
 * @tc.name: StoreMetaData
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: MY
 */
HWTEST_F(ServiceMetaDataTest, StoreMetaData008, TestSize.Level1)
{
    StoreMetaData storeMetaData("100", "appid", "test_store");
    storeMetaData.instanceId = 1;
    storeMetaData.dataDir = "008_dataDir";
    storeMetaData.deviceId = "008_uuid";
    storeMetaData.bundleName = "008_bundleName";

    std::string key = "KvStoreMetaDataLocal###008_uuid###100###default###008_bundleName###test_store###1";
    EXPECT_EQ(storeMetaData.GetKeyLocalWithoutPath(), key);
}

/**
 * @tc.name: StoreMetaData
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: MY
 */
HWTEST_F(ServiceMetaDataTest, StoreMetaData009, TestSize.Level1)
{
    StoreMetaData storeMetaData("100", "appid", "test_store");
    storeMetaData.instanceId = 1;
    storeMetaData.dataDir = "009_dataDir";
    storeMetaData.deviceId = "009_uuid";
    storeMetaData.bundleName = "009_bundleName";

    std::string key = "StoreDfxInfo###009_uuid###100###default###009_bundleName###test_store###1###";
    EXPECT_EQ(storeMetaData.GetDfxInfoKeyWithoutPath(), key);
}

/**
 * @tc.name: GetStoreInfo
 * @tc.desc: test StoreMetaData GetStoreInfo function
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: SQL
 */
HWTEST_F(ServiceMetaDataTest, GetStoreInfo, TestSize.Level1)
{
    StoreMetaData storeMetaData("100", "appid", "test_store");
    storeMetaData.version = TEST_CURRENT_VERSION;
    storeMetaData.instanceId = 1;

    auto result = storeMetaData.GetStoreInfo();
    EXPECT_EQ(result.instanceId, storeMetaData.instanceId);
    EXPECT_EQ(result.bundleName, storeMetaData.bundleName);
    EXPECT_EQ(result.storeName, storeMetaData.storeId);
}

/**
 * @tc.name: StrategyMeta001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: SQL
 */
HWTEST_F(ServiceMetaDataTest, StrategyMeta001, TestSize.Level1)
{
    auto deviceId = "deviceId";
    StrategyMeta strategyMeta(deviceId, "100", "ohos.test.demo", "test_store");
    std::vector<std::string> local = { "local1" };
    std::vector<std::string> remote = { "remote1" };
    strategyMeta.capabilityRange.localLabel = local;
    strategyMeta.capabilityRange.remoteLabel = remote;
    strategyMeta.capabilityEnabled = true;
    auto result = strategyMeta.IsEffect();
    EXPECT_TRUE(result);
    StrategyMeta strategyMetaData(deviceId, "200", "ohos.test.test", "test_stores");

    std::string key = strategyMeta.GetKey();
    EXPECT_EQ(key, "StrategyMetaData###deviceId###100###default###ohos.test.demo###test_store");
    std::initializer_list<std::string> fields = { deviceId, "100", "default", "ohos.test.demo", "test_store" };
    std::string prefix = strategyMeta.GetPrefix(fields);
    EXPECT_EQ(prefix, "StrategyMetaData###deviceId###100###default###ohos.test.demo###test_store");

    result = MetaDataManager::GetInstance().SaveMeta(key, strategyMeta, true);
    EXPECT_TRUE(result);
    result = MetaDataManager::GetInstance().LoadMeta(key, strategyMetaData, true);
    EXPECT_TRUE(result);
    EXPECT_EQ(strategyMeta.GetKey(), strategyMetaData.GetKey());
    EXPECT_EQ(strategyMeta.GetPrefix(fields), strategyMetaData.GetPrefix(fields));

    result = MetaDataManager::GetInstance().DelMeta(key, true);
    EXPECT_TRUE(result);

    result = MetaDataManager::GetInstance().SaveMeta(key, strategyMeta);
    EXPECT_TRUE(result);
    result = MetaDataManager::GetInstance().LoadMeta(key, strategyMetaData);
    EXPECT_TRUE(result);
    EXPECT_EQ(strategyMeta.GetKey(), strategyMetaData.GetKey());
    EXPECT_EQ(strategyMeta.GetPrefix(fields), strategyMetaData.GetPrefix(fields));

    result = MetaDataManager::GetInstance().DelMeta(key);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: StrategyMeta
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: SQL
 */
HWTEST_F(ServiceMetaDataTest, StrategyMeta002, TestSize.Level1)
{
    auto deviceId = "deviceId";
    StrategyMeta strategyMeta(deviceId, "100", "ohos.test.demo", "test_store");
    std::vector<std::string> local = { "local1" };
    std::vector<std::string> remote = { "remote1" };
    strategyMeta.capabilityRange.localLabel = local;
    strategyMeta.capabilityRange.remoteLabel = remote;
    strategyMeta.capabilityEnabled = true;
    auto result = strategyMeta.IsEffect();
    EXPECT_TRUE(result);
    strategyMeta.instanceId = 1;
    StrategyMeta strategyMetaData(deviceId, "200", "ohos.test.test", "test_stores");

    std::string key = strategyMeta.GetKey();
    EXPECT_EQ(key, "StrategyMetaData###deviceId###100###default###ohos.test.demo###test_store###1");

    result = MetaDataManager::GetInstance().SaveMeta(key, strategyMeta, true);
    EXPECT_TRUE(result);
    result = MetaDataManager::GetInstance().LoadMeta(key, strategyMetaData, true);
    EXPECT_TRUE(result);
    EXPECT_EQ(strategyMeta.GetKey(), strategyMetaData.GetKey());
    result = MetaDataManager::GetInstance().DelMeta(key, true);
    EXPECT_TRUE(result);

    result = MetaDataManager::GetInstance().SaveMeta(key, strategyMeta);
    EXPECT_TRUE(result);
    result = MetaDataManager::GetInstance().LoadMeta(key, strategyMetaData);
    EXPECT_TRUE(result);
    EXPECT_EQ(strategyMeta.GetKey(), strategyMetaData.GetKey());
    result = MetaDataManager::GetInstance().DelMeta(key);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: MetaData
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: SQL
 */
HWTEST_F(ServiceMetaDataTest, MetaData, TestSize.Level1)
{
    StoreMetaData storeMetaData("100", "appid", "test_store");
    storeMetaData.dataDir = "testDir1";
    SecretKeyMetaData secretKeyMetaData;
    MetaData metaData;
    MetaData metaDataLoad;
    metaData.storeMetaData = storeMetaData;
    metaData.secretKeyMetaData = secretKeyMetaData;
    metaData.storeType = 1;
    std::initializer_list<std::string> fields = { "time", "skey" };
    std::string key = metaData.storeMetaData.GetKey();
    std::string secretkey = metaData.secretKeyMetaData.GetKey(fields);

    auto result = MetaDataManager::GetInstance().SaveMeta(key, metaData, true);
    EXPECT_TRUE(result);
    result = MetaDataManager::GetInstance().LoadMeta(key, metaDataLoad, true);
    EXPECT_TRUE(result);
    EXPECT_EQ(key, metaDataLoad.storeMetaData.GetKey());
    EXPECT_EQ(secretkey, metaDataLoad.secretKeyMetaData.GetKey(fields));
    result = MetaDataManager::GetInstance().DelMeta(key, true);
    EXPECT_TRUE(result);

    result = MetaDataManager::GetInstance().SaveMeta(key, metaData);
    EXPECT_TRUE(result);
    result = MetaDataManager::GetInstance().LoadMeta(key, metaDataLoad);
    EXPECT_TRUE(result);
    EXPECT_EQ(key, metaDataLoad.storeMetaData.GetKey());
    EXPECT_EQ(secretkey, metaDataLoad.secretKeyMetaData.GetKey(fields));
    result = MetaDataManager::GetInstance().DelMeta(key);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: CapMetaData
 * @tc.desc: test CapMetaData function
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: SQL
 */
HWTEST_F(ServiceMetaDataTest, CapMetaData, TestSize.Level1)
{
    CapMetaData capMetaData;
    capMetaData.version = CapMetaData::CURRENT_VERSION;
    Serializable::json node1;
    capMetaData.Marshal(node1);
    EXPECT_EQ(node1["version"], CapMetaData::CURRENT_VERSION);

    CapMetaData capMeta;
    capMeta.Unmarshal(node1);
    EXPECT_EQ(capMeta.version, CapMetaData::CURRENT_VERSION);

    CapMetaRow capMetaRow;
    auto key = capMetaRow.GetKeyFor("PEER_DEVICE_ID");
    std::string str = "CapabilityMeta###PEER_DEVICE_ID";
    std::vector<uint8_t> testKey = { str.begin(), str.end() };
    EXPECT_EQ(key, testKey);
}

/**
 * @tc.name: UserMetaData
 * @tc.desc: test UserMetaData function
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: SQL
 */
HWTEST_F(ServiceMetaDataTest, UserMetaData, TestSize.Level1)
{
    UserMetaData userMetaData;
    userMetaData.deviceId = "PEER_DEVICE_ID";

    UserStatus userStatus;
    userStatus.isActive = true;
    userStatus.id = USER_ID1;
    userMetaData.users = { userStatus };
    userStatus.id = USER_ID2;
    userMetaData.users.emplace_back(userStatus);

    Serializable::json node1;
    userMetaData.Marshal(node1);
    EXPECT_EQ(node1["deviceId"], "PEER_DEVICE_ID");

    UserMetaData userMeta;
    userMeta.Unmarshal(node1);
    EXPECT_EQ(userMeta.deviceId, "PEER_DEVICE_ID");

    Serializable::json node2;
    userStatus.Marshal(node2);
    EXPECT_EQ(node2["isActive"], true);
    EXPECT_EQ(node2["id"], USER_ID2);

    UserStatus userUnmarshal;
    userUnmarshal.Unmarshal(node2);
    EXPECT_EQ(userUnmarshal.isActive, true);
    EXPECT_EQ(userUnmarshal.id, USER_ID2);

    UserMetaRow userMetaRow;
    auto key = userMetaRow.GetKeyFor(userMetaData.deviceId);
    EXPECT_EQ(key, "UserMeta###PEER_DEVICE_ID");
}

/**
 * @tc.name: CapabilityRange
 * @tc.desc: test CapabilityRange function
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: SQL
 */
HWTEST_F(ServiceMetaDataTest, CapabilityRange, TestSize.Level1)
{
    CapabilityRange capabilityRange;
    std::vector<std::string> local = { "local1" };
    std::vector<std::string> remote = { "remote1" };
    capabilityRange.localLabel = local;
    capabilityRange.remoteLabel = remote;
    Serializable::json node1;
    capabilityRange.Marshal(node1);
    EXPECT_EQ(node1["localLabel"], local);
    EXPECT_EQ(node1["remoteLabel"], remote);

    CapabilityRange capRange;
    capRange.Unmarshal(node1);
    EXPECT_EQ(capRange.localLabel, local);
    EXPECT_EQ(capRange.remoteLabel, remote);
}

/**
 * @tc.name: MatrixMetaData
 * @tc.desc: test MatrixMetaData operator!= function
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: nhj
 */
HWTEST_F(ServiceMetaDataTest, MatrixMetaData, TestSize.Level1)
{
    MatrixMetaData matrixMetaData1;
    matrixMetaData1.version = 0;
    matrixMetaData1.deviceId = "PEER_DEVICE_ID";

    MatrixMetaData matrixMetaData2;
    matrixMetaData2.version = 0;
    matrixMetaData2.deviceId = "PEER_DEVICE_ID";

    MatrixMetaData matrixMetaData3;
    matrixMetaData3.version = 1;
    matrixMetaData3.deviceId = "DEVICE_ID";
    EXPECT_TRUE(matrixMetaData1 != matrixMetaData3);
    EXPECT_FALSE(matrixMetaData1 != matrixMetaData2);

    std::string key = matrixMetaData3.GetConsistentKey();
    EXPECT_EQ(key, "MatrixMeta###DEVICE_ID###Consistent");
}

/**
 * @tc.name: DeviceMetaData
 * @tc.desc: test DeviceMetaData function
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: yl
 */
HWTEST_F(ServiceMetaDataTest, DeviceMetaData, TestSize.Level1)
{
    DeviceMetaData  metaData;
    std::string newUuid = "newuuid";
    metaData.newUuid = newUuid;
    Serializable::json node1;
    metaData.Marshal(node1);
    EXPECT_EQ(node1["newUuid"], newUuid);

    DeviceMetaData newMetaData;
    newMetaData.Unmarshal(node1);
    EXPECT_EQ(newMetaData.newUuid, newUuid);
}

/**
* @tc.name: InitMeta
* @tc.desc: test Init TestMeta
* @tc.type: FUNC
* @tc.require:
* @tc.author: yl
*/
HWTEST_F(ServiceMetaDataTest, InitTestMeta, TestSize.Level1)
{
    StoreMetaData oldMeta;
    oldMeta.deviceId = "mockOldUuid";
    oldMeta.user = "200";
    oldMeta.bundleName = "test_appid_001";
    oldMeta.storeId = "test_storeid_001";
    oldMeta.isEncrypt = true;
    oldMeta.dataDir = "testDir2";
    bool isSuccess = MetaDataManager::GetInstance().SaveMeta(oldMeta.GetKey(), oldMeta, true);
    EXPECT_TRUE(isSuccess);
    StoreMetaDataLocal metaDataLocal;
    isSuccess = MetaDataManager::GetInstance().SaveMeta(oldMeta.GetKeyLocal(), metaDataLocal, true);
    EXPECT_TRUE(isSuccess);
    SwitchesMetaData switchesMetaData;
    isSuccess = MetaDataManager::GetInstance().SaveMeta(SwitchesMetaData::GetPrefix({"mockOldUuid"}),
        switchesMetaData, true);
    EXPECT_TRUE(isSuccess);
    AutoLaunchMetaData autoLaunchMetaData;
    MetaDataManager::GetInstance().SaveMeta(AutoLaunchMetaData::GetPrefix({ oldMeta.deviceId, oldMeta.user,
        "default", oldMeta.bundleName, "" }), autoLaunchMetaData, true);
    EXPECT_TRUE(isSuccess);
    MatrixMetaData matrixMeta0;
    isSuccess = MetaDataManager::GetInstance().SaveMeta(MatrixMetaData::GetPrefix({"mockOldUuid"}), matrixMeta0, true);
    EXPECT_TRUE(isSuccess);

    isSuccess = MetaDataManager::GetInstance().SaveMeta(oldMeta.GetKeyWithoutPath(), oldMeta);
    EXPECT_TRUE(isSuccess);
    MatrixMetaData matrixMeta;
    isSuccess = MetaDataManager::GetInstance().SaveMeta(MatrixMetaData::GetPrefix({"mockOldUuid"}), matrixMeta);
    EXPECT_TRUE(isSuccess);
    UserMetaData userMeta;
    isSuccess = MetaDataManager::GetInstance().SaveMeta(UserMetaRow::GetKeyFor("mockOldUuid"), userMeta);
    EXPECT_TRUE(isSuccess);
    CapMetaData capMetaData;
    auto capKey = CapMetaRow::GetKeyFor("mockOldUuid");
    isSuccess = MetaDataManager::GetInstance().SaveMeta(std::string(capKey.begin(), capKey.end()), capMetaData);
    EXPECT_TRUE(isSuccess);
    StrategyMeta strategyMeta;
    isSuccess = MetaDataManager::GetInstance().SaveMeta(oldMeta.GetStrategyKey(), strategyMeta);
    EXPECT_TRUE(isSuccess);
}

/**
* @tc.name: UpdateStoreMetaData
* @tc.desc: test UpdateStoreMetaData function
* @tc.type: FUNC
* @tc.require:
* @tc.author: yl
*/
HWTEST_F(ServiceMetaDataTest, UpdateStoreMetaData, TestSize.Level1)
{
    std::string mockNewUuid = "mockNewUuid";
    std::string mockOldUuid = "mockOldUuid";
    StoreMetaData newMeta;
    newMeta.deviceId = "mockNewUuid";
    newMeta.user = "200";
    newMeta.bundleName = "test_appid_001";
    newMeta.storeId = "test_storeid_001";
    newMeta.dataDir = "testDir2";
    KvStoreMetaManager::GetInstance().UpdateStoreMetaData(mockNewUuid, mockOldUuid);
    bool isSuccess = MetaDataManager::GetInstance().LoadMeta(newMeta.GetKey(), newMeta, true);
    EXPECT_TRUE(isSuccess);
    EXPECT_TRUE(newMeta.isNeedUpdateDeviceId);
    isSuccess = MetaDataManager::GetInstance().LoadMeta(newMeta.GetKeyWithoutPath(), newMeta);
    EXPECT_TRUE(isSuccess);
    AutoLaunchMetaData autoLaunchMetaData;
    isSuccess = MetaDataManager::GetInstance().LoadMeta(AutoLaunchMetaData::GetPrefix({ newMeta.deviceId, newMeta.user,
        "default", newMeta.bundleName, "" }), autoLaunchMetaData, true);
    EXPECT_TRUE(isSuccess);
    StrategyMeta strategyMeta;
    isSuccess = MetaDataManager::GetInstance().LoadMeta(newMeta.GetStrategyKey(), strategyMeta);
    EXPECT_TRUE(isSuccess);
}

/**
* @tc.name: UpdateMetaDatas
* @tc.desc: test UpdateMetaDatas function
* @tc.type: FUNC
* @tc.require:
* @tc.author: yl
*/
HWTEST_F(ServiceMetaDataTest, UpdateMetaDatas, TestSize.Level1)
{
    std::string mockNewUuid = "mockNewUuid";
    std::string mockOldUuid = "mockOldUuid";
    KvStoreMetaManager::GetInstance().UpdateMetaDatas(mockNewUuid, mockOldUuid);
    MatrixMetaData matrixMeta;
    bool isSuccess = MetaDataManager::GetInstance().LoadMeta(MatrixMetaData::GetPrefix({ "mockNewUuid" }),
        matrixMeta, true);
    EXPECT_TRUE(isSuccess);
    isSuccess = MetaDataManager::GetInstance().LoadMeta(MatrixMetaData::GetPrefix({ "mockNewUuid" }), matrixMeta);
    EXPECT_TRUE(isSuccess);
    UserMetaData userMeta;
    isSuccess = MetaDataManager::GetInstance().LoadMeta(MatrixMetaData::GetPrefix({ "mockNewUuid" }), userMeta);
    EXPECT_TRUE(isSuccess);
    CapMetaData capMetaData;
    auto capKey = CapMetaRow::GetKeyFor("mockNewUuid");
    isSuccess = MetaDataManager::GetInstance().LoadMeta(std::string(capKey.begin(), capKey.end()), capMetaData);
    EXPECT_TRUE(isSuccess);
    SwitchesMetaData switchesMetaData;
    isSuccess = MetaDataManager::GetInstance().LoadMeta(SwitchesMetaData::GetPrefix({ "mockNewUuid" }),
        switchesMetaData, true);
    EXPECT_TRUE(isSuccess);
}

/**
* @tc.name: DelInitTestMeta
* @tc.desc: test Del TestMeta
* @tc.type: FUNC
* @tc.require:
* @tc.author: yl
*/
HWTEST_F(ServiceMetaDataTest, DelTestMeta, TestSize.Level1)
{
    StoreMetaData newMeta;
    newMeta.deviceId = "mockNewUuid";
    newMeta.user = "200";
    newMeta.bundleName = "test_appid_001";
    newMeta.storeId = "test_storeid_001";
    newMeta.dataDir = "testDir2";
    bool isSuccess = MetaDataManager::GetInstance().DelMeta(newMeta.GetKey(), true);
    EXPECT_TRUE(isSuccess);
    isSuccess = MetaDataManager::GetInstance().DelMeta(newMeta.GetKeyLocal(), true);
    EXPECT_TRUE(isSuccess);
    isSuccess = MetaDataManager::GetInstance().DelMeta(SwitchesMetaData::GetPrefix({ "mockNewUuid" }), true);
    EXPECT_TRUE(isSuccess);
    MetaDataManager::GetInstance().DelMeta(AutoLaunchMetaData::GetPrefix({ "mockNewUuid", newMeta.user,
        "default", newMeta.bundleName, "" }), true);
    EXPECT_TRUE(isSuccess);
    isSuccess = MetaDataManager::GetInstance().DelMeta(MatrixMetaData::GetPrefix({ "mockNewUuid" }), true);
    EXPECT_TRUE(isSuccess);

    isSuccess = MetaDataManager::GetInstance().DelMeta(newMeta.GetKeyWithoutPath());
    EXPECT_TRUE(isSuccess);
    isSuccess = MetaDataManager::GetInstance().DelMeta(MatrixMetaData::GetPrefix({"mockNewUuid"}));
    EXPECT_TRUE(isSuccess);
    isSuccess = MetaDataManager::GetInstance().DelMeta(UserMetaRow::GetKeyFor("mockNewUuid"));
    EXPECT_TRUE(isSuccess);
    auto capKey = CapMetaRow::GetKeyFor("mockNewUuid");
    isSuccess = MetaDataManager::GetInstance().DelMeta(std::string(capKey.begin(), capKey.end()));
    EXPECT_TRUE(isSuccess);
    isSuccess = MetaDataManager::GetInstance().DelMeta(newMeta.GetStrategyKey());
    EXPECT_TRUE(isSuccess);
}

/**
* @tc.name: GetKeyTest
* @tc.desc: GetKey
* @tc.type: FUNC
* @tc.require:
* @tc.author: yl
*/
HWTEST_F(ServiceMetaDataTest, GetKey, TestSize.Level1)
{
    DeviceMetaData metaData;
    std::string expectedPrefix = "DeviceMeta";
    std::string prefix = metaData.GetKey();
    EXPECT_EQ(prefix, expectedPrefix);
}

/**
* @tc.name: ObjectUserMetaDataGetKey
* @tc.desc: ObjectUserMetaDataGetKey
* @tc.type: FUNC
*/
HWTEST_F(ServiceMetaDataTest, ObjectUserMetaDataGetKey, TestSize.Level1)
{
    ObjectUserMetaData metaData;
    std::string expectedPrefix = "ObjectUserMetaData";
    std::string prefix = metaData.GetKey();
    EXPECT_EQ(prefix, expectedPrefix);
}
} // namespace OHOS::Test