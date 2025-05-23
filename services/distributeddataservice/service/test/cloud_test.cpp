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

#define LOG_TAG "CloudTest"
#include <string>

#include "account/account_delegate.h"
#include "cloud/cloud_server.h"
#include "cloud/sync_event.h"
#include "gtest/gtest.h"
#include "ipc_skeleton.h"
#include "metadata/meta_data_manager.h"
#include "mock/db_store_mock.h"
using namespace testing::ext;
using namespace OHOS::DistributedData;
using Database = SchemaMeta::Database;
namespace OHOS::Test {
class CloudTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void){};
    void SetUp(){};
    void TearDown(){};

protected:
    static constexpr const char* TEST_CLOUD_BUNDLE = "test_cloud_bundleName";
    static constexpr const char* TEST_CLOUD_STORE = "test_cloud_database_name";
    static std::shared_ptr<DBStoreMock> dbStoreMock_;
};
std::shared_ptr<DBStoreMock> CloudTest::dbStoreMock_ = std::make_shared<DBStoreMock>();

void CloudTest::SetUpTestCase(void)
{
    MetaDataManager::GetInstance().Initialize(dbStoreMock_, nullptr, "");
}

/**
* @tc.name: EventInfo
* @tc.desc:
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(CloudTest, EventInfo, TestSize.Level1)
{
    const int32_t mode = 1;
    const int32_t wait = 10;
    const bool retry = true;
    std::shared_ptr<GenQuery> query = nullptr;
    int sign = 0;
    auto async = [&sign](const GenDetails& details) {
        ++sign;
    };
    SyncEvent::EventInfo eventInfo1(mode, wait, retry, query, async);
    SyncEvent::EventInfo eventInfo2(std::move(eventInfo1));
    SyncEvent::EventInfo eventInfo3 = std::move(eventInfo2);
    StoreInfo storeInfo{ IPCSkeleton::GetCallingTokenID(), TEST_CLOUD_BUNDLE, TEST_CLOUD_STORE, 0 };
    SyncEvent evt(storeInfo, eventInfo3);
    EXPECT_EQ(evt.GetMode(), mode);
    EXPECT_EQ(evt.GetWait(), wait);
    EXPECT_EQ(evt.AutoRetry(), retry);
    EXPECT_EQ(evt.GetQuery(), query);
    evt.GetAsyncDetail()(GenDetails());
    EXPECT_NE(0, sign);
}

/**
* @tc.name: Serializable_Marshal
* @tc.desc:
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(CloudTest, Serializable_Marshal, TestSize.Level1)
{
    SchemaMeta schemaMeta;
    bool ret = schemaMeta.IsValid();
    EXPECT_EQ(false, ret);

    SchemaMeta::Database database;
    database.name = TEST_CLOUD_STORE;
    database.alias = "database_alias_test";

    schemaMeta.version = 1;
    schemaMeta.bundleName = TEST_CLOUD_BUNDLE;
    schemaMeta.databases.emplace_back(database);
    ret = schemaMeta.IsValid();
    EXPECT_EQ(true, ret);

    Serializable::json node = schemaMeta.Marshall();
    SchemaMeta schemaMeta2;
    schemaMeta2.Unmarshal(node);

    EXPECT_EQ(schemaMeta.version, schemaMeta2.version);
    EXPECT_EQ(schemaMeta.bundleName, schemaMeta2.bundleName);
    Database database2 = schemaMeta2.GetDataBase(TEST_CLOUD_STORE);
    EXPECT_EQ(database.alias, database2.alias);

    std::string storeId = "storeId";
    Database database3 = schemaMeta2.GetDataBase(storeId);
    EXPECT_NE(database.alias, database3.alias);
}

/**
* @tc.name: Field_Marshal
* @tc.desc:
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(CloudTest, Field_Marshal, TestSize.Level1)
{
    Field field;
    field.colName = "field_name1_test";
    field.alias = "field_alias1_test";
    field.type = 1;
    field.primary = true;
    field.nullable = false;

    Serializable::json node = field.Marshall();
    Field field2;
    field2.Unmarshal(node);

    EXPECT_EQ(field.colName, field2.colName);
    EXPECT_EQ(field.alias, field2.alias);
    EXPECT_EQ(field.type, field2.type);
    EXPECT_EQ(field.primary, field2.primary);
    EXPECT_EQ(field.nullable, field2.nullable);
}

/**
* @tc.name: Database_Marshal
* @tc.desc:
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(CloudTest, Database_Marshal, TestSize.Level1)
{
    SchemaMeta::Table table1;
    table1.name = "test_cloud_table_name1";
    table1.alias = "test_cloud_table_alias1";
    SchemaMeta::Table table2;
    table2.name = "test_cloud_table_name2";
    table2.alias = "test_cloud_table_alias2";

    SchemaMeta::Database database1;
    database1.name = TEST_CLOUD_STORE;
    database1.alias = "test_cloud_database_alias";
    database1.tables.emplace_back(table1);
    database1.tables.emplace_back(table2);

    Serializable::json node = database1.Marshall();
    SchemaMeta::Database database2;
    database2.Unmarshal(node);

    EXPECT_EQ(database1.name, database2.name);
    EXPECT_EQ(database1.alias, database2.alias);
    std::vector<std::string> tableNames1 = database1.GetTableNames();
    std::vector<std::string> tableNames2 = database2.GetTableNames();
    EXPECT_EQ(tableNames1.size(), tableNames2.size());
    for (uint32_t i = 0; i < tableNames1.size(); ++i) {
        EXPECT_EQ(tableNames1[i], tableNames2[i]);
    }
}

/**
 * @tc.name: Load old cloudInfo
 * @tc.desc: The obtained maxUploadBatchNumber and maxUploadBatchSize are not equal to 0
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: ht
 */
HWTEST_F(CloudTest, CloudInfoUpgrade, TestSize.Level0)
{
    int32_t defaultUser = 100;
    CloudInfo oldInfo;
    auto user = defaultUser;
    oldInfo.user = user;
    EXPECT_NE(oldInfo.maxNumber, CloudInfo::DEFAULT_BATCH_NUMBER);
    EXPECT_NE(oldInfo.maxSize, CloudInfo::DEFAULT_BATCH_SIZE);
    ASSERT_TRUE(MetaDataManager::GetInstance().SaveMeta(oldInfo.GetKey(), oldInfo, true));
    CloudInfo newInfo;
    ASSERT_TRUE(MetaDataManager::GetInstance().LoadMeta(oldInfo.GetKey(), newInfo, true));
    EXPECT_EQ(newInfo.maxNumber, CloudInfo::DEFAULT_BATCH_NUMBER);
    EXPECT_EQ(newInfo.maxSize, CloudInfo::DEFAULT_BATCH_SIZE);
}
} // namespace OHOS::Test