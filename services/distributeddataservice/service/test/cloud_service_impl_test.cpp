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
#define LOG_TAG "CloudServiceImplTest"
#include "cloud_service_impl.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <unistd.h>

#include "accesstoken_kit.h"
#include "account/account_delegate.h"
#include "bootstrap.h"
#include "checker_mock.h"
#include "cloud/change_event.h"
#include "cloud/cloud_event.h"
#include "cloud/cloud_server.h"
#include "cloud/cloud_share_event.h"
#include "cloud/schema_meta.h"
#include "cloud_types.h"
#include "cloud_types_util.h"
#include "cloud_value_util.h"
#include "communicator/device_manager_adapter.h"
#include "device_matrix.h"
#include "eventcenter/event_center.h"
#include "feature/feature_system.h"
#include "ipc_skeleton.h"
#include "log_print.h"
#include "metadata/meta_data_manager.h"
#include "metadata/store_meta_data.h"
#include "metadata/store_meta_data_local.h"
#include "mock/db_store_mock.h"
#include "mock/general_store_mock.h"
#include "mock/meta_data_manager_mock.h"
#include "model/component_config.h"
#include "network/network_delegate.h"
#include "network_delegate_mock.h"
#include "rdb_query.h"
#include "rdb_service.h"
#include "rdb_service_impl.h"
#include "rdb_types.h"
#include "store/auto_cache.h"
#include "store/store_info.h"
#include "token_setproc.h"

using namespace testing::ext;
using namespace testing;
using namespace OHOS::DistributedData;
using namespace OHOS::Security::AccessToken;
using Confirmation = OHOS::CloudData::Confirmation;
using Status = OHOS::CloudData::CloudService::Status;
using CloudSyncScene = OHOS::CloudData::CloudServiceImpl::CloudSyncScene;

namespace OHOS::Test {
namespace DistributedDataTest {
static constexpr const char *TEST_CLOUD_BUNDLE = "test_cloud_bundleName";
static constexpr const char *TEST_CLOUD_APPID = "test_cloud_appid";
static constexpr const char *TEST_CLOUD_STORE = "test_cloud_store";
static constexpr const char *TEST_CLOUD_DATABASE_ALIAS_1 = "test_cloud_database_alias_1";
class CloudServiceImplTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    static std::shared_ptr<CloudData::CloudServiceImpl> cloudServiceImpl_;
    static inline std::shared_ptr<MetaDataManagerMock> metaDataManagerMock = nullptr;
    static NetworkDelegateMock delegate_;
};
std::shared_ptr<CloudData::CloudServiceImpl> CloudServiceImplTest::cloudServiceImpl_ =
    std::make_shared<CloudData::CloudServiceImpl>();
NetworkDelegateMock CloudServiceImplTest::delegate_;

void CloudServiceImplTest::SetUpTestCase(void)
{
    metaDataManagerMock = std::make_shared<MetaDataManagerMock>();
    BMetaDataManager::metaDataManager = metaDataManagerMock;
    size_t max = 12;
    size_t min = 5;
    auto executor = std::make_shared<ExecutorPool>(max, min);
    DeviceManagerAdapter::GetInstance().Init(executor);
    NetworkDelegate::RegisterNetworkInstance(&delegate_);
}

void CloudServiceImplTest::TearDownTestCase()
{
    metaDataManagerMock = nullptr;
    BMetaDataManager::metaDataManager = nullptr;
}

void CloudServiceImplTest::SetUp() { }

void CloudServiceImplTest::TearDown() { }

/**
 * @tc.name: EnableCloud001
 * @tc.desc: Test EnableCloud functions with user is invalid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CloudServiceImplTest, EnableCloud001, TestSize.Level0)
{
    ZLOGI("CloudServiceImplTest EnableCloud001 start");
    std::map<std::string, int32_t> switches;
    switches.insert_or_assign(TEST_CLOUD_BUNDLE, CloudData::CloudService::SWITCH_ON);
    auto status = cloudServiceImpl_->EnableCloud(TEST_CLOUD_APPID, switches);
    EXPECT_EQ(status, CloudData::CloudService::ERROR);
}

/**
 * @tc.name: DisableCloud001
 * @tc.desc: Test DisableCloud functions with user is invalid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CloudServiceImplTest, DisableCloud001, TestSize.Level0)
{
    ZLOGI("CloudServiceImplTest DisableCloud001 start");
    auto status = cloudServiceImpl_->DisableCloud(TEST_CLOUD_APPID);
    EXPECT_EQ(status, CloudData::CloudService::ERROR);
}

/**
 * @tc.name: ChangeAppSwitch001
 * @tc.desc: Test ChangeAppSwitch functions with user is invalid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CloudServiceImplTest, ChangeAppSwitch001, TestSize.Level0)
{
    ZLOGI("CloudServiceImplTest ChangeAppSwitch001 start");
    auto status =
        cloudServiceImpl_->ChangeAppSwitch(TEST_CLOUD_APPID, TEST_CLOUD_BUNDLE, CloudData::CloudService::SWITCH_ON);
    EXPECT_EQ(status, CloudData::CloudService::ERROR);
}

/**
 * @tc.name: Clean001
 * @tc.desc: Test Clean functions with user is invalid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CloudServiceImplTest, Clean001, TestSize.Level0)
{
    ZLOGI("CloudServiceImplTest Clean001 start");
    std::map<std::string, int32_t> actions;
    actions.insert_or_assign(TEST_CLOUD_BUNDLE, CloudData::CloudService::SWITCH_ON);
    auto status = cloudServiceImpl_->Clean(TEST_CLOUD_APPID, actions);
    EXPECT_EQ(status, CloudData::CloudService::ERROR);
}

/**
 * @tc.name: NotifyDataChange001
 * @tc.desc: Test the EnableCloud function in case it doesn't get cloudInfo.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CloudServiceImplTest, NotifyDataChange001, TestSize.Level0)
{
    ZLOGI("CloudServiceImplTest NotifyDataChange001 start");
    auto status = cloudServiceImpl_->NotifyDataChange(TEST_CLOUD_APPID, TEST_CLOUD_BUNDLE);
    EXPECT_EQ(status, CloudData::CloudService::INVALID_ARGUMENT);
}

/**
 * @tc.name: ExecuteStatistics001
 * @tc.desc: Test the ExecuteStatistics function if the package name does not support CloudSync.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CloudServiceImplTest, ExecuteStatistics001, TestSize.Level0)
{
    ZLOGI("CloudServiceImplTest ExecuteStatistics001 start");
    CloudInfo cloudInfo;
    CloudInfo::AppInfo appInfo;
    appInfo.bundleName = TEST_CLOUD_BUNDLE;
    cloudInfo.apps[TEST_CLOUD_BUNDLE] = std::move(appInfo);
    SchemaMeta::Database database;
    database.name = TEST_CLOUD_STORE;
    database.alias = TEST_CLOUD_DATABASE_ALIAS_1;
    SchemaMeta schemaMeta;
    schemaMeta.bundleName = "testBundle";
    schemaMeta.databases.emplace_back(database);
    auto result = cloudServiceImpl_->ExecuteStatistics("", cloudInfo, schemaMeta);
    EXPECT_TRUE(result.empty());
}

/**
 * @tc.name: QueryStatistics001
 * @tc.desc: When metadata is not supported store test the QueryStatistics function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CloudServiceImplTest, QueryStatistics001, TestSize.Level0)
{
    ZLOGI("CloudServiceImplTest QueryStatistics start");
    StoreMetaData metaData;
    metaData.storeType = -1;
    DistributedData::Database database;
    auto result = cloudServiceImpl_->QueryStatistics(metaData, database);
    EXPECT_TRUE(result.empty());
}

/**
 * @tc.name: QueryLastSyncInfo001
 * @tc.desc: Test QueryLastSyncInfo functions with invalid parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CloudServiceImplTest, QueryLastSyncInfo001, TestSize.Level0)
{
    ZLOGI("CloudServiceImplTest QueryLastSyncInfo start");
    auto [status, result] = cloudServiceImpl_->QueryLastSyncInfo(TEST_CLOUD_APPID, TEST_CLOUD_BUNDLE, TEST_CLOUD_STORE);
    EXPECT_EQ(status, CloudData::CloudService::ERROR);
    EXPECT_TRUE(result.empty());
}

/**
 * @tc.name: OnBind001
 * @tc.desc: Test OnBind functions with invalid parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CloudServiceImplTest, OnBind001, TestSize.Level0)
{
    ZLOGI("CloudServiceImplTest OnBind001 start");
    auto status = cloudServiceImpl_->OnBind({});
    EXPECT_EQ(status, GeneralError::E_INVALID_ARGS);
}

/**
 * @tc.name: UpdateSchema001
 * @tc.desc: Test UpdateSchema001 functions with invalid parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CloudServiceImplTest, UpdateSchema001, TestSize.Level0)
{
    ZLOGI("CloudServiceImplTest UpdateSchema001 start");
    int user = -1;
    auto status = cloudServiceImpl_->UpdateSchema(user, CloudSyncScene::ENABLE_CLOUD);
    EXPECT_FALSE(status);
}

/**
 * @tc.name: GetAppSchemaFromServer001
 * @tc.desc: Test GetAppSchemaFromServer functions not support CloudService.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CloudServiceImplTest, GetAppSchemaFromServer001, TestSize.Level0)
{
    ZLOGI("CloudServiceImplTest GetAppSchemaFromServer001 start");
    int user = -1;
    auto [status, result] = cloudServiceImpl_->GetAppSchemaFromServer(user, TEST_CLOUD_BUNDLE);
    EXPECT_EQ(status, CloudData::CloudService::SERVER_UNAVAILABLE);
}

/**
 * @tc.name: GetCloudInfoFromServer001
 * @tc.desc: Test GetCloudInfoFromServer functions not support CloudService.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CloudServiceImplTest, GetCloudInfoFromServer001, TestSize.Level0)
{
    ZLOGI("CloudServiceImplTest GetCloudInfoFromServer001 start");
    int user = -1;
    auto [status, result] = cloudServiceImpl_->GetCloudInfoFromServer(user);
    EXPECT_EQ(status, CloudData::CloudService::SERVER_UNAVAILABLE);
}

/**
 * @tc.name: GetCloudInfoFromServer002
 * @tc.desc: Test GetCloudInfoFromServer functions with cloudinfo is empty.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CloudServiceImplTest, GetCloudInfoFromServer002, TestSize.Level0)
{
    ZLOGI("CloudServiceImplTest GetCloudInfoFromServer002 start");
    CloudServer cloudServer;
    CloudServer::RegisterCloudInstance(&cloudServer);
    int user = 100;
    auto [status, result] = cloudServiceImpl_->GetCloudInfoFromServer(user);
    EXPECT_EQ(status, E_ERROR);
    CloudServer::instance_ = nullptr;
}

/**
 * @tc.name: ReleaseUserInfo001
 * @tc.desc: Test ReleaseUserInfo functions with invalid parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CloudServiceImplTest, ReleaseUserInfo001, TestSize.Level0)
{
    ZLOGI("CloudServiceImplTest ReleaseUserInfo001 start");
    int user = 100;
    auto status = cloudServiceImpl_->ReleaseUserInfo(user, CloudSyncScene::ENABLE_CLOUD);
    EXPECT_TRUE(status);
}

/**
 * @tc.name: DoSubscribe
 * @tc.desc: Test the DoSubscribe with not support CloudService
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CloudServiceImplTest, DoSubscribe, TestSize.Level0)
{
    int32_t user = 100;
    auto status = cloudServiceImpl_->DoSubscribe(user, CloudSyncScene::ENABLE_CLOUD);
    EXPECT_TRUE(status);
}

/**
 * @tc.name: OnAppInstallTest
 * @tc.desc: Test the OnAppInstallTest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CloudServiceImplTest, OnAppInstallTest, TestSize.Level0)
{
    ZLOGI("CloudServiceImplTest OnAppInstallTest start");
    ASSERT_NE(cloudServiceImpl_, nullptr);
    ASSERT_NE(cloudServiceImpl_->factory_.staticActs_, nullptr);
    int32_t user = 0;
    int32_t index = 0;
    auto status = cloudServiceImpl_->factory_.staticActs_->OnAppInstall(TEST_CLOUD_BUNDLE, user, index);
    EXPECT_EQ(status, GeneralError::E_ERROR);
}

/**
 * @tc.name: OnAppUpdateTest
 * @tc.desc: Test the OnAppUpdateTest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CloudServiceImplTest, OnAppUpdateTest, TestSize.Level0)
{
    ZLOGI("CloudServiceImplTest OnAppUpdateTest start");
    ASSERT_NE(cloudServiceImpl_, nullptr);
    ASSERT_NE(cloudServiceImpl_->factory_.staticActs_, nullptr);
    int32_t user = 0;
    int32_t index = 0;
    auto status = cloudServiceImpl_->factory_.staticActs_->OnAppUpdate(TEST_CLOUD_BUNDLE, user, index);
    EXPECT_EQ(status, CloudData::CloudService::SUCCESS);
}

/**
 * @tc.name: CloudDriverCheckTest
 * @tc.desc: Test the CloudDriverCheck
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CloudServiceImplTest, CloudDriverCheckTest, TestSize.Level0)
{
    ZLOGI("CloudServiceImplTest CloudDriverCheckTest start");
    ASSERT_NE(cloudServiceImpl_, nullptr);
    ASSERT_NE(cloudServiceImpl_->factory_.staticActs_, nullptr);
    CloudServer cloudServer;
    CloudServer::RegisterCloudInstance(&cloudServer);
    int32_t user = 0;
    auto result = cloudServiceImpl_->factory_.staticActs_->CloudDriverCheck(TEST_CLOUD_BUNDLE, user);
    EXPECT_EQ(result, false);
    CloudServer::instance_ = nullptr;
}

/**
 * @tc.name: UpdateSchemaFromServerTest_001
 * @tc.desc: Test UpdateSchemaFromServer functions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CloudServiceImplTest, UpdateSchemaFromServerTest_001, TestSize.Level0)
{
    ZLOGI("CloudServiceImplTest UpdateSchemaFromServerTest_001 start");
    CloudServer cloudServer;
    CloudServer::RegisterCloudInstance(&cloudServer);
    int user = 100;
    auto status = cloudServiceImpl_->UpdateSchemaFromServer(user);
    EXPECT_EQ(status, E_ERROR);
    CloudServer::instance_ = nullptr;
}

/**
 * @tc.name: UpdateSchemaFromServerTest_002
 * @tc.desc: Test UpdateSchemaFromServer functions.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CloudServiceImplTest, UpdateSchemaFromServerTest_002, TestSize.Level0)
{
    ZLOGI("CloudServiceImplTest UpdateSchemaFromServerTest_002 start");
    CloudServer cloudServer;
    CloudServer::RegisterCloudInstance(&cloudServer);
    int user = 0;
    CloudInfo cloudInfo;
    cloudInfo.user = user;
    DistributedData::CloudInfo::AppInfo appInfo;
    appInfo.bundleName = TEST_CLOUD_BUNDLE;
    appInfo.appId = TEST_CLOUD_APPID;
    appInfo.cloudSwitch = true;
    cloudInfo.apps = {{ TEST_CLOUD_BUNDLE, appInfo }};
    auto status = cloudServiceImpl_->UpdateSchemaFromServer(cloudInfo, user);
    EXPECT_EQ(status, CloudData::CloudService::SUCCESS);
    CloudServer::instance_ = nullptr;
}

/**
 * @tc.name: UpdateE2eeEnableTest
 * @tc.desc: Test UpdateE2eeEnable functions.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CloudServiceImplTest, UpdateE2eeEnableTest, TestSize.Level0)
{
    ZLOGI("CloudServiceImplTest UpdateE2eeEnableTest start");
    ASSERT_NE(cloudServiceImpl_, nullptr);
    CloudServer cloudServer;
    auto result = cloudServer.CloudDriverUpdated(TEST_CLOUD_BUNDLE);
    EXPECT_EQ(result, false);

    std::string schemaKey = "schemaKey";
    cloudServiceImpl_->UpdateE2eeEnable(schemaKey, true, TEST_CLOUD_BUNDLE);
    SchemaMeta schemaMeta;
    ASSERT_FALSE(MetaDataManager::GetInstance().LoadMeta(schemaKey, schemaMeta, true));
}

/**
 * @tc.name: Share001
 * @tc.desc: Test the Share with invalid parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CloudServiceImplTest, Share001, TestSize.Level0)
{
    std::string sharingRes;
    CloudData::Participants participants;
    CloudData::Results results;
    auto status = cloudServiceImpl_->Share(sharingRes, participants, results);
    EXPECT_EQ(status, GeneralError::E_ERROR);
}

/**
 * @tc.name: Unshare001
 * @tc.desc: Test the Unshare with invalid parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CloudServiceImplTest, Unshare001, TestSize.Level0)
{
    std::string sharingRes;
    CloudData::Participants participants;
    CloudData::Results results;
    auto status = cloudServiceImpl_->Unshare(sharingRes, participants, results);
    EXPECT_EQ(status, GeneralError::E_ERROR);
}

/**
 * @tc.name: Exit001
 * @tc.desc: Test the Exit with invalid parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CloudServiceImplTest, Exit001, TestSize.Level0)
{
    std::string sharingRes;
    std::pair<int32_t, std::string> result;
    auto status = cloudServiceImpl_->Exit(sharingRes, result);
    EXPECT_EQ(status, GeneralError::E_ERROR);
}

/**
 * @tc.name: ChangePrivilege001
 * @tc.desc: Test the ChangePrivilege with invalid parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CloudServiceImplTest, ChangePrivilege001, TestSize.Level0)
{
    std::string sharingRes;
    CloudData::Participants participants;
    CloudData::Results results;
    auto status = cloudServiceImpl_->ChangePrivilege(sharingRes, participants, results);
    EXPECT_EQ(status, GeneralError::E_ERROR);
}

/**
 * @tc.name: Query001
 * @tc.desc: Test the Query with invalid parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CloudServiceImplTest, Query001, TestSize.Level0)
{
    std::string sharingRes;
    CloudData::QueryResults results;
    auto status = cloudServiceImpl_->Query(sharingRes, results);
    EXPECT_EQ(status, GeneralError::E_ERROR);
}

/**
 * @tc.name: QueryByInvitation001
 * @tc.desc: Test the QueryByInvitation with invalid parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CloudServiceImplTest, QueryByInvitation001, TestSize.Level0)
{
    std::string invitation;
    CloudData::QueryResults results;
    auto status = cloudServiceImpl_->QueryByInvitation(invitation, results);
    EXPECT_EQ(status, GeneralError::E_ERROR);
}

/**
 * @tc.name: ConfirmInvitation001
 * @tc.desc: Test the ConfirmInvitation with invalid parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CloudServiceImplTest, ConfirmInvitation001, TestSize.Level0)
{
    int32_t confirmation = 0;
    std::tuple<int32_t, std::string, std::string> result { 0, "", "" };
    std::string invitation;
    auto status = cloudServiceImpl_->ConfirmInvitation(invitation, confirmation, result);
    EXPECT_EQ(status, GeneralError::E_ERROR);
}

/**
 * @tc.name: GetStoreMetaData_001
 * @tc.desc: test GetStoreMetaData LoadMeta success.
 * @tc.type: FUNC
 */
HWTEST_F(CloudServiceImplTest, GetStoreMetaData_001, TestSize.Level1)
{
    EXPECT_CALL(*metaDataManagerMock, LoadMeta(_, _, _)).WillOnce(Return(true)).WillOnce(Return(false));
    StoreMetaData meta;
    bool res = cloudServiceImpl_->GetStoreMetaData(meta);
    EXPECT_EQ(res, false);
}

/**
 * @tc.name: GetStoreMetaData_002
 * @tc.desc: test GetStoreMetaData LoadMeta failed and user is 0.
 * @tc.type: FUNC
 */
HWTEST_F(CloudServiceImplTest, GetStoreMetaData_002, TestSize.Level1)
{
    EXPECT_CALL(*metaDataManagerMock, LoadMeta(_, _, _)).WillOnce(Return(false)).WillOnce(Return(false));
    StoreMetaData meta;
    meta.user = "0";
    bool res = cloudServiceImpl_->GetStoreMetaData(meta);
    EXPECT_EQ(res, false);
}

/**
 * @tc.name: GetStoreMetaData_003
 * @tc.desc: test GetStoreMetaData LoadMeta failed and user is not 0.
 * @tc.type: FUNC
 */
HWTEST_F(CloudServiceImplTest, GetStoreMetaData_003, TestSize.Level1)
{
    EXPECT_CALL(*metaDataManagerMock, LoadMeta(_, _, _)).WillOnce(Return(false)).WillOnce(Return(false));
    StoreMetaData meta;
    meta.user = "100";
    bool res = cloudServiceImpl_->GetStoreMetaData(meta);
    EXPECT_EQ(res, false);
}

/**
 * @tc.name: GetStoreMetaData_004
 * @tc.desc: test GetStoreMetaData First load of metadata failed and the user is not 0,
 * then the load of metadata succeeded.
 * @tc.type: FUNC
 */
HWTEST_F(CloudServiceImplTest, GetStoreMetaData_004, TestSize.Level1)
{
    EXPECT_CALL(*metaDataManagerMock, LoadMeta(_, _, _)).WillOnce(Return(false)).WillRepeatedly(Return(true));
    StoreMetaData meta;
    meta.user = "100";
    bool res = cloudServiceImpl_->GetStoreMetaData(meta);
    EXPECT_EQ(res, false);
}

/**
 * @tc.name: PreShare_001
 * @tc.desc: test PreShare is dataDir empty.
 * @tc.type: FUNC
 */
HWTEST_F(CloudServiceImplTest, PreShare_001, TestSize.Level1)
{
    EXPECT_CALL(*metaDataManagerMock, LoadMeta(_, _, _)).WillRepeatedly(Return(false));
    StoreInfo storeInfo;
    storeInfo.path = "";
    std::shared_ptr<GenQuery> query;
    auto [errCode, cursor] = cloudServiceImpl_->PreShare(storeInfo, *query);
    EXPECT_EQ(errCode, E_ERROR);
    ASSERT_EQ(cursor, nullptr);
    storeInfo.path = "test";
    std::tie(errCode, cursor) = cloudServiceImpl_->PreShare(storeInfo, *query);
    EXPECT_EQ(errCode, E_ERROR);
    ASSERT_EQ(cursor, nullptr);
}

/**
 * @tc.name: ChangeConfirmation001
 * @tc.desc: Test the ChangeConfirmation with invalid parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CloudServiceImplTest, ChangeConfirmation001, TestSize.Level0)
{
    int32_t confirmation = 0;
    std::string sharingRes;
    std::pair<int32_t, std::string> result;
    auto status = cloudServiceImpl_->ChangeConfirmation(sharingRes, confirmation, result);
    EXPECT_EQ(status, GeneralError::E_ERROR);
}

/**
 * @tc.name: GetSharingHandle001
 * @tc.desc: Test the GetSharingHandle with invalid parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CloudServiceImplTest, GetSharingHandle001, TestSize.Level0)
{
    CloudData::CloudServiceImpl::HapInfo hapInfo;
    auto status = cloudServiceImpl_->GetSharingHandle(hapInfo);
    EXPECT_EQ(status, nullptr);
}

/**
 * @tc.name: SetCloudStrategy001
 * @tc.desc: Test the SetCloudStrategy with get hapInfo failed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CloudServiceImplTest, SetCloudStrategy001, TestSize.Level0)
{
    CloudData::Strategy strategy = CloudData::Strategy::STRATEGY_NETWORK;
    std::vector<CommonType::Value> values;
    values.push_back(CloudData::NetWorkStrategy::WIFI);

    auto status = cloudServiceImpl_->SetCloudStrategy(strategy, values);
    EXPECT_EQ(status, CloudData::CloudService::ERROR);
}

/**
 * @tc.name: SetGlobalCloudStrategy001
 * @tc.desc: Test the SetGlobalCloudStrategy with get hapInfo failed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CloudServiceImplTest, SetGlobalCloudStrategy001, TestSize.Level0)
{
    CloudData::Strategy strategy = CloudData::Strategy::STRATEGY_NETWORK;
    std::vector<CommonType::Value> values;
    values.push_back(CloudData::NetWorkStrategy::WIFI);

    auto status = cloudServiceImpl_->SetGlobalCloudStrategy(strategy, values);
    EXPECT_EQ(status, CloudData::CloudService::ERROR);
}

/**
 * @tc.name: CheckNotifyConditions001
 * @tc.desc: Test the CheckNotifyConditions with invalid parameters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CloudServiceImplTest, CheckNotifyConditions, TestSize.Level0)
{
    CloudInfo cloudInfo;
    cloudInfo.enableCloud = false;
    cloudInfo.id = TEST_CLOUD_APPID;

    auto status = cloudServiceImpl_->CheckNotifyConditions(TEST_CLOUD_APPID, TEST_CLOUD_BUNDLE, cloudInfo);
    EXPECT_EQ(status, CloudData::CloudService::CLOUD_DISABLE);
    cloudInfo.enableCloud = true;
    CloudInfo::AppInfo appInfo;
    appInfo.bundleName = TEST_CLOUD_BUNDLE;
    appInfo.cloudSwitch = false;
    cloudInfo.apps.insert_or_assign(TEST_CLOUD_BUNDLE, appInfo);
    status = cloudServiceImpl_->CheckNotifyConditions(TEST_CLOUD_APPID, TEST_CLOUD_BUNDLE, cloudInfo);
    EXPECT_EQ(status, CloudData::CloudService::CLOUD_DISABLE_SWITCH);
}

/**
 * @tc.name: GetDfxFaultType
 * @tc.desc: test GetDfxFaultType function
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author:
 */
HWTEST_F(CloudServiceImplTest, GetDfxFaultType, TestSize.Level0)
{
    ASSERT_NE(cloudServiceImpl_, nullptr);
    EXPECT_EQ(cloudServiceImpl_->GetDfxFaultType(CloudSyncScene::ENABLE_CLOUD), "ENABLE_CLOUD");
    EXPECT_EQ(cloudServiceImpl_->GetDfxFaultType(CloudSyncScene::DISABLE_CLOUD), "DISABLE_CLOUD");
    EXPECT_EQ(cloudServiceImpl_->GetDfxFaultType(CloudSyncScene::SWITCH_ON), "SWITCH_ON");
    EXPECT_EQ(cloudServiceImpl_->GetDfxFaultType(CloudSyncScene::SWITCH_OFF), "SWITCH_OFF");
    EXPECT_EQ(cloudServiceImpl_->GetDfxFaultType(CloudSyncScene::QUERY_SYNC_INFO), "QUERY_SYNC_INFO");
    EXPECT_EQ(cloudServiceImpl_->GetDfxFaultType(CloudSyncScene::USER_CHANGE), "USER_CHANGE");
    EXPECT_EQ(cloudServiceImpl_->GetDfxFaultType(CloudSyncScene::USER_UNLOCK), "USER_UNLOCK");
    EXPECT_EQ(cloudServiceImpl_->GetDfxFaultType(CloudSyncScene::NETWORK_RECOVERY), "NETWORK_RECOVERY");
    EXPECT_EQ(cloudServiceImpl_->GetDfxFaultType(CloudSyncScene::SERVICE_INIT), "SERVICE_INIT");
    EXPECT_EQ(cloudServiceImpl_->GetDfxFaultType(CloudSyncScene::ACCOUNT_STOP), "SYNC_TASK");
}

class ComponentConfigTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void ComponentConfigTest::SetUpTestCase(void) { }

void ComponentConfigTest::TearDownTestCase() { }

void ComponentConfigTest::SetUp() { }

void ComponentConfigTest::TearDown() { }

/**
 * @tc.name: CapabilityRange
 * @tc.desc: test CapabilityRange Marshal function
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: suoqilong
 */
HWTEST_F(ComponentConfigTest, ComponentConfig, TestSize.Level0)
{
    DistributedData::ComponentConfig config;
    config.description = "description";
    config.lib = "lib";
    config.constructor = "constructor";
    config.destructor = "destructor";
    config.params = "";
    Serializable::json node;
    EXPECT_EQ(config.params.empty(), true);

    EXPECT_EQ(config.Marshal(node), true);
    EXPECT_EQ(node["description"], config.description);
    EXPECT_EQ(node["lib"], config.lib);
    EXPECT_EQ(node["constructor"], config.constructor);
    EXPECT_EQ(node["destructor"], config.destructor);

    DistributedData::ComponentConfig componentConfig;
    componentConfig.description = "description";
    componentConfig.lib = "lib";
    componentConfig.constructor = "constructor";
    componentConfig.destructor = "destructor";
    componentConfig.params = "params";
    Serializable::json node1;
    EXPECT_EQ(componentConfig.params.empty(), false);

    EXPECT_EQ(componentConfig.Marshal(node1), true);
    EXPECT_EQ(node["description"], componentConfig.description);
    EXPECT_EQ(node["lib"], componentConfig.lib);
    EXPECT_EQ(node["constructor"], componentConfig.constructor);
    EXPECT_EQ(node["destructor"], componentConfig.destructor);
}
} // namespace DistributedDataTest
} // namespace OHOS::Test