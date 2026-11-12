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
#include <gtest/gtest.h>

#include "delay_data_acquire_container.h"
#include "delay_data_prepare_container.h"
#include "iremote_stub.h"
#include "synced_device_container.h"

using namespace OHOS::UDMF;
using namespace testing::ext;
using namespace testing;

namespace OHOS::Test {
namespace DistributedDataTest {
class UdmfDelayDataContainerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp()
    {
        Reset();
    }
    void TearDown()
    {
        Reset();
    }
    void Reset()
    {
        auto &container = DelayDataPrepareContainer::GetInstance();
        container.BindExecutor(nullptr);
        container.dataLoadCallback_.clear();
        container.blockDelayDataCache_.clear();
        container.origins_.clear();
        container.cachedBytes_ = 0;
    }
};

/**
* @tc.name: DataLoadCallbackTest001
* @tc.desc: Test Execute data load callback with return false
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(UdmfDelayDataContainerTest, DataLoadCallbackTest001, TestSize.Level1)
{
    UnifiedData data;
    QueryOption query;
    query.key = "";
    auto ret = DelayDataPrepareContainer::GetInstance().HandleDelayLoad(query, data);
    EXPECT_EQ(ret, DelayLoadStatus::NOT_DELAY_DATA);

    query.key = "udmf://drag/com.example.app/1233455";
    ret = DelayDataPrepareContainer::GetInstance().HandleDelayLoad(query, data);
    EXPECT_EQ(ret, DelayLoadStatus::NOT_DELAY_DATA);
}

/**
* @tc.name: DataLoadCallbackTest002
* @tc.desc: Test Execute data load callback after registering callback
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(UdmfDelayDataContainerTest, DataLoadCallbackTest002, TestSize.Level1)
{
    DelayDataPrepareContainer::GetInstance().dataLoadCallback_.clear();
    std::string key = "";
    sptr<UdmfNotifierProxy> callback = nullptr;
    DelayDataPrepareContainer::GetInstance().RegisterDataLoadCallback(key, callback);
    EXPECT_TRUE(DelayDataPrepareContainer::GetInstance().dataLoadCallback_.empty());

    key = "udmf://drag/com.example.app/1233455";
    DelayDataPrepareContainer::GetInstance().RegisterDataLoadCallback(key, callback);
    EXPECT_TRUE(DelayDataPrepareContainer::GetInstance().dataLoadCallback_.empty());
    sptr<IRemoteObject> re = nullptr;
    callback = new (std::nothrow) UdmfNotifierProxy(re);
    DelayDataPrepareContainer::GetInstance().RegisterDataLoadCallback(key, callback);
    EXPECT_FALSE(DelayDataPrepareContainer::GetInstance().dataLoadCallback_.empty());

    QueryOption query;
    query.key = key;
    UnifiedData data;
    auto ret = DelayDataPrepareContainer::GetInstance().HandleDelayLoad(query, data);
    EXPECT_EQ(ret, DelayLoadStatus::WAITING);
    ret = DelayDataPrepareContainer::GetInstance().HandleDelayLoad(query, data);
    EXPECT_EQ(ret, DelayLoadStatus::WAITING);
    DelayDataPrepareContainer::GetInstance().dataLoadCallback_.clear();
}

/**
* @tc.name: DataLoadCallbackTest003
* @tc.desc: Test Execute data load callback after registering callback
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(UdmfDelayDataContainerTest, DataLoadCallbackTest003, TestSize.Level1)
{
    DelayDataPrepareContainer::GetInstance().dataLoadCallback_.clear();
    std::string key = "udmf://drag/com.example.app/1233455";
    sptr<IRemoteObject> re = nullptr;
    sptr<UdmfNotifierProxy> callback = new (std::nothrow) UdmfNotifierProxy(re);
    DelayDataPrepareContainer::GetInstance().RegisterDataLoadCallback(key, callback);
    EXPECT_TRUE(DelayDataPrepareContainer::GetInstance().dataLoadCallback_.size() == 1);

    using CacheData = BlockData<std::optional<DelayDeliveryResult>, std::chrono::milliseconds>;
    BlockDelayData data;
    data.tokenId = 1111;
    data.blockData = std::make_shared<CacheData>(100);
    DelayDataPrepareContainer::GetInstance().blockDelayDataCache_.insert_or_assign(key, data);

    UnifiedData insertedData;
    insertedData.AddRecord(std::make_shared<UnifiedRecord>());
    data.blockData->SetValue(DelayDeliveryResult{ insertedData, E_OK, false });

    QueryOption query;
    query.key = key;
    UnifiedData getData;
    auto ret = DelayDataPrepareContainer::GetInstance().HandleDelayLoad(query, getData);
    EXPECT_EQ(ret, DelayLoadStatus::NO_PERMISSION);
    EXPECT_TRUE(getData.GetRecords().empty());

    query.tokenId = 1111;
    ret = DelayDataPrepareContainer::GetInstance().HandleDelayLoad(query, getData);
    EXPECT_EQ(ret, DelayLoadStatus::DATA_READY);
    EXPECT_TRUE(getData.GetRecords().size() == 1);
    DelayDataPrepareContainer::GetInstance().dataLoadCallback_.clear();
    DelayDataPrepareContainer::GetInstance().blockDelayDataCache_.clear();
}

/**
* @tc.name: ExecDataLoadCallback001
* @tc.desc: Test Execute data load callback after registering callback
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(UdmfDelayDataContainerTest, ExecDataLoadCallback001, TestSize.Level1)
{
    DelayDataPrepareContainer::GetInstance().dataLoadCallback_.clear();
    std::string key = "udmf://drag/com.example.app/1233455";
    sptr<IRemoteObject> re = nullptr;
    sptr<UdmfNotifierProxy> callback = new (std::nothrow) UdmfNotifierProxy(re);
    DelayDataPrepareContainer::GetInstance().RegisterDataLoadCallback(key, callback);

    QueryOption query;
    query.key = key;
    UnifiedData data;
    auto ret = DelayDataPrepareContainer::GetInstance().HandleDelayLoad(query, data);
    EXPECT_EQ(ret, DelayLoadStatus::WAITING);
    DataLoadInfo info;
    auto execRet = DelayDataPrepareContainer::GetInstance().ExecDataLoadCallback(query.key, info);
    EXPECT_EQ(execRet, true);
    DelayDataPrepareContainer::GetInstance().dataLoadCallback_.clear();
}

/**
* @tc.name: ExecDataLoadCallback002
* @tc.desc: Test Execute data load callback after registering callback
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(UdmfDelayDataContainerTest, ExecDataLoadCallback002, TestSize.Level1)
{
    DelayDataPrepareContainer::GetInstance().dataLoadCallback_.clear();
    std::string key = "udmf://drag/com.example.app/1233455";
    sptr<IRemoteObject> re = nullptr;
    sptr<UdmfNotifierProxy> callback = new (std::nothrow) UdmfNotifierProxy(re);
    DelayDataPrepareContainer::GetInstance().RegisterDataLoadCallback(key, callback);
    EXPECT_TRUE(DelayDataPrepareContainer::GetInstance().dataLoadCallback_.size() == 1);
    EXPECT_NO_FATAL_FAILURE(DelayDataPrepareContainer::GetInstance().ExecAllDataLoadCallback());
    EXPECT_EQ(DelayDataPrepareContainer::GetInstance().QueryDataLoadCallbackSize(), 1);
    DelayDataPrepareContainer::GetInstance().dataLoadCallback_.clear();
}

/**
* @tc.name: ExecDataLoadCallback003
* @tc.desc: Test Execute data load callback after registering callback
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(UdmfDelayDataContainerTest, ExecDataLoadCallback003, TestSize.Level1)
{
    DelayDataPrepareContainer::GetInstance().dataLoadCallback_.clear();
    std::string key = "udmf://drag/com.example.app/1233455";
    DelayDataPrepareContainer::GetInstance().dataLoadCallback_.insert_or_assign(key, nullptr);
    EXPECT_NO_FATAL_FAILURE(DelayDataPrepareContainer::GetInstance().ExecAllDataLoadCallback());
    EXPECT_TRUE(DelayDataPrepareContainer::GetInstance().dataLoadCallback_.empty());
    DelayDataPrepareContainer::GetInstance().dataLoadCallback_.clear();
}

/**
* @tc.name: RegisterDelayDataCallback001
* @tc.desc: Test RegisterDelayDataCallback
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(UdmfDelayDataContainerTest, RegisterDelayDataCallback001, TestSize.Level1)
{
    DelayDataAcquireContainer::GetInstance().delayDataCallback_.clear();
    EXPECT_TRUE(DelayDataAcquireContainer::GetInstance().delayDataCallback_.empty());
    std::string key = "";
    DelayGetDataInfo info;
    DelayDataAcquireContainer::GetInstance().RegisterDelayDataCallback(key, info);
    EXPECT_TRUE(DelayDataAcquireContainer::GetInstance().delayDataCallback_.empty());
    key = "udmf://drag/com.example.app/1233455";
    info.tokenId = 12345;
    DelayDataAcquireContainer::GetInstance().RegisterDelayDataCallback(key, info);
    EXPECT_TRUE(DelayDataAcquireContainer::GetInstance().delayDataCallback_.size() == 1);
    EXPECT_EQ(DelayDataAcquireContainer::GetInstance().delayDataCallback_.at(key).info.tokenId, 12345);

    info.tokenId = 23456;
    DelayDataAcquireContainer::GetInstance().RegisterDelayDataCallback(key, info);
    EXPECT_EQ(DelayDataAcquireContainer::GetInstance().delayDataCallback_.at(key).info.tokenId, 12345);

    info.tokenId = 12345;
    DelayDataAcquireContainer::GetInstance().RegisterDelayDataCallback(key, info);
    EXPECT_EQ(DelayDataAcquireContainer::GetInstance().delayDataCallback_.at(key).info.tokenId, 12345);

    DelayDataAcquireContainer::GetInstance().delayDataCallback_.clear();
}

/**
* @tc.name: HandleDelayDataCallback001
* @tc.desc: Test HandleDelayDataCallback
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(UdmfDelayDataContainerTest, HandleDelayDataCallback001, TestSize.Level1)
{
    DelayDataAcquireContainer::GetInstance().delayDataCallback_.clear();
    EXPECT_TRUE(DelayDataAcquireContainer::GetInstance().delayDataCallback_.empty());
    std::string key = "udmf://drag/com.example.app/1233455";
    UnifiedData data;
    auto ret = DelayDataAcquireContainer::GetInstance().HandleDelayDataCallback(key, data);
    EXPECT_FALSE(ret);
    DelayGetDataInfo getDataInfo;
    DelayDataAcquireContainer::GetInstance().RegisterDelayDataCallback(key, getDataInfo);
    ret = DelayDataAcquireContainer::GetInstance().HandleDelayDataCallback(key, data);
    EXPECT_FALSE(ret);

    DelayDataAcquireContainer::GetInstance().delayDataCallback_.clear();
}

/**
* @tc.name: QueryDelayGetDataInfo001
* @tc.desc: Test RegisterDelayDataCallback
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(UdmfDelayDataContainerTest, QueryDelayGetDataInfo001, TestSize.Level1)
{
    DelayDataAcquireContainer::GetInstance().delayDataCallback_.clear();
    EXPECT_TRUE(DelayDataAcquireContainer::GetInstance().delayDataCallback_.empty());
    std::string key = "udmf://drag/com.example.app/1233455";
    DelayGetDataInfo getDataInfo;
    auto ret = DelayDataAcquireContainer::GetInstance().QueryDelayGetDataInfo(key, getDataInfo);
    EXPECT_EQ(ret, false);
    DelayGetDataInfo info;
    info.tokenId = 12345;
    DelayDataAcquireContainer::GetInstance().RegisterDelayDataCallback(key, info);
    ret = DelayDataAcquireContainer::GetInstance().QueryDelayGetDataInfo(key, getDataInfo);
    EXPECT_EQ(getDataInfo.tokenId, 12345);
    EXPECT_TRUE(ret);
    DelayDataAcquireContainer::GetInstance().delayDataCallback_.clear();
}

/**
* @tc.name: QueryAllDelayKeys001
* @tc.desc: Test QueryAllDelayKeys
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(UdmfDelayDataContainerTest, QueryAllDelayKeys001, TestSize.Level1)
{
    DelayDataAcquireContainer::GetInstance().delayDataCallback_.clear();
    EXPECT_TRUE(DelayDataAcquireContainer::GetInstance().delayDataCallback_.empty());
    DelayDataAcquireContainer::GetInstance().delayDataCallback_.insert_or_assign(
        "key1", DelayDataAcquireContainer::Request());
    DelayDataAcquireContainer::GetInstance().delayDataCallback_.insert_or_assign(
        "", DelayDataAcquireContainer::Request());
    DelayDataAcquireContainer::GetInstance().delayDataCallback_.insert_or_assign(
        "key2", DelayDataAcquireContainer::Request());
    auto keys = DelayDataAcquireContainer::GetInstance().QueryAllDelayKeys();
    EXPECT_TRUE(keys.size() == 2);
    EXPECT_TRUE(std::find(keys.begin(), keys.end(), "key1") != keys.end());
    DelayDataAcquireContainer::GetInstance().delayDataCallback_.clear();
}

/**
* @tc.name: QueryBlockDelayData001
* @tc.desc: Test QueryBlockDelayData
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(UdmfDelayDataContainerTest, QueryBlockDelayData001, TestSize.Level1)
{
    DelayDataPrepareContainer::GetInstance().blockDelayDataCache_.clear();
    std::shared_ptr<BlockData<std::optional<DelayDeliveryResult>, std::chrono::milliseconds>> blockData;
    std::string key = "udmf://drag/com.example.app/1233455";
    DelayDataPrepareContainer::GetInstance().blockDelayDataCache_.insert_or_assign(
        key, BlockDelayData{12345, blockData});
    BlockDelayData data;
    auto ret = DelayDataPrepareContainer::GetInstance().QueryBlockDelayData("111", data);
    EXPECT_FALSE(ret);
    ret = DelayDataPrepareContainer::GetInstance().QueryBlockDelayData(key, data);
    EXPECT_TRUE(ret);
    DelayDataPrepareContainer::GetInstance().blockDelayDataCache_.clear();
}

/**
* @tc.name: SaveDelayDragDeviceInfo001
* @tc.desc: Test QueryBlockDelayData
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(UdmfDelayDataContainerTest, SaveDelayDragDeviceInfo001, TestSize.Level1)
{
    SyncedDeviceContainer::GetInstance().pulledDeviceInfo_.clear();
    SyncedDeviceContainer::GetInstance().SaveSyncedDeviceInfo("");
    EXPECT_TRUE(SyncedDeviceContainer::GetInstance().pulledDeviceInfo_.empty());
    std::string deviceId = "deviceId";
    SyncedDeviceContainer::GetInstance().SaveSyncedDeviceInfo(deviceId);
    EXPECT_TRUE(SyncedDeviceContainer::GetInstance().pulledDeviceInfo_.size() == 1);
    std::string deviceId1 = "deviceId1";
    SyncedDeviceContainer::GetInstance().SaveSyncedDeviceInfo(deviceId1);
    EXPECT_TRUE(SyncedDeviceContainer::GetInstance().pulledDeviceInfo_.size() == 2);

    auto devices = SyncedDeviceContainer::GetInstance().QueryDeviceInfo();
    EXPECT_TRUE(devices.size() == 2);
    EXPECT_EQ(devices[0], deviceId);
    SyncedDeviceContainer::GetInstance().pulledDeviceInfo_.clear();
}
} // namespace DistributedDataTest
} // namespace OHOS::Test

namespace OHOS::Test::DistributedDataTest {
/**
 * @tc.name: HandleDelayLoad_ReadPending_RetainsUntilExplicitCompletion
 * @tc.desc: Verify the receiver-side event contract through public interfaces.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfDelayDataContainerTest, HandleDelayLoad_ReadPending_RetainsUntilExplicitCompletion, TestSize.Level1)
{
    auto &container = DelayDataPrepareContainer::GetInstance();
    const std::string key = "auth-delay-pending";
    sptr<IRemoteObject> remote;
    sptr<UdmfNotifierProxy> notifier = new UdmfNotifierProxy(remote);
    container.RegisterDataLoadCallback(key, notifier);
    QueryOption query;
    query.key = key;
    query.tokenId = 41;
    UnifiedData output;
    ASSERT_EQ(container.HandleDelayLoad(query, output), DelayLoadStatus::WAITING);
    BlockDelayData pending;
    ASSERT_TRUE(container.QueryBlockDelayData(key, pending));
    ASSERT_NE(pending.blockData, nullptr);
    UnifiedData payload;
    payload.AddRecord(std::make_shared<UnifiedRecord>());
    pending.blockData->SetValue(DelayDeliveryResult{ payload, E_OK, false });
    ASSERT_EQ(container.HandleDelayLoad(query, output), DelayLoadStatus::DATA_READY);
    EXPECT_EQ(output.GetRecords().size(), 1u);
    EXPECT_TRUE(container.QueryBlockDelayData(key, pending));
    EXPECT_FALSE(container.CompleteDelayLoad(key, 42));
    EXPECT_TRUE(container.QueryBlockDelayData(key, pending));
    EXPECT_TRUE(container.CompleteDelayLoad(key, 41));
    EXPECT_FALSE(container.QueryBlockDelayData(key, pending));
}
/**
 * @tc.name: HandleDelayLoad_DenialOrOversize_PropagatesWithoutPayload
 * @tc.desc: Verify the receiver-side event contract through public interfaces.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfDelayDataContainerTest, HandleDelayLoad_DenialOrOversize_PropagatesWithoutPayload, TestSize.Level1)
{
    auto &container = DelayDataPrepareContainer::GetInstance();
    const std::string key = "auth-delay-failure";
    sptr<IRemoteObject> remote;
    sptr<UdmfNotifierProxy> notifier = new UdmfNotifierProxy(remote);
    container.RegisterDataLoadCallback(key, notifier);
    QueryOption query;
    query.key = key;
    query.tokenId = 43;
    UnifiedData output;
    ASSERT_EQ(container.HandleDelayLoad(query, output), DelayLoadStatus::WAITING);
    BlockDelayData pending;
    ASSERT_TRUE(container.QueryBlockDelayData(key, pending));
    for (auto status : { E_NO_PERMISSION, E_INVALID_PARAMETERS, E_ERROR }) {
        pending.blockData->SetValue(DelayDeliveryResult{ UnifiedData(), status, false });
        auto expected = status == E_NO_PERMISSION        ? DelayLoadStatus::NO_PERMISSION
                        : status == E_INVALID_PARAMETERS ? DelayLoadStatus::INVALID_PARAMETERS
                                                         : DelayLoadStatus::LOAD_ERROR;
        EXPECT_EQ(container.HandleDelayLoad(query, output), expected);
        EXPECT_TRUE(output.IsEmpty());
        EXPECT_TRUE(container.QueryBlockDelayData(key, pending));
    }
    EXPECT_TRUE(container.CompleteDelayLoad(key, 43));
}
/**
 * @tc.name: HandleDelayLoad_RemoteReadPrepared_DoesNotRepeatAuthorization
 * @tc.desc: Verify the receiver-side event contract through public interfaces.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfDelayDataContainerTest, HandleDelayLoad_RemoteReadPrepared_DoesNotRepeatAuthorization, TestSize.Level1)
{
    auto &container = DelayDataPrepareContainer::GetInstance();
    const std::string key = "auth-delay-prepared";
    sptr<IRemoteObject> remote;
    sptr<UdmfNotifierProxy> notifier = new UdmfNotifierProxy(remote);
    container.RegisterDataLoadCallback(key, notifier);
    QueryOption query;
    query.key = key;
    query.tokenId = 44;
    UnifiedData output;
    ASSERT_EQ(container.HandleDelayLoad(query, output), DelayLoadStatus::WAITING);
    BlockDelayData pending;
    ASSERT_TRUE(container.QueryBlockDelayData(key, pending));
    UnifiedData payload;
    payload.AddRecord(std::make_shared<UnifiedRecord>());
    pending.blockData->SetValue(DelayDeliveryResult{ payload, E_OK, true });
    EXPECT_EQ(container.HandleDelayLoad(query, output), DelayLoadStatus::DATA_READY_PREPARED);
    EXPECT_EQ(output.GetRecords().size(), 1u);
    EXPECT_TRUE(container.CompleteDelayLoad(key, 44));
}

/**
 * @tc.name: CompleteDelayLoad_MissingWrongOwnerAndRepeatedCall_AreNonDestructive
 * @tc.desc: Verify public behavior, failure propagation and observable state.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(
    UdmfDelayDataContainerTest, CompleteDelayLoad_MissingWrongOwnerAndRepeatedCall_AreNonDestructive, TestSize.Level1)
{
    auto &container = DelayDataPrepareContainer::GetInstance();
    const std::string key = "auth-tdd-completion-owner";
    EXPECT_FALSE(container.CompleteDelayLoad(key, 73));
    sptr<IRemoteObject> remote;
    container.RegisterDataLoadCallback(key, new UdmfNotifierProxy(remote));
    QueryOption query;
    query.key = key;
    query.tokenId = 73;
    UnifiedData output;
    ASSERT_EQ(container.HandleDelayLoad(query, output), DelayLoadStatus::WAITING);
    BlockDelayData pending;
    ASSERT_TRUE(container.QueryBlockDelayData(key, pending));
    auto sameBlock = pending.blockData;
    EXPECT_FALSE(container.CompleteDelayLoad(key, 74));
    ASSERT_TRUE(container.QueryBlockDelayData(key, pending));
    EXPECT_EQ(pending.tokenId, 73u);
    EXPECT_EQ(pending.blockData, sameBlock);
    EXPECT_TRUE(container.CompleteDelayLoad(key, 73));
    EXPECT_FALSE(container.QueryBlockDelayData(key, pending));
    EXPECT_FALSE(container.CompleteDelayLoad(key, 73));
    EXPECT_EQ(container.HandleDelayLoad(query, output), DelayLoadStatus::NOT_DELAY_DATA);
}
/**
 * @tc.name: HandleDelayLoad_AnotherReader_CannotReceiveOrConsumeCompletedPayload
 * @tc.desc: Verify public behavior, failure propagation and observable state.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(
    UdmfDelayDataContainerTest, HandleDelayLoad_AnotherReader_CannotReceiveOrConsumeCompletedPayload, TestSize.Level1)
{
    auto &container = DelayDataPrepareContainer::GetInstance();
    const std::string key = "auth-tdd-reader-isolation";
    sptr<IRemoteObject> remote;
    container.RegisterDataLoadCallback(key, new UdmfNotifierProxy(remote));
    QueryOption owner;
    owner.key = key;
    owner.tokenId = 75;
    UnifiedData output;
    ASSERT_EQ(container.HandleDelayLoad(owner, output), DelayLoadStatus::WAITING);
    BlockDelayData pending;
    ASSERT_TRUE(container.QueryBlockDelayData(key, pending));
    UnifiedData payload;
    payload.AddRecord(std::make_shared<UnifiedRecord>(PLAIN_TEXT, std::string("owner-only")));
    pending.blockData->SetValue(DelayDeliveryResult{ payload, E_OK, false });
    QueryOption other = owner;
    other.tokenId = 76;
    EXPECT_EQ(container.HandleDelayLoad(other, output), DelayLoadStatus::NO_PERMISSION);
    EXPECT_TRUE(output.IsEmpty());
    ASSERT_TRUE(container.QueryBlockDelayData(key, pending));
    EXPECT_EQ(container.HandleDelayLoad(owner, output), DelayLoadStatus::DATA_READY);
    ASSERT_EQ(output.GetRecords().size(), 1u);
    EXPECT_EQ(std::get<std::string>(output.GetRecords()[0]->GetOriginValue()), "owner-only");
    EXPECT_TRUE(container.CompleteDelayLoad(key, owner.tokenId));
}

/**
 * @tc.name: QueryDataLoadCallbackSize_RegistrationDispatchAndMissingKey_AreConsistent
 * @tc.desc: Verify public behavior, failure propagation and observable state.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfDelayDataContainerTest, QueryDataLoadCallbackSize_RegistrationDispatchAndMissingKey_AreConsistent,
    TestSize.Level1)
{
    auto &container = DelayDataPrepareContainer::GetInstance();
    const std::string key = "auth-tdd-callback-count";
    const int baseline = container.QueryDataLoadCallbackSize();
    DataLoadInfo info;
    EXPECT_FALSE(container.ExecDataLoadCallback(key, info));
    sptr<IRemoteObject> remote;
    container.RegisterDataLoadCallback(key, new UdmfNotifierProxy(remote));
    EXPECT_EQ(container.QueryDataLoadCallbackSize(), baseline + 1);
    container.RegisterDataLoadCallback(key, new UdmfNotifierProxy(remote));
    EXPECT_EQ(container.QueryDataLoadCallbackSize(), baseline + 1);
    EXPECT_TRUE(container.ExecDataLoadCallback(key, info));
    EXPECT_EQ(container.QueryDataLoadCallbackSize(), baseline + 1);
    EXPECT_TRUE(container.ExecDataLoadCallback(key, info));
    EXPECT_EQ(container.QueryDataLoadCallbackSize(), baseline + 1);
}

/**
 * @tc.name: ReleaseDelivery_DeniedAttempt_ReloadsAndCannotEraseNewAttempt
 * @tc.desc: Failure drops payload only; retry reloads from source and stale completion is harmless.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfDelayDataContainerTest, ReleaseDelivery_DeniedAttempt_ReloadsAndCannotEraseNewAttempt, TestSize.Level1)
{
    auto &container = DelayDataPrepareContainer::GetInstance();
    const std::string key = "udmf://drag/com.test/release-retry";
    sptr<IRemoteObject> remote;
    ASSERT_TRUE(container.RegisterDataLoadCallback(key, new UdmfNotifierProxy(remote), 17));
    QueryOption query{ .key = key, .tokenId = 19 };
    UnifiedData ignored;
    BlockDelayData first;
    EXPECT_EQ(container.HandleDelayLoad(query, ignored, &first), DelayLoadStatus::WAITING);
    UnifiedData payload;
    payload.AddRecord(std::make_shared<UnifiedRecord>(PLAIN_TEXT, std::string("secret")));
    EXPECT_TRUE(container.StoreDelivery(key, first, { payload, E_OK, false }));
    EXPECT_GT(container.cachedBytes_, 0);
    auto wrongOwner = first;
    ++wrongOwner.tokenId;
    EXPECT_FALSE(container.ReleaseDelivery(key, wrongOwner));
    EXPECT_TRUE(container.ReleaseDelivery(key, first));
    EXPECT_EQ(container.cachedBytes_, 0);
    EXPECT_EQ(container.QueryDataLoadCallbackSize(), 1);
    BlockDelayData retry;
    EXPECT_EQ(container.HandleDelayLoad(query, ignored, &retry), DelayLoadStatus::WAITING);
    EXPECT_NE(first.blockData, retry.blockData);
    EXPECT_FALSE(container.ReleaseDelivery(key, first));
    EXPECT_FALSE(container.CompleteDelayLoad(key, 19, &first));
    EXPECT_FALSE(container.StoreDelivery(key, first, { payload, E_OK, false }));
    EXPECT_TRUE(container.StoreDelivery(key, retry, { payload, E_OK, false }));
    EXPECT_TRUE(container.CompleteDelayLoad(key, 19, &retry));
    EXPECT_EQ(container.cachedBytes_, 0);
    EXPECT_EQ(container.QueryDataLoadCallbackSize(), 0);
}

/**
 * @tc.name: CacheBounds_EntryLimitExpiryAndTokenRemoval_ReclaimResources
 * @tc.desc: Origin registrations have a finite count and lifetime even when receivers abandon requests.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfDelayDataContainerTest, CacheBounds_EntryLimitExpiryAndTokenRemoval_ReclaimResources, TestSize.Level1)
{
    auto &container = DelayDataPrepareContainer::GetInstance();
    sptr<IRemoteObject> remote;
    sptr<IUdmfNotifier> callback = new UdmfNotifierProxy(remote);
    for (size_t i = 0; i < container.MAX_DELAY_ENTRIES; ++i) {
        ASSERT_TRUE(container.RegisterDataLoadCallback("limit-" + std::to_string(i), callback, 17));
    }
    EXPECT_FALSE(container.RegisterDataLoadCallback("overflow", callback, 17));
    EXPECT_EQ(container.QueryDataLoadCallbackSize(), static_cast<int>(container.MAX_DELAY_ENTRIES));
    container.RemoveByToken(18);
    EXPECT_EQ(container.QueryDataLoadCallbackSize(), static_cast<int>(container.MAX_DELAY_ENTRIES));
    container.PurgeExpired(DelayDataPrepareContainer::Clock::now() + std::chrono::seconds(31));
    EXPECT_EQ(container.QueryDataLoadCallbackSize(), 0);
    EXPECT_TRUE(container.RegisterDataLoadCallback("owner", callback, 17));
    container.RemoveByToken(17);
    EXPECT_EQ(container.QueryDataLoadCallbackSize(), 0);
    EXPECT_TRUE(container.RegisterDataLoadCallback("cancelled", callback, 17));
    container.Remove("cancelled");
    EXPECT_EQ(container.QueryDataLoadCallbackSize(), 0);
}

/**
 * @tc.name: StoreDelivery_AggregateByteBudget_RejectsAndReclaims
 * @tc.desc: Receiver delivery is empty on capacity failure and overwriting a result releases its old byte charge.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfDelayDataContainerTest, StoreDelivery_AggregateByteBudget_RejectsAndReclaims, TestSize.Level1)
{
    auto &container = DelayDataPrepareContainer::GetInstance();
    sptr<IRemoteObject> remote;
    const std::string key = "budget";
    ASSERT_TRUE(container.RegisterDataLoadCallback(key, new UdmfNotifierProxy(remote), 17));
    QueryOption query{ .key = key, .tokenId = 19 };
    UnifiedData output;
    BlockDelayData pending;
    EXPECT_EQ(container.HandleDelayLoad(query, output, &pending), DelayLoadStatus::WAITING);
    UnifiedData payload;
    payload.AddRecord(std::make_shared<UnifiedRecord>(PLAIN_TEXT, std::string("content")));
    class SizedRecord final : public UnifiedRecord {
    public:
        int64_t GetSize() override
        {
            return UnifiedData::MAX_DATA_SIZE;
        }
    };
    const std::string otherKey = "full-budget";
    ASSERT_TRUE(container.RegisterDataLoadCallback(otherKey, new UdmfNotifierProxy(remote), 18));
    QueryOption otherQuery{ .key = otherKey, .tokenId = 20 };
    BlockDelayData other;
    EXPECT_EQ(container.HandleDelayLoad(otherQuery, output, &other), DelayLoadStatus::WAITING);
    UnifiedData full;
    full.AddRecord(std::make_shared<SizedRecord>());
    ASSERT_TRUE(container.StoreDelivery(otherKey, other, { full, E_OK, false }));
    EXPECT_FALSE(container.StoreDelivery(key, pending, { payload, E_OK, false }));
    EXPECT_EQ(container.HandleDelayLoad(query, output), DelayLoadStatus::LOAD_ERROR);
    EXPECT_TRUE(output.IsEmpty());
    container.Remove(otherKey);
    EXPECT_TRUE(container.StoreDelivery(key, pending, { payload, E_OK, false }));
    EXPECT_EQ(container.cachedBytes_, payload.GetSize());
    EXPECT_TRUE(container.StoreDelivery(key, pending, { UnifiedData(), E_NO_PERMISSION, false }));
    EXPECT_EQ(container.cachedBytes_, 0);
    container.RemoveByToken(19);
    EXPECT_FALSE(container.QueryBlockDelayData(key, pending));
    EXPECT_EQ(container.QueryDataLoadCallbackSize(), 0);
}

/**
 * @tc.name: BindExecutor_RebindAndUnbind_ReleaseOldExecutor
 * @tc.desc: Cleanup scheduling uses the supplied executor and does not retain retired thread pools.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfDelayDataContainerTest, BindExecutor_RebindAndUnbind_ReleaseOldExecutor, TestSize.Level1)
{
    auto &container = DelayDataPrepareContainer::GetInstance();
    auto first = std::make_shared<ExecutorPool>(1, 0);
    auto second = std::make_shared<ExecutorPool>(1, 0);
    std::weak_ptr<ExecutorPool> old = first;
    container.BindExecutor(first);
    container.BindExecutor(first);
    container.BindExecutor(second);
    first.reset();
    EXPECT_TRUE(old.expired());
    old = second;
    container.BindExecutor(nullptr);
    second.reset();
    EXPECT_TRUE(old.expired());
}

/**
 * @tc.name: StoreDelivery_MissingWrongOwnerAndInvalidSize_DoNotDeliver
 * @tc.desc: Invalid writers cannot overwrite another receiver and invalid measured sizes fail empty.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfDelayDataContainerTest, StoreDelivery_MissingWrongOwnerAndInvalidSize_DoNotDeliver, TestSize.Level1)
{
    auto &container = DelayDataPrepareContainer::GetInstance();
    BlockDelayData pending;
    EXPECT_FALSE(container.StoreDelivery("missing", pending, {}));
    sptr<IRemoteObject> remote;
    ASSERT_TRUE(container.RegisterDataLoadCallback("owner", new UdmfNotifierProxy(remote), 17));
    QueryOption query{ .key = "owner", .tokenId = 19 };
    UnifiedData output;
    EXPECT_EQ(container.HandleDelayLoad(query, output, &pending), DelayLoadStatus::WAITING);
    auto wrong = pending;
    ++wrong.tokenId;
    EXPECT_FALSE(container.StoreDelivery("owner", wrong, {}));
    container.RemoveByToken(20);
    BlockDelayData retained;
    EXPECT_TRUE(container.QueryBlockDelayData("owner", retained));
    EXPECT_EQ(retained.blockData, pending.blockData);
    class InvalidSizeRecord final : public UnifiedRecord {
    public:
        int64_t GetSize() override
        {
            return -1;
        }
    };
    UnifiedData invalid;
    invalid.AddRecord(std::make_shared<InvalidSizeRecord>());
    EXPECT_FALSE(container.StoreDelivery("owner", pending, { invalid, E_OK, false }));
    EXPECT_EQ(container.HandleDelayLoad(query, output), DelayLoadStatus::LOAD_ERROR);
    EXPECT_TRUE(output.IsEmpty());
}

/**
 * @tc.name: ExecDataLoadCallback_ReceiverFailure_RetainsOriginForRetry
 * @tc.desc: Dispatching source work must not consume the registration before receiver authorization.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfDelayDataContainerTest, ExecDataLoadCallback_ReceiverFailure_RetainsOriginForRetry, TestSize.Level1)
{
    auto &container = DelayDataPrepareContainer::GetInstance();
    const std::string key = "udmf://drag/com.test/async-retry";
    sptr<IRemoteObject> remote;
    ASSERT_TRUE(container.RegisterDataLoadCallback(key, new UdmfNotifierProxy(remote), 17));
    EXPECT_TRUE(container.ExecDataLoadCallback(key, DataLoadInfo()));
    EXPECT_EQ(container.QueryDataLoadCallbackSize(), 1);
    EXPECT_TRUE(container.ExecDataLoadCallback(key, DataLoadInfo()));
    EXPECT_EQ(container.QueryDataLoadCallbackSize(), 1);
}

class CountingDelayOrigin final : public IRemoteStub<IUdmfNotifier> {
public:
    void HandleDelayObserver(const std::string &, const DataLoadInfo &) override
    {
        ++calls;
    }
    int calls = 0;
};

/**
 * @tc.name: ReleaseDataLoad_RetryAndReplacement_OnlyMatchingAttemptCanFinish
 * @tc.desc: Duplicate source requests coalesce; failed receivers can reload without stale cleanup.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfDelayDataContainerTest, ReleaseDataLoad_RetryAndReplacement_OnlyMatchingAttemptCanFinish, TestSize.Level1)
{
    auto &container = DelayDataPrepareContainer::GetInstance();
    sptr<CountingDelayOrigin> origin = new CountingDelayOrigin();
    const std::string key = "load-attempt-identity";
    ASSERT_TRUE(container.RegisterDataLoadCallback(key, origin, 17));
    ASSERT_TRUE(container.ExecDataLoadCallback(key, DataLoadInfo(), 10));
    DelayDataPrepareContainer::LoadToken first;
    ASSERT_TRUE(container.QueryDataLoadToken(key, first));
    EXPECT_TRUE(container.ExecDataLoadCallback(key, DataLoadInfo(), 10));
    EXPECT_EQ(origin->calls, 1);
    EXPECT_TRUE(container.ReleaseDataLoad(key, first));
    EXPECT_TRUE(container.ExecDataLoadCallback(key, DataLoadInfo(), 10));
    EXPECT_EQ(origin->calls, 2);
    DelayDataPrepareContainer::LoadToken retry;
    ASSERT_TRUE(container.QueryDataLoadToken(key, retry));
    EXPECT_NE(first.loadId, retry.loadId);
    EXPECT_FALSE(container.CompleteDataLoad(key, first));
    EXPECT_FALSE(container.ReleaseDataLoad(key, first));
    EXPECT_TRUE(container.ExecDataLoadCallback(key, DataLoadInfo(), 11));
    EXPECT_EQ(origin->calls, 3);
    EXPECT_FALSE(container.CompleteDataLoad(key, retry));
    ASSERT_TRUE(container.QueryDataLoadToken(key, retry));
    EXPECT_TRUE(container.CompleteDataLoad(key, retry));
    EXPECT_EQ(container.QueryDataLoadCallbackSize(), 0);
}

/**
 * @tc.name: CompleteDataLoad_CompletedAndFailedRegistrations_ReleaseCapacity
 * @tc.desc: Finishing work returns its slot immediately rather than imposing a 30-second rate limit.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfDelayDataContainerTest, CompleteDataLoad_CompletedAndFailedRegistrations_ReleaseCapacity, TestSize.Level1)
{
    auto &container = DelayDataPrepareContainer::GetInstance();
    sptr<CountingDelayOrigin> origin = new CountingDelayOrigin();
    constexpr size_t ENTRY_LIMIT = 128;
    for (size_t i = 0; i < ENTRY_LIMIT + 1; ++i) {
        const auto key = "completed-async-" + std::to_string(i);
        DelayDataPrepareContainer::LoadToken token;
        ASSERT_TRUE(container.RegisterDataLoadCallback(key, origin, 17, &token));
        if (i % 2 == 0) {
            ASSERT_TRUE(container.ExecDataLoadCallback(key, DataLoadInfo()));
            ASSERT_TRUE(container.QueryDataLoadToken(key, token));
        }
        EXPECT_TRUE(container.CompleteDataLoad(key, token));
        EXPECT_EQ(container.QueryDataLoadCallbackSize(), 0);
    }
    EXPECT_EQ(origin->calls, static_cast<int>(ENTRY_LIMIT / 2 + 1));
    EXPECT_TRUE(container.RegisterDataLoadCallback("after-completion", origin, 17));
}

/**
 * @tc.name: CompleteDataLoad_RegistrationReplacedOrExpired_DoesNotEraseNewOrigin
 * @tc.desc: Rollback and late completion compare registration identity even when no BlockData exists.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(
    UdmfDelayDataContainerTest, CompleteDataLoad_RegistrationReplacedOrExpired_DoesNotEraseNewOrigin, TestSize.Level1)
{
    auto &container = DelayDataPrepareContainer::GetInstance();
    sptr<CountingDelayOrigin> origin = new CountingDelayOrigin();
    DelayDataPrepareContainer::LoadToken first;
    EXPECT_FALSE(container.QueryDataLoadToken("missing", first));
    EXPECT_FALSE(container.CompleteDataLoad("missing", first));
    EXPECT_FALSE(container.ReleaseDataLoad("missing", first));
    ASSERT_TRUE(container.RegisterDataLoadCallback("replacement", origin, 17, &first));
    DelayDataPrepareContainer::LoadToken next;
    ASSERT_TRUE(container.RegisterDataLoadCallback("replacement", origin, 17, &next));
    EXPECT_NE(first.generation, next.generation);
    EXPECT_FALSE(container.CompleteDataLoad("replacement", first));
    EXPECT_FALSE(container.ReleaseDataLoad("replacement", first));
    EXPECT_EQ(container.QueryDataLoadCallbackSize(), 1);
    EXPECT_TRUE(container.CompleteDataLoad("replacement", next));
    EXPECT_FALSE(container.CompleteDataLoad("replacement", next));
    ASSERT_TRUE(container.RegisterDataLoadCallback("expired", origin, 17, &first));
    container.PurgeExpired(DelayDataPrepareContainer::Clock::now() + std::chrono::seconds(31));
    EXPECT_FALSE(container.ReleaseDataLoad("expired", first));
    EXPECT_FALSE(container.CompleteDataLoad("expired", first));
}

/**
 * @tc.name: TakeDelayDataCallback_ReusedRemoteAndReplacedReceiver_DropsOldCompletion
 * @tc.desc: A new request remains distinct even when the same native callback object is reused.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfDelayDataContainerTest, TakeDelayDataCallback_ReusedRemoteAndReplacedReceiver_DropsOldCompletion,
    TestSize.Level1)
{
    auto &container = DelayDataAcquireContainer::GetInstance();
    const std::string key = "receiver-generation";
    sptr<CountingDelayOrigin> remote = new CountingDelayOrigin();
    DelayGetDataInfo info{ .tokenId = 19, .dataCallback = remote->AsObject() };
    DelayDataAcquireContainer::Request first;
    ASSERT_TRUE(container.RegisterDelayDataCallback(key, info, &first));
    DelayDataAcquireContainer::Request next;
    ASSERT_TRUE(container.RegisterDelayDataCallback(key, info, &next));
    EXPECT_NE(first.generation, next.generation);
    EXPECT_EQ(container.TakeDelayDataCallback(key, {}), nullptr);
    EXPECT_EQ(container.TakeDelayDataCallback(key, first), nullptr);
    EXPECT_TRUE(container.IsContainDelayData(key));
    auto other = info;
    other.tokenId = 20;
    EXPECT_FALSE(container.RegisterDelayDataCallback(key, other));
    EXPECT_EQ(container.TakeDelayDataCallback(key, next), remote->AsObject());
    EXPECT_FALSE(container.IsContainDelayData(key));
    EXPECT_EQ(container.TakeDelayDataCallback(key, next), nullptr);
    EXPECT_FALSE(container.QueryDelayDataRequest(key, next));
    EXPECT_FALSE(container.RegisterDelayDataCallback("", info));
}

/**
 * @tc.name: ExecAllDataLoadCallback_RepeatedNotifications_CoalesceUntilAttemptReleased
 * @tc.desc: Source work stays retryable while duplicate remote-pull notifications do not dispatch twice.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfDelayDataContainerTest, ExecAllDataLoadCallback_RepeatedNotifications_CoalesceUntilAttemptReleased,
    TestSize.Level1)
{
    auto &container = DelayDataPrepareContainer::GetInstance();
    sptr<CountingDelayOrigin> origin = new CountingDelayOrigin();
    ASSERT_TRUE(container.RegisterDataLoadCallback("remote-pull", origin, 17));
    container.ExecAllDataLoadCallback();
    container.ExecAllDataLoadCallback();
    EXPECT_EQ(origin->calls, 1);
    EXPECT_EQ(container.QueryDataLoadCallbackSize(), 1);
    DelayDataPrepareContainer::LoadToken token;
    ASSERT_TRUE(container.QueryDataLoadToken("remote-pull", token));
    EXPECT_TRUE(container.ReleaseDataLoad("remote-pull", token));
    container.ExecAllDataLoadCallback();
    EXPECT_EQ(origin->calls, 2);
    ASSERT_TRUE(container.QueryDataLoadToken("remote-pull", token));
    EXPECT_TRUE(container.CompleteDataLoad("remote-pull", token));
    EXPECT_EQ(container.QueryDataLoadCallbackSize(), 0);
}

/**
 * @tc.name: CompleteDelayLoad_NewerAsyncFetch_PreservesItsOriginAndLoadingState
 * @tc.desc: An older synchronous completion cannot consume or restart a newer source fetch.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(
    UdmfDelayDataContainerTest, CompleteDelayLoad_NewerAsyncFetch_PreservesItsOriginAndLoadingState, TestSize.Level1)
{
    auto &container = DelayDataPrepareContainer::GetInstance();
    for (bool complete : { false, true }) {
        const std::string key = complete ? "sync-complete" : "sync-release";
        sptr<CountingDelayOrigin> origin = new CountingDelayOrigin();
        ASSERT_TRUE(container.RegisterDataLoadCallback(key, origin, 17));
        UnifiedData output;
        BlockDelayData first;
        QueryOption query{ .key = key, .tokenId = 19 };
        EXPECT_EQ(container.HandleDelayLoad(query, output, &first), DelayLoadStatus::WAITING);
        EXPECT_TRUE(container.ExecDataLoadCallback(key, DataLoadInfo(), 10));
        EXPECT_EQ(origin->calls, 2);
        EXPECT_TRUE(complete ? container.CompleteDelayLoad(key, 19, &first) : container.ReleaseDelivery(key, first));
        EXPECT_EQ(container.QueryDataLoadCallbackSize(), 1);
        EXPECT_TRUE(container.ExecDataLoadCallback(key, DataLoadInfo(), 10));
        EXPECT_EQ(origin->calls, 2);
        DelayDataPrepareContainer::LoadToken current;
        ASSERT_TRUE(container.QueryDataLoadToken(key, current));
        EXPECT_TRUE(container.CompleteDataLoad(key, current));
    }
}

/**
 * @tc.name: CompleteDataLoad_PrefetchOverlapsNewBlockedRead_CannotEraseNewDelivery
 * @tc.desc: A new blocked receiver owns a fresh fetch even while a background fetch is in flight.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfDelayDataContainerTest, CompleteDataLoad_PrefetchOverlapsNewBlockedRead_CannotEraseNewDelivery,
    TestSize.Level1)
{
    auto &container = DelayDataPrepareContainer::GetInstance();
    const std::string key = "prefetch-to-blocked";
    sptr<CountingDelayOrigin> origin = new CountingDelayOrigin();
    ASSERT_TRUE(container.RegisterDataLoadCallback(key, origin, 17));
    EXPECT_TRUE(container.ExecDataLoadCallback(key, DataLoadInfo()));
    DelayDataPrepareContainer::LoadToken prefetch;
    ASSERT_TRUE(container.QueryDataLoadToken(key, prefetch));
    QueryOption query{ .key = key, .tokenId = 19 };
    UnifiedData output;
    BlockDelayData receiver;
    EXPECT_EQ(container.HandleDelayLoad(query, output, &receiver), DelayLoadStatus::WAITING);
    EXPECT_EQ(origin->calls, 2);
    EXPECT_NE(receiver.origin.loadId, prefetch.loadId);
    EXPECT_FALSE(container.CompleteDataLoad(key, prefetch));
    BlockDelayData retained;
    EXPECT_TRUE(container.QueryBlockDelayData(key, retained));
    EXPECT_EQ(retained.blockData, receiver.blockData);
    EXPECT_TRUE(container.CompleteDelayLoad(key, query.tokenId, &receiver));
}

} // namespace OHOS::Test::DistributedDataTest
