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

#define LOG_TAG "UdmfObserverTest"
#include <chrono>
#include <thread>

#include "gtest/gtest.h"

#include "accesstoken_kit.h"
#include "bootstrap.h"
#include "observer_factory.h"
#include "drag_observer.h"
#include "data_handler.h"
#include "delay_data_acquire_container.h"
#include "device_manager_adapter.h"
#include "ipc_skeleton.h"
#include "iremote_stub.h"
#include "kvstore_meta_manager.h"
#include "lifecycle_manager.h"
#include "log_print.h"
#include "nativetoken_kit.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"
#include "udmf_notifier_proxy.h"
#include "udmf_service_impl.h"


using namespace OHOS::UDMF;
using namespace OHOS::Security::AccessToken;
using namespace testing::ext;
using namespace testing;
namespace OHOS::Test {
namespace DistributedDataTest {
constexpr size_t NUM_MIN = 1;
constexpr size_t NUM_MAX = 3;
constexpr size_t MAX_ENTRIES = 10000;
static void GrantPermissionNative()
{
    const char **perms = new const char *[3];
    perms[0] = "ohos.permission.DISTRIBUTED_DATASYNC";
    perms[1] = "ohos.permission.ACCESS_SERVICE_DM";
    perms[2] = "ohos.permission.MONITOR_DEVICE_NETWORK_STATE"; // perms[2] is a permission parameter
    TokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 3,
        .aclsNum = 0,
        .dcaps = nullptr,
        .perms = perms,
        .acls = nullptr,
        .processName = "distributed_data_test",
        .aplStr = "system_basic",
    };
    uint64_t tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
    AccessTokenKit::ReloadNativeTokenInfo();
    delete[] perms;
}

class UdmfObserverTest : public testing::Test {
public:
    static void SetUpTestCase(void)
    {
        auto executors = std::make_shared<ExecutorPool>(NUM_MAX, NUM_MIN);
        LifeCycleManager::GetInstance().SetThreadPool(executors);
        GrantPermissionNative();
        DistributedData::Bootstrap::GetInstance().LoadComponents();
        DistributedData::Bootstrap::GetInstance().LoadDirectory();
        DistributedData::Bootstrap::GetInstance().LoadCheckers();
        OHOS::DistributedData::DeviceManagerAdapter::GetInstance().Init(executors);
        DistributedKv::KvStoreMetaManager::GetInstance().BindExecutor(executors);
        DistributedKv::KvStoreMetaManager::GetInstance().InitMetaParameter();
        DistributedKv::KvStoreMetaManager::GetInstance().InitMetaListener();
    }
    static void TearDownTestCase(void) {}
    void SetUp()
    {
        savedService_ = UdmfServiceImpl::factory_.product_;
        LifeCycleManager::GetInstance().ClearUdKeys();
    }
    void TearDown()
    {
        auto store = StoreCache::GetInstance().GetStore("drag");
        for (const auto &key : ownedKeys_) {
            if (store != nullptr) {
                store->Delete(UnifiedKey(key).GetKeyCommonPrefix());
            }
        }
        LifeCycleManager::GetInstance().ClearUdKeys();
        DelayDataAcquireContainer::GetInstance().delayDataCallback_.clear();
        UdmfServiceImpl::factory_.product_ = savedService_;
    }

    std::vector<std::string> ownedKeys_;
    std::shared_ptr<UdmfServiceImpl> savedService_;
};

class StoreChangedData : public DistributedDB::KvStoreChangedData {
public:
    const std::list<DistributedDB::Entry> &GetEntriesInserted() const
    {
        return insertedEntries_;
    }

    const std::list<DistributedDB::Entry> &GetEntriesUpdated() const
    {
        return updatedEntries_;
    }

    const std::list<DistributedDB::Entry> &GetEntriesDeleted() const
    {
        return deletedEntries_;
    }

    bool IsCleared() const
    {
        return true;
    }

    std::list<DistributedDB::Entry> insertedEntries_;
    std::list<DistributedDB::Entry> updatedEntries_;
    std::list<DistributedDB::Entry> deletedEntries_;
};

class ObserverDelayCallback final : public IRemoteStub<IDelayDataCallback> {
public:
    void DelayDataCallback(const std::string &, const UnifiedData &data) override
    {
        delivered = data;
        ++calls;
    }

    size_t calls = 0;
    UnifiedData delivered;
};

UnifiedData MakeObserverPayload(uint32_t tokenId, const std::string &groupId)
{
    UnifiedData data;
    Runtime runtime;
    runtime.key = UnifiedKey("drag", "com.example.observer", groupId);
    runtime.tokenId = tokenId;
    runtime.recordTotalNum = 1;
    runtime.privileges = { { tokenId, "", "" } };
    data.SetRuntime(runtime);
    data.AddRecord(std::make_shared<UnifiedRecord>(PLAIN_TEXT, std::string("observer data")));
    return data;
}

StoreChangedData MakeObserverChange(UnifiedData &data)
{
    std::vector<DistributedDB::Entry> entries;
    DataHandler::MarshalToEntries(data, entries);
    StoreChangedData change;
    change.updatedEntries_.assign(entries.begin(), entries.end());
    return change;
}

bool WaitForLifecycleRemoval()
{
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (LifeCycleManager::GetInstance().udKeys_.Size() != 0) {
        if (std::chrono::steady_clock::now() >= deadline) {
            return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return true;
}

/**
* @tc.name: ObserverFactoryTest001
* @tc.desc: Test ObserverFactory with return invalid param
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(UdmfObserverTest, ObserverFactoryTest001, TestSize.Level1)
{
    auto observer = ObserverFactory::GetObserver("data_hub");
    EXPECT_EQ(observer, nullptr);
}

/**
* @tc.name: OnChange_StoredDelayData_DeliversAndRemovesLifecycleKey
* @tc.desc: A real receiver allows delayed delivery and asynchronous consume-on-read cleanup.
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(UdmfObserverTest, OnChange_StoredDelayData_DeliversAndRemovesLifecycleKey, TestSize.Level1)
{
    auto observer = ObserverFactory::GetObserver("drag");
    ASSERT_NE(observer, nullptr);
    auto tokenId = IPCSkeleton::GetSelfTokenID();
    auto data = MakeObserverPayload(tokenId, "11111111111111111111111111111111");
    auto key = data.GetRuntime()->key.GetUnifiedKey();
    ownedKeys_.push_back(key);
    UdmfServiceImpl::factory_.product_ = std::make_shared<UdmfServiceImpl>();
    auto store = StoreCache::GetInstance().GetStore("drag");
    ASSERT_NE(store, nullptr);
    Summary summary;
    ASSERT_EQ(store->Put(data, summary), E_OK);
    sptr<ObserverDelayCallback> callback = new ObserverDelayCallback();
    DelayGetDataInfo delayGetDataInfo;
    delayGetDataInfo.tokenId = tokenId;
    delayGetDataInfo.dataCallback = callback->AsObject();
    ASSERT_TRUE(DelayDataAcquireContainer::GetInstance().RegisterDelayDataCallback(key, delayGetDataInfo));
    auto changedData = MakeObserverChange(data);
    observer->OnChange(changedData);
    EXPECT_EQ(callback->calls, 1u);
    EXPECT_EQ(callback->delivered.GetRecords().size(), 1u);
    EXPECT_TRUE(WaitForLifecycleRemoval());
    EXPECT_FALSE(DelayDataAcquireContainer::GetInstance().IsContainDelayData(key));
}

/**
* @tc.name: OnChange_MissingDelayData_PreservesReceiverAndLifecycleKey
* @tc.desc: A missing stored payload must retain the receiver until data becomes available.
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(UdmfObserverTest, OnChange_MissingDelayData_PreservesReceiverAndLifecycleKey, TestSize.Level1)
{
    auto observer = ObserverFactory::GetObserver("drag");
    ASSERT_NE(observer, nullptr);
    auto data = MakeObserverPayload(123, "22222222222222222222222222222222");
    auto key = data.GetRuntime()->key.GetUnifiedKey();
    ownedKeys_.push_back(key);
    auto store = StoreCache::GetInstance().GetStore("drag");
    ASSERT_NE(store, nullptr);
    ASSERT_EQ(store->Delete(UnifiedKey(key).GetKeyCommonPrefix()), E_OK);
    UdmfServiceImpl::factory_.product_ = std::make_shared<UdmfServiceImpl>();
    sptr<ObserverDelayCallback> callback = new ObserverDelayCallback();
    DelayGetDataInfo delayGetDataInfo;
    delayGetDataInfo.tokenId = 123;
    delayGetDataInfo.dataCallback = callback->AsObject();
    ASSERT_TRUE(DelayDataAcquireContainer::GetInstance().RegisterDelayDataCallback(key, delayGetDataInfo));
    auto changedData = MakeObserverChange(data);
    observer->OnChange(changedData);
    EXPECT_EQ(callback->calls, 0u);
    EXPECT_EQ(LifeCycleManager::GetInstance().udKeys_.Size(), 1u);
    EXPECT_TRUE(LifeCycleManager::GetInstance().udKeys_.Contains(123));
    EXPECT_TRUE(DelayDataAcquireContainer::GetInstance().IsContainDelayData(key));
}

/**
* @tc.name: OnChange_WaitingRuntime_PreservesReceiverWithoutLifecycleEntry
* @tc.desc: A waiting runtime does not trigger delivery before the source data becomes complete.
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(UdmfObserverTest, OnChange_WaitingRuntime_PreservesReceiverWithoutLifecycleEntry, TestSize.Level1)
{
    auto observer = ObserverFactory::GetObserver("drag");
    ASSERT_NE(observer, nullptr);
    auto data = MakeObserverPayload(123, "33333333333333333333333333333333");
    data.GetRuntime()->dataStatus = DataStatus::WAITING;
    auto key = data.GetRuntime()->key.GetUnifiedKey();
    sptr<ObserverDelayCallback> callback = new ObserverDelayCallback();
    DelayGetDataInfo info;
    info.tokenId = 123;
    info.dataCallback = callback->AsObject();
    ASSERT_TRUE(DelayDataAcquireContainer::GetInstance().RegisterDelayDataCallback(key, info));
    auto changedData = MakeObserverChange(data);
    observer->OnChange(changedData);
    EXPECT_EQ(callback->calls, 0u);
    EXPECT_EQ(LifeCycleManager::GetInstance().udKeys_.Size(), 0u);
    EXPECT_TRUE(DelayDataAcquireContainer::GetInstance().IsContainDelayData(key));
}

/**
* @tc.name: DragObserverTest003
* @tc.desc: Test DragObserver with the normal delay data
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(UdmfObserverTest, DragObserverTest003, TestSize.Level1)
{
    auto observer = ObserverFactory::GetObserver("drag");
    EXPECT_NE(observer, nullptr);

    auto record = std::make_shared<UnifiedRecord>();
    record->AddEntry("type1", "value1");
    record->AddEntry("type2", "value2");
    auto properties = std::make_shared<UnifiedDataProperties>();
    UnifiedData data(properties);
    Runtime runtime;
    runtime.key = UnifiedKey("drag", "com.example.test", "22222");
    runtime.tokenId = 123;
    data.SetRuntime(runtime);
    data.SetRecords({record});
    std::vector<DistributedDB::Entry> entries;
    DataHandler::MarshalToEntries(data, entries);

    std::list<DistributedDB::Entry> entriesList(entries.begin(), entries.end());
    StoreChangedData changedData;
    changedData.insertedEntries_ = entriesList;

    EXPECT_EQ(0, LifeCycleManager::GetInstance().udKeys_.Size());
    EXPECT_FALSE(DelayDataAcquireContainer::GetInstance().IsContainDelayData(runtime.key.GetUnifiedKey()));
    EXPECT_NO_FATAL_FAILURE(observer->OnChange(changedData));
    EXPECT_EQ(1, LifeCycleManager::GetInstance().udKeys_.Size());
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    EXPECT_TRUE(LifeCycleManager::GetInstance().udKeys_.Contains(123));
    EXPECT_FALSE(DelayDataAcquireContainer::GetInstance().IsContainDelayData(runtime.key.key));
}

/**
* @tc.name: DragObserverTest004
* @tc.desc: Test DragObserver with the delete data
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(UdmfObserverTest, DragObserverTest004, TestSize.Level1)
{
    auto observer = ObserverFactory::GetObserver("drag");
    EXPECT_NE(observer, nullptr);

    auto record = std::make_shared<UnifiedRecord>();
    record->AddEntry("type1", "value1");
    record->AddEntry("type2", "value2");
    auto properties = std::make_shared<UnifiedDataProperties>();
    UnifiedData data(properties);
    Runtime runtime;
    auto key = UnifiedKey("drag", "com.example.test", "22222");
    key.GetUnifiedKey();
    runtime.key = key;
    runtime.tokenId = 123;
    data.SetRuntime(runtime);
    data.SetRecords({record});
    std::vector<DistributedDB::Entry> entries;
    DataHandler::MarshalToEntries(data, entries);

    std::list<DistributedDB::Entry> entriesList(entries.begin(), entries.end());
    StoreChangedData changedData;
    changedData.deletedEntries_ = entriesList;
    
    LifeCycleManager::GetInstance().InsertUdKey(123, runtime.key.key);
    EXPECT_EQ(1, LifeCycleManager::GetInstance().udKeys_.Size());
    EXPECT_NO_FATAL_FAILURE(observer->OnChange(changedData));
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    EXPECT_EQ(0, LifeCycleManager::GetInstance().udKeys_.Size());
}

/**
* @tc.name: DragObserverTest005
* @tc.desc: Test DragObserver batch processing runtime entries exceeding MAX_RUNTIME_ENTRIES
* @tc.type: FUNC
* @tc.require:
* @tc.author: agent
*/
HWTEST_F(UdmfObserverTest, DragObserverTest005, TestSize.Level1)
{
    auto observer = ObserverFactory::GetObserver("drag");
    EXPECT_NE(observer, nullptr);

    std::list<DistributedDB::Entry> entriesList;
    for (size_t i = 0; i < MAX_ENTRIES + 1; ++i) {
        Runtime runtime;
        runtime.key = UnifiedKey("drag", "com.example.test", std::to_string(i));
        runtime.key.GetUnifiedKey();
        runtime.dataStatus = DataStatus::WORKING;
        runtime.tokenId = static_cast<uint32_t>(i + 1);
        UnifiedData data;
        data.SetRuntime(runtime);
        std::vector<DistributedDB::Entry> entries;
        DataHandler::MarshalToEntries(data, entries);
        entriesList.insert(entriesList.end(), entries.begin(), entries.end());
    }

    StoreChangedData changedData;
    changedData.insertedEntries_ = entriesList;

    observer->OnChange(changedData);
    EXPECT_EQ(LifeCycleManager::GetInstance().udKeys_.Size(), MAX_ENTRIES + 1);
}

} // DistributedDataTest
} // OHOS::UDMF
