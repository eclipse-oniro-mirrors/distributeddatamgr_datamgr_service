/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <cmath>
#include <gtest/gtest.h>

#include "data_fabric_address_errors.h"
#include "data_fabric_address_test_utils.h"
#include "fakes/navigation_mock.h"
#include "navigation_common_utils.h"
#include "navigation_manager.h"

using namespace OHOS;
using namespace OHOS::DataFabricAddress;
using namespace NativePreferences;
using namespace testing;
using namespace testing::ext;
using DataFabricAddressTest::TestDataFabricAddressCallbackStub;

class DataFabricAddressNavigationManagerTest : public testing::Test {
public:
    void SetUp() override
    {
        auto &manager = NavigationManager::GetInstance();
        manager.state_ = NavigationManager::State::NOT_SUBSCRIBED;
        DataFabricAddressTest::ResetNavigationDataCollectMock();
    }

    void TearDown() override
    {
        auto &manager = NavigationManager::GetInstance();
        manager.state_ = NavigationManager::State::NOT_SUBSCRIBED;
        DataFabricAddressTest::ResetNavigationDataCollectMock();
    }
};

/**
 * @tc.name: DataFabricAddressNavigationManagerTest001
 * @tc.desc: Test subscribe action returns ok when the manager has been subscribed.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressNavigationManagerTest, DataFabricAddressNavigationManagerTest001, TestSize.Level0)
{
    auto &manager = NavigationManager::GetInstance();
    manager.state_ = NavigationManager::State::SUBSCRIBED;
    NativePreferences::LocationPoint homePoint = DataFabricAddressTest::MakeWgs84HomePoint();
    NativePreferences::LocationPoint companyPoint = DataFabricAddressTest::MakeWgs84CompanyPoint();
    sptr<NativePreferences::IDataFabricAddressCallback> callback = new TestDataFabricAddressCallbackStub();
    int32_t result = manager.SubscribeNavigationManager(ActionType::SUBSCRIPTION, homePoint, companyPoint, callback);
    EXPECT_EQ(result, RUN_OK);
}

/**
 * @tc.name: DataFabricAddressNavigationManagerTest002
 * @tc.desc: Test subscribe action with a null callback returns internal error.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressNavigationManagerTest, DataFabricAddressNavigationManagerTest002, TestSize.Level0)
{
    auto &manager = NavigationManager::GetInstance();
    NativePreferences::LocationPoint homePoint = DataFabricAddressTest::MakeWgs84HomePoint();
    NativePreferences::LocationPoint companyPoint = DataFabricAddressTest::MakeWgs84CompanyPoint();
    int32_t result = manager.SubscribeNavigationManager(ActionType::SUBSCRIPTION, homePoint, companyPoint, nullptr);
    EXPECT_EQ(result, INTERNAL_EXCEPTION);
}

/**
 * @tc.name: DataFabricAddressNavigationManagerTest003
 * @tc.desc: Test update action returns abnormal when the manager has not been subscribed.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressNavigationManagerTest, DataFabricAddressNavigationManagerTest003, TestSize.Level0)
{
    auto &manager = NavigationManager::GetInstance();
    NativePreferences::LocationPoint homePoint = DataFabricAddressTest::MakeWgs84HomePoint();
    NativePreferences::LocationPoint companyPoint = DataFabricAddressTest::MakeWgs84CompanyPoint();
    int32_t result = manager.SubscribeNavigationManager(ActionType::UPDATE, homePoint, companyPoint, nullptr);
    EXPECT_EQ(result, ABNORMAL_OPERATION_EXCEPTION);
}

/**
 * @tc.name: DataFabricAddressNavigationManagerTest004
 * @tc.desc: Test update action updates the reference points when subscribed.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressNavigationManagerTest, DataFabricAddressNavigationManagerTest004, TestSize.Level0)
{
    auto &manager = NavigationManager::GetInstance();
    manager.state_ = NavigationManager::State::SUBSCRIBED;
    NativePreferences::LocationPoint homePoint = DataFabricAddressTest::MakeWgs84HomePoint();
    NativePreferences::LocationPoint companyPoint = DataFabricAddressTest::MakeWgs84CompanyPoint();
    int32_t result = manager.SubscribeNavigationManager(ActionType::UPDATE, homePoint, companyPoint, nullptr);
    EXPECT_EQ(result, RUN_OK);
}

/**
 * @tc.name: DataFabricAddressNavigationManagerTest005
 * @tc.desc: Test subscribe action with an invalid action type returns parameter error.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressNavigationManagerTest, DataFabricAddressNavigationManagerTest005, TestSize.Level0)
{
    auto &manager = NavigationManager::GetInstance();
    NativePreferences::LocationPoint homePoint = DataFabricAddressTest::MakeWgs84HomePoint();
    NativePreferences::LocationPoint companyPoint = DataFabricAddressTest::MakeWgs84CompanyPoint();
    int32_t result = manager.SubscribeNavigationManager(static_cast<ActionType>(100),
        homePoint, companyPoint, nullptr);
    EXPECT_EQ(result, PARAMETER_EXCEPTION);
}

/**
 * @tc.name: DataFabricAddressNavigationManagerTest006
 * @tc.desc: Test unsubscribe returns ok when the manager has not been subscribed.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressNavigationManagerTest, DataFabricAddressNavigationManagerTest006, TestSize.Level0)
{
    auto &manager = NavigationManager::GetInstance();
    int32_t result = manager.UnsubscribeNavigationManager();
    EXPECT_EQ(result, RUN_OK);
}

/**
 * @tc.name: DataFabricAddressNavigationManagerTest007
 * @tc.desc: Test unsubscribe resets the subscribed state.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressNavigationManagerTest, DataFabricAddressNavigationManagerTest007, TestSize.Level0)
{
    auto &manager = NavigationManager::GetInstance();
    manager.state_ = NavigationManager::State::SUBSCRIBED;
    int32_t result = manager.UnsubscribeNavigationManager();
    EXPECT_EQ(result, NativePreferences::RUN_OK);
    EXPECT_EQ(manager.state_, NavigationManager::State::NOT_SUBSCRIBED);
}

/**
 * @tc.name: DataFabricAddressNavigationManagerTest008
 * @tc.desc: Test subscribe action subscribes both the live view monitor and the passive location handler.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DataFabricAddressNavigationManagerTest, DataFabricAddressNavigationManagerTest008, TestSize.Level0)
{
    auto &manager = NavigationManager::GetInstance();
    NativePreferences::LocationPoint homePoint = DataFabricAddressTest::MakeWgs84HomePoint();
    NativePreferences::LocationPoint companyPoint = DataFabricAddressTest::MakeWgs84CompanyPoint();
    sptr<NativePreferences::IDataFabricAddressCallback> callback = new TestDataFabricAddressCallbackStub();
    int32_t result = manager.SubscribeNavigationManager(ActionType::SUBSCRIPTION, homePoint, companyPoint, callback);
    EXPECT_EQ(result, RUN_OK);
    EXPECT_EQ(manager.state_, NavigationManager::State::SUBSCRIBED);
    EXPECT_EQ(DataFabricAddressTest::GetLiveViewSubscribeCount(), 1);
    EXPECT_EQ(DataFabricAddressTest::GetPassiveLocationSubscribeCount(), 1);
    NativePreferences::LocationPoint cachedHomePoint;
    NativePreferences::LocationPoint cachedCompanyPoint;
    EXPECT_TRUE(DataFabricAddressTest::GetLastReferenceLocation(cachedHomePoint, cachedCompanyPoint));
    EXPECT_DOUBLE_EQ(cachedHomePoint.latitude, homePoint.latitude);
    EXPECT_DOUBLE_EQ(cachedCompanyPoint.longitude, companyPoint.longitude);
}

/**
 * @tc.name: DataFabricAddressNavigationManagerTest009
 * @tc.desc: Test subscribe action fails when the live view monitor subscription fails.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DataFabricAddressNavigationManagerTest, DataFabricAddressNavigationManagerTest009, TestSize.Level0)
{
    DataFabricAddressTest::SetLiveViewSubscribeResult(INTERNAL_EXCEPTION);
    auto &manager = NavigationManager::GetInstance();
    NativePreferences::LocationPoint homePoint = DataFabricAddressTest::MakeWgs84HomePoint();
    NativePreferences::LocationPoint companyPoint = DataFabricAddressTest::MakeWgs84CompanyPoint();
    sptr<NativePreferences::IDataFabricAddressCallback> callback = new TestDataFabricAddressCallbackStub();
    int32_t result = manager.SubscribeNavigationManager(ActionType::SUBSCRIPTION, homePoint, companyPoint, callback);
    EXPECT_EQ(result, INTERNAL_EXCEPTION);
    EXPECT_EQ(manager.state_, NavigationManager::State::NOT_SUBSCRIBED);
    EXPECT_EQ(DataFabricAddressTest::GetPassiveLocationSubscribeCount(), 0);
}

/**
 * @tc.name: DataFabricAddressNavigationManagerTest010
 * @tc.desc: Test subscribe action fails when the passive location subscription fails.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DataFabricAddressNavigationManagerTest, DataFabricAddressNavigationManagerTest010, TestSize.Level0)
{
    DataFabricAddressTest::SetPassiveLocationSubscribeResult(INTERNAL_EXCEPTION);
    auto &manager = NavigationManager::GetInstance();
    NativePreferences::LocationPoint homePoint = DataFabricAddressTest::MakeWgs84HomePoint();
    NativePreferences::LocationPoint companyPoint = DataFabricAddressTest::MakeWgs84CompanyPoint();
    sptr<NativePreferences::IDataFabricAddressCallback> callback = new TestDataFabricAddressCallbackStub();
    int32_t result = manager.SubscribeNavigationManager(ActionType::SUBSCRIPTION, homePoint, companyPoint, callback);
    EXPECT_EQ(result, INTERNAL_EXCEPTION);
    EXPECT_EQ(manager.state_, NavigationManager::State::NOT_SUBSCRIBED);
    EXPECT_EQ(DataFabricAddressTest::GetLiveViewSubscribeCount(), 1);
    EXPECT_EQ(DataFabricAddressTest::GetPassiveLocationSubscribeCount(), 1);
    // The live view subscription of this action is rolled back.
    EXPECT_EQ(DataFabricAddressTest::GetLiveViewUnsubscribeCount(), 1);
}

/**
 * @tc.name: DataFabricAddressNavigationManagerTest011
 * @tc.desc: Test update action refreshes the reference points of the live view monitor.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DataFabricAddressNavigationManagerTest, DataFabricAddressNavigationManagerTest011, TestSize.Level0)
{
    auto &manager = NavigationManager::GetInstance();
    manager.state_ = NavigationManager::State::SUBSCRIBED;
    NativePreferences::LocationPoint homePoint = { 30.5, 120.5 };
    NativePreferences::LocationPoint companyPoint = { 30.6, 120.6 };
    int32_t result = manager.SubscribeNavigationManager(ActionType::UPDATE, homePoint, companyPoint, nullptr);
    EXPECT_EQ(result, RUN_OK);
    NativePreferences::LocationPoint cachedHomePoint;
    NativePreferences::LocationPoint cachedCompanyPoint;
    EXPECT_TRUE(DataFabricAddressTest::GetLastReferenceLocation(cachedHomePoint, cachedCompanyPoint));
    EXPECT_DOUBLE_EQ(cachedHomePoint.latitude, homePoint.latitude);
    EXPECT_DOUBLE_EQ(cachedHomePoint.longitude, homePoint.longitude);
    EXPECT_DOUBLE_EQ(cachedCompanyPoint.latitude, companyPoint.latitude);
    EXPECT_DOUBLE_EQ(cachedCompanyPoint.longitude, companyPoint.longitude);
}

/**
 * @tc.name: DataFabricAddressNavigationManagerTest012
 * @tc.desc: Test unsubscribe resets the subscribed state when the passive location unsubscription fails but the
 * live view is still torn down.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DataFabricAddressNavigationManagerTest, DataFabricAddressNavigationManagerTest012, TestSize.Level0)
{
    DataFabricAddressTest::SetPassiveLocationUnsubscribeResult(INTERNAL_EXCEPTION);
    auto &manager = NavigationManager::GetInstance();
    manager.state_ = NavigationManager::State::SUBSCRIBED;
    int32_t result = manager.UnsubscribeNavigationManager();
    EXPECT_EQ(result, INTERNAL_EXCEPTION);
    EXPECT_EQ(manager.state_, NavigationManager::State::NOT_SUBSCRIBED);
    EXPECT_EQ(DataFabricAddressTest::GetPassiveLocationUnsubscribeCount(), 1);
    EXPECT_EQ(DataFabricAddressTest::GetLiveViewUnsubscribeCount(), 1);
}

/**
 * @tc.name: DataFabricAddressNavigationManagerTest013
 * @tc.desc: Test unsubscribe resets the subscribed state when the live view unsubscription fails.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DataFabricAddressNavigationManagerTest, DataFabricAddressNavigationManagerTest013, TestSize.Level0)
{
    DataFabricAddressTest::SetLiveViewUnsubscribeResult(INTERNAL_EXCEPTION);
    auto &manager = NavigationManager::GetInstance();
    manager.state_ = NavigationManager::State::SUBSCRIBED;
    int32_t result = manager.UnsubscribeNavigationManager();
    EXPECT_EQ(result, INTERNAL_EXCEPTION);
    EXPECT_EQ(manager.state_, NavigationManager::State::NOT_SUBSCRIBED);
    EXPECT_EQ(DataFabricAddressTest::GetPassiveLocationUnsubscribeCount(), 1);
    EXPECT_EQ(DataFabricAddressTest::GetLiveViewUnsubscribeCount(), 1);
}

/**
 * @tc.name: DataFabricAddressNavigationManagerTest014
 * @tc.desc: Test unsubscribe unsubscribes both the passive location handler and the live view monitor.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DataFabricAddressNavigationManagerTest, DataFabricAddressNavigationManagerTest014, TestSize.Level0)
{
    auto &manager = NavigationManager::GetInstance();
    manager.state_ = NavigationManager::State::SUBSCRIBED;
    int32_t result = manager.UnsubscribeNavigationManager();
    EXPECT_EQ(result, RUN_OK);
    EXPECT_EQ(manager.state_, NavigationManager::State::NOT_SUBSCRIBED);
    EXPECT_EQ(DataFabricAddressTest::GetPassiveLocationUnsubscribeCount(), 1);
    EXPECT_EQ(DataFabricAddressTest::GetLiveViewUnsubscribeCount(), 1);
}

/**
 * @tc.name: DataFabricAddressNavigationManagerTest015
 * @tc.desc: Test subscribe action is idempotent and does not subscribe the dependencies twice.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DataFabricAddressNavigationManagerTest, DataFabricAddressNavigationManagerTest015, TestSize.Level0)
{
    auto &manager = NavigationManager::GetInstance();
    manager.state_ = NavigationManager::State::SUBSCRIBED;
    NativePreferences::LocationPoint homePoint = DataFabricAddressTest::MakeWgs84HomePoint();
    NativePreferences::LocationPoint companyPoint = DataFabricAddressTest::MakeWgs84CompanyPoint();
    sptr<NativePreferences::IDataFabricAddressCallback> callback = new TestDataFabricAddressCallbackStub();
    int32_t result = manager.SubscribeNavigationManager(ActionType::SUBSCRIPTION, homePoint, companyPoint, callback);
    EXPECT_EQ(result, RUN_OK);
    EXPECT_EQ(manager.state_, NavigationManager::State::SUBSCRIBED);
    EXPECT_EQ(DataFabricAddressTest::GetLiveViewSubscribeCount(), 0);
    EXPECT_EQ(DataFabricAddressTest::GetPassiveLocationSubscribeCount(), 0);
}

/**
 * @tc.name: DataFabricAddressNavigationManagerTest016
 * @tc.desc: Test subscribe action still returns internal error when rolling back the live view subscription fails.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DataFabricAddressNavigationManagerTest, DataFabricAddressNavigationManagerTest016, TestSize.Level0)
{
    DataFabricAddressTest::SetPassiveLocationSubscribeResult(INTERNAL_EXCEPTION);
    DataFabricAddressTest::SetLiveViewUnsubscribeResult(INTERNAL_EXCEPTION);
    auto &manager = NavigationManager::GetInstance();
    NativePreferences::LocationPoint homePoint = DataFabricAddressTest::MakeWgs84HomePoint();
    NativePreferences::LocationPoint companyPoint = DataFabricAddressTest::MakeWgs84CompanyPoint();
    sptr<NativePreferences::IDataFabricAddressCallback> callback = new TestDataFabricAddressCallbackStub();
    int32_t result = manager.SubscribeNavigationManager(ActionType::SUBSCRIPTION, homePoint, companyPoint, callback);
    EXPECT_EQ(result, INTERNAL_EXCEPTION);
    EXPECT_EQ(manager.state_, NavigationManager::State::NOT_SUBSCRIBED);
    EXPECT_EQ(DataFabricAddressTest::GetLiveViewSubscribeCount(), 1);
    EXPECT_EQ(DataFabricAddressTest::GetLiveViewUnsubscribeCount(), 1);
}

/**
 * @tc.name: DataFabricAddressNavigationManagerTest017
 * @tc.desc: Test a subscribe action retried after a rollback subscribes the dependencies again.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DataFabricAddressNavigationManagerTest, DataFabricAddressNavigationManagerTest017, TestSize.Level0)
{
    DataFabricAddressTest::SetPassiveLocationSubscribeResult(INTERNAL_EXCEPTION);
    auto &manager = NavigationManager::GetInstance();
    NativePreferences::LocationPoint homePoint = DataFabricAddressTest::MakeWgs84HomePoint();
    NativePreferences::LocationPoint companyPoint = DataFabricAddressTest::MakeWgs84CompanyPoint();
    sptr<NativePreferences::IDataFabricAddressCallback> callback = new TestDataFabricAddressCallbackStub();
    EXPECT_EQ(manager.SubscribeNavigationManager(ActionType::SUBSCRIPTION, homePoint, companyPoint, callback),
        INTERNAL_EXCEPTION);
    EXPECT_EQ(DataFabricAddressTest::GetLiveViewUnsubscribeCount(), 1);

    DataFabricAddressTest::SetPassiveLocationSubscribeResult(RUN_OK);
    EXPECT_EQ(manager.SubscribeNavigationManager(ActionType::SUBSCRIPTION, homePoint, companyPoint, callback),
        RUN_OK);
    EXPECT_EQ(manager.state_, NavigationManager::State::SUBSCRIBED);
    EXPECT_EQ(DataFabricAddressTest::GetLiveViewSubscribeCount(), 2);
    EXPECT_EQ(DataFabricAddressTest::GetPassiveLocationSubscribeCount(), 2);
    EXPECT_EQ(DataFabricAddressTest::GetLiveViewUnsubscribeCount(), 1);
}

/**
 * @tc.name: DataFabricAddressNavigationManagerTest018
 * @tc.desc: Test unsubscribe attempts both dependencies and resets the subscribed state when both unsubscriptions
 * fail.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DataFabricAddressNavigationManagerTest, DataFabricAddressNavigationManagerTest018, TestSize.Level0)
{
    DataFabricAddressTest::SetPassiveLocationUnsubscribeResult(INTERNAL_EXCEPTION);
    DataFabricAddressTest::SetLiveViewUnsubscribeResult(INTERNAL_EXCEPTION);
    auto &manager = NavigationManager::GetInstance();
    manager.state_ = NavigationManager::State::SUBSCRIBED;
    int32_t result = manager.UnsubscribeNavigationManager();
    EXPECT_EQ(result, INTERNAL_EXCEPTION);
    EXPECT_EQ(manager.state_, NavigationManager::State::NOT_SUBSCRIBED);
    EXPECT_EQ(DataFabricAddressTest::GetPassiveLocationUnsubscribeCount(), 1);
    EXPECT_EQ(DataFabricAddressTest::GetLiveViewUnsubscribeCount(), 1);
}

/**
 * @tc.name: DataFabricAddressNavigationManagerTest019
 * @tc.desc: Test unsubscribe can be retried after a partial failure and finally resets the subscribed state.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DataFabricAddressNavigationManagerTest, DataFabricAddressNavigationManagerTest019, TestSize.Level0)
{
    DataFabricAddressTest::SetPassiveLocationUnsubscribeResult(INTERNAL_EXCEPTION);
    auto &manager = NavigationManager::GetInstance();
    manager.state_ = NavigationManager::State::SUBSCRIBED;
    EXPECT_EQ(manager.UnsubscribeNavigationManager(), INTERNAL_EXCEPTION);
    // A partial failure leaves the dependencies inconsistent, so the manager reports itself as not
    // subscribed and the next action rebuilds both dependencies.
    EXPECT_EQ(manager.state_, NavigationManager::State::NOT_SUBSCRIBED);
    EXPECT_EQ(DataFabricAddressTest::GetLiveViewUnsubscribeCount(), 1);

    DataFabricAddressTest::SetPassiveLocationUnsubscribeResult(RUN_OK);
    // The dependencies are retried even though the manager is no longer subscribed.
    EXPECT_EQ(manager.UnsubscribeNavigationManager(), RUN_OK);
    EXPECT_EQ(manager.state_, NavigationManager::State::NOT_SUBSCRIBED);
    EXPECT_EQ(DataFabricAddressTest::GetPassiveLocationUnsubscribeCount(), 2);
    EXPECT_EQ(DataFabricAddressTest::GetLiveViewUnsubscribeCount(), 2);
}

/**
 * @tc.name: DataFabricAddressNavigationManagerTest020
 * @tc.desc: Test subscribe rebuilds both dependencies after a partial unsubscribe failure.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DataFabricAddressNavigationManagerTest, DataFabricAddressNavigationManagerTest020, TestSize.Level0)
{
    DataFabricAddressTest::SetPassiveLocationUnsubscribeResult(INTERNAL_EXCEPTION);
    auto &manager = NavigationManager::GetInstance();
    manager.state_ = NavigationManager::State::SUBSCRIBED;
    EXPECT_EQ(manager.UnsubscribeNavigationManager(), INTERNAL_EXCEPTION);
    EXPECT_EQ(manager.state_, NavigationManager::State::NOT_SUBSCRIBED);

    NativePreferences::LocationPoint homePoint = DataFabricAddressTest::MakeWgs84HomePoint();
    NativePreferences::LocationPoint companyPoint = DataFabricAddressTest::MakeWgs84CompanyPoint();
    sptr<NativePreferences::IDataFabricAddressCallback> callback = new TestDataFabricAddressCallbackStub();
    EXPECT_EQ(manager.SubscribeNavigationManager(ActionType::SUBSCRIPTION, homePoint, companyPoint, callback),
        RUN_OK);
    EXPECT_EQ(manager.state_, NavigationManager::State::SUBSCRIBED);
    EXPECT_EQ(DataFabricAddressTest::GetLiveViewSubscribeCount(), 1);
    EXPECT_EQ(DataFabricAddressTest::GetPassiveLocationSubscribeCount(), 1);
}

/**
 * @tc.name: SubscribeNavigationManager_DependenciesInFlight_ManagerLockNotHeld
 * @tc.desc: Test the dependencies are subscribed while the manager lock is not held and the manager reports the
 * subscribing state meanwhile.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DataFabricAddressNavigationManagerTest, SubscribeNavigationManager_DependenciesInFlight_ManagerLockNotHeld,
    TestSize.Level0)
{
    auto &manager = NavigationManager::GetInstance();
    bool lockAcquired = false;
    bool stateIsSubscribing = false;
    DataFabricAddressTest::SetNavigationDataCollectHook([&manager, &lockAcquired, &stateIsSubscribing]() {
        if (!manager.mutex_.try_lock()) {
            return;
        }
        lockAcquired = true;
        stateIsSubscribing = manager.state_ == NavigationManager::State::SUBSCRIBING;
        manager.mutex_.unlock();
    });
    NativePreferences::LocationPoint homePoint = DataFabricAddressTest::MakeWgs84HomePoint();
    NativePreferences::LocationPoint companyPoint = DataFabricAddressTest::MakeWgs84CompanyPoint();
    sptr<NativePreferences::IDataFabricAddressCallback> callback = new TestDataFabricAddressCallbackStub();
    int32_t result = manager.SubscribeNavigationManager(ActionType::SUBSCRIPTION, homePoint, companyPoint, callback);
    EXPECT_EQ(result, RUN_OK);
    // The hook runs for the live view monitor and for the passive location handler.
    EXPECT_EQ(DataFabricAddressTest::GetNavigationDataCollectHookCallCount(), 2);
    EXPECT_TRUE(lockAcquired);
    EXPECT_TRUE(stateIsSubscribing);
}

/**
 * @tc.name: UnsubscribeNavigationManager_DependenciesInFlight_ManagerLockNotHeld
 * @tc.desc: Test the dependencies are unsubscribed while the manager lock is not held and the manager reports the
 * unsubscribing state meanwhile.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DataFabricAddressNavigationManagerTest, UnsubscribeNavigationManager_DependenciesInFlight_ManagerLockNotHeld,
    TestSize.Level0)
{
    auto &manager = NavigationManager::GetInstance();
    manager.state_ = NavigationManager::State::SUBSCRIBED;
    bool lockAcquired = false;
    bool stateIsUnsubscribing = false;
    DataFabricAddressTest::SetNavigationDataCollectHook([&manager, &lockAcquired, &stateIsUnsubscribing]() {
        if (!manager.mutex_.try_lock()) {
            return;
        }
        lockAcquired = true;
        stateIsUnsubscribing = manager.state_ == NavigationManager::State::UNSUBSCRIBING;
        manager.mutex_.unlock();
    });
    int32_t result = manager.UnsubscribeNavigationManager();
    EXPECT_EQ(result, RUN_OK);
    // The hook runs for the passive location handler and for the live view monitor.
    EXPECT_EQ(DataFabricAddressTest::GetNavigationDataCollectHookCallCount(), 2);
    EXPECT_TRUE(lockAcquired);
    EXPECT_TRUE(stateIsUnsubscribing);
    EXPECT_EQ(manager.state_, NavigationManager::State::NOT_SUBSCRIBED);
}

/**
 * @tc.name: SubscribeNavigationManager_UpdateReferenceLocation_ManagerLockNotHeld
 * @tc.desc: Test the reference points are refreshed while the manager lock is not held.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DataFabricAddressNavigationManagerTest, SubscribeNavigationManager_UpdateReferenceLocation_ManagerLockNotHeld,
    TestSize.Level0)
{
    auto &manager = NavigationManager::GetInstance();
    manager.state_ = NavigationManager::State::SUBSCRIBED;
    bool lockAcquired = false;
    bool stateIsSubscribed = false;
    DataFabricAddressTest::SetNavigationDataCollectHook([&manager, &lockAcquired, &stateIsSubscribed]() {
        if (!manager.mutex_.try_lock()) {
            return;
        }
        lockAcquired = true;
        stateIsSubscribed = manager.state_ == NavigationManager::State::SUBSCRIBED;
        manager.mutex_.unlock();
    });
    NativePreferences::LocationPoint homePoint = DataFabricAddressTest::MakeWgs84HomePoint();
    NativePreferences::LocationPoint companyPoint = DataFabricAddressTest::MakeWgs84CompanyPoint();
    int32_t result = manager.SubscribeNavigationManager(ActionType::UPDATE, homePoint, companyPoint, nullptr);
    EXPECT_EQ(result, RUN_OK);
    EXPECT_EQ(DataFabricAddressTest::GetNavigationDataCollectHookCallCount(), 1);
    EXPECT_TRUE(lockAcquired);
    EXPECT_TRUE(stateIsSubscribed);
}

class DataFabricAddressNavigationCommonUtilTest : public testing::Test {
public:
    void SetUp() override {}
    void TearDown() override {}
};

/**
 * @tc.name: DataFabricAddressNavigationCommonUtilTest001
 * @tc.desc: Test GetDistance with an invalid source latitude.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressNavigationCommonUtilTest, DataFabricAddressNavigationCommonUtilTest001, TestSize.Level0)
{
    NativePreferences::LocationPoint invalidPoint { 91.0, 121.0 };
    NativePreferences::LocationPoint validPoint = DataFabricAddressTest::MakeWgs84HomePoint();
    double distance = 0.0;
    EXPECT_FALSE(NavigationCommonUtil::GetDistance(invalidPoint, validPoint, distance));
}

/**
 * @tc.name: DataFabricAddressNavigationCommonUtilTest002
 * @tc.desc: Test GetDistance with an invalid target longitude.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressNavigationCommonUtilTest, DataFabricAddressNavigationCommonUtilTest002, TestSize.Level0)
{
    NativePreferences::LocationPoint validPoint = DataFabricAddressTest::MakeWgs84HomePoint();
    NativePreferences::LocationPoint invalidPoint { 31.0, 181.0 };
    double distance = 0.0;
    EXPECT_FALSE(NavigationCommonUtil::GetDistance(validPoint, invalidPoint, distance));
}

/**
 * @tc.name: DataFabricAddressNavigationCommonUtilTest003
 * @tc.desc: Test Gcj02ToWgs84 with an invalid input coordinate.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressNavigationCommonUtilTest, DataFabricAddressNavigationCommonUtilTest003, TestSize.Level0)
{
    NativePreferences::LocationPoint invalidPoint { 100.0, 121.0 };
    NativePreferences::LocationPoint outputPoint;
    EXPECT_FALSE(NavigationCommonUtil::Gcj02ToWgs84(invalidPoint, outputPoint));
}

/**
 * @tc.name: DataFabricAddressNavigationCommonUtilTest004
 * @tc.desc: Test Gcj02ToWgs84 with a valid input coordinate.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressNavigationCommonUtilTest, DataFabricAddressNavigationCommonUtilTest004, TestSize.Level0)
{
    NativePreferences::LocationPoint gcj02Point = DataFabricAddressTest::MakeWgs84HomePoint();
    NativePreferences::LocationPoint wgs84Point;
    EXPECT_TRUE(NavigationCommonUtil::Gcj02ToWgs84(gcj02Point, wgs84Point));
    EXPECT_TRUE(std::isfinite(wgs84Point.latitude));
    EXPECT_TRUE(std::isfinite(wgs84Point.longitude));
    EXPECT_GT(std::abs(wgs84Point.latitude - gcj02Point.latitude), 1e-6);
    EXPECT_NE(wgs84Point.longitude, gcj02Point.longitude);
}

/**
 * @tc.name: DataFabricAddressNavigationCommonUtilTest005
 * @tc.desc: Test TransformLat returns a finite offset value.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressNavigationCommonUtilTest, DataFabricAddressNavigationCommonUtilTest005, TestSize.Level0)
{
    double offset = NavigationCommonUtil::TransformLat(121.4737, 31.2304);
    double originOffset = NavigationCommonUtil::TransformLat(0.0, 0.0);
    EXPECT_TRUE(std::isfinite(offset));
    EXPECT_TRUE(std::isfinite(originOffset));
    EXPECT_NE(offset, originOffset);
    EXPECT_GT(std::abs(offset), std::abs(originOffset));
}

/**
 * @tc.name: DataFabricAddressNavigationCommonUtilTest006
 * @tc.desc: Test TransformLng returns a finite offset value.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressNavigationCommonUtilTest, DataFabricAddressNavigationCommonUtilTest006, TestSize.Level0)
{
    double offset = NavigationCommonUtil::TransformLng(121.4737, 31.2304);
    double originOffset = NavigationCommonUtil::TransformLng(0.0, 0.0);
    EXPECT_TRUE(std::isfinite(offset));
    EXPECT_TRUE(std::isfinite(originOffset));
    EXPECT_NE(offset, originOffset);
    EXPECT_GT(std::abs(offset), std::abs(originOffset));
}

/**
 * @tc.name: DataFabricAddressNavigationCommonUtilTest007
 * @tc.desc: Test CalculateGcj02Delta produces a non-zero finite delta.
 * @tc.type: FUNC
 */
HWTEST_F(DataFabricAddressNavigationCommonUtilTest, DataFabricAddressNavigationCommonUtilTest007, TestSize.Level0)
{
    double dlng = 0.0;
    double dlat = 0.0;
    NavigationCommonUtil::CalculateGcj02Delta(121.4737, 31.2304, dlng, dlat);
    EXPECT_TRUE(std::isfinite(dlng));
    EXPECT_TRUE(std::isfinite(dlat));
    EXPECT_NE(dlng, 0.0);
    EXPECT_NE(dlat, 0.0);
}

/**
 * @tc.name: DataFabricAddressNavigationCommonUtilTest008
 * @tc.desc: Test GetNowSecondTimestamp returns a positive second timestamp.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DataFabricAddressNavigationCommonUtilTest, DataFabricAddressNavigationCommonUtilTest008, TestSize.Level0)
{
    int64_t firstTimestamp = NavigationCommonUtil::GetNowSecondTimestamp();
    int64_t secondTimestamp = NavigationCommonUtil::GetNowSecondTimestamp();
    EXPECT_GT(firstTimestamp, 0);
    EXPECT_LE(firstTimestamp, secondTimestamp);
}

/**
 * @tc.name: DataFabricAddressNavigationCommonUtilTest010
 * @tc.desc: Test the default distance thresholds of the navigation commute scenario.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DataFabricAddressNavigationCommonUtilTest, DataFabricAddressNavigationCommonUtilTest010, TestSize.Level0)
{
    EXPECT_DOUBLE_EQ(DEFAULT_MIN_SUPPORTED_COMMUTE_DISTANCE, 500.0);
    EXPECT_DOUBLE_EQ(DEFAULT_MAX_NAVIGATION_END_DISTANCE, 2000.0);
    EXPECT_DOUBLE_EQ(DEFAULT_MAX_WAYPOINT_COLLECT_DISTANCE, 2000.0);
}

/**
 * @tc.name: DataFabricAddressNavigationCommonUtilTest011
 * @tc.desc: Test Gcj02ToWgs84 rejects the coordinate whose latitude is too close to the pole.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DataFabricAddressNavigationCommonUtilTest, DataFabricAddressNavigationCommonUtilTest011, TestSize.Level0)
{
    // The cosine of the near-pole latitude collapses the longitude delta divisor.
    NativePreferences::LocationPoint polarPoint { 89.9999999999999, 121.0 };
    NativePreferences::LocationPoint wgs84Point;
    EXPECT_FALSE(NavigationCommonUtil::Gcj02ToWgs84(polarPoint, wgs84Point));
}
