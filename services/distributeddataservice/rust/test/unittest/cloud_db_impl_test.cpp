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

#define LOG_TAG "CloudDbImplTest"

#include "cloud_db_impl.h"
#include "extension_util.h"

#include <gtest/gtest.h>

using namespace OHOS;
using namespace OHOS::CloudData;
using namespace OHOS::DistributedData;
using namespace testing::ext;

class CloudDbImplTest : public testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

/**
 * @tc.name: Close_WhenDatabaseIsNull_001
 * @tc.desc: Close on a CloudDbImpl constructed with nullptr should return E_OK and not crash.
 * @tc.type: FUNC
 */
HWTEST_F(CloudDbImplTest, Close_WhenDatabaseIsNull_001, TestSize.Level0)
{
    CloudDbImpl impl(nullptr);
    EXPECT_EQ(impl.Close(), DBErr::E_OK);
}

/**
 * @tc.name: Close_Twice_001
 * @tc.desc: Calling Close twice should not crash or double-free. Second Close returns E_OK.
 * @tc.type: FUNC
 */
HWTEST_F(CloudDbImplTest, Close_Twice_001, TestSize.Level0)
{
    CloudDbImpl impl(nullptr);
    EXPECT_EQ(impl.Close(), DBErr::E_OK);
    EXPECT_EQ(impl.Close(), DBErr::E_OK);
}

/**
 * @tc.name: Execute_WhenDatabaseIsNull_001
 * @tc.desc: Execute on null database should return E_ERROR after mutex protection is added.
 * @tc.type: FUNC
 */
HWTEST_F(CloudDbImplTest, Execute_WhenDatabaseIsNull_001, TestSize.Level0)
{
    CloudDbImpl impl(nullptr);
    DBVBucket extend;
    EXPECT_EQ(impl.Execute("table", "SELECT * FROM table", extend), DBErr::E_ERROR);
}

/**
 * @tc.name: BatchInsert_WhenDatabaseIsNull_001
 * @tc.desc: BatchInsert on null database should return E_ERROR.
 * @tc.type: FUNC
 */
HWTEST_F(CloudDbImplTest, BatchInsert_WhenDatabaseIsNull_001, TestSize.Level0)
{
    CloudDbImpl impl(nullptr);
    DBVBuckets values;
    DBVBuckets extends;
    EXPECT_EQ(impl.BatchInsert("table", std::move(values), extends), DBErr::E_ERROR);
}

/**
 * @tc.name: BatchUpdate_WhenDatabaseIsNull_001
 * @tc.desc: BatchUpdate (mutable extends) on null database should return E_ERROR.
 * @tc.type: FUNC
 */
HWTEST_F(CloudDbImplTest, BatchUpdate_WhenDatabaseIsNull_001, TestSize.Level0)
{
    CloudDbImpl impl(nullptr);
    DBVBuckets values;
    DBVBuckets extends;
    EXPECT_EQ(impl.BatchUpdate("table", std::move(values), extends), DBErr::E_ERROR);
}

/**
 * @tc.name: BatchUpdate_WhenDatabaseIsNull_002
 * @tc.desc: BatchUpdate (const extends) on null database should return E_ERROR.
 * @tc.type: FUNC
 */
HWTEST_F(CloudDbImplTest, BatchUpdate_WhenDatabaseIsNull_002, TestSize.Level0)
{
    CloudDbImpl impl(nullptr);
    DBVBuckets values;
    const DBVBuckets extends;
    EXPECT_EQ(impl.BatchUpdate("table", std::move(values), extends), DBErr::E_ERROR);
}

/**
 * @tc.name: BatchDelete_WhenDatabaseIsNull_001
 * @tc.desc: BatchDelete on null database should return E_ERROR.
 * @tc.type: FUNC
 */
HWTEST_F(CloudDbImplTest, BatchDelete_WhenDatabaseIsNull_001, TestSize.Level0)
{
    CloudDbImpl impl(nullptr);
    DBVBuckets extends;
    EXPECT_EQ(impl.BatchDelete("table", extends), DBErr::E_ERROR);
}

/**
 * @tc.name: Query_WhenDatabaseIsNull_001
 * @tc.desc: Query on null database should return {E_ERROR, nullptr}.
 * @tc.type: FUNC
 */
HWTEST_F(CloudDbImplTest, Query_WhenDatabaseIsNull_001, TestSize.Level0)
{
    CloudDbImpl impl(nullptr);
    DBVBucket extend;
    auto [code, cursor] = impl.Query("table", extend);
    EXPECT_EQ(code, DBErr::E_ERROR);
    EXPECT_EQ(cursor, nullptr);
}

/**
 * @tc.name: Lock_WhenDatabaseIsNull_001
 * @tc.desc: Lock on null database should return E_ERROR.
 * @tc.type: FUNC
 */
HWTEST_F(CloudDbImplTest, Lock_WhenDatabaseIsNull_001, TestSize.Level0)
{
    CloudDbImpl impl(nullptr);
    EXPECT_EQ(impl.Lock(), DBErr::E_ERROR);
}

/**
 * @tc.name: Heartbeat_WhenDatabaseIsNull_001
 * @tc.desc: Heartbeat on null database should return E_ERROR.
 * @tc.type: FUNC
 */
HWTEST_F(CloudDbImplTest, Heartbeat_WhenDatabaseIsNull_001, TestSize.Level0)
{
    CloudDbImpl impl(nullptr);
    EXPECT_EQ(impl.Heartbeat(), DBErr::E_ERROR);
}

/**
 * @tc.name: Unlock_WhenDatabaseIsNull_001
 * @tc.desc: Unlock on null database should return E_ERROR.
 * @tc.type: FUNC
 */
HWTEST_F(CloudDbImplTest, Unlock_WhenDatabaseIsNull_001, TestSize.Level0)
{
    CloudDbImpl impl(nullptr);
    EXPECT_EQ(impl.Unlock(), DBErr::E_ERROR);
}

/**
 * @tc.name: AliveTime_WhenDatabaseIsNull_001
 * @tc.desc: AliveTime on null database should return 0 (initial interval_ value).
 * @tc.type: FUNC
 */
HWTEST_F(CloudDbImplTest, AliveTime_WhenDatabaseIsNull_001, TestSize.Level0)
{
    CloudDbImpl impl(nullptr);
    EXPECT_EQ(impl.AliveTime(), 0);
}

/**
 * @tc.name: MethodsAfterClose_001
 * @tc.desc: After Close, all methods should return E_ERROR (database_ set to nullptr).
 *           This verifies the mutex-protected null check added by the bug2 fix.
 * @tc.type: FUNC
 */
HWTEST_F(CloudDbImplTest, MethodsAfterClose_001, TestSize.Level0)
{
    CloudDbImpl impl(nullptr);
    ASSERT_EQ(impl.Close(), DBErr::E_OK);

    DBVBucket extend;
    EXPECT_EQ(impl.Execute("table", "sql", extend), DBErr::E_ERROR);

    DBVBuckets values;
    DBVBuckets extends;
    EXPECT_EQ(impl.BatchInsert("table", std::move(values), extends), DBErr::E_ERROR);

    EXPECT_EQ(impl.Lock(), DBErr::E_ERROR);
    EXPECT_EQ(impl.Heartbeat(), DBErr::E_ERROR);
    EXPECT_EQ(impl.Unlock(), DBErr::E_ERROR);

    auto [code, cursor] = impl.Query("table", extend);
    EXPECT_EQ(code, DBErr::E_ERROR);
    EXPECT_EQ(cursor, nullptr);
}
