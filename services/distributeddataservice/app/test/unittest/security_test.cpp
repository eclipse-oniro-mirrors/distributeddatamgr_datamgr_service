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

#include "security.h"

#include <gtest/gtest.h>

#include "device_manager_adapter.h"
#include "screen/screen_manager.h"
#include "screen_manager_mock.h"
#include "store/general_store.h"
#include "utils/constant.h"

using namespace testing::ext;
using namespace OHOS::DistributedKv;
using namespace DistributedDB;
using SecurityOption = DistributedDB::SecurityOption;
using DBStatus = DistributedDB::DBStatus;
namespace OHOS::Test {
class SecurityTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

protected:
    static constexpr const char *FILE_TEST_PATH = "/data/test/KvStoreDataServiceTest";
    static constexpr const char *INVALID_FILE_PATH = "/data/test/invalidTest";
    static constexpr const char *DIR_PATH = "/data/test";
};

void SecurityTest::SetUpTestCase(void)
{
}

void SecurityTest::TearDownTestCase(void)
{
}

void SecurityTest::SetUp(void)
{
}

void SecurityTest::TearDown(void)
{
}

/**
 * @tc.name: IsXattrValueValid
 * @tc.desc: Test for IsXattrValueValid value is empty.
 * @tc.type: FUNC
 */
HWTEST_F(SecurityTest, IsXattrValueValid001, TestSize.Level1)
{
    auto security = std::make_shared<DistributedKv::Security>();
    std::string value = "";
    auto res = security->IsXattrValueValid(value);
    EXPECT_EQ(res, false);
}

/**
 * @tc.name: SetSecurityOption001
 * @tc.desc: Test for SetSecurityOption filePath is empty.
 * @tc.type: FUNC
 */
HWTEST_F(SecurityTest, SetSecurityOption001, TestSize.Level1)
{
    auto security = std::make_shared<DistributedKv::Security>();
    std::string filePath;
    SecurityOption option;
    auto res = security->SetSecurityOption(filePath, option);
    EXPECT_EQ(res, DBStatus::INVALID_ARGS);
}

/**
 * @tc.name: SetSecurityOption002
 * @tc.desc: Test for SetSecurityOption filePath is invalid.
 * @tc.type: FUNC
 */
HWTEST_F(SecurityTest, SetSecurityOption002, TestSize.Level1)
{
    auto security = std::make_shared<DistributedKv::Security>();
    std::string filePath = INVALID_FILE_PATH;
    SecurityOption option;
    auto res = security->SetSecurityOption(filePath, option);
    EXPECT_EQ(res, DBStatus::INVALID_ARGS);
}

/**
 * @tc.name: SetSecurityOption003
 * @tc.desc: Test for SetSecurityOption securityLabel is NOT_SET.
 * @tc.type: FUNC
 */
HWTEST_F(SecurityTest, SetSecurityOption003, TestSize.Level1)
{
    auto security = std::make_shared<DistributedKv::Security>();
    std::string filePath = FILE_TEST_PATH;
    SecurityOption option;
    option.securityLabel = NOT_SET;
    auto res = security->SetSecurityOption(filePath, option);
    EXPECT_EQ(res, DBStatus::OK);
}

/**
 * @tc.name: SetSecurityOption004
 * @tc.desc: Test for SetSecurityOption securityLabel is invalid.
 * @tc.type: FUNC
 */
HWTEST_F(SecurityTest, SetSecurityOption004, TestSize.Level1)
{
    auto security = std::make_shared<DistributedKv::Security>();
    std::string filePath = FILE_TEST_PATH;
    SecurityOption option;
    option.securityLabel = INVALID_SEC_LABEL;
    auto res = security->SetSecurityOption(filePath, option);
    EXPECT_EQ(res, DBStatus::INVALID_ARGS);
}

/**
 * @tc.name: SetSecurityOption005
 * @tc.desc: Test for SetSecurityOption securityLabel is normal.
 * @tc.type: FUNC
 */
HWTEST_F(SecurityTest, SetSecurityOption005, TestSize.Level1)
{
    auto security = std::make_shared<DistributedKv::Security>();
    std::string filePath = FILE_TEST_PATH;
    SecurityOption option;
    option.securityLabel = S0;
    auto res = security->SetSecurityOption(filePath, option);
    EXPECT_EQ(res, DBStatus::OK);
}

/**
 * @tc.name: GetSecurityOption001
 * @tc.desc: Test for GetSecurityOption filePath is empty.
 * @tc.type: FUNC
 */
HWTEST_F(SecurityTest, GetSecurityOption001, TestSize.Level1)
{
    auto security = std::make_shared<DistributedKv::Security>();
    std::string filePath;
    SecurityOption option;
    auto res = security->GetSecurityOption(filePath, option);
    EXPECT_EQ(res, DBStatus::INVALID_ARGS);
}

/**
 * @tc.name: GetSecurityOption002
 * @tc.desc: Test for GetSecurityOption DIR_PATH is NOT_SUPPORT.
 * @tc.type: FUNC
 */
HWTEST_F(SecurityTest, GetSecurityOption002, TestSize.Level1)
{
    auto security = std::make_shared<DistributedKv::Security>();
    std::string filePath = DIR_PATH;
    SecurityOption option;
    auto res = security->GetSecurityOption(filePath, option);
    EXPECT_EQ(res, DBStatus::NOT_SUPPORT);
}

/**
 * @tc.name: GetSecurityOption003
 * @tc.desc: Test for GetSecurityOption filePath is invalid.
 * @tc.type: FUNC
 */
HWTEST_F(SecurityTest, GetSecurityOption003, TestSize.Level1)
{
    auto security = std::make_shared<DistributedKv::Security>();
    std::string filePath = INVALID_FILE_PATH;
    SecurityOption option;
    auto res = security->GetSecurityOption(filePath, option);
    EXPECT_EQ(res, DBStatus::OK);
    EXPECT_EQ(option.securityLabel, NOT_SET);
    EXPECT_EQ(option.securityFlag, ECE);
}

/**
 * @tc.name: GetSecurityOption004
 * @tc.desc: Test for GetSecurityOption file of securityLabel is S3.
 * @tc.type: FUNC
 */
HWTEST_F(SecurityTest, GetSecurityOption004, TestSize.Level1)
{
    auto security = std::make_shared<DistributedKv::Security>();
    std::string filePath = FILE_TEST_PATH;
    SecurityOption setOption;
    setOption.securityLabel = S3;
    auto res = security->SetSecurityOption(filePath, setOption);
    EXPECT_EQ(res, DBStatus::OK);
    SecurityOption getOption;
    res = security->GetSecurityOption(filePath, getOption);
    EXPECT_EQ(res, DBStatus::OK);
    EXPECT_EQ(getOption.securityLabel, S3);
    EXPECT_EQ(getOption.securityFlag, SECE);
}

/**
 * @tc.name: Security_IsAccessControlled_PropertyEL4UserLocked_ReturnsTrue
 * @tc.desc: Test that IsAccessControlled with property returns true when the area is EL4 and the
 *           screen of the user in the property is locked, the keys of the store are unloaded
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(SecurityTest, Security_IsAccessControlled_PropertyEL4UserLocked_ReturnsTrue, TestSize.Level1)
{
    auto screenManagerMock = std::make_shared<DistributedData::ScreenManagerMock>();
    EXPECT_CALL(*screenManagerMock, IsLocked(100)).WillOnce(testing::Return(true));
    DistributedData::ScreenManager::RegisterInstance(screenManagerMock);

    auto security = std::make_shared<DistributedKv::Security>();
    DistributedDB::Property property = {
        { OHOS::DistributedData::Constant::USER_ID, static_cast<uint32_t>(100) },
        { OHOS::DistributedData::Constant::AREA, static_cast<uint32_t>(OHOS::DistributedData::GeneralStore::EL4) },
    };
    EXPECT_TRUE(security->IsAccessControlled(property));

    DistributedData::ScreenManager::RegisterInstance(nullptr);
}

/**
 * @tc.name: Security_IsAccessControlled_PropertyEL4UserUnlocked_ReturnsFalse
 * @tc.desc: Test that IsAccessControlled with property returns false when the area is EL4 but the
 *           screen of the user in the property is unlocked
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(SecurityTest, Security_IsAccessControlled_PropertyEL4UserUnlocked_ReturnsFalse, TestSize.Level1)
{
    auto screenManagerMock = std::make_shared<DistributedData::ScreenManagerMock>();
    EXPECT_CALL(*screenManagerMock, IsLocked(100)).WillOnce(testing::Return(false));
    DistributedData::ScreenManager::RegisterInstance(screenManagerMock);

    auto security = std::make_shared<DistributedKv::Security>();
    DistributedDB::Property property = {
        { OHOS::DistributedData::Constant::USER_ID, static_cast<uint32_t>(100) },
        { OHOS::DistributedData::Constant::AREA, static_cast<uint32_t>(OHOS::DistributedData::GeneralStore::EL4) },
    };
    EXPECT_FALSE(security->IsAccessControlled(property));

    DistributedData::ScreenManager::RegisterInstance(nullptr);
}

/**
 * @tc.name: Security_IsAccessControlled_PropertyUserZero_ReturnsFalse
 * @tc.desc: Test that IsAccessControlled with property returns false when the user is 0,
 *           the system user takes no user level lock state
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(SecurityTest, Security_IsAccessControlled_PropertyUserZero_ReturnsFalse, TestSize.Level1)
{
    auto screenManagerMock = std::make_shared<DistributedData::ScreenManagerMock>();
    // the lock state of user 0 must not be queried
    EXPECT_CALL(*screenManagerMock, IsLocked(0)).Times(0);
    DistributedData::ScreenManager::RegisterInstance(screenManagerMock);

    auto security = std::make_shared<DistributedKv::Security>();
    DistributedDB::Property property = {
        { OHOS::DistributedData::Constant::USER_ID, static_cast<uint32_t>(0) },
        { OHOS::DistributedData::Constant::AREA,
            static_cast<uint32_t>(OHOS::DistributedData::GeneralStore::EL4) },
    };
    EXPECT_FALSE(security->IsAccessControlled(property));

    DistributedData::ScreenManager::RegisterInstance(nullptr);
}
/**
 * @tc.name: Security_IsAccessControlled_PropertyNotEL4_ReturnsFalse
 * @tc.desc: Test that IsAccessControlled with property returns false when the area is not EL4,
 *           the keys of the non el4 store are not unloaded with the screen lock
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(SecurityTest, Security_IsAccessControlled_PropertyNotEL4_ReturnsFalse, TestSize.Level1)
{
    auto screenManagerMock = std::make_shared<DistributedData::ScreenManagerMock>();
    EXPECT_CALL(*screenManagerMock, IsLocked(100)).Times(0); // must not be queried for a non el4 area
    DistributedData::ScreenManager::RegisterInstance(screenManagerMock);

    auto security = std::make_shared<DistributedKv::Security>();
    DistributedDB::Property property = {
        { OHOS::DistributedData::Constant::USER_ID, static_cast<uint32_t>(100) },
        { OHOS::DistributedData::Constant::AREA, static_cast<uint32_t>(OHOS::DistributedData::GeneralStore::EL2) },
    };
    EXPECT_FALSE(security->IsAccessControlled(property));

    DistributedData::ScreenManager::RegisterInstance(nullptr);
}

/**
 * @tc.name: Security_IsAccessControlled_PropertyKeysMissing_ReturnsFalse
 * @tc.desc: Test that IsAccessControlled with property returns false when the user or the area is
 *           missing in the property or holds an unexpected type, keep the legacy behavior
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(SecurityTest, Security_IsAccessControlled_PropertyKeysMissing_ReturnsFalse, TestSize.Level1)
{
    auto screenManagerMock = std::make_shared<DistributedData::ScreenManagerMock>();
    DistributedData::ScreenManager::RegisterInstance(screenManagerMock);

    auto security = std::make_shared<DistributedKv::Security>();
    // empty property, nothing is set
    DistributedDB::Property emptyProperty;
    EXPECT_FALSE(security->IsAccessControlled(emptyProperty));

    // only the area is set
    DistributedDB::Property areaOnlyProperty = {
        { OHOS::DistributedData::Constant::AREA, static_cast<uint32_t>(OHOS::DistributedData::GeneralStore::EL4) },
    };
    EXPECT_FALSE(security->IsAccessControlled(areaOnlyProperty));

    // only the user is set
    DistributedDB::Property userOnlyProperty = {
        { OHOS::DistributedData::Constant::USER_ID, static_cast<uint32_t>(100) },
    };
    EXPECT_FALSE(security->IsAccessControlled(userOnlyProperty));

    // the user is not a number, the value type is unexpected
    DistributedDB::Property badTypeProperty = {
        { OHOS::DistributedData::Constant::USER_ID, std::string("100") },
        { OHOS::DistributedData::Constant::AREA, static_cast<uint32_t>(OHOS::DistributedData::GeneralStore::EL4) },
    };
    EXPECT_FALSE(security->IsAccessControlled(badTypeProperty));

    DistributedData::ScreenManager::RegisterInstance(nullptr);
}
} // namespace OHOS::Test