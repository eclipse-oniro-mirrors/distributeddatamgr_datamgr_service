/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#define LOG_TAG "DatashareURIUtilsTest"
#include <gtest/gtest.h>
#include <string>

#include "utils.h"
#include "log_print.h"

namespace OHOS {
namespace DataShare {
using namespace testing::ext;
using namespace OHOS::DataShare;
class DatashareURIUtilsTest : public testing::Test {
public:
    static void SetUpTestCase(void){};
    static void TearDownTestCase(void){};
    void SetUp(){};
    void TearDown(){};
};

HWTEST_F(DatashareURIUtilsTest, GeneralAnonymous_001, TestSize.Level0)
{
    EXPECT_EQ(StringUtils::GeneralAnonymous("DataShareTable"), "Data***able");
}

HWTEST_F(DatashareURIUtilsTest, GeneralAnonymous_002, TestSize.Level0)
{
    EXPECT_EQ(StringUtils::GeneralAnonymous("1bc"), "******");
}

HWTEST_F(DatashareURIUtilsTest, GeneralAnonymous_003, TestSize.Level0)
{
    EXPECT_EQ(StringUtils::GeneralAnonymous("contact"), "cont***");
}

HWTEST_F(DatashareURIUtilsTest, GeneralAnonymous_004, TestSize.Level0)
{
    EXPECT_EQ(StringUtils::GeneralAnonymous("name"), "******");
}

HWTEST_F(DatashareURIUtilsTest, GeneralAnonymous_005, TestSize.Level0)
{
    EXPECT_EQ(StringUtils::GeneralAnonymous(""), "******");
}

HWTEST_F(DatashareURIUtilsTest, GeneralAnonymous_006, TestSize.Level0)
{
    EXPECT_EQ(StringUtils::GeneralAnonymous("store.db"), "stor***");
}

/**
 * @tc.name: GetSystemAbilityId001
 * @tc.desc: Verify the behavior of GetSystemAbilityId for various URI formats
 * @tc.type: FUNC
 * @tc.precon: URIUtils is initialized and ready to process URIs
 * @tc.step:
 *   1. Test with an invalid URI "test", expect INVALID_SA_ID
 *   2. Test with a base URI, expect INVALID_SA_ID
 *   3. Test with a URI missing bundleName, expect INVALID_SA_ID
 *   4. Test with a URI with bundleName but invalid path, expect INVALID_SA_ID
 *   5. Test with a valid URI, expect SAID 123
 *   6. Test with a URI with multiple segments, expect INVALID_SA_ID
 *   7. Test with a URI containing query parameters, expect SAID 123
 * @tc.expect:
 *   1. Return INVALID_SA_ID for invalid or unexpected URI formats
 *   2. Return the correct SAID when URI format is valid and within expected range
 */
HWTEST_F(DatashareURIUtilsTest, GetSystemAbilityId001, TestSize.Level0)
{
    ZLOGI("DatashareURIUtilsTest GetSystemAbilityId001 start");
    int32_t saId = URIUtils::GetSystemAbilityId("test");
    EXPECT_EQ(saId, URIUtils::INVALID_SA_ID);

    saId = URIUtils::GetSystemAbilityId("datashareproxy://");
    EXPECT_EQ(saId, URIUtils::INVALID_SA_ID);

    saId = URIUtils::GetSystemAbilityId("datashare:///SAID=123");
    EXPECT_EQ(saId, URIUtils::INVALID_SA_ID);

    saId = URIUtils::GetSystemAbilityId("datashareproxy://bundleName/SAID=123");
    EXPECT_EQ(saId, URIUtils::INVALID_SA_ID);

    saId = URIUtils::GetSystemAbilityId("datashareproxy://bundleName/SAID=123/xx");
    EXPECT_EQ(saId, 123);

    saId = URIUtils::GetSystemAbilityId("datashareproxy://bundleName/moduleName/SAID=123");
    EXPECT_EQ(saId, URIUtils::INVALID_SA_ID);

    saId = URIUtils::GetSystemAbilityId("datashare:///bundleName/SAID=123/xx?SAID=456");
    EXPECT_EQ(saId, 123);
    ZLOGI("DatashareURIUtilsTest GetSystemAbilityId001 end");
}

/**
 * @tc.name: GetSystemAbilityId002
 * @tc.desc: Verify the behavior of GetSystemAbilityId for edge cases and invalid SAIDs
 * @tc.type: FUNC
 * @tc.precon: URIUtils is initialized and ready to process URIs
 * @tc.step:
 *   1. Test with a URI containing invalid SAID format, expect INVALID_SA_ID
 *   2. Test with a URI containing empty SAID, expect INVALID_SA_ID
 *   3. Test with a URI containing negative SAID, expect INVALID_SA_ID
 *   4. Test with a URI containing lowercase "SAID", expect INVALID_SA_ID
 *   5. Test with a URI containing zero SAID, expect INVALID_SA_ID
 *   6. Test with a URI containing out-of-range SAID, expect INVALID_SA_ID
 *   7. Test with a URI containing non-numeric SAID, expect INVALID_SA_ID
 * @tc.expect:
 *   1. Return INVALID_SA_ID for invalid or unexpected URI formats
 *   2. Handle edge cases such as negative numbers, zero, and non-numeric strings
 */
HWTEST_F(DatashareURIUtilsTest, GetSystemAbilityId002, TestSize.Level0)
{
    ZLOGI("DatashareURIUtilsTest GetSystemAbilityId002 start");
    int32_t saId = URIUtils::GetSystemAbilityId("datashareproxy://bundleName/xxxSAID=123/xx?SAID=456&user=123");
    EXPECT_EQ(saId, URIUtils::INVALID_SA_ID);
    
    saId = URIUtils::GetSystemAbilityId("datashareproxy://bundleName/SAID=/xx");
    EXPECT_EQ(saId, URIUtils::INVALID_SA_ID);
    
    saId = URIUtils::GetSystemAbilityId("datashareproxy://bundleName/SAID=-123/xx");
    EXPECT_EQ(saId, URIUtils::INVALID_SA_ID);

    saId = URIUtils::GetSystemAbilityId("datashareproxy://bundleName/said=12321/xx");
    EXPECT_EQ(saId, URIUtils::INVALID_SA_ID);

    saId = URIUtils::GetSystemAbilityId("datashareproxy://bundleName/SAID=0/xx");
    EXPECT_EQ(saId, URIUtils::INVALID_SA_ID);

    saId = URIUtils::GetSystemAbilityId("datashareproxy://bundleName/SAID=16777215/xx");
    EXPECT_EQ(saId, URIUtils::INVALID_SA_ID);

    saId = URIUtils::GetSystemAbilityId("datashareproxy://bundleName/SAID=167772ddd15/xx");
    EXPECT_EQ(saId, URIUtils::INVALID_SA_ID);
    ZLOGI("DatashareURIUtilsTest GetSystemAbilityId002 end");
}

/**
 * @tc.name: HasUserIdPlaceholder_001
 * @tc.desc: Verify HasUserIdPlaceholder detects the {USERID} placeholder in uri
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DatashareURIUtilsTest, HasUserIdPlaceholder_001, TestSize.Level0)
{
    ZLOGI("DatashareURIUtilsTest HasUserIdPlaceholder_001 start");
    EXPECT_TRUE(URIUtils::HasUserIdPlaceholder(
        "datashareproxy://com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_{USERID}"));
    EXPECT_FALSE(URIUtils::HasUserIdPlaceholder(
        "datashareproxy://com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_100"));
    EXPECT_FALSE(URIUtils::HasUserIdPlaceholder(""));
    // placeholder token is case-sensitive
    EXPECT_FALSE(URIUtils::HasUserIdPlaceholder(
        "datashareproxy://com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_{userid}"));
    ZLOGI("DatashareURIUtilsTest HasUserIdPlaceholder_001 end");
}

/**
 * @tc.name: ReplaceUserIdPlaceholder_001
 * @tc.desc: Verify ReplaceUserIdPlaceholder replaces all occurrences of {USERID} with the user id
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DatashareURIUtilsTest, ReplaceUserIdPlaceholder_001, TestSize.Level0)
{
    ZLOGI("DatashareURIUtilsTest ReplaceUserIdPlaceholder_001 start");
    EXPECT_EQ(URIUtils::ReplaceUserIdPlaceholder(
                  "datashareproxy://com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_{USERID}", 100),
        "datashareproxy://com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_100");
    // replace all occurrences
    EXPECT_EQ(URIUtils::ReplaceUserIdPlaceholder("datashareproxy://test/{USERID}/table_{USERID}", 101),
        "datashareproxy://test/101/table_101");
    // no placeholder, uri unchanged
    EXPECT_EQ(
        URIUtils::ReplaceUserIdPlaceholder("datashareproxy://test/table_100", 101), "datashareproxy://test/table_100");
    ZLOGI("DatashareURIUtilsTest ReplaceUserIdPlaceholder_001 end");
}

/**
 * @tc.name: MatchProxyUri_LiteralExactMatch_001
 * @tc.desc: Verify MatchProxyUri returns true only for exact literal uri match
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DatashareURIUtilsTest, MatchProxyUri_LiteralExactMatch_001, TestSize.Level0)
{
    ZLOGI("DatashareURIUtilsTest MatchProxyUri_LiteralExactMatch_001 start");
    std::vector<int32_t> userIds = { 0, 100, 101 };
    EXPECT_TRUE(URIUtils::MatchProxyUri(
        "datashareproxy://com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_SECURE_100",
        "datashareproxy://com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_SECURE_100", userIds));
    // same prefix but longer request must not match (prefix matching removed)
    EXPECT_FALSE(URIUtils::MatchProxyUri("datashareproxy://com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA",
        "datashareproxy://com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_100", userIds));
    // different table name
    EXPECT_FALSE(URIUtils::MatchProxyUri("datashareproxy://com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA",
        "datashareproxy://com.ohos.settingsdata/entry/settingsdata/SETTINGSDATA", userIds));
    ZLOGI("DatashareURIUtilsTest MatchProxyUri_LiteralExactMatch_001 end");
}

/**
 * @tc.name: MatchProxyUri_CaseVariationNotMatch_001
 * @tc.desc: Verify MatchProxyUri rejects case-variated uri, closing the privilege escalation bypass
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DatashareURIUtilsTest, MatchProxyUri_CaseVariationNotMatch_001, TestSize.Level0)
{
    ZLOGI("DatashareURIUtilsTest MatchProxyUri_CaseVariationNotMatch_001 start");
    std::vector<int32_t> userIds = { 0, 100, 101 };
    // literal secure entry must not match case-variated request
    EXPECT_FALSE(URIUtils::MatchProxyUri(
        "datashareproxy://com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_SECURE_100",
        "datashareproxy://com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_secure_100", userIds));
    // template secure entry must not match case-variated request either
    EXPECT_FALSE(URIUtils::MatchProxyUri(
        "datashareproxy://com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_SECURE_{USERID}",
        "datashareproxy://com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_secure_100", userIds));
    // permissive entry must not match case-variated request (no prefix fallthrough)
    EXPECT_FALSE(
        URIUtils::MatchProxyUri("datashareproxy://com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_{USERID}",
            "datashareproxy://com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_secure_100", userIds));
    ZLOGI("DatashareURIUtilsTest MatchProxyUri_CaseVariationNotMatch_001 end");
}

/**
 * @tc.name: MatchProxyUri_TemplateSubstitution_001
 * @tc.desc: Verify MatchProxyUri matches template uri after substituting each cached user id
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DatashareURIUtilsTest, MatchProxyUri_TemplateSubstitution_001, TestSize.Level0)
{
    ZLOGI("DatashareURIUtilsTest MatchProxyUri_TemplateSubstitution_001 start");
    std::vector<int32_t> userIds = { 0, 100, 101 };
    EXPECT_TRUE(URIUtils::MatchProxyUri(
        "datashareproxy://com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_SECURE_{USERID}",
        "datashareproxy://com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_SECURE_100", userIds));
    EXPECT_TRUE(URIUtils::MatchProxyUri(
        "datashareproxy://com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_SECURE_{USERID}",
        "datashareproxy://com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_SECURE_101", userIds));
    // user 0 is part of the substitution set
    EXPECT_TRUE(
        URIUtils::MatchProxyUri("datashareproxy://com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_{USERID}",
            "datashareproxy://com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_0", userIds));
    ZLOGI("DatashareURIUtilsTest MatchProxyUri_TemplateSubstitution_001 end");
}

/**
 * @tc.name: MatchProxyUri_TemplateUserNotExist_001
 * @tc.desc: Verify MatchProxyUri rejects request whose suffix is not an existing user id
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DatashareURIUtilsTest, MatchProxyUri_TemplateUserNotExist_001, TestSize.Level0)
{
    ZLOGI("DatashareURIUtilsTest MatchProxyUri_TemplateUserNotExist_001 start");
    std::vector<int32_t> userIds = { 0, 100 };
    EXPECT_FALSE(URIUtils::MatchProxyUri(
        "datashareproxy://com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_SECURE_{USERID}",
        "datashareproxy://com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_SECURE_999", userIds));
    // suffix abuse like _100_101 must not match
    EXPECT_FALSE(
        URIUtils::MatchProxyUri("datashareproxy://com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_{USERID}",
            "datashareproxy://com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_100_101", userIds));
    // empty user id cache matches nothing for template entry
    std::vector<int32_t> emptyUsers;
    EXPECT_FALSE(
        URIUtils::MatchProxyUri("datashareproxy://com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_{USERID}",
            "datashareproxy://com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_100", emptyUsers));
    ZLOGI("DatashareURIUtilsTest MatchProxyUri_TemplateUserNotExist_001 end");
}
} // namespace DataShare
} // namespace OHOS