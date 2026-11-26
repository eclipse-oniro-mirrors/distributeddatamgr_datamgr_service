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

#include "log_print.h"
#include "utils.h"

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
 * @tc.name: MatchProxyUri_LiteralExactMatch_001
 * @tc.desc: Verify MatchProxyUri returns true only for exact literal uri match
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DatashareURIUtilsTest, MatchProxyUri_LiteralExactMatch_001, TestSize.Level0)
{
    ZLOGI("DatashareURIUtilsTest MatchProxyUri_LiteralExactMatch_001 start");
    EXPECT_TRUE(URIUtils::MatchProxyUri(
        "datashareproxy://com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_SECURE_100",
        "datashareproxy://com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_SECURE_100"));
    // same prefix but longer request must not match, prefix matching is removed for literal entries
    EXPECT_FALSE(URIUtils::MatchProxyUri("datashareproxy://com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA",
        "datashareproxy://com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_100"));
    // different table name
    EXPECT_FALSE(URIUtils::MatchProxyUri("datashareproxy://com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA",
        "datashareproxy://com.ohos.settingsdata/entry/settingsdata/SETTINGSDATA"));
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
    std::string attack = "datashareproxy://com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_secure_100";
    // literal secure entry must not match case-variated request
    EXPECT_FALSE(URIUtils::MatchProxyUri(
        "datashareproxy://com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_SECURE_100", attack));
    // template secure entry must not match case-variated request either
    EXPECT_FALSE(URIUtils::MatchProxyUri(
        "datashareproxy://com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_SECURE_{USERID}", attack));
    // permissive entry must not match case-variated request: letters in the placeholder part are
    // rejected, so the request can never fall through to a permissive prefix entry
    EXPECT_FALSE(URIUtils::MatchProxyUri(
        "datashareproxy://com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_{USERID}", attack));
    ZLOGI("DatashareURIUtilsTest MatchProxyUri_CaseVariationNotMatch_001 end");
}

/**
 * @tc.name: MatchProxyUri_PlaceholderDigitsMatch_001
 * @tc.desc: Verify MatchProxyUri matches template uri whose placeholder stands for pure digits
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DatashareURIUtilsTest, MatchProxyUri_PlaceholderDigitsMatch_001, TestSize.Level0)
{
    ZLOGI("DatashareURIUtilsTest MatchProxyUri_PlaceholderDigitsMatch_001 start");
    EXPECT_TRUE(URIUtils::MatchProxyUri(
        "datashareproxy://com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_SECURE_{USERID}",
        "datashareproxy://com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_SECURE_100"));
    EXPECT_TRUE(URIUtils::MatchProxyUri(
        "datashareproxy://com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_SECURE_{USERID}",
        "datashareproxy://com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_SECURE_101"));
    // user 0 is a valid digit suffix
    EXPECT_TRUE(
        URIUtils::MatchProxyUri("datashareproxy://com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_{USERID}",
            "datashareproxy://com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_0"));
    // whole segment placeholder
    EXPECT_TRUE(URIUtils::MatchProxyUri("datashareproxy://com.ohos.settingsdata/entry/settingsdata/{USERID}",
        "datashareproxy://com.ohos.settingsdata/entry/settingsdata/100"));
    ZLOGI("DatashareURIUtilsTest MatchProxyUri_PlaceholderDigitsMatch_001 end");
}

/**
 * @tc.name: MatchProxyUri_PlaceholderNonDigitsReject_001
 * @tc.desc: Verify MatchProxyUri rejects placeholder part containing non-digit characters
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DatashareURIUtilsTest, MatchProxyUri_PlaceholderNonDigitsReject_001, TestSize.Level0)
{
    ZLOGI("DatashareURIUtilsTest MatchProxyUri_PlaceholderNonDigitsReject_001 start");
    std::string entry = "datashareproxy://com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_{USERID}";
    // underscore in the placeholder part
    EXPECT_FALSE(URIUtils::MatchProxyUri(
        entry, "datashareproxy://com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_100_101"));
    // letter in the placeholder part
    EXPECT_FALSE(URIUtils::MatchProxyUri(
        entry, "datashareproxy://com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_100a"));
    // empty placeholder part
    EXPECT_FALSE(
        URIUtils::MatchProxyUri(entry, "datashareproxy://com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_"));
    // secure prefix abuse: permissive entry can not swallow SECURE_xxx
    EXPECT_FALSE(URIUtils::MatchProxyUri(
        entry, "datashareproxy://com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_SECURE_100"));
    ZLOGI("DatashareURIUtilsTest MatchProxyUri_PlaceholderNonDigitsReject_001 end");
}

/**
 * @tc.name: MatchProxyUri_SegmentStructure_001
 * @tc.desc: Verify MatchProxyUri compares uri structure, segment count and literal segments must equal
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DatashareURIUtilsTest, MatchProxyUri_SegmentStructure_001, TestSize.Level0)
{
    ZLOGI("DatashareURIUtilsTest MatchProxyUri_SegmentStructure_001 start");
    std::string entry = "datashareproxy://com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_{USERID}";
    // extra path segment in request is rejected
    EXPECT_FALSE(URIUtils::MatchProxyUri(
        entry, "datashareproxy://com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_100/extra"));
    // different module segment is rejected
    EXPECT_FALSE(
        URIUtils::MatchProxyUri(entry, "datashareproxy://com.ohos.settingsdata/entry/settings/USER_SETTINGSDATA_100"));
    // different authority is rejected
    EXPECT_FALSE(
        URIUtils::MatchProxyUri(entry, "datashareproxy://com.ohos.otherdata/entry/settingsdata/USER_SETTINGSDATA_100"));
    // two placeholders inside one segment are not supported
    EXPECT_FALSE(
        URIUtils::MatchProxyUri("datashareproxy://com.ohos.settingsdata/entry/settingsdata/TBL_{USERID}_{USERID}",
            "datashareproxy://com.ohos.settingsdata/entry/settingsdata/TBL_100_101"));
    ZLOGI("DatashareURIUtilsTest MatchProxyUri_SegmentStructure_001 end");
}

/**
 * @tc.name: MatchUserIdPlaceholderSegment_001
 * @tc.desc: Verify segment matcher requires literal prefix, digits and literal suffix
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DatashareURIUtilsTest, MatchUserIdPlaceholderSegment_001, TestSize.Level0)
{
    ZLOGI("DatashareURIUtilsTest MatchUserIdPlaceholderSegment_001 start");
    EXPECT_TRUE(URIUtils::MatchUserIdPlaceholderSegment("USER_SETTINGSDATA_{USERID}", "USER_SETTINGSDATA_100"));
    EXPECT_TRUE(URIUtils::MatchUserIdPlaceholderSegment("{USERID}", "100"));
    // digits with literal suffix
    EXPECT_TRUE(URIUtils::MatchUserIdPlaceholderSegment("{USERID}_TBL", "100_TBL"));
    // non-digit or empty placeholder part
    EXPECT_FALSE(URIUtils::MatchUserIdPlaceholderSegment("USER_SETTINGSDATA_{USERID}", "USER_SETTINGSDATA_10a0"));
    EXPECT_FALSE(URIUtils::MatchUserIdPlaceholderSegment("USER_SETTINGSDATA_{USERID}", "USER_SETTINGSDATA_"));
    EXPECT_FALSE(URIUtils::MatchUserIdPlaceholderSegment("USER_SETTINGSDATA_{USERID}", "USER_SETTINGSDATA_100_"));
    // non-digit remainder after the literal prefix
    EXPECT_FALSE(URIUtils::MatchUserIdPlaceholderSegment("USER_SETTINGSDATA_{USERID}", "USER_SETTINGSDATA2_100"));
    // no placeholder in entry segment falls back to exact comparison
    EXPECT_TRUE(URIUtils::MatchUserIdPlaceholderSegment("USER_SETTINGSDATA", "USER_SETTINGSDATA"));
    EXPECT_FALSE(URIUtils::MatchUserIdPlaceholderSegment("USER_SETTINGSDATA", "USER_SETTINGSDATA_100"));
    ZLOGI("DatashareURIUtilsTest MatchUserIdPlaceholderSegment_001 end");
}
} // namespace DataShare
} // namespace OHOS
