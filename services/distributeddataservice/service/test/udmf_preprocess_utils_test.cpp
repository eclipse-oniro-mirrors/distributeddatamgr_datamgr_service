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

#include "preprocess_utils.h"
#include "gtest/gtest.h"
#include "text.h"

namespace OHOS::UDMF {
using namespace testing::ext;
class UdmfPreProcessUtilsTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp() {}
    void TearDown() {}
};

/**
* @tc.name: RuntimeDataImputation001
* @tc.desc: Abnormal test of FillRuntimeInfo, option is invalid
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(UdmfPreProcessUtilsTest, RuntimeDataImputation001, TestSize.Level1)
{
    UnifiedData data;
    CustomOption option;
    PreProcessUtils preProcessUtils;
    int32_t ret = preProcessUtils.FillRuntimeInfo(data, option);
    EXPECT_EQ(ret, E_ERROR);
}

/**
* @tc.name: GetHapUidByToken001
* @tc.desc: Abnormal test of GetHapUidByToken, tokenId is invalid
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(UdmfPreProcessUtilsTest, GetHapUidByToken001, TestSize.Level1)
{
    uint32_t tokenId = 0;
    int userId = 0;
    PreProcessUtils preProcessUtils;
    int32_t ret = preProcessUtils.GetHapUidByToken(tokenId, userId);
    EXPECT_EQ(ret, E_ERROR);
}

/**
* @tc.name: SetRemoteData001
* @tc.desc: Abnormal test of SetRemoteData, data is null
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(UdmfPreProcessUtilsTest, SetRemoteData001, TestSize.Level1)
{
    UnifiedData data;
    PreProcessUtils preProcessUtils;
    EXPECT_NO_FATAL_FAILURE(preProcessUtils.SetRemoteData(data));
}

/**
* @tc.name: SetRemoteData002
* @tc.desc: Normal test of SetRemoteData
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(UdmfPreProcessUtilsTest, SetRemoteData002, TestSize.Level1)
{
    UnifiedData data;
    std::vector<std::shared_ptr<UnifiedRecord>> inputRecords;
    for (int32_t i = 0; i < 512; ++i) {
        inputRecords.emplace_back(std::make_shared<Text>());
    }
    data.SetRecords(inputRecords);
    data.runtime_ = std::make_shared<Runtime>();
    PreProcessUtils preProcessUtils;
    EXPECT_NO_FATAL_FAILURE(preProcessUtils.SetRemoteData(data));
}

/**
* @tc.name: IsFileType001
* @tc.desc: Abnormal test of IsFileType, record is nullptr
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(UdmfPreProcessUtilsTest, IsFileType001, TestSize.Level1)
{
    std::shared_ptr<UnifiedRecord> record = nullptr;
    PreProcessUtils preProcessUtils;
    bool ret = preProcessUtils.IsFileType(record);
    EXPECT_EQ(ret, false);
}

/**
* @tc.name: GetDfsUrisFromLocal001
* @tc.desc: Abnormal test of GetDfsUrisFromLocal, uris is null
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(UdmfPreProcessUtilsTest, GetDfsUrisFromLocal001, TestSize.Level1)
{
    const std::vector<std::string> uris;
    int32_t userId = 0;
    UnifiedData data;
    PreProcessUtils preProcessUtils;
    int32_t ret = preProcessUtils.GetDfsUrisFromLocal(uris, userId, data);
    EXPECT_EQ(ret, E_FS_ERROR);
}

/**
* @tc.name: CheckUriAuthorization001
* @tc.desc: Abnormal test of CheckUriAuthorization, uris is invalid
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(UdmfPreProcessUtilsTest, CheckUriAuthorization001, TestSize.Level1)
{
    const std::vector<std::string> uris = {"test"};
    uint32_t tokenId = 0;
    PreProcessUtils preProcessUtils;
    bool ret = preProcessUtils.CheckUriAuthorization(uris, tokenId);
    EXPECT_EQ(ret, false);
}

/**
* @tc.name: GetInstIndex001
* @tc.desc: Normal test of GetInstIndex
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(UdmfPreProcessUtilsTest, GetInstIndex001, TestSize.Level1)
{
    uint32_t tokenId = 0;
    int32_t instIndex = 0;
    PreProcessUtils preProcessUtils;
    bool ret = preProcessUtils.GetInstIndex(tokenId, instIndex);
    EXPECT_EQ(instIndex, 0);
    EXPECT_EQ(ret, true);
}

/**
* @tc.name: ProcessFileType001
* @tc.desc: Abnormal test of ProcessFileType, records is nullptr
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(UdmfPreProcessUtilsTest, ProcessFileType001, TestSize.Level1)
{
    std::vector<std::shared_ptr<UnifiedRecord>> records = { nullptr };
    std::function<bool(std::shared_ptr<Object>)> callback;
    PreProcessUtils preProcessUtils;
    EXPECT_NO_FATAL_FAILURE(preProcessUtils.ProcessFileType(records, callback));
}

/**
* @tc.name: GetHtmlFileUris001
* @tc.desc: Abnormal test of GetHtmlFileUris, uris is invalid
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(UdmfPreProcessUtilsTest, GetHtmlFileUris001, TestSize.Level1)
{
    uint32_t tokenId = 0;
    UnifiedData data;
    bool isLocal = false;
    std::vector<std::string> uris = {"test"};
    PreProcessUtils preProcessUtils;
    EXPECT_NO_FATAL_FAILURE(preProcessUtils.GetHtmlFileUris(tokenId, data, isLocal, uris));
}

/**
* @tc.name: GetAppId001
* @tc.desc: Abnormal test of GetAppId, samgrProxy is nullptr
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(UdmfPreProcessUtilsTest, GetAppId001, TestSize.Level1)
{
    std::string bundleName = "test";
    PreProcessUtils preProcessUtils;
    std::string appId = preProcessUtils.GetAppId(bundleName);
    EXPECT_EQ(appId, "");
}
}; // namespace UDMF