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

#include <gtest/gtest.h>

#include <limits>

#include "auth_event_builder.h"
using namespace testing::ext;
namespace OHOS::UDMF {
class UdmfAuthEventBuilderTest : public testing::Test {};
/**
 * @tc.name: Build_ProductionIdentityAndEscapedContent_UsesSingleEvent
 * @tc.desc: Verify the receiver-side event contract through public interfaces.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfAuthEventBuilderTest, Build_ProductionIdentityAndEscapedContent_UsesSingleEvent, TestSize.Level1)
{
    AuthEventContract contract;
    contract.encode = [](const DragAuthContext &, DistributedData::Serializable::json &content) {
        content["text"] = "quote\"\n";
        return AuthBuildStatus::SUCCESS;
    };
    AuthEventBuilder builder(contract);
    DragAuthContext context;
    context.crossApplication = true;
    DragAuthEvent event;
    ASSERT_EQ(builder.Build(context, event), AuthBuildStatus::SUCCESS);
    EXPECT_EQ(event.eventId, INT64_C(0x0F810000));
    EXPECT_EQ(event.version, "1.0");
    EXPECT_EQ(DistributedData::Serializable::json::parse(event.jsonContent)["text"], "quote\"\n");
    context.crossApplication = false;
    EXPECT_EQ(builder.Build(context, event), AuthBuildStatus::INVALID_DATA);
}
/**
 * @tc.name: Build_ExactLimitAndOneByteOver_RejectsWithoutTruncation
 * @tc.desc: Verify the receiver-side event contract through public interfaces.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfAuthEventBuilderTest, Build_ExactLimitAndOneByteOver_RejectsWithoutTruncation, TestSize.Level1)
{
    size_t bytes = 10240 - 8;
    AuthEventContract contract;
    contract.encode = [&bytes](const DragAuthContext &, DistributedData::Serializable::json &content) {
        content["a"] = std::string(bytes, 'x');
        return AuthBuildStatus::SUCCESS;
    };
    AuthEventBuilder builder(contract);
    DragAuthContext context;
    context.crossApplication = true;
    DragAuthEvent event;
    ASSERT_EQ(builder.Build(context, event), AuthBuildStatus::SUCCESS);
    EXPECT_EQ(event.jsonContent.size(), 10240u);
    auto accepted = event.jsonContent;
    bytes++;
    EXPECT_EQ(builder.Build(context, event), AuthBuildStatus::TOO_LARGE);
    EXPECT_EQ(event.jsonContent, accepted);
}
/**
 * @tc.name: Build_Utf8AndEscapes_CountsSerializedBytes
 * @tc.desc: Verify the receiver-side event contract through public interfaces.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfAuthEventBuilderTest, Build_Utf8AndEscapes_CountsSerializedBytes, TestSize.Level1)
{
    std::string value = u8"中文";
    AuthEventContract contract;
    contract.maxContentBytes = 14;
    contract.encode = [&value](const DragAuthContext &, DistributedData::Serializable::json &content) {
        content["a"] = value;
        return AuthBuildStatus::SUCCESS;
    };
    DragAuthContext context;
    context.crossApplication = true;
    DragAuthEvent event;
    ASSERT_EQ(AuthEventBuilder(contract).Build(context, event), AuthBuildStatus::SUCCESS);
    EXPECT_EQ(event.jsonContent.size(), 14u);
    contract.maxContentBytes = 13;
    EXPECT_EQ(AuthEventBuilder(contract).Build(context, event), AuthBuildStatus::TOO_LARGE);
    value = std::string(4, '\n');
    EXPECT_EQ(AuthEventBuilder(contract).Build(context, event), AuthBuildStatus::TOO_LARGE);
}
/**
 * @tc.name: Build_MissingInvalidOrFailedEncoder_PreservesOutput
 * @tc.desc: Verify the receiver-side event contract through public interfaces.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfAuthEventBuilderTest, Build_MissingInvalidOrFailedEncoder_PreservesOutput, TestSize.Level1)
{
    DragAuthContext context;
    context.crossApplication = true;
    DragAuthEvent event{ 99, "previous", "unchanged" };
    EXPECT_FALSE(AuthEventBuilder().IsReady());
    EXPECT_EQ(AuthEventBuilder().Build(context, event), AuthBuildStatus::INVALID_DATA);
    AuthEventContract contract;
    contract.encode = [](const DragAuthContext &, DistributedData::Serializable::json &) {
        return AuthBuildStatus::TOO_LARGE;
    };
    EXPECT_EQ(AuthEventBuilder(contract).Build(context, event), AuthBuildStatus::TOO_LARGE);
    contract.encode = [](const DragAuthContext &, DistributedData::Serializable::json &content) {
        content = "scalar";
        return AuthBuildStatus::SUCCESS;
    };
    EXPECT_EQ(AuthEventBuilder(contract).Build(context, event), AuthBuildStatus::INVALID_DATA);
    contract.maxContentBytes = 10241;
    EXPECT_FALSE(AuthEventBuilder(contract).IsReady());
    EXPECT_EQ(event.jsonContent, "unchanged");
}
/**
 * @tc.name: IsReady_EachInvalidContractField_RejectsBeforeEncoder
 * @tc.desc: Verify public behavior, failure propagation and observable state.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfAuthEventBuilderTest, IsReady_EachInvalidContractField_RejectsBeforeEncoder, TestSize.Level1)
{
    int encoded = 0;
    AuthEventContract valid;
    valid.encode = [&](const DragAuthContext &, auto &node) {
        ++encoded;
        node = DistributedData::Serializable::json::object();
        return AuthBuildStatus::SUCCESS;
    };
    std::vector<AuthEventContract> invalid(5, valid);
    invalid[0].eventId = 0;
    invalid[1].eventId = -1;
    invalid[2].version.clear();
    invalid[3].maxContentBytes = 0;
    invalid[4].encode = {};
    DragAuthEvent event{ 99, "original", "untouched" };
    DragAuthContext context;
    context.crossApplication = true;
    for (const auto &contract : invalid) {
        AuthEventBuilder builder(contract);
        EXPECT_FALSE(builder.IsReady());
        EXPECT_EQ(builder.Build(context, event), AuthBuildStatus::INVALID_DATA);
        EXPECT_EQ(event.eventId, 99);
        EXPECT_EQ(event.version, "original");
        EXPECT_EQ(event.jsonContent, "untouched");
    }
    EXPECT_EQ(encoded, 0);
}
/**
 * @tc.name: Build_EmptyObjectAndMinimumBudget_UsesExactSerializedSize
 * @tc.desc: Verify public behavior, failure propagation and observable state.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfAuthEventBuilderTest, Build_EmptyObjectAndMinimumBudget_UsesExactSerializedSize, TestSize.Level1)
{
    AuthEventContract contract;
    contract.maxContentBytes = 2;
    contract.encode = [](const DragAuthContext &, auto &node) {
        node = DistributedData::Serializable::json::object();
        return AuthBuildStatus::SUCCESS;
    };
    DragAuthContext context;
    context.crossApplication = true;
    DragAuthEvent event;
    ASSERT_EQ(AuthEventBuilder(contract).Build(context, event), AuthBuildStatus::SUCCESS);
    EXPECT_EQ(event.jsonContent, "{}");
    contract.maxContentBytes = 1;
    EXPECT_EQ(AuthEventBuilder(contract).Build(context, event), AuthBuildStatus::TOO_LARGE);
    EXPECT_EQ(event.jsonContent, "{}");
}
/**
 * @tc.name: Build_EachNonObjectEncoderResult_PreservesWholeEvent
 * @tc.desc: Verify public behavior, failure propagation and observable state.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfAuthEventBuilderTest, Build_EachNonObjectEncoderResult_PreservesWholeEvent, TestSize.Level1)
{
    using Json = DistributedData::Serializable::json;
    for (const auto &node : std::vector<Json>{ nullptr, true, 17, "text", Json::array() }) {
        AuthEventContract contract;
        contract.encode = [node](const DragAuthContext &, auto &output) {
            output = node;
            return AuthBuildStatus::SUCCESS;
        };
        DragAuthContext context;
        context.crossApplication = true;
        DragAuthEvent event{ 99, "original", "untouched" };
        EXPECT_EQ(AuthEventBuilder(contract).Build(context, event), AuthBuildStatus::INVALID_DATA);
        EXPECT_EQ(event.eventId, 99);
        EXPECT_EQ(event.version, "original");
        EXPECT_EQ(event.jsonContent, "untouched");
    }
}
/**
 * @tc.name: Build_EncoderStatusFailure_DoesNotCommitPartialMetadata
 * @tc.desc: Verify public behavior, failure propagation and observable state.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfAuthEventBuilderTest, Build_EncoderStatusFailure_DoesNotCommitPartialMetadata, TestSize.Level1)
{
    for (auto failure : { AuthBuildStatus::INVALID_DATA, AuthBuildStatus::TOO_LARGE }) {
        AuthEventContract contract;
        contract.encode = [failure](const DragAuthContext &, auto &output) {
            output["partial"] = "never dispatch";
            return failure;
        };
        DragAuthContext context;
        context.crossApplication = true;
        DragAuthEvent event{ 99, "original", "untouched" };
        EXPECT_EQ(AuthEventBuilder(contract).Build(context, event), failure);
        EXPECT_EQ(event.eventId, 99);
        EXPECT_EQ(event.version, "original");
        EXPECT_EQ(event.jsonContent, "untouched");
    }
}
/**
 * @tc.name: Build_InvalidUtf8_RejectsReplacementAndEnforcesSize
 * @tc.desc: Verify public behavior, failure propagation and observable state.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfAuthEventBuilderTest, Build_InvalidUtf8_RejectsReplacementAndEnforcesSize, TestSize.Level1)
{
    const std::string expected = "{\"text\":\"\xef\xbf\xbd\"}";
    AuthEventContract contract;
    contract.maxContentBytes = expected.size();
    contract.encode = [](const DragAuthContext &, auto &output) {
        output["text"] = std::string(1, static_cast<char>(0xff));
        return AuthBuildStatus::SUCCESS;
    };
    DragAuthContext context;
    context.crossApplication = true;
    DragAuthEvent event;
    ASSERT_EQ(AuthEventBuilder(contract).Build(context, event), AuthBuildStatus::INVALID_ENCODING);
    EXPECT_TRUE(event.jsonContent.empty());
    --contract.maxContentBytes;
    EXPECT_EQ(AuthEventBuilder(contract).Build(context, event), AuthBuildStatus::TOO_LARGE);
    EXPECT_TRUE(event.jsonContent.empty());
}
/**
 * @tc.name: Build_LargeEventIdAndCustomVersion_PreserveContractIdentity
 * @tc.desc: Verify public behavior, failure propagation and observable state.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfAuthEventBuilderTest, Build_LargeEventIdAndCustomVersion_PreserveContractIdentity, TestSize.Level1)
{
    AuthEventContract contract;
    contract.eventId = INT64_C(5000000001);
    contract.version = "version-test";
    contract.encode = [](const DragAuthContext &, auto &output) {
        output["payload"] = true;
        return AuthBuildStatus::SUCCESS;
    };
    DragAuthContext context;
    context.crossApplication = true;
    DragAuthEvent event;
    AuthEventBuilder builder(contract);
    ASSERT_TRUE(builder.IsReady());
    EXPECT_EQ(builder.GetEventId(), contract.eventId);
    ASSERT_EQ(builder.Build(context, event), AuthBuildStatus::SUCCESS);
    EXPECT_EQ(event.eventId, contract.eventId);
    EXPECT_EQ(event.version, contract.version);
    EXPECT_EQ(DistributedData::Serializable::json::parse(event.jsonContent)["payload"], true);
}
/**
 * @tc.name: Build_InvalidUtf8KeysAndValues_RejectWithoutReplacingOriginalEvent
 * @tc.desc: Preserve all original fields or fail instead of merging replacement characters.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfAuthEventBuilderTest, Build_InvalidUtf8KeysAndValues_RejectWithoutReplacingOriginalEvent, TestSize.Level1)
{
    for (bool keys : { false, true }) {
        AuthEventContract contract;
        contract.encode = [keys](const DragAuthContext &, auto &node) {
            node = DistributedData::Serializable::json::object();
            if (keys) {
                node[std::string(1, static_cast<char>(0x80))] = "SECRET";
                node[std::string(1, static_cast<char>(0x81))] = "clean";
            } else {
                node["nested"] = { { "text", std::string(1, static_cast<char>(0xff)) } };
            }
            return AuthBuildStatus::SUCCESS;
        };
        DragAuthEvent event{ 99, "saved", "unchanged" };
        EXPECT_EQ(
            AuthEventBuilder(contract).Build({ true, 17, 19, nullptr }, event), AuthBuildStatus::INVALID_ENCODING);
        EXPECT_EQ(event.jsonContent, "unchanged");
        EXPECT_EQ(event.eventId, 99);
    }
}

/**
 * @tc.name: Build_NestedArrayUtf8AndNonFiniteNumber_PreserveOrRejectWholeEvent
 * @tc.desc: Validate nested keys and values without changing Unicode or dropping non-finite numbers.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfAuthEventBuilderTest, Build_NestedArrayUtf8AndNonFiniteNumber_PreserveOrRejectWholeEvent, TestSize.Level1)
{
    AuthEventContract contract;
    contract.encode = [](const auto &, auto &output) {
        output["中文"] = { "拖拽😀", 1, true, nullptr };
        return AuthBuildStatus::SUCCESS;
    };
    DragAuthEvent event;
    ASSERT_EQ(AuthEventBuilder(contract).Build({ true, 17, 19, nullptr }, event), AuthBuildStatus::SUCCESS);
    const auto original = event.jsonContent;
    auto decoded = DistributedData::Serializable::json::parse(original);
    EXPECT_EQ(decoded["中文"][0], "拖拽😀");
    contract.encode = [](const auto &, auto &output) {
        output["number"] = std::numeric_limits<double>::infinity();
        return AuthBuildStatus::SUCCESS;
    };
    EXPECT_EQ(AuthEventBuilder(contract).Build({ true, 17, 19, nullptr }, event), AuthBuildStatus::INVALID_ENCODING);
    EXPECT_EQ(event.jsonContent, original);
}

} // namespace OHOS::UDMF
