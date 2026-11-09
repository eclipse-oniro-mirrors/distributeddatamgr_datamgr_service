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

#include "drag_auth_event_encoder.h"
#include "pixel_map.h"
#include "unified_data.h"
#include "want.h"
using namespace testing::ext;
namespace OHOS::UDMF {
class UdmfDragAuthEncoderTest : public testing::Test {};
/**
 * @tc.name: Build_RealUnifiedData_PreservesIdentityAndAllEntries
 * @tc.desc: Verify the receiver-side event contract through public interfaces.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfDragAuthEncoderTest, Build_RealUnifiedData_PreservesIdentityAndAllEntries, TestSize.Level1)
{
    auto data = std::make_shared<UnifiedData>();
    auto record = std::make_shared<UnifiedRecord>(UDType::PLAIN_TEXT, std::string("hello\"\n"));
    auto extra = std::make_shared<Object>();
    extra->value_["uri"] = std::string("file://test/document");
    extra->value_["count"] = int64_t(42);
    record->AddEntry("application.test.extra", extra);
    data->AddRecord(record);
    DragAuthContext context{ true, 17, 19, data };
    DragAuthEvent event;
    ASSERT_EQ(CreateDragAuthEventBuilder()->Build(context, event), AuthBuildStatus::SUCCESS);
    EXPECT_EQ(event.eventId, DRAG_AUTH_EVENT_ID);
    EXPECT_EQ(event.version, "1.0");
    auto json = DistributedData::Serializable::json::parse(event.jsonContent);
    EXPECT_EQ(json["sourceTokenId"], 17);
    EXPECT_EQ(json["targetTokenId"], 19);
    ASSERT_EQ(json["content"]["entries"].size(), 1u);
    const auto &entries = json["content"]["entries"][0]["entries"];
    EXPECT_EQ(entries[record->GetUtdId()][VALUE_TYPE], "hello\"\n");
    EXPECT_EQ(entries["application.test.extra"]["count"], 42);
    EXPECT_EQ(entries["application.test.extra"]["uri"], "file://test/document");
}
/**
 * @tc.name: Build_ExactProductionBudget_OneExtraByteFails
 * @tc.desc: Verify the receiver-side event contract through public interfaces.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfDragAuthEncoderTest, Build_ExactProductionBudget_OneExtraByteFails, TestSize.Level1)
{
    auto makeData = [](size_t length) {
        auto data = std::make_shared<UnifiedData>();
        data->AddRecord(std::make_shared<UnifiedRecord>(UDType::PLAIN_TEXT, std::string(length, 'x')));
        return data;
    };
    DragAuthContext context{ true, 17, 19, makeData(0) };
    auto builder = CreateDragAuthEventBuilder();
    DragAuthEvent event;
    ASSERT_EQ(builder->Build(context, event), AuthBuildStatus::SUCCESS);
    auto overhead = event.jsonContent.size();
    ASSERT_LT(overhead, DRAG_AUTH_MAX_CONTENT_BYTES);
    context.data = makeData(DRAG_AUTH_MAX_CONTENT_BYTES - overhead);
    ASSERT_EQ(builder->Build(context, event), AuthBuildStatus::SUCCESS);
    EXPECT_EQ(event.jsonContent.size(), DRAG_AUTH_MAX_CONTENT_BYTES);
    auto accepted = event.jsonContent;
    context.data = makeData(DRAG_AUTH_MAX_CONTENT_BYTES - overhead + 1);
    EXPECT_EQ(builder->Build(context, event), AuthBuildStatus::TOO_LARGE);
    EXPECT_EQ(event.jsonContent, accepted);
}
/**
 * @tc.name: Build_BinaryAndNullValues_PreservesContent
 * @tc.desc: Verify the receiver-side event contract through public interfaces.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfDragAuthEncoderTest, Build_BinaryAndNullValues_PreservesContent, TestSize.Level1)
{
    auto object = std::make_shared<Object>();
    object->value_["bytes"] = std::vector<uint8_t>{ 0, 127, 255 };
    object->value_["nullable"] = nullptr;
    object->value_["enabled"] = true;
    auto data = std::make_shared<UnifiedData>();
    auto record = std::make_shared<UnifiedRecord>(UDType::PLAIN_TEXT, object);
    data->AddRecord(record);
    DragAuthContext context{ true, 17, 19, data };
    DragAuthEvent event;
    ASSERT_EQ(CreateDragAuthEventBuilder()->Build(context, event), AuthBuildStatus::SUCCESS);
    auto json = DistributedData::Serializable::json::parse(event.jsonContent);
    auto value = json["content"]["entries"][0]["entries"][record->GetUtdId()];
    EXPECT_EQ(value["bytes"]["bytes"][2], 255);
    EXPECT_TRUE(value["nullable"].is_null());
    EXPECT_EQ(value["enabled"], true);
}
/**
 * @tc.name: Build_NullOrLargeRecord_LeavesOutputUntouched
 * @tc.desc: Verify the receiver-side event contract through public interfaces.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfDragAuthEncoderTest, Build_NullOrLargeRecord_LeavesOutputUntouched, TestSize.Level1)
{
    auto builder = CreateDragAuthEventBuilder();
    DragAuthContext context{ true, 17, 19, nullptr };
    DragAuthEvent event{ 0, "old", "old" };
    EXPECT_EQ(builder->Build(context, event), AuthBuildStatus::INVALID_DATA);
    auto data = std::make_shared<UnifiedData>();
    data->AddRecord(std::make_shared<UnifiedRecord>(UDType::PLAIN_TEXT, std::string(10241, 'x')));
    context.data = data;
    EXPECT_EQ(builder->Build(context, event), AuthBuildStatus::TOO_LARGE);
    EXPECT_EQ(event.jsonContent, "old");
}
/**
 * @tc.name: Build_WantAndNullHandles_PreservesTypedValues
 * @tc.desc: Verify the receiver-side event contract through public interfaces.
 * @tc.type: FUNC
 * @tc.author: agent
 */

HWTEST_F(UdmfDragAuthEncoderTest, Build_WantAndNullHandles_PreservesTypedValues, TestSize.Level1)
{
    auto want = std::make_shared<AAFwk::Want>();
    want->SetAction("test.drag.action");
    auto object = std::make_shared<Object>();
    object->value_["want"] = want;
    object->value_["noWant"] = std::shared_ptr<AAFwk::Want>();
    object->value_["noPixels"] = std::shared_ptr<Media::PixelMap>();
    object->value_["noObject"] = std::shared_ptr<Object>();
    object->value_["fraction"] = 1.5;
    auto record = std::make_shared<UnifiedRecord>(UDType::PLAIN_TEXT, object);
    auto data = std::make_shared<UnifiedData>();
    data->AddRecord(record);
    DragAuthEvent event;
    ASSERT_EQ(CreateDragAuthEventBuilder()->Build({ true, 17, 19, data }, event), AuthBuildStatus::SUCCESS);
    auto json = DistributedData::Serializable::json::parse(event.jsonContent);
    const auto &value = json["content"]["entries"][0]["entries"][record->GetUtdId()];
    EXPECT_EQ(value["want"]["kind"], "want");
    EXPECT_EQ(value["want"]["value"], want->ToString());
    EXPECT_TRUE(value["noWant"].is_null());
    EXPECT_TRUE(value["noPixels"].is_null());
    EXPECT_TRUE(value["noObject"].is_null());
    EXPECT_EQ(value["fraction"], 1.5);
}
/**
 * @tc.name: Build_PixelMap_PreservesEncodedBytes
 * @tc.desc: Verify the receiver-side event contract through public interfaces.
 * @tc.type: FUNC
 * @tc.author: agent
 */

HWTEST_F(UdmfDragAuthEncoderTest, Build_PixelMap_PreservesEncodedBytes, TestSize.Level1)
{
    uint32_t colors[] = { 0xff000000, 0xffffffff, 0xff112233, 0xff445566 };
    Media::InitializationOptions options;
    options.size = { 2, 2 };
    options.pixelFormat = Media::PixelFormat::ARGB_8888;
    options.srcPixelFormat = Media::PixelFormat::ARGB_8888;
    options.allocatorType = Media::AllocatorType::HEAP_ALLOC;
    std::shared_ptr<Media::PixelMap> pixels = Media::PixelMap::Create(colors, 4, options);
    ASSERT_NE(pixels, nullptr);
    auto record = std::make_shared<UnifiedRecord>(UDType::SYSTEM_DEFINED_PIXEL_MAP, pixels);
    auto data = std::make_shared<UnifiedData>();
    data->AddRecord(record);
    DragAuthEvent event;
    ASSERT_EQ(CreateDragAuthEventBuilder()->Build({ true, 17, 19, data }, event), AuthBuildStatus::SUCCESS);
    auto json = DistributedData::Serializable::json::parse(event.jsonContent);
    const auto &value = json["content"]["entries"][0]["entries"][record->GetUtdId()][VALUE_TYPE];
    EXPECT_EQ(value["kind"], "pixelmap-tlv");
    std::vector<uint8_t> expected;
    ASSERT_TRUE(pixels->EncodeTlv(expected));
    EXPECT_EQ(value["value"]["bytes"], expected);
}
/**
 * @tc.name: Build_MultipleRecords_AggregateLimitDoesNotDropRecords
 * @tc.desc: Verify the receiver-side event contract through public interfaces.
 * @tc.type: FUNC
 * @tc.author: agent
 */

HWTEST_F(UdmfDragAuthEncoderTest, Build_MultipleRecords_AggregateLimitDoesNotDropRecords, TestSize.Level1)
{
    auto data = std::make_shared<UnifiedData>();
    data->AddRecord(std::make_shared<UnifiedRecord>(UDType::PLAIN_TEXT, std::string(6000, 'a')));
    data->AddRecord(std::make_shared<UnifiedRecord>(UDType::PLAIN_TEXT, std::string(6000, 'b')));
    DragAuthEvent event{ 0, "old", "unchanged" };
    EXPECT_EQ(CreateDragAuthEventBuilder()->Build({ true, 17, 19, data }, event), AuthBuildStatus::TOO_LARGE);
    EXPECT_EQ(event.jsonContent, "unchanged");
}
/**
 * @tc.name: Build_EscapingExpansion_UsesSerializedByteLimit
 * @tc.desc: Verify the receiver-side event contract through public interfaces.
 * @tc.type: FUNC
 * @tc.author: agent
 */

HWTEST_F(UdmfDragAuthEncoderTest, Build_EscapingExpansion_UsesSerializedByteLimit, TestSize.Level1)
{
    auto data = std::make_shared<UnifiedData>();
    data->AddRecord(std::make_shared<UnifiedRecord>(UDType::PLAIN_TEXT, std::string(2000, '\0')));
    DragAuthEvent event{ 0, "old", "unchanged" };
    EXPECT_EQ(CreateDragAuthEventBuilder()->Build({ true, 17, 19, data }, event), AuthBuildStatus::TOO_LARGE);
    EXPECT_EQ(event.jsonContent, "unchanged");
}
/**
 * @tc.name: Build_InvalidRecordsAndMetadata_FailsWithoutPartialEvent
 * @tc.desc: Verify the receiver-side event contract through public interfaces.
 * @tc.type: FUNC
 * @tc.author: agent
 */

HWTEST_F(UdmfDragAuthEncoderTest, Build_InvalidRecordsAndMetadata_FailsWithoutPartialEvent, TestSize.Level1)
{
    auto builder = CreateDragAuthEventBuilder();
    auto data = std::make_shared<UnifiedData>();
    data->SetRecords({ nullptr });
    DragAuthEvent event{ 0, "old", "unchanged" };
    EXPECT_EQ(builder->Build({ true, 17, 19, data }, event), AuthBuildStatus::INVALID_DATA);
    auto record = std::make_shared<UnifiedRecord>(UDType::PLAIN_TEXT, std::string("content"));
    record->SetUtdId(std::string(DRAG_AUTH_MAX_CONTENT_BYTES + 1, 't'));
    data->SetRecords({ record });
    EXPECT_EQ(builder->Build({ true, 17, 19, data }, event), AuthBuildStatus::TOO_LARGE);
    record = std::make_shared<UnifiedRecord>(UDType::PLAIN_TEXT, std::string("x"));
    data->SetRecords(std::vector<std::shared_ptr<UnifiedRecord>>(DRAG_AUTH_MAX_CONTENT_BYTES / 2 + 1, record));
    EXPECT_EQ(builder->Build({ true, 17, 19, data }, event), AuthBuildStatus::TOO_LARGE);
    EXPECT_EQ(event.jsonContent, "unchanged");
}
/**
 * @tc.name: Build_DeepObjectsAndEscapedKeys_FailsWithoutDroppingFields
 * @tc.desc: Verify the receiver-side event contract through public interfaces.
 * @tc.type: FUNC
 * @tc.author: agent
 */

HWTEST_F(UdmfDragAuthEncoderTest, Build_DeepObjectsAndEscapedKeys_FailsWithoutDroppingFields, TestSize.Level1)
{
    auto data = std::make_shared<UnifiedData>();
    auto object = std::make_shared<Object>();
    object->value_[std::string(2000, '\0')] = std::string("value");
    auto record = std::make_shared<UnifiedRecord>(UDType::PLAIN_TEXT, object);
    data->SetRecords({ record });
    DragAuthEvent event{ 0, "old", "unchanged" };
    auto builder = CreateDragAuthEventBuilder();
    EXPECT_EQ(builder->Build({ true, 17, 19, data }, event), AuthBuildStatus::TOO_LARGE);
    object = std::make_shared<Object>();
    auto node = object;
    for (size_t i = 0; i < 66; ++i) {
        auto child = std::make_shared<Object>();
        node->value_["child"] = child;
        node = child;
    }
    record = std::make_shared<UnifiedRecord>(UDType::PLAIN_TEXT, object);
    data->SetRecords({ record });
    EXPECT_EQ(builder->Build({ true, 17, 19, data }, event), AuthBuildStatus::TOO_LARGE);
    EXPECT_EQ(event.jsonContent, "unchanged");
}
/**
 * @tc.name: Build_InvalidAndLargePixelMap_NoPartialImageEvent
 * @tc.desc: Verify the receiver-side event contract through public interfaces.
 * @tc.type: FUNC
 * @tc.author: agent
 */

HWTEST_F(UdmfDragAuthEncoderTest, Build_InvalidAndLargePixelMap_NoPartialImageEvent, TestSize.Level1)
{
    auto data = std::make_shared<UnifiedData>();
    auto pixels = std::make_shared<Media::PixelMap>();
    data->AddRecord(std::make_shared<UnifiedRecord>(UDType::SYSTEM_DEFINED_PIXEL_MAP, pixels));
    auto builder = CreateDragAuthEventBuilder();
    DragAuthEvent event{ 0, "old", "unchanged" };
    EXPECT_EQ(builder->Build({ true, 17, 19, data }, event), AuthBuildStatus::INVALID_DATA);
    Media::InitializationOptions options;
    options.size = { 64, 40 };
    options.pixelFormat = Media::PixelFormat::ARGB_8888;
    options.allocatorType = Media::AllocatorType::HEAP_ALLOC;
    pixels = Media::PixelMap::Create(options);
    ASSERT_NE(pixels, nullptr);
    data->SetRecords({ std::make_shared<UnifiedRecord>(UDType::SYSTEM_DEFINED_PIXEL_MAP, pixels) });
    EXPECT_EQ(builder->Build({ true, 17, 19, data }, event), AuthBuildStatus::TOO_LARGE);
    EXPECT_EQ(event.jsonContent, "unchanged");
}

namespace {
// An untrusted/derived record can report a misleading raw size. The encoder must still bound every value.
class SizedAuthRecord : public UnifiedRecord {
public:
    explicit SizedAuthRecord(const ValueType &value, int64_t size = 0) : UnifiedRecord(PLAIN_TEXT, value), size_(size)
    {
    }
    int64_t GetSize() override
    {
        return size_;
    }

private:
    int64_t size_;
};
} // namespace
/**
 * @tc.name: Build_NegativeAndOversizedReportedSize_RejectsBeforeCopy
 * @tc.desc: Verify public behavior, failure propagation and observable state.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfDragAuthEncoderTest, Build_NegativeAndOversizedReportedSize_RejectsBeforeCopy, TestSize.Level1)
{
    for (int64_t size : { -1, 10241 }) {
        auto data = std::make_shared<UnifiedData>();
        data->AddRecord(std::make_shared<SizedAuthRecord>(std::string("small"), size));
        DragAuthEvent event{ 1, "unchanged", "sentinel" };
        EXPECT_EQ(CreateDragAuthEventBuilder()->Build({ true, 1, 2, data }, event), AuthBuildStatus::TOO_LARGE);
        EXPECT_EQ(event.jsonContent, "sentinel");
        EXPECT_EQ(event.eventId, 1);
    }
}
/**
 * @tc.name: Build_MisleadingSourceSize_StillChecksStringBinaryAndWant
 * @tc.desc: Verify public behavior, failure propagation and observable state.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfDragAuthEncoderTest, Build_MisleadingSourceSize_StillChecksStringBinaryAndWant, TestSize.Level1)
{
    auto want = std::make_shared<AAFwk::Want>();
    want->SetParam("oversized", std::string(10241, 'w'));
    std::vector<ValueType> values = { std::string(10241, 'x'), std::vector<uint8_t>(10241, 255), want };
    for (const auto &value : values) {
        auto data = std::make_shared<UnifiedData>();
        data->AddRecord(std::make_shared<SizedAuthRecord>(value));
        DragAuthEvent event{ 1, "unchanged", "sentinel" };
        EXPECT_EQ(CreateDragAuthEventBuilder()->Build({ true, 1, 2, data }, event), AuthBuildStatus::TOO_LARGE);
        EXPECT_EQ(event.jsonContent, "sentinel");
    }
}
/**
 * @tc.name: Build_CyclicObject_RejectsAndReleasesCycle
 * @tc.desc: Verify public behavior, failure propagation and observable state.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfDragAuthEncoderTest, Build_CyclicObject_RejectsAndReleasesCycle, TestSize.Level1)
{
    auto object = std::make_shared<Object>();
    object->value_["self"] = object;
    auto data = std::make_shared<UnifiedData>();
    data->AddRecord(std::make_shared<SizedAuthRecord>(object));
    DragAuthEvent event{ 1, "unchanged", "sentinel" };
    auto status = CreateDragAuthEventBuilder()->Build({ true, 1, 2, data }, event);
    object->value_.clear();
    EXPECT_EQ(status, AuthBuildStatus::TOO_LARGE);
    EXPECT_EQ(event.jsonContent, "sentinel");
}
/**
 * @tc.name: Build_OversizedEntryKeyAndRecordOverhead_AreRejected
 * @tc.desc: Verify public behavior, failure propagation and observable state.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfDragAuthEncoderTest, Build_OversizedEntryKeyAndRecordOverhead_AreRejected, TestSize.Level1)
{
    auto object = std::make_shared<Object>();
    object->value_[std::string(10241, 'k')] = int32_t(1);
    auto record = std::make_shared<SizedAuthRecord>(object);
    auto data = std::make_shared<UnifiedData>();
    data->AddRecord(record);
    DragAuthEvent event{ 1, "unchanged", "sentinel" };
    EXPECT_EQ(CreateDragAuthEventBuilder()->Build({ true, 1, 2, data }, event), AuthBuildStatus::TOO_LARGE);
    object->value_.clear();
    record->SetUtdId(std::string(10240, '\n'));
    EXPECT_EQ(CreateDragAuthEventBuilder()->Build({ true, 1, 2, data }, event), AuthBuildStatus::TOO_LARGE);
    EXPECT_EQ(event.jsonContent, "sentinel");
}
/**
 * @tc.name: Build_AliasedAcyclicObjectsAndNumericTypes_EncodeWithoutFalseCycle
 * @tc.desc: Verify public behavior, failure propagation and observable state.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(UdmfDragAuthEncoderTest, Build_AliasedAcyclicObjectsAndNumericTypes_EncodeWithoutFalseCycle, TestSize.Level1)
{
    auto child = std::make_shared<Object>();
    child->value_["i32"] = int32_t(-7);
    child->value_["i64"] = int64_t(5000000001);
    child->value_["double"] = double(1.25);
    child->value_["nullObject"] = std::shared_ptr<Object>();
    auto parent = std::make_shared<Object>();
    parent->value_["first"] = child;
    parent->value_["second"] = child;
    auto record = std::make_shared<SizedAuthRecord>(parent);
    auto data = std::make_shared<UnifiedData>();
    data->AddRecord(record);
    DragAuthEvent event;
    ASSERT_EQ(CreateDragAuthEventBuilder()->Build({ true, 0, UINT32_MAX, data }, event), AuthBuildStatus::SUCCESS);
    auto json = DistributedData::Serializable::json::parse(event.jsonContent);
    auto node = json["content"]["entries"][0]["entries"][record->GetUtdId()];
    EXPECT_EQ(node["first"], node["second"]);
    EXPECT_EQ(node["first"]["i32"], -7);
    EXPECT_EQ(node["first"]["i64"], 5000000001LL);
    EXPECT_EQ(node["first"]["double"], 1.25);
    EXPECT_TRUE(node["first"]["nullObject"].is_null());
    EXPECT_EQ(json["targetTokenId"], UINT32_MAX);
}
} // namespace OHOS::UDMF
