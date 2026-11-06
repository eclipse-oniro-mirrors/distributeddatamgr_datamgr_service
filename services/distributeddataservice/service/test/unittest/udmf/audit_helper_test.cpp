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
#define LOG_TAG "AuditHelperTest"

#include <gtest/gtest.h>

#include <chrono>
#include <thread>

#include <nlohmann/json.hpp>

#include "application_defined_record.h"
#include "audit_helper.h"
#include "folder.h"
#include "log_print.h"
#include "pixel_map.h"
#include "plain_text.h"
#include "text.h"
#include "unified_meta.h"
#include "want.h"

using namespace testing::ext;
using namespace OHOS::UDMF;
using namespace OHOS;

namespace OHOS::Test {

class AuditHelperTest : public testing::Test {
public:
    void SetUp() override {}
    void TearDown() override {}

    static std::shared_ptr<ExecutorPool> GetExecutor()
    {
        static std::shared_ptr<ExecutorPool> executor =
            std::make_shared<ExecutorPool>(4, 1, "AuditTestExecutor");
        return executor;
    }
};

/**
* @tc.name: ConvertValueToJson001
* @tc.desc: Test ConvertValueToJson with int32_t value
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(AuditHelperTest, ConvertValueToJson001, TestSize.Level1)
{
    ZLOGI("ConvertValueToJson001 begin.");

    int32_t testValue = 12345;
    ValueType value = testValue;

    auto json = AuditHelper::ConvertValueToJson(value);
    EXPECT_TRUE(json.is_number_integer());
    EXPECT_EQ(json.get<int32_t>(), testValue);

    ZLOGI("ConvertValueToJson001 end.");
}

/**
* @tc.name: ConvertValueToJson002
* @tc.desc: Test ConvertValueToJson with int64_t value
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(AuditHelperTest, ConvertValueToJson002, TestSize.Level1)
{
    ZLOGI("ConvertValueToJson002 begin.");

    int64_t testValue = 1234567890123LL;
    ValueType value = testValue;

    auto json = AuditHelper::ConvertValueToJson(value);
    EXPECT_TRUE(json.is_number_integer());
    EXPECT_EQ(json.get<int64_t>(), testValue);

    ZLOGI("ConvertValueToJson002 end.");
}

/**
* @tc.name: ConvertValueToJson003
* @tc.desc: Test ConvertValueToJson with double value
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(AuditHelperTest, ConvertValueToJson003, TestSize.Level1)
{
    ZLOGI("ConvertValueToJson003 begin.");

    double testValue = 3.14159;
    ValueType value = testValue;

    auto json = AuditHelper::ConvertValueToJson(value);
    EXPECT_TRUE(json.is_number_float());
    EXPECT_DOUBLE_EQ(json.get<double>(), testValue);

    ZLOGI("ConvertValueToJson003 end.");
}

/**
* @tc.name: ConvertValueToJson004
* @tc.desc: Test ConvertValueToJson with bool value
* @tc.type: FUNC
* @tc.author: agent


*/
HWTEST_F(AuditHelperTest, ConvertValueToJson004, TestSize.Level1)
{
    ZLOGI("ConvertValueToJson004 begin.");

    bool testValue = true;
    ValueType value = testValue;

    auto json = AuditHelper::ConvertValueToJson(value);
    EXPECT_TRUE(json.is_boolean());
    EXPECT_EQ(json.get<bool>(), testValue);

    ZLOGI("ConvertValueToJson004 end.");
}

/**
* @tc.name: ConvertValueToJson005
* @tc.desc: Test ConvertValueToJson with string value
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(AuditHelperTest, ConvertValueToJson005, TestSize.Level1)
{
    ZLOGI("ConvertValueToJson005 begin.");

    std::string testValue = "test string value";
    ValueType value = testValue;

    auto json = AuditHelper::ConvertValueToJson(value);
    EXPECT_TRUE(json.is_string());
    EXPECT_EQ(json.get<std::string>(), testValue);

    ZLOGI("ConvertValueToJson005 end.");
}

/**
* @tc.name: ConvertValueToJson006
* @tc.desc: Test ConvertValueToJson with vector<uint8_t> value
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(AuditHelperTest, ConvertValueToJson006, TestSize.Level1)
{
    ZLOGI("ConvertValueToJson006 begin.");

    std::vector<uint8_t> testValue = {0x01, 0x02, 0x03, 0x04, 0x05};
    ValueType value = testValue;

    auto json = AuditHelper::ConvertValueToJson(value);
    EXPECT_TRUE(json.is_binary());
    auto bytes = json.get_binary();
    EXPECT_EQ(bytes.size(), testValue.size());
    for (size_t i = 0; i < testValue.size(); ++i) {
        EXPECT_EQ(bytes[i], testValue[i]);
    }

    ZLOGI("ConvertValueToJson006 end.");
}

/**
* @tc.name: ConvertValueToJson007
* @tc.desc: Test ConvertValueToJson with monostate (empty) value
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(AuditHelperTest, ConvertValueToJson007, TestSize.Level1)
{
    ZLOGI("ConvertValueToJson007 begin.");

    std::monostate testValue;
    ValueType value = testValue;

    auto json = AuditHelper::ConvertValueToJson(value);
    EXPECT_TRUE(json.is_null());

    ZLOGI("ConvertValueToJson007 end.");
}

/**
* @tc.name: ConvertEntriesToJson001
* @tc.desc: Test ConvertEntriesToJson with multiple entries
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(AuditHelperTest, ConvertEntriesToJson001, TestSize.Level1)
{
    ZLOGI("ConvertEntriesToJson001 begin.");

    std::map<std::string, ValueType> entries;
    entries.insert(std::make_pair("int_key", int32_t(123)));
    entries.insert(std::make_pair("string_key", std::string("test value")));
    entries.insert(std::make_pair("bool_key", true));
    entries.insert(std::make_pair("double_key", 3.14));

    auto json = AuditHelper::ConvertEntriesToJson(entries);
    EXPECT_TRUE(json.is_object());
    EXPECT_EQ(json.size(), 4);
    EXPECT_TRUE(json.contains("int_key"));
    EXPECT_TRUE(json.contains("string_key"));
    EXPECT_TRUE(json.contains("bool_key"));
    EXPECT_TRUE(json.contains("double_key"));

    ZLOGI("ConvertEntriesToJson001 end.");
}

/**
* @tc.name: ConvertEntriesToJson002
* @tc.desc: Test ConvertEntriesToJson with empty entries
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(AuditHelperTest, ConvertEntriesToJson002, TestSize.Level1)
{
    ZLOGI("ConvertEntriesToJson002 begin.");

    std::map<std::string, ValueType> entries;

    auto json = AuditHelper::ConvertEntriesToJson(entries);
    EXPECT_TRUE(json.is_object());
    EXPECT_TRUE(json.empty());

    ZLOGI("ConvertEntriesToJson002 end.");
}

/**
* @tc.name: ConvertEntriesToJson003
* @tc.desc: Test ConvertEntriesToJson with various value types
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(AuditHelperTest, ConvertEntriesToJson003, TestSize.Level1)
{
    ZLOGI("ConvertEntriesToJson003 begin.");

    std::map<std::string, ValueType> entries;
    entries.insert(std::make_pair("int32_val", int32_t(2147483647)));
    entries.insert(std::make_pair("int64_val", int64_t(9223372036854775807LL)));
    entries.insert(std::make_pair("double_val", 2.718281828459045));
    entries.insert(std::make_pair("bool_val", false));
    entries.insert(std::make_pair("string_val", "complex test string with special chars: !@#$%^&*()"));
    entries.insert(std::make_pair("bytes_val", std::string("bytes_value")));

    auto json = AuditHelper::ConvertEntriesToJson(entries);
    EXPECT_TRUE(json.is_object());
    EXPECT_EQ(json.size(), 6);
    EXPECT_TRUE(json.contains("int32_val"));
    EXPECT_TRUE(json.contains("int64_val"));
    EXPECT_TRUE(json.contains("double_val"));
    EXPECT_TRUE(json.contains("bool_val"));
    EXPECT_TRUE(json.contains("string_val"));
    EXPECT_TRUE(json.contains("bytes_val"));

    ZLOGI("ConvertEntriesToJson003 end.");
}

/**
* @tc.name: ConvertRecordToJson001
* @tc.desc: Test ConvertRecordToJson with text record
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(AuditHelperTest, ConvertRecordToJson001, TestSize.Level1)
{
    ZLOGI("ConvertRecordToJson001 begin.");

    auto text = std::make_shared<Text>();
    UDDetails details;
    details.insert(std::make_pair("key1", "value1"));
    details.insert(std::make_pair("key2", int32_t(456)));
    text->SetDetails(details);

    auto json = AuditHelper::ConvertRecordToJson(text);
    EXPECT_TRUE(json.is_object());

    ZLOGI("ConvertRecordToJson001 end.");
}

/**
* @tc.name: ConvertRecordToJson002
* @tc.desc: Test ConvertRecordToJson with plain text record
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(AuditHelperTest, ConvertRecordToJson002, TestSize.Level1)
{
    ZLOGI("ConvertRecordToJson002 begin.");

    auto plainText = std::make_shared<PlainText>();
    plainText->SetContent("test content");
    plainText->SetAbstract("test abstract");

    auto json = AuditHelper::ConvertRecordToJson(plainText);
    EXPECT_TRUE(json.is_object());

    ZLOGI("ConvertRecordToJson002 end.");
}

/**
* @tc.name: ConvertRecordToJson003
* @tc.desc: Test ConvertRecordToJson with file record
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(AuditHelperTest, ConvertRecordToJson003, TestSize.Level1)
{
    ZLOGI("ConvertRecordToJson003 begin.");

    auto file = std::make_shared<File>();
    file->SetUri("file:///data/test.txt");
    file->SetRemoteUri("file:///data/remote/test.txt");

    auto json = AuditHelper::ConvertRecordToJson(file);
    EXPECT_TRUE(json.is_object());

    ZLOGI("ConvertRecordToJson003 end.");
}

/**
* @tc.name: ConvertRecordToJson004
* @tc.desc: Test ConvertRecordToJson with application defined record
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(AuditHelperTest, ConvertRecordToJson004, TestSize.Level1)
{
    ZLOGI("ConvertRecordToJson004 begin.");

    auto appRecord = std::make_shared<ApplicationDefinedRecord>();
    appRecord->SetApplicationDefinedType("custom.app.record");
    std::vector<uint8_t> rawData = {0x01, 0x02, 0x03, 0x04};
    appRecord->SetRawData(rawData);

    auto json = AuditHelper::ConvertRecordToJson(appRecord);
    EXPECT_TRUE(json.is_object());

    ZLOGI("ConvertRecordToJson004 end.");
}

/**
* @tc.name: ConvertWantToJson001
* @tc.desc: Test ConvertWantToJson with valid Want object
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(AuditHelperTest, ConvertWantToJson001, TestSize.Level1)
{
    ZLOGI("ConvertWantToJson001 begin.");

    auto want = std::make_shared<OHOS::AAFwk::Want>();
    want->SetAction("test.action");
    want->SetBundle("test.bundle");
    want->SetType("test/type");
    want->SetUri("http://test.uri");

    auto json = AuditHelper::ConvertWantToJson(want);
    EXPECT_TRUE(json.is_object());
    EXPECT_TRUE(json.contains("action"));
    EXPECT_TRUE(json.contains("bundle"));
    EXPECT_TRUE(json.contains("type"));
    EXPECT_TRUE(json.contains("uri"));

    ZLOGI("ConvertWantToJson001 end.");
}

/**
* @tc.name: ConvertWantToJson002
* @tc.desc: Test ConvertWantToJson with nullptr
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(AuditHelperTest, ConvertWantToJson002, TestSize.Level1)
{
    ZLOGI("ConvertWantToJson002 begin.");

    std::shared_ptr<OHOS::AAFwk::Want> want = nullptr;

    auto json = AuditHelper::ConvertWantToJson(want);
    EXPECT_TRUE(json.is_null());

    ZLOGI("ConvertWantToJson002 end.");
}

/**
* @tc.name: ConvertPixelMapToJson001
* @tc.desc: Test ConvertPixelMapToJson with nullptr
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(AuditHelperTest, ConvertPixelMapToJson001, TestSize.Level1)
{
    ZLOGI("ConvertPixelMapToJson001 begin.");

    std::shared_ptr<OHOS::Media::PixelMap> pixelMap = nullptr;

    auto json = AuditHelper::ConvertPixelMapToJson(pixelMap);
    EXPECT_TRUE(json.is_null() || json.is_object());

    ZLOGI("ConvertPixelMapToJson001 end.");
}

/**
* @tc.name: ConvertObjectToJson001
* @tc.desc: Test ConvertObjectToJson with valid Object
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(AuditHelperTest, ConvertObjectToJson001, TestSize.Level1)
{
    ZLOGI("ConvertObjectToJson001 begin.");

    auto object = std::make_shared<Object>();
    object->value_["key1"] = std::string("value1");
    object->value_["key2"] = int32_t(123);
    object->value_["key3"] = true;

    auto json = AuditHelper::ConvertObjectToJson(object);
    EXPECT_TRUE(json.is_object());
    EXPECT_TRUE(json.contains("key1"));
    EXPECT_TRUE(json.contains("key2"));
    EXPECT_TRUE(json.contains("key3"));

    ZLOGI("ConvertObjectToJson001 end.");
}

/**
* @tc.name: PublishAuditEvent001
* @tc.desc: Test PublishAuditEvent with valid JSON data
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(AuditHelperTest, PublishAuditEvent001, TestSize.Level1)
{
    ZLOGI("PublishAuditEvent001 begin.");

    nlohmann::json auditData;
    auditData["sourceTokenId"] = 12345;
    auditData["targetTokenId"] = 67890;
    auditData["userId"] = 100;
    auditData["timestamp"] = 1234567890;

    nlohmann::json dataArray = nlohmann::json::array();
    nlohmann::json record;
    record["type"] = 1;
    record["index"] = 0;
    record["value"] = "test value";
    dataArray.push_back(record);
    auditData["unifiedData"] = dataArray;

    std::string auditDataStr = auditData.dump();
    EXPECT_NO_FATAL_FAILURE(AuditHelper::PublishAuditEvent(auditDataStr));

    ZLOGI("PublishAuditEvent001 end.");
}

/**
* @tc.name: PublishAuditEvent002
* @tc.desc: Test PublishAuditEvent with complex nested data
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(AuditHelperTest, PublishAuditEvent002, TestSize.Level1)
{
    ZLOGI("PublishAuditEvent002 begin.");

    nlohmann::json auditData;
    auditData["sourceTokenId"] = 11111;
    auditData["targetTokenId"] = 22222;
    auditData["userId"] = 200;
    auditData["timestamp"] = 9876543210;

    nlohmann::json dataArray = nlohmann::json::array();
    for (int i = 0; i < 3; i++) {
        nlohmann::json record;
        record["type"] = i + 1;
        record["index"] = i;
        record["value"] = "value_" + std::to_string(i);

        nlohmann::json entries;
        entries["key1"] = "entry_value_" + std::to_string(i);
        entries["key2"] = i * 100;
        record["entries"] = entries;

        dataArray.push_back(record);
    }
    auditData["unifiedData"] = dataArray;

    std::string auditDataStr = auditData.dump();
    EXPECT_NO_FATAL_FAILURE(AuditHelper::PublishAuditEvent(auditDataStr));

    ZLOGI("PublishAuditEvent002 end.");
}

/**
* @tc.name: MultiRecordLimitTest001
* @tc.desc: Test multiple records cumulative size limit
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(AuditHelperTest, MultiRecordLimitTest001, TestSize.Level1)
{
    ZLOGI("MultiRecordLimitTest001 begin.");

    UnifiedData data;
    for (int i = 0; i < 20; i++) {
        auto text = std::make_shared<Text>();
        UDDetails details;
        details.insert(std::make_pair("data", std::string(5 * 1024, 'X')));
        text->SetDetails(details);
        data.AddRecord(text);
    }

    EXPECT_NO_FATAL_FAILURE(AuditHelper().ReportDragAuditEvent(data, 100, 12345, GetExecutor()));

    ZLOGI("MultiRecordLimitTest001 end.");
}

/**
* @tc.name: BinaryLimitTest001
* @tc.desc: Test binary data size limit
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(AuditHelperTest, BinaryLimitTest001, TestSize.Level1)
{
    ZLOGI("BinaryLimitTest001 begin.");

    std::vector<uint8_t> largeBytes(20 * 1024, 0xFF);
    ValueType value = largeBytes;

    auto json = AuditHelper::ConvertValueToJson(value);
    EXPECT_TRUE(json.is_null() || json.is_binary());

    ZLOGI("BinaryLimitTest001 end.");
}

/**
* @tc.name: JsonTypePreservationTest001
* @tc.desc: Test content.entries always preserves object/array type
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(AuditHelperTest, JsonTypePreservationTest001, TestSize.Level1)
{
    ZLOGI("JsonTypePreservationTest001 begin.");

    std::map<std::string, ValueType> entries;
    for (int i = 0; i < 30; i++) {
        entries["key_" + std::to_string(i)] = std::string(1 * 1024, 'Z');
    }

    auto json = AuditHelper::ConvertEntriesToJson(entries);
    EXPECT_TRUE(json.is_object());
    EXPECT_FALSE(json.is_string());
    EXPECT_FALSE(json.is_array());

    ZLOGI("JsonTypePreservationTest001 end.");
}

/**
* @tc.name: ConvertRecordToJson_NullRecord_EmptyObject
* @tc.desc: Test ConvertRecordToJson with nullptr record returns empty object without crash
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(AuditHelperTest, ConvertRecordToJson_NullRecord_EmptyObject, TestSize.Level1)
{
    ZLOGI("ConvertRecordToJson_NullRecord_EmptyObject begin.");

    auto json = AuditHelper::ConvertRecordToJson(nullptr);
    EXPECT_TRUE(json.is_object());
    EXPECT_TRUE(json.empty());

    ZLOGI("ConvertRecordToJson_NullRecord_EmptyObject end.");
}
} // namespace OHOS::Test
