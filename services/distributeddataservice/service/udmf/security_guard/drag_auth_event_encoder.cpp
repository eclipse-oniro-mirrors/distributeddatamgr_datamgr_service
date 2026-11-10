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

#include "drag_auth_event_encoder.h"

#include <algorithm>
#include <map>
#include <string>
#include <type_traits>
#include <unordered_set>
#include <utility>
#include <variant>
#include <vector>

#include "pixel_map.h"
#include "unified_data.h"
#include "want.h"
namespace OHOS::UDMF {
namespace {
using Json = DistributedData::Serializable::json;
constexpr size_t MAX_OBJECT_DEPTH = 64;
constexpr size_t JSON_OBJECT_BRACES_BYTES = 2;
constexpr size_t JSON_MEMBER_SEPARATOR_BYTES = 1;
constexpr size_t JSON_KEY_VALUE_SEPARATOR_BYTES = 1;
class ContentBudget {
public:
    bool Consume(size_t bytes)
    {
        if (bytes > remaining_) {
            return false;
        }
        remaining_ -= bytes;
        return true;
    }
    bool ConsumeJson(const Json &node)
    {
        return Consume(node.dump(-1, ' ', false, DistributedData::Serializable::error_handler_t::replace).size());
    }
    size_t Remaining() const
    {
        return remaining_;
    }

private:
    size_t remaining_ = DRAG_AUTH_MAX_CONTENT_BYTES;
};
size_t Utf8PrefixLength(const std::string &value, size_t length)
{
    if (length >= value.size()) {
        return value.size();
    }
    while (length > 0 && (static_cast<unsigned char>(value[length]) & 0xc0) == 0x80) {
        --length;
    }
    return length;
}

AuthBuildStatus EncodeTextPreview(const std::string &value, Json &output, ContentBudget &budget)
{
    if (budget.Remaining() >= 2 && value.size() <= budget.Remaining() - 2) {
        Json complete = value;
        if (budget.ConsumeJson(complete)) {
            output = std::move(complete);
            return AuthBuildStatus::SUCCESS;
        }
    }
    size_t low = 0;
    size_t high = std::min(value.size(), budget.Remaining());
    while (low < high) {
        size_t length = Utf8PrefixLength(value, low + (high - low + 1) / 2);
        Json candidate = value.substr(0, length);
        if (candidate.dump(-1, ' ', false, DistributedData::Serializable::error_handler_t::replace).size() <=
            budget.Remaining()) {
            low = low + (high - low + 1) / 2;
        } else {
            high = low + (high - low + 1) / 2 - 1;
        }
    }
    output = value.substr(0, Utf8PrefixLength(value, low));
    if (!budget.ConsumeJson(output)) {
        return AuthBuildStatus::TOO_LARGE;
    }
    return low == value.size() ? AuthBuildStatus::SUCCESS : AuthBuildStatus::TOO_LARGE;
}
AuthBuildStatus EncodeBinaryPreview(const std::vector<uint8_t> &value, Json &output, ContentBudget &budget)
{
    size_t low = 0;
    size_t high = std::min(value.size(), budget.Remaining());
    while (low < high) {
        size_t middle = low + (high - low + 1) / 2;
        Json candidate = Json::binary(std::vector<uint8_t>(value.begin(), value.begin() + middle));
        if (candidate.dump().size() <= budget.Remaining()) {
            low = middle;
        } else {
            high = middle - 1;
        }
    }
    output = Json::binary(std::vector<uint8_t>(value.begin(), value.begin() + low));
    if (!budget.ConsumeJson(output)) {
        return AuthBuildStatus::TOO_LARGE;
    }
    return low == value.size() ? AuthBuildStatus::SUCCESS : AuthBuildStatus::TOO_LARGE;
}
AuthBuildStatus EncodeValue(const ValueType &value, Json &output, ContentBudget &budget,
    std::unordered_set<const Object *> &active, size_t depth);
AuthBuildStatus EncodeEntries(const std::map<std::string, ValueType> &entries, Json &output, ContentBudget &budget,
    std::unordered_set<const Object *> &active, size_t depth)
{
    output = Json::object();
    if (!budget.Consume(JSON_OBJECT_BRACES_BYTES)) {
        return AuthBuildStatus::TOO_LARGE;
    }
    for (const auto &[key, value] : entries) {
        if (key.size() > DRAG_AUTH_MAX_CONTENT_BYTES || !budget.ConsumeJson(Json(key)) ||
            !budget.Consume(JSON_KEY_VALUE_SEPARATOR_BYTES + (output.empty() ? 0 : JSON_MEMBER_SEPARATOR_BYTES))) {
            return AuthBuildStatus::TOO_LARGE;
        }
        Json encoded;
        auto before = budget.Remaining();
        auto status = EncodeValue(value, encoded, budget, active, depth + 1);
        if (status == AuthBuildStatus::INVALID_DATA || status == AuthBuildStatus::INVALID_ENCODING) {
            return status;
        }
        if (status == AuthBuildStatus::SUCCESS || budget.Remaining() < before) {
            output[key] = std::move(encoded);
        }
        if (status == AuthBuildStatus::TOO_LARGE) {
            return status;
        }
    }
    return AuthBuildStatus::SUCCESS;
}
AuthBuildStatus EncodeWant(const std::shared_ptr<AAFwk::Want> &want, Json &output)
{
    if (!want) {
        output = nullptr;
        return AuthBuildStatus::SUCCESS;
    }
    auto text = want->ToString();
    output = { { "kind", "want" }, { "value", std::move(text) } };
    return AuthBuildStatus::SUCCESS;
}

AuthBuildStatus EncodePixelMap(const std::shared_ptr<Media::PixelMap> &pixels, Json &output)
{
    if (!pixels) {
        output = nullptr;
        return AuthBuildStatus::SUCCESS;
    }
    auto bytes = pixels->GetByteCount();
    if (bytes < 0) {
        return AuthBuildStatus::INVALID_DATA;
    }
    if (static_cast<size_t>(bytes) > DRAG_AUTH_MAX_CONTENT_BYTES) {
        output = { { "kind", "pixelmap-tlv" }, { "value", Json::binary(std::vector<uint8_t>{}) } };
        return AuthBuildStatus::SUCCESS;
    }
    std::vector<uint8_t> encoded;
    if (!pixels->EncodeTlv(encoded)) {
        return AuthBuildStatus::INVALID_DATA;
    }
    output = { { "kind", "pixelmap-tlv" }, { "value", Json::binary(encoded) } };
    return AuthBuildStatus::SUCCESS;
}

AuthBuildStatus EncodeLeafValue(const ValueType &value, Json &output)
{
    if (std::holds_alternative<std::shared_ptr<AAFwk::Want>>(value)) {
        return EncodeWant(std::get<std::shared_ptr<AAFwk::Want>>(value), output);
    } else if (std::holds_alternative<std::shared_ptr<Media::PixelMap>>(value)) {
        return EncodePixelMap(std::get<std::shared_ptr<Media::PixelMap>>(value), output);
    } else {
        std::visit(
            [&output](const auto &item) {
                using T = std::decay_t<decltype(item)>;
                if constexpr (std::is_arithmetic_v<T>) {
                    output = item;
                } else {
                    output = nullptr;
                }
            },
            value);
    }
    return AuthBuildStatus::SUCCESS;
}

AuthBuildStatus EncodeTypedPreview(Json &output, ContentBudget &budget)
{
    auto overhead = Json({ { "kind", output["kind"] }, { "value", "" } }).dump().size() - 2;
    size_t minimum = output["value"].is_string() ? 2 : Json::binary(std::vector<uint8_t>{}).dump().size();
    if (overhead + minimum > budget.Remaining()) {
        return AuthBuildStatus::TOO_LARGE;
    }
    budget.Consume(overhead);
    if (output["value"].is_string()) {
        auto source = std::move(output["value"].get_ref<std::string &>());
        return EncodeTextPreview(source, output["value"], budget);
    }
    if (output["value"].is_binary()) {
        auto source = std::move(output["value"].get_binary());
        return EncodeBinaryPreview(source, output["value"], budget);
    }
    return AuthBuildStatus::INVALID_DATA;
}

AuthBuildStatus EncodeValue(const ValueType &value, Json &output, ContentBudget &budget,
    std::unordered_set<const Object *> &active, size_t depth)
{
    if (depth > MAX_OBJECT_DEPTH) {
        return AuthBuildStatus::INVALID_ENCODING;
    }
    if (std::holds_alternative<std::shared_ptr<Object>>(value)) {
        auto object = std::get<std::shared_ptr<Object>>(value);
        if (object) {
            if (!active.insert(object.get()).second) {
                return AuthBuildStatus::INVALID_ENCODING;
            }
            auto status = EncodeEntries(object->value_, output, budget, active, depth);
            active.erase(object.get());
            return status;
        }
        output = nullptr;
    } else if (std::holds_alternative<std::string>(value)) {
        return EncodeTextPreview(std::get<std::string>(value), output, budget);
    } else if (std::holds_alternative<std::vector<uint8_t>>(value)) {
        return EncodeBinaryPreview(std::get<std::vector<uint8_t>>(value), output, budget);
    } else {
        auto status = EncodeLeafValue(value, output);
        if (status != AuthBuildStatus::SUCCESS) {
            return status;
        }
        if (output.is_object() && output.contains("kind") && output.contains("value")) {
            return EncodeTypedPreview(output, budget);
        }
    }
    return budget.ConsumeJson(output) ? AuthBuildStatus::SUCCESS : AuthBuildStatus::TOO_LARGE;
}

AuthBuildStatus EncodeRecord(const std::shared_ptr<UnifiedRecord> &record, Json &encodedRecords, ContentBudget &budget,
    std::unordered_set<const Object *> &active)
{
    if (!record) {
        return AuthBuildStatus::INVALID_DATA;
    }
    // A negative size is malformed; large records are encoded as a bounded preview.
    auto sourceBytes = record->GetSize();
    if (sourceBytes < 0) {
        return AuthBuildStatus::INVALID_ENCODING;
    }
    auto type = record->GetUtdId();
    if (type.size() > DRAG_AUTH_MAX_CONTENT_BYTES) {
        return AuthBuildStatus::TOO_LARGE;
    }
    Json node = { { "utdId", std::move(type) }, { "entries", Json::object() } };
    // EncodeEntries charges its own object braces; the surrounding array charges commas here.
    auto overhead = node.dump(-1, ' ', false, DistributedData::Serializable::error_handler_t::replace).size() -
                    JSON_OBJECT_BRACES_BYTES;
    if (!encodedRecords.empty()) {
        overhead += JSON_MEMBER_SEPARATOR_BYTES;
    }
    if (budget.Remaining() < overhead + JSON_OBJECT_BRACES_BYTES || !budget.Consume(overhead)) {
        return AuthBuildStatus::TOO_LARGE;
    }
    auto entries = record->GetEntries();
    if (!entries) {
        return AuthBuildStatus::INVALID_DATA;
    }
    auto status = EncodeEntries(*entries, node["entries"], budget, active, 0);
    if (status == AuthBuildStatus::INVALID_DATA || status == AuthBuildStatus::INVALID_ENCODING) {
        return status;
    }
    encodedRecords.push_back(std::move(node));
    return status;
}
} // namespace
AuthBuildStatus EncodeDragAuthContent(const DragAuthContext &context, Json &content)
{
    if (!context.data) {
        return AuthBuildStatus::INVALID_DATA;
    }
    Json root = { { "sourceTokenId", context.sourceTokenId }, { "targetTokenId", context.targetTokenId },
        { "content", { { "entries", Json::array() } } } };
    ContentBudget budget;
    if (!budget.ConsumeJson(root)) {
        return AuthBuildStatus::TOO_LARGE;
    }
    std::unordered_set<const Object *> active;
    auto records = context.data->GetRecords();
    for (const auto &record : records) {
        auto status = EncodeRecord(record, root["content"]["entries"], budget, active);
        if (status == AuthBuildStatus::INVALID_DATA || status == AuthBuildStatus::INVALID_ENCODING) {
            return status;
        }
        if (status == AuthBuildStatus::TOO_LARGE) {
            break;
        }
    }
    content = std::move(root);
    return AuthBuildStatus::SUCCESS;
}
std::shared_ptr<const AuthEventBuilder> CreateDragAuthEventBuilder()
{
    AuthEventContract contract;
    contract.encode = EncodeDragAuthContent;
    return std::make_shared<AuthEventBuilder>(std::move(contract));
}
} // namespace OHOS::UDMF
