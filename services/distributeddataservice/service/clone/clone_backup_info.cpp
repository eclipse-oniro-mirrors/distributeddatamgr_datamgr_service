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
#include "clone_backup_info.h"

namespace OHOS {
namespace DistributedData {
bool CloneEncryptionInfo::Unmarshal(const json &node)
{
    bool res = GetValue(node, "encryption_symkey", symkey);
    res = GetValue(node, "encryption_algname", algName) && res;
    res = GetValue(node, "gcmParams_iv", iv) && res;
    return res;
}

bool CloneEncryptionInfo::Marshal(json &node) const
{
    return false;
}

CloneEncryptionInfo::~CloneEncryptionInfo()
{
    symkey.assign(symkey.size(), 0);
    algName.assign(algName.size(), 0);
    iv.assign(iv.size(), 0);
}

bool CloneBundleInfo::Unmarshal(const json &node)
{
    bool res = GetValue(node, GET_NAME(bundleName), bundleName);
    res = GetValue(node, GET_NAME(accessTokenId), accessTokenId) && res;
    return res;
}

bool CloneBundleInfo::Marshal(json &node) const
{
    return false;
}

bool CloneBackupInfo::Unmarshal(const json &node)
{
    auto items = DistributedData::Serializable::ToJson(node);
    // Parses a list of typed entries ({"type": ..., "detail": ...}) shared by both input
    // shapes: the framework's nested unicast "details" list and the legacy flat array.
    auto parseDetails = [this](const json &entries) {
        std::string type;
        for (const auto &entry : entries) {
            if (!GetValue(entry, GET_NAME(type), type) || type.empty()) {
                continue;
            }
            if (type == "encryption_info") {
                GetValue(entry, "detail", encryptionInfo);
            } else if (type == "application_selection") {
                GetValue(entry, "detail", bundleInfos);
            } else if (type == "user_info" || type == "userId") {
                GetValue(entry, "detail", userId);
            } else if (type == "OSVersion") {
                GetValue(entry, "detail", osVersion);
            }
        }
    };
    if (items.is_array()) {
        // Legacy shape: a flat top-level array of typed entries.
        parseDetails(items);
        return true;
    }
    if (!items.is_object()) {
        return false;
    }
    // Framework shape: {"infos": [{"type": "unicast", "details": [typed entries...]}, ...],
    // "concurrentId": "..."}; the peer OS version arrives as an "OSVersion" entry.
    auto infos = items.find("infos");
    if (infos == items.end() || !infos->is_array()) {
        return false;
    }
    for (const auto &info : *infos) {
        auto details = info.find("details");
        if (details != info.end() && details->is_array()) {
            parseDetails(*details);
        }
    }
    return true;
}

bool CloneBackupInfo::Marshal(json &node) const
{
    return false;
}

bool CloneReplyResult::Marshal(json &node) const
{
    SetValue(node[GET_NAME(type)], type);
    SetValue(node[GET_NAME(errorCode)], errorCode);
    SetValue(node[GET_NAME(errorInfo)], errorInfo);
    return true;
}

bool CloneReplyResult::Unmarshal(const json &node)
{
    return false;
}

bool CloneReplyCode::Marshal(json &node) const
{
    SetValue(node[GET_NAME(resultInfo)], resultInfo);
    return true;
}

bool CloneReplyCode::Unmarshal(const json &node)
{
    return false;
}
} // namespace DistributedData
} // namespace OHOS
