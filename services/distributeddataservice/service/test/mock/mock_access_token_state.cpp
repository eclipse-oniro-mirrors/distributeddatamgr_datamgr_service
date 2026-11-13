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
#include "mock_access_token_state.h"

#include <algorithm>
#include <map>
#include <mutex>

#include "securec.h"
#include "token_setproc.h"

namespace OHOS::Security::AccessToken {
namespace {
struct TokenRecord {
    AccessTokenIDEx id{};
    ATokenTypeEnum type = TOKEN_INVALID;
    HapTokenInfo hap{};
    NativeTokenInfo native{};
    std::map<std::string, int> permissions;
};

struct TokenState {
    std::map<AccessTokenID, TokenRecord> tokens;
    uint32_t next = 1;
    uint64_t self = 0;
};

struct Registry {
    std::mutex mutex;
    TokenState current;
    TokenState saved;
};

Registry &GetRegistry()
{
    // AccountDelegate cleanup may call the token mock during process teardown.
    // Keep the registry alive until process exit so static destruction order
    // cannot invalidate state used by that cleanup.
    static Registry *registry = new Registry();
    return *registry;
}


AccessTokenID NextId(TokenState &state, ATokenTypeEnum type, int dlpType = 0)
{
    AccessTokenIDInner inner{};
    inner.tokenUniqueID = state.next++;
    inner.type = type;
    inner.dlpFlag = dlpType > DLP_COMMON ? 1 : 0;
    inner.version = 1;
    AccessTokenID id = 0;
    static_assert(sizeof(inner) == sizeof(id));
    if (memcpy_s(&id, sizeof(id), &inner, sizeof(inner)) != EOK) {
        return 0;
    }
    return id;
}

void CopyPolicy(TokenRecord &record, const HapPolicyParams &policy)
{
    record.permissions.clear();
    for (const auto &permission : policy.permStateList) {
        auto granted = !permission.grantStatus.empty() &&
            std::all_of(permission.grantStatus.begin(), permission.grantStatus.end(),
                [](int status) { return status == PERMISSION_GRANTED; });
        record.permissions[permission.permissionName] = granted ? PERMISSION_GRANTED : PERMISSION_DENIED;
    }
}

uint64_t AddNative(TokenState &state, const NativeTokenInfoParams &info)
{
    auto iter = std::find_if(state.tokens.begin(), state.tokens.end(), [&info](const auto &entry) {
        return entry.second.type == TOKEN_NATIVE && entry.second.native.processName == info.processName;
    });
    TokenRecord record;
    record.id.tokenIdExStruct.tokenID = iter == state.tokens.end() ? NextId(state, TOKEN_NATIVE) : iter->first;
    record.type = TOKEN_NATIVE;
    record.native.processName = info.processName;
    record.native.apl = APL_SYSTEM_BASIC;
    for (int32_t i = 0; i < info.permsNum; ++i) {
        if (info.perms != nullptr && info.perms[i] != nullptr) {
            record.permissions[info.perms[i]] = PERMISSION_GRANTED;
        }
    }
    state.tokens[record.id.tokenIdExStruct.tokenID] = record;
    return record.id.tokenIDEx;
}

void Initialize(TokenState &state)
{
    if (!state.tokens.empty() || state.next != 1) {
        return;
    }
    for (const auto *name : { "foundation", "distributeddata", "storage_manager", "msdp_sa", "distributed_test" }) {
        NativeTokenInfoParams info{};
        info.processName = name;
        auto id = AddNative(state, info);
        if (state.self == 0) {
            state.self = id;
        }
    }
}
} // namespace

void MockAccessTokenState::Save()
{
    auto &registry = GetRegistry();
    std::lock_guard<std::mutex> lock(registry.mutex);
    Initialize(registry.current);
    registry.saved = registry.current;
}

void MockAccessTokenState::Restore()
{
    auto &registry = GetRegistry();
    std::lock_guard<std::mutex> lock(registry.mutex);
    auto next = registry.current.next;
    registry.current = registry.saved;
    registry.current.next = std::max(next, registry.current.next);
}

AccessTokenIDEx MockAccessTokenState::Allocate(const HapInfoParams &info, const HapPolicyParams &policy)
{
    auto &registry = GetRegistry();
    std::lock_guard<std::mutex> lock(registry.mutex);
    Initialize(registry.current);
    TokenRecord record;
    record.id.tokenIdExStruct.tokenID = NextId(registry.current, TOKEN_HAP, info.dlpType);
    for (const auto &[id, existing] : registry.current.tokens) {
        if (existing.type == TOKEN_HAP && existing.hap.userID == info.userID &&
            existing.hap.bundleName == info.bundleName && existing.hap.instIndex == info.instIndex) {
            record.id.tokenIdExStruct.tokenID = id;
            break;
        }
    }
    record.id.tokenIdExStruct.tokenAttr = info.isSystemApp ? 1 : 0;
    record.type = TOKEN_HAP;
    record.hap.userID = info.userID;
    record.hap.bundleName = info.bundleName;
    record.hap.instIndex = info.instIndex;
    record.hap.apiVersion = info.apiVersion;
    record.hap.dlpType = info.dlpType;
    record.hap.tokenID = record.id.tokenIdExStruct.tokenID;
    record.hap.tokenAttr = record.id.tokenIdExStruct.tokenAttr;
    CopyPolicy(record, policy);
    registry.current.tokens[record.hap.tokenID] = record;
    return record.id;
}

uint64_t MockAccessTokenState::AllocateNative(const NativeTokenInfoParams &info)
{
    if (info.processName == nullptr || info.permsNum < 0) {
        return 0;
    }
    auto &registry = GetRegistry();
    std::lock_guard<std::mutex> lock(registry.mutex);
    Initialize(registry.current);
    return AddNative(registry.current, info);
}

AccessTokenIDEx MockAccessTokenState::FindHap(int user, const std::string &bundle, int instance)
{
    auto &registry = GetRegistry();
    std::lock_guard<std::mutex> lock(registry.mutex);
    Initialize(registry.current);
    for (const auto &[id, record] : registry.current.tokens) {
        if (record.type == TOKEN_HAP && record.hap.userID == user &&
            record.hap.bundleName == bundle && record.hap.instIndex == instance) {
            return record.id;
        }
    }
    return {};
}

int MockAccessTokenState::Delete(AccessTokenID token)
{
    auto &registry = GetRegistry();
    std::lock_guard<std::mutex> lock(registry.mutex);
    Initialize(registry.current);
    return registry.current.tokens.erase(token) == 1 ? RET_SUCCESS : RET_FAILED;
}

ATokenTypeEnum MockAccessTokenState::Type(AccessTokenID token)
{
    auto &registry = GetRegistry();
    std::lock_guard<std::mutex> lock(registry.mutex);
    Initialize(registry.current);
    auto iter = registry.current.tokens.find(token);
    return iter == registry.current.tokens.end() ? TOKEN_INVALID : iter->second.type;
}

int MockAccessTokenState::HapInfo(AccessTokenID token, HapTokenInfo &info)
{
    auto &registry = GetRegistry();
    std::lock_guard<std::mutex> lock(registry.mutex);
    Initialize(registry.current);
    auto iter = registry.current.tokens.find(token);
    if (iter == registry.current.tokens.end() || iter->second.type != TOKEN_HAP) {
        return RET_FAILED;
    }
    info = iter->second.hap;
    return RET_SUCCESS;
}

int MockAccessTokenState::NativeInfo(AccessTokenID token, NativeTokenInfo &info)
{
    auto &registry = GetRegistry();
    std::lock_guard<std::mutex> lock(registry.mutex);
    Initialize(registry.current);
    auto iter = registry.current.tokens.find(token);
    if (iter == registry.current.tokens.end() || iter->second.type != TOKEN_NATIVE) {
        return RET_FAILED;
    }
    info = iter->second.native;
    return RET_SUCCESS;
}

int MockAccessTokenState::Verify(AccessTokenID token, const std::string &permission)
{
    auto &registry = GetRegistry();
    std::lock_guard<std::mutex> lock(registry.mutex);
    Initialize(registry.current);
    auto iter = registry.current.tokens.find(token);
    if (iter == registry.current.tokens.end()) {
        return PERMISSION_DENIED;
    }
    auto grant = iter->second.permissions.find(permission);
    return grant == iter->second.permissions.end() ? PERMISSION_DENIED : grant->second;
}

int MockAccessTokenState::SetPermission(AccessTokenID token, const std::string &permission, int status)
{
    auto &registry = GetRegistry();
    std::lock_guard<std::mutex> lock(registry.mutex);
    auto iter = registry.current.tokens.find(token);
    if (iter == registry.current.tokens.end() || permission.empty()) {
        return RET_FAILED;
    }
    iter->second.permissions[permission] = status;
    return RET_SUCCESS;
}

bool MockAccessTokenState::IsSystem(uint64_t token)
{
    AccessTokenIDEx id{};
    id.tokenIDEx = token;
    return (id.tokenIdExStruct.tokenAttr & 1) != 0;
}

uint64_t MockAccessTokenState::Self()
{
    auto &registry = GetRegistry();
    std::lock_guard<std::mutex> lock(registry.mutex);
    Initialize(registry.current);
    return registry.current.self;
}

void MockAccessTokenState::SetSelf(uint64_t token)
{
    auto &registry = GetRegistry();
    std::lock_guard<std::mutex> lock(registry.mutex);
    Initialize(registry.current);
    registry.current.self = token;
}

} // namespace OHOS::Security::AccessToken
