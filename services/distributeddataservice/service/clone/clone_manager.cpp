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
#define LOG_TAG "CloneManager"
#include "clone_manager.h"

#include <cerrno>
#include <cstdlib>
#include <fcntl.h>

#include "crypto/crypto_manager.h"
#include "dfx/reporter.h"
#include "hisysevent.h"
#include "unique_fd.h"
#include "directory/directory_manager.h"
#include "log_print.h"
#include "metadata/meta_data_manager.h"
#include "utils/anonymous.h"
#include "utils/base64_utils.h"
#include "utils/constant.h"
#include "utils/secure_clear_guard.h"

namespace OHOS::DistributedKv {
using namespace OHOS::DistributedData;
using namespace OHOS::DistributedDataDfx;
using SecretKeyMeta = DistributedData::SecretKeyMetaData;

constexpr const char *CLONE_KEY_ALIAS = "distributed_db_backup_key";
constexpr int KEY_SIZE = 32;
// The shared iv is the backup framework's existing protocol field and keeps its legacy
// 32-byte length; the per-item nonce is generated locally with the GCM-standard 12-byte
// size used by CryptoManager's random-nonce path, so the two lengths intentionally differ.
constexpr int AES_256_NONCE_SIZE = 32;
constexpr int AES_GCM_NONCE_SIZE = 12;
// The new per-item-nonce backup format starts at peer OS version 7.1.
constexpr long NEW_FORMAT_VERSION_MAJOR = 7;
constexpr long NEW_FORMAT_VERSION_MINOR = 1;
// A parseable OS version needs at least "major.minor".
constexpr size_t MIN_VERSION_SEGMENTS = 2;

std::string GetBackupReplyCode(int replyCode, const std::string &info)
{
    CloneReplyCode reply;
    CloneReplyResult result;
    result.errorCode = std::to_string(replyCode);
    result.errorInfo = info;
    reply.resultInfo.push_back(std::move(result));
    return Serializable::Marshall(reply);
}

std::vector<uint8_t> ConvertDecStrToVec(const std::string &inData)
{
    std::vector<uint8_t> outData;
    auto splitedToken = Constant::Split(inData, ",");
    outData.reserve(splitedToken.size());
    for (auto &token : splitedToken) {
        outData.push_back(static_cast<uint8_t>(atoi(token.c_str())));
    }
    return outData;
}

bool ImportCloneKey(const std::string &keyStr)
{
    auto key = ConvertDecStrToVec(keyStr);
    SecureClearGuard<std::vector<uint8_t>> keyGuard(key);
    if (key.size() != KEY_SIZE) {
        ZLOGE("ImportKey failed, key size not correct, key size:%{public}zu", key.size());
        return false;
    }

    auto cloneKeyAlias = std::vector<uint8_t>(CLONE_KEY_ALIAS, CLONE_KEY_ALIAS + strlen(CLONE_KEY_ALIAS));
    if (!CryptoManager::GetInstance().ImportKey(key, cloneKeyAlias)) {
        return false;
    }
    return true;
}

void DeleteCloneKey()
{
    auto cloneKeyAlias = std::vector<uint8_t>(CLONE_KEY_ALIAS, CLONE_KEY_ALIAS + strlen(CLONE_KEY_ALIAS));
    CryptoManager::GetInstance().DeleteKey(cloneKeyAlias);
}

bool WriteBackupInfo(const std::string &content, const std::string &backupPath)
{
    FILE *fp = fopen(backupPath.c_str(), "w");

    if (!fp) {
        ZLOGE("Secret key backup file fopen failed, path: %{public}s, errno: %{public}d",
            Anonymous::Change(backupPath).c_str(), errno);
        return false;
    }
    size_t ret = fwrite(content.c_str(), 1, content.length(), fp);
    if (ret != content.length()) {
        ZLOGE("Secret key backup file fwrite failed, path: %{public}s, errno: %{public}d",
            Anonymous::Change(backupPath).c_str(), errno);
        (void)fclose(fp);
        return false;
    }

    (void)fflush(fp);
    (void)fsync(fileno(fp));
    (void)fclose(fp);
    return true;
}

std::vector<uint8_t> ReEncryptKey(const SecretKeyMetaData &secretKeyMeta,
    const StoreMetaData &metaData, std::vector<uint8_t> &nonce)
{
    CryptoManager::CryptoParams decryptParams = {
        .area = secretKeyMeta.area, .userId = metaData.user, .nonce = secretKeyMeta.nonce
    };
    auto password = CryptoManager::GetInstance().Decrypt(secretKeyMeta.sKey, decryptParams);
    if (password.empty()) {
        return {};
    }
    SecureClearGuard<std::vector<uint8_t>> passwordGuard(password);
    auto cloneKeyAlias = std::vector<uint8_t>(CLONE_KEY_ALIAS, CLONE_KEY_ALIAS + strlen(CLONE_KEY_ALIAS));
    // nonce is in/out: empty makes Encrypt generate a fresh random per-item nonce, which is
    // written back below so restore can decrypt with the very nonce used here; non-empty is
    // used as-is (the shared iv for the old format).
    CryptoManager::CryptoParams encryptParams = { .keyAlias = cloneKeyAlias, .nonce = nonce };
    auto reEncryptedKey = CryptoManager::GetInstance().Encrypt(password, encryptParams);
    if (reEncryptedKey.size() == 0) {
        return {};
    };
    nonce = encryptParams.nonce;
    return reEncryptedKey;
}

// Bundles the parameters for ReportCloneResult so callers pass a single aggregate
// instead of a long positional argument list.
struct CloneReportInfo {
    BehaviourType behaviourType;  // DATABASE_BACKUP or DATABASE_RECOVERY
    std::string userId;
    std::string osVersion;
    bool oldFormat;
    int32_t total;
    int32_t skipped;
};

// Emits a per-operation DFX summary so that the old/new format split and the outcome are
// observable even when the flow returns normally: an info log for traceability (userId in
// plaintext via %{public}s), a behaviour report via the existing Reporter singleton
// (DATABASE_BEHAVIOUR event, summary packed into extensionInfo), and -- when any item was
// skipped -- a FAULT event via DISTRIBUTED_DATA_RDB_FAULT so partial failures remain
// visible on the fault channel.
void ReportCloneResult(const CloneReportInfo &info)
{
    int32_t success = info.total - info.skipped;
    const char *formatType = info.oldFormat ? "old" : "new";
    ZLOGI("Clone summary, userId:%{public}s, osVersion:%{public}s, format:%{public}s, "
        "total:%{public}d, success:%{public}d, skipped:%{public}d",
        info.userId.c_str(), info.osVersion.c_str(), formatType,
        info.total, success, info.skipped);
    // Reuse the existing BehaviourReporter (writes DATABASE_BEHAVIOUR); pack the clone summary
    // (peer OSVersion, format selection, item counts) into extensionInfo.
    std::string extensionInfo = "osVersion:" + info.osVersion + ", format:" + formatType +
        ", total:" + std::to_string(info.total) + ", success:" + std::to_string(success) +
        ", skipped:" + std::to_string(info.skipped);
    Reporter::GetInstance()->GetBehaviourReporter()->Report(
        { Anonymous::Change(info.userId), "clone", "", info.behaviourType, extensionInfo });
    if (info.skipped <= 0) {
        return;
    }
    const char *faultType = info.behaviourType == BehaviourType::DATABASE_BACKUP
        ? "CLONE_BACKUP_PARTIAL_FAIL" : "CLONE_RESTORE_PARTIAL_FAIL";
    std::string appendix = "userId:" + Anonymous::Change(info.userId) +
        ", total:" + std::to_string(info.total) +
        ", skipped:" + std::to_string(info.skipped);
    ZLOGE("Clone partial fail, total:%{public}d, skipped:%{public}d, userId:%{public}s",
        info.total, info.skipped, Anonymous::Change(info.userId).c_str());
    HiSysEventWrite(OHOS::HiviewDFX::HiSysEvent::Domain::DISTRIBUTED_DATAMGR,
        "DISTRIBUTED_DATA_RDB_FAULT",
        OHOS::HiviewDFX::HiSysEvent::EventType::FAULT,
        "FAULT_TYPE", faultType,
        "BUNDLE_NAME", "clone",
        "ERROR_CODE", info.skipped,
        "APPENDIX", appendix.c_str());
}

void ReportCloneBackup(const std::string &userId, const std::string &osVersion,
    int32_t total, int32_t skipped)
{
    ReportCloneResult({
        .behaviourType = BehaviourType::DATABASE_BACKUP,
        .userId = userId,
        .osVersion = osVersion,
        .oldFormat = IsOldOsVersion(osVersion),
        .total = total,
        .skipped = skipped,
    });
}

void ReportCloneRestore(const std::string &userId, const std::string &osVersion,
    int32_t total, int32_t skipped)
{
    ReportCloneResult({
        .behaviourType = BehaviourType::DATABASE_RECOVERY,
        .userId = userId,
        .osVersion = osVersion,
        .oldFormat = IsOldOsVersion(osVersion),
        .total = total,
        .skipped = skipped,
    });
}

std::string GetSecretKeyBackup(const std::vector<DistributedData::CloneBundleInfo> &bundleInfos,
    const std::string &userId, const std::vector<uint8_t> &iv, const std::string &localDeviceId,
    const std::string &osVersion)
{
    SecretKeyBackupData backupInfos;
    int32_t total = 0, skipped = 0;
    bool oldFormat = IsOldOsVersion(osVersion);
    for (const auto &bundleInfo : bundleInfos) {
        std::string metaPrefix = StoreMetaData::GetKey(
            { localDeviceId, userId, "default", bundleInfo.bundleName });
        std::vector<StoreMetaData> storeMetas;
        if (!MetaDataManager::GetInstance().LoadMeta(metaPrefix, storeMetas, true)) {
            continue;
        }
        for (const auto &storeMeta : storeMetas) {
            if (!storeMeta.isEncrypt) {
                continue;
            }
            ++total;
            auto key = storeMeta.GetSecretKey();
            SecretKeyMetaData secretKeyMeta;
            if (!MetaDataManager::GetInstance().LoadMeta(key, secretKeyMeta, true)) {
                ++skipped;
                continue;
            }
            std::vector<uint8_t> nonce = oldFormat ? iv : std::vector<uint8_t>{};
            auto reEncryptedKey = ReEncryptKey(secretKeyMeta, storeMeta, nonce);
            if (reEncryptedKey.size() == 0) {
                ++skipped;
                continue;
            }
            SecretKeyBackupData::BackupItem item;
            item.time = secretKeyMeta.time;
            item.bundleName = bundleInfo.bundleName;
            item.dbName = storeMeta.storeId;
            item.instanceId = storeMeta.instanceId;
            item.sKey = DistributedData::Base64::Encode(reEncryptedKey);
            item.storeType = secretKeyMeta.storeType;
            item.user = userId;
            item.area = storeMeta.area;
            if (!oldFormat) {
                item.nonce = DistributedData::Base64::Encode(nonce);
            }
            backupInfos.infos.push_back(std::move(item));
        }
    }
    ReportCloneBackup(userId, osVersion, total, skipped);
    return Serializable::Marshall(backupInfos);
}

int32_t OnBackup(MessageParcel &data, MessageParcel &reply, const std::string &localDeviceId)
{
    CloneBackupInfo backupInfo;
    if (!backupInfo.Unmarshal(data.ReadString()) || backupInfo.bundleInfos.empty() || backupInfo.userId.empty()) {
        return -1;
    }

    auto iv = ConvertDecStrToVec(backupInfo.encryptionInfo.iv);
    SecureClearGuard<std::vector<uint8_t>> ivGuard(iv);
    if (iv.size() != AES_256_NONCE_SIZE) {
        ZLOGE("Iv size not correct, iv size:%{public}zu", iv.size());
        return -1;
    }

    // Validate the userId before importing the HUKS clone key: if the input is invalid we
    // return immediately so the heavy ImportCloneKey operation is never triggered, avoiding
    // any HKS key residue that would otherwise need cleanup.
    if (!IsNumber(backupInfo.userId)) {
        ZLOGE("userId is not number, userId:%{public}s", backupInfo.userId.c_str());
        return -1;
    }

    if (!ImportCloneKey(backupInfo.encryptionInfo.symkey)) {
        return -1;
    }

    auto content = GetSecretKeyBackup(backupInfo.bundleInfos, backupInfo.userId, iv, localDeviceId,
        backupInfo.osVersion);
    DeleteCloneKey();

    std::string backupPath = DirectoryManager::GetInstance().GetClonePath(backupInfo.userId);
    if (backupPath.empty()) {
        ZLOGE("GetClonePath failed, userId:%{public}s errno: %{public}d", backupInfo.userId.c_str(), errno);
        return -1;
    }
    if (!WriteBackupInfo(content, backupPath)) {
        return -1;
    }

    UniqueFd fd(-1);
    fd = UniqueFd(open(backupPath.c_str(), O_RDONLY));
    if (fd < 0) {
        ZLOGE("OnBackup open failed, errno:%{public}d", errno);
        return -1;
    }
    uint64_t cloneTag = fdsan_create_owner_tag(FDSAN_OWNER_TYPE_FILE, 0xD001610);
    fdsan_exchange_owner_tag(fd, 0, cloneTag);

    std::string replyCode = GetBackupReplyCode(0);
    if (!reply.WriteFileDescriptor(fd) || !reply.WriteString(replyCode)) {
        ZLOGE("OnBackup fail: reply wirte fail, fd:%{public}d", fd.Get());
        fdsan_close_with_tag(fd.Release(), cloneTag);
        return -1;
    }

    fdsan_close_with_tag(fd.Release(), cloneTag);
    return 0;
}

int32_t ReplyForRestore(MessageParcel &reply, int32_t result)
{
    std::string replyCode = GetBackupReplyCode(result);
    if (!reply.WriteString(replyCode)) {
        return -1;
    }
    return result;
}

bool ParseSecretKeyFile(MessageParcel &data, SecretKeyBackupData &backupData)
{
    UniqueFd fd(data.ReadFileDescriptor());
    struct stat statBuf;
    if (fd.Get() < 0 || fstat(fd.Get(), &statBuf) < 0) {
        ZLOGE("Parse backup secret key failed, fd:%{public}d, errno:%{public}d", fd.Get(), errno);
        return false;
    }
    const off_t sizeMax = 1024 * 1024 * 500;
    if (statBuf.st_size > sizeMax) {
        ZLOGE("Secret key file size exceeds the upper limit, fd:%{public}d, errno:%{public}d", fd.Get(), errno);
        return false;
    }
    std::vector<char> buffer(statBuf.st_size);
    ssize_t fileSize = read(fd.Get(), buffer.data(), statBuf.st_size);
    if (fileSize < 0) {
        ZLOGE("Read backup secret key failed. errno:%{public}d", errno);
        return false;
    }
    SecureClearGuard<std::vector<char>> bufferGuard(buffer);
    std::string keyLoad(buffer.data(), static_cast<size_t>(fileSize));
    SecureClearGuard<std::string> keyLoadGuard(keyLoad);
    DistributedData::Serializable::Unmarshall(keyLoad, backupData);
    return true;
}

bool RestoreSecretKey(
    const SecretKeyBackupData::BackupItem &item, const std::string &userId, const std::vector<uint8_t> &iv)
{
    auto sKey = DistributedData::Base64::Decode(item.sKey);
    SecureClearGuard<std::vector<uint8_t>> sKeyGuard(sKey);
    auto cloneKeyAlias = std::vector<uint8_t>(CLONE_KEY_ALIAS, CLONE_KEY_ALIAS + strlen(CLONE_KEY_ALIAS));
    CryptoManager::CryptoParams decryptParams = { .keyAlias = cloneKeyAlias, .nonce = iv };
    // New format: a per-item nonce that decodes to exactly 12 bytes decrypts this item with
    // that nonce. An absent nonce, or one that decodes to nothing, falls back to the shared
    // iv (pre-7.1 format); any other decoded length fails the item.
    auto itemNonce = DistributedData::Base64::Decode(item.nonce);
    if (itemNonce.size() == AES_GCM_NONCE_SIZE) {
        decryptParams.nonce = itemNonce;
    } else if (!itemNonce.empty()) {
        ZLOGW("Item nonce size invalid, skip item, nonceSize:%{public}zu, bundleName:%{public}s",
            itemNonce.size(), item.bundleName.c_str());
        return false;
    }
    auto rawKey = CryptoManager::GetInstance().Decrypt(sKey, decryptParams);
    if (rawKey.empty()) {
        ZLOGE("Decrypt failed, bundleName:%{public}s, storeName:%{public}s, storeType:%{public}d",
            item.bundleName.c_str(), Anonymous::Change(item.dbName).c_str(), item.storeType);
        return false;
    }
    SecureClearGuard<std::vector<uint8_t>> rawKeyGuard(rawKey);

    StoreMetaData metaData;
    metaData.bundleName = item.bundleName;
    metaData.storeId = item.dbName;
    metaData.user = item.user == "0" ? "0" : userId;
    metaData.instanceId = item.instanceId;

    SecretKeyMetaData secretKey;
    CryptoManager::CryptoParams encryptParams = { .area = item.area, .userId = metaData.user };
    secretKey.sKey = CryptoManager::GetInstance().Encrypt(rawKey, encryptParams);
    if (secretKey.sKey.empty()) {
        ZLOGE("Encrypt failed, bundleName:%{public}s, storeName:%{public}s, storeType:%{public}d",
            item.bundleName.c_str(), Anonymous::Change(item.dbName).c_str(), item.storeType);
        return false;
    }
    secretKey.storeType = item.storeType;
    secretKey.nonce = encryptParams.nonce;
    secretKey.area = item.area;
    secretKey.time = { item.time.begin(), item.time.end() };

    return MetaDataManager::GetInstance().SaveMeta(metaData.GetCloneSecretKey(), secretKey, true);
}

int32_t OnRestore(MessageParcel &data, MessageParcel &reply)
{
    SecretKeyBackupData backupData;
    if (!ParseSecretKeyFile(data, backupData) || backupData.infos.size() == 0) {
        return ReplyForRestore(reply, -1);
    }
    CloneBackupInfo backupInfo;
    bool ret = backupInfo.Unmarshal(data.ReadString());
    if (!ret || backupInfo.userId.empty()) {
        return ReplyForRestore(reply, -1);
    }

    auto iv = ConvertDecStrToVec(backupInfo.encryptionInfo.iv);
    SecureClearGuard<std::vector<uint8_t>> ivGuard(iv);
    if (iv.size() != AES_256_NONCE_SIZE) {
        ZLOGE("Iv size not correct, iv size:%{public}zu", iv.size());
        return ReplyForRestore(reply, -1);
    }

    if (!ImportCloneKey(backupInfo.encryptionInfo.symkey)) {
        DeleteCloneKey();
        return ReplyForRestore(reply, -1);
    }

    int32_t total = 0;
    int32_t skipped = 0;
    for (const auto &item : backupData.infos) {
        ++total;
        if (!item.IsValid() || !RestoreSecretKey(item, backupInfo.userId, iv)) {
            ++skipped;
            continue;
        }
    }
    ReportCloneRestore(backupInfo.userId, backupInfo.osVersion, total, skipped);
    DeleteCloneKey();
    return ReplyForRestore(reply, 0);
}

bool IsOldOsVersion(const std::string &osVersion)
{
    if (osVersion.empty()) {
        return true;
    }
    // The backup framework sends the OSVersion entry in four-segment form (e.g. "7.0.0.115");
    // only the leading "<major>.<minor>" is compared. Anything unparseable is treated as an
    // old version so the backup falls back to the old shared-iv format.
    auto tokens = Constant::Split(osVersion, ".");
    auto isDigits = [](const std::string &token) {
        return !token.empty() && std::all_of(token.begin(), token.end(),
            [](unsigned char c) { return std::isdigit(c); });
    };
    if (tokens.size() < MIN_VERSION_SEGMENTS || !isDigits(tokens[0]) || !isDigits(tokens[1])) {
        ZLOGW("Peer device version form is unparseable, use old backup format, version:%{public}s",
            osVersion.c_str());
        return true;
    }
    // strtol with errno replaces atol: atol has undefined behavior (signed overflow) on
    // excessively long numeric strings, whereas strtol clamps to LONG_MAX/LONG_MIN and
    // sets errno=ERANGE. A version segment that overflows is clearly >= 7.1, so the peer
    // is treated as a new-format device.
    errno = 0;
    long major = strtol(tokens[0].c_str(), nullptr, 10);
    if (errno == ERANGE) {
        ZLOGW("Peer device version major overflow, treat as new format, version:%{public}s",
            osVersion.c_str());
        return false;
    }
    errno = 0;
    long minor = strtol(tokens[1].c_str(), nullptr, 10);
    if (errno == ERANGE) {
        ZLOGW("Peer device version minor overflow, treat as new format, version:%{public}s",
            osVersion.c_str());
        return false;
    }
    return major < NEW_FORMAT_VERSION_MAJOR ||
        (major == NEW_FORMAT_VERSION_MAJOR && minor < NEW_FORMAT_VERSION_MINOR);
}

bool IsNumber(const std::string& str)
{
    return !str.empty() && std::all_of(str.begin(), str.end(), [](unsigned char c) { return std::isdigit(c); });
}
} // namespace OHOS::DistributedKv