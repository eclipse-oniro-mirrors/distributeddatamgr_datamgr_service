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
#include "clone_manager.h"

#include <fcntl.h>

#include "crypto/crypto_manager.h"
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

std::vector<uint8_t> ReEncryptKey(const std::string &key, SecretKeyMetaData &secretKeyMeta,
    const StoreMetaData &metaData, std::vector<uint8_t> &nonce)
{
    if (!MetaDataManager::GetInstance().LoadMeta(key, secretKeyMeta, true)) {
        return {};
    };
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

// Item-level failures are skipped by design, so the flow result alone cannot reveal them;
// emit a summary log and a fault event whenever any item was skipped.
void ReportClonePartialFail(const char *eventName, const std::string &userId, int32_t total, int32_t skipped)
{
    ZLOGE("Clone partial fail, total:%{public}d, skipped:%{public}d, userId:%{public}s", total, skipped,
        Anonymous::Change(userId).c_str());
    HiSysEventWrite(OHOS::HiviewDFX::HiSysEvent::Domain::DISTRIBUTED_DATAMGR, eventName,
        OHOS::HiviewDFX::HiSysEvent::EventType::FAULT, "USER_ID", Anonymous::Change(userId).c_str(),
        "TOTAL_COUNT", total, "SKIPPED_COUNT", skipped);
}

std::string GetSecretKeyBackup(const std::vector<DistributedData::CloneBundleInfo> &bundleInfos,
    const std::string &userId, const std::vector<uint8_t> &iv, const std::string &localDeviceId,
    const std::string &peerDeviceVersion)
{
    SecretKeyBackupData backupInfos;
    int32_t total = 0;
    int32_t skipped = 0;
    bool oldFormat = IsOldOsVersion(peerDeviceVersion);
    for (const auto &bundleInfo : bundleInfos) {
        std::string metaPrefix = StoreMetaData::GetKey({ localDeviceId, userId, "default", bundleInfo.bundleName });
        std::vector<StoreMetaData> StoreMetas;
        if (!MetaDataManager::GetInstance().LoadMeta(metaPrefix, StoreMetas, true)) {
            continue;
        };
        for (const auto &storeMeta : StoreMetas) {
            if (!storeMeta.isEncrypt) {
                continue;
            };
            ++total;
            auto key = storeMeta.GetSecretKey();
            SecretKeyMetaData secretKeyMeta;
            // Old format reuses the shared iv handed in by the framework; new format starts
            // with an empty nonce so ReEncryptKey generates a fresh random one per item.
            std::vector<uint8_t> nonce = oldFormat ? iv : std::vector<uint8_t>{};
            auto reEncryptedKey = ReEncryptKey(key, secretKeyMeta, storeMeta, nonce);
            if (reEncryptedKey.size() == 0) {
                ++skipped;
                continue;
            };
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
    if (skipped > 0) {
        ReportClonePartialFail("CLONE_BACKUP_PARTIAL_FAIL", userId, total, skipped);
    }
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

    if (!ImportCloneKey(backupInfo.encryptionInfo.symkey)) {
        return -1;
    }

    auto content = GetSecretKeyBackup(backupInfo.bundleInfos, backupInfo.userId, iv, localDeviceId,
        backupInfo.peerDeviceVersion);
    DeleteCloneKey();

    if (!IsNumber(backupInfo.userId)) {
        ZLOGE("userId is not number, userId:%{public}s", backupInfo.userId.c_str());
        return -1;
    }
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
    if (skipped > 0) {
        ReportClonePartialFail("CLONE_RESTORE_PARTIAL_FAIL", backupInfo.userId, total, skipped);
    }
    DeleteCloneKey();
    return ReplyForRestore(reply, 0);
}

bool IsOldOsVersion(const std::string &peerDeviceVersion)
{
    if (peerDeviceVersion.empty()) {
        return true;
    }
    // Placeholder contract: the peer version form is pending alignment with the backup
    // framework. Only "<major>.<minor>[...]" forms are accepted; anything else is treated
    // as an old version so the backup falls back to the old shared-iv format.
    auto tokens = Constant::Split(peerDeviceVersion, ".");
    auto isDigits = [](const std::string &token) {
        return !token.empty() && std::all_of(token.begin(), token.end(),
            [](unsigned char c) { return std::isdigit(c); });
    };
    if (tokens.size() < MIN_VERSION_SEGMENTS || !isDigits(tokens[0]) || !isDigits(tokens[1])) {
        ZLOGW("Peer device version form is unparseable, use old backup format, version:%{public}s",
            peerDeviceVersion.c_str());
        return true;
    }
    long major = atol(tokens[0].c_str());
    long minor = atol(tokens[1].c_str());
    return major < NEW_FORMAT_VERSION_MAJOR ||
        (major == NEW_FORMAT_VERSION_MAJOR && minor < NEW_FORMAT_VERSION_MINOR);
}

bool IsNumber(const std::string& str)
{
    return !str.empty() && std::all_of(str.begin(), str.end(), [](unsigned char c) { return std::isdigit(c); });
}
} // namespace OHOS::DistributedKv