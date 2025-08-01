/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#ifndef OHOS_DISTRIBUTED_DATA_SERVICES_SERVICE_CRYPTO_CRYPTO_MANAGER_H
#define OHOS_DISTRIBUTED_DATA_SERVICES_SERVICE_CRYPTO_CRYPTO_MANAGER_H

#include <cstdint>
#include <mutex>
#include <vector>
#include "metadata/secret_key_meta_data.h"
#include "metadata/store_meta_data.h"
#include "visibility.h"

namespace OHOS::DistributedData {
class API_EXPORT CryptoManager {
public:
    static constexpr const char *DEFAULT_USER = "0";

    enum SecretKeyType {
        LOCAL_SECRET_KEY,
        CLONE_SECRET_KEY,
    };

    enum Area : int32_t {
        EL0,
        EL1,
        EL2,
        EL3,
        EL4,
        EL5,
    };

    enum ErrCode : int32_t {
        SUCCESS,
        NOT_EXIST,
        ERROR,
    };

    struct CryptoParams {
        int32_t area = Area::EL1;
        std::string userId = DEFAULT_USER;
        std::vector<uint8_t> keyAlias;
        std::vector<uint8_t> nonce;
    };

    struct ParamConfig {
        uint32_t purpose;
        uint32_t storageLevel;
        std::string userId;
        std::vector<uint8_t> nonce;
        std::vector<uint8_t> aadValue;
    };

    static CryptoManager &GetInstance();

    int32_t GenerateRootKey();
    int32_t CheckRootKey();

    std::vector<uint8_t> Encrypt(const std::vector<uint8_t> &password, CryptoParams &encryptParams);
    std::vector<uint8_t> Decrypt(const std::vector<uint8_t> &source, CryptoParams &decryptParams);
    void UpdateSecretMeta(const std::vector<uint8_t> &password, const StoreMetaData &metaData,
        const std::string &metaKey, SecretKeyMetaData &secretKey);

    bool ImportKey(const std::vector<uint8_t> &key, const std::vector<uint8_t> &keyAlias);
    bool DeleteKey(const std::vector<uint8_t> &keyAlias);

private:
    CryptoManager();
    ~CryptoManager();

    uint32_t GetStorageLevel(int32_t area);
    int32_t GenerateRootKey(uint32_t storageLevel, const std::string &userId);
    int32_t CheckRootKey(uint32_t storageLevel, const std::string &userId);
    int32_t PrepareRootKey(uint32_t storageLevel, const std::string &userId);

    std::mutex mutex_;
    std::vector<uint8_t> vecRootKeyAlias_{};
    std::vector<uint8_t> vecNonce_{};
    std::vector<uint8_t> vecAad_{};
};
} // namespace OHOS::DistributedData
#endif // OHOS_DISTRIBUTED_DATA_SERVICES_SERVICE_CRYPTO_CRYPTO_MANAGER_H