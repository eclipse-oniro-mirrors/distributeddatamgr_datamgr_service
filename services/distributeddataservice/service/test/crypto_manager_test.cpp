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

#include "crypto_manager.h"

#include <random>

#include "crypto_manager.h"
#include "gtest/gtest.h"
#include "metadata/secret_key_meta_data.h"
#include "metadata/store_meta_data.h"
#include "types.h"
using namespace testing::ext;
using namespace OHOS::DistributedData;
namespace OHOS::Test {
namespace DistributedDataTest {
class CryptoManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(){};
    void TearDown(){};
    static std::vector<uint8_t> Random(uint32_t len);

protected:
    static std::vector<uint8_t> randomKey;
};

static const uint32_t KEY_LENGTH = 32;
static const uint32_t ENCRYPT_KEY_LENGTH = 48;
static constexpr int32_t EL2 = 2;
static constexpr int32_t EL4 = 4;
static constexpr const char *TEST_USERID = "100";
std::vector<uint8_t> CryptoManagerTest::randomKey;
void CryptoManagerTest::SetUpTestCase(void)
{
    randomKey = Random(KEY_LENGTH);
}

void CryptoManagerTest::TearDownTestCase(void)
{
    randomKey.assign(randomKey.size(), 0);
}

std::vector<uint8_t> CryptoManagerTest::Random(uint32_t len)
{
    std::random_device randomDevice;
    std::uniform_int_distribution<int> distribution(0, std::numeric_limits<uint8_t>::max());
    std::vector<uint8_t> key(len);
    for (uint32_t i = 0; i < len; i++) {
        key[i] = static_cast<uint8_t>(distribution(randomDevice));
    }
    return key;
}

/**
* @tc.name: GenerateRootKey
* @tc.desc: generate the root key
* @tc.type: FUNC
* @tc.require:
* @tc.author: zuojiangjiang
*/
HWTEST_F(CryptoManagerTest, GenerateRootKey, TestSize.Level0)
{
    auto errCode = CryptoManager::GetInstance().GenerateRootKey();
    EXPECT_EQ(errCode, CryptoManager::ErrCode::SUCCESS);
}

/**
* @tc.name: CheckRootKey
* @tc.desc: check root key exist;
* @tc.type: FUNC
* @tc.require:
* @tc.author: zuojiangjiang
*/
HWTEST_F(CryptoManagerTest, CheckRootKey, TestSize.Level0)
{
    auto errCode = CryptoManager::GetInstance().CheckRootKey();
    EXPECT_EQ(errCode, CryptoManager::ErrCode::SUCCESS);
}

/**
* @tc.name: Encrypt001
* @tc.desc: encrypt random key;
* @tc.type: FUNC
* @tc.require:
* @tc.author: zuojiangjiang
*/
HWTEST_F(CryptoManagerTest, Encrypt001, TestSize.Level0)
{
    auto encryptKey = CryptoManager::GetInstance().Encrypt(randomKey, DEFAULT_ENCRYPTION_LEVEL, DEFAULT_USER);
    EXPECT_EQ(encryptKey.size(), ENCRYPT_KEY_LENGTH);
    encryptKey.assign(encryptKey.size(), 0);
}

/**
* @tc.name: Encrypt002
* @tc.desc: encrypt empty key;
* @tc.type: FUNC
* @tc.require:
* @tc.author: zuojiangjiang
*/
HWTEST_F(CryptoManagerTest, Encrypt002, TestSize.Level0)
{
    auto encryptKey = CryptoManager::GetInstance().Encrypt({ }, DEFAULT_ENCRYPTION_LEVEL, DEFAULT_USER);
    EXPECT_TRUE(encryptKey.empty());
}

/**
* @tc.name: Encrypt003
* @tc.desc: Check root key fail;
* @tc.type: FUNC
* @tc.require:
* @tc.author: yanhui
*/
HWTEST_F(CryptoManagerTest, Encrypt003, TestSize.Level0)
{
    auto encryptKey = CryptoManager::GetInstance().Encrypt(randomKey, EL2, DEFAULT_USER);
    EXPECT_TRUE(encryptKey.empty());
    encryptKey = CryptoManager::GetInstance().Encrypt(randomKey, EL4, DEFAULT_USER);
    EXPECT_TRUE(encryptKey.empty());

    encryptKey = CryptoManager::GetInstance().Encrypt(randomKey, EL2, TEST_USERID);
    // check interact across local accounts permission failed
    EXPECT_TRUE(encryptKey.empty());
    encryptKey = CryptoManager::GetInstance().Encrypt(randomKey, EL4, TEST_USERID);
    // check interact across local accounts permission failed
    EXPECT_TRUE(encryptKey.empty());
}

/**
* @tc.name: Encrypt004
* @tc.desc: Encrypt clone key, but root key not imported;
* @tc.type: FUNC
* @tc.require:
* @tc.author: yanhui
*/
HWTEST_F(CryptoManagerTest, Encrypt004, TestSize.Level0)
{
    const std::string str = "distributed_db_backup_key";
    auto cloneKey = std::vector<uint8_t>(str.begin(), str.end());
    std::vector<uint8_t> nonce{};
    CryptoManager::EncryptParams params = { .keyAlias = cloneKey, .nonce = nonce };
    auto encryptKey = CryptoManager::GetInstance().Encrypt(randomKey, params);
    EXPECT_TRUE(encryptKey.empty());
    std::vector<uint8_t> key;

    auto result = CryptoManager::GetInstance().Decrypt(encryptKey, key, params);
    ASSERT_FALSE(result);
}

/**
* @tc.name: DecryptKey001
* @tc.desc: decrypt the encrypt key;
* @tc.type: FUNC
* @tc.require:
* @tc.author: zuojiangjiang
*/
HWTEST_F(CryptoManagerTest, DecryptKey001, TestSize.Level0)
{
    auto encryptKey = CryptoManager::GetInstance().Encrypt(randomKey, DEFAULT_ENCRYPTION_LEVEL, DEFAULT_USER);
    std::vector<uint8_t> key;
    auto result = CryptoManager::GetInstance().Decrypt(encryptKey, key, DEFAULT_ENCRYPTION_LEVEL, DEFAULT_USER);
    EXPECT_TRUE(result);
    EXPECT_EQ(key.size(), KEY_LENGTH);
    encryptKey.assign(encryptKey.size(), 0);
}

/**
* @tc.name: DecryptKey002
* @tc.desc: decrypt the key, the source key is not encrypt;
* @tc.type: FUNC
* @tc.require:
* @tc.author: zuojiangjiang
*/
HWTEST_F(CryptoManagerTest, DecryptKey002, TestSize.Level0)
{
    std::vector<uint8_t> key;
    auto result = CryptoManager::GetInstance().Decrypt(randomKey, key, DEFAULT_ENCRYPTION_LEVEL, DEFAULT_USER);
    EXPECT_FALSE(result);
    EXPECT_TRUE(key.empty());
}

/**
* @tc.name: DecryptKey003
* @tc.desc: decrypt the key, the source key is empty;
* @tc.type: FUNC
* @tc.require:
* @tc.author: zuojiangjiang
*/
HWTEST_F(CryptoManagerTest, DecryptKey003, TestSize.Level0)
{
    std::vector<uint8_t> srcKey {};
    std::vector<uint8_t> key;
    auto result = CryptoManager::GetInstance().Decrypt(srcKey, key, DEFAULT_ENCRYPTION_LEVEL, DEFAULT_USER);
    EXPECT_FALSE(result);
    EXPECT_TRUE(key.empty());
}

/**
* @tc.name: DecryptKey004
* @tc.desc: Check root key fail;
* @tc.type: FUNC
* @tc.require:
* @tc.author: yanhui
*/
HWTEST_F(CryptoManagerTest, DecryptKey004, TestSize.Level0)
{
    std::vector<uint8_t> key;
    auto result = CryptoManager::GetInstance().Decrypt(randomKey, key, EL2, DEFAULT_USER);
    EXPECT_FALSE(result);
    EXPECT_TRUE(key.empty());
    result = CryptoManager::GetInstance().Decrypt(randomKey, key, EL4, DEFAULT_USER);
    EXPECT_FALSE(result);
    EXPECT_TRUE(key.empty());
}

/**
* @tc.name: Decrypt001
* @tc.desc: SecretKeyMetaData is old.
* @tc.type: FUNC
* @tc.require:
* @tc.author: yanhui
*/
HWTEST_F(CryptoManagerTest, Decrypt001, TestSize.Level0)
{
    SecretKeyMetaData secretKeyMeta;
    StoreMetaData metaData;
    std::vector<uint8_t> key;
    secretKeyMeta.sKey = CryptoManager::GetInstance().Encrypt(randomKey, DEFAULT_ENCRYPTION_LEVEL, DEFAULT_USER);
    auto result = CryptoManager::GetInstance().Decrypt(metaData, secretKeyMeta, key);
    EXPECT_TRUE(result);
}

/**
* @tc.name: Decrypt002
* @tc.desc: SecretKeyMetaData is new.
* @tc.type: FUNC
* @tc.require:
* @tc.author: yanhui
*/
HWTEST_F(CryptoManagerTest, Decrypt002, TestSize.Level0)
{
    SecretKeyMetaData secretKeyMeta;
    secretKeyMeta.area = 1;
    StoreMetaData metaData;
    std::vector<uint8_t> key;
    secretKeyMeta.sKey = CryptoManager::GetInstance().Encrypt(randomKey, DEFAULT_ENCRYPTION_LEVEL, DEFAULT_USER);
    auto result = CryptoManager::GetInstance().Decrypt(metaData, secretKeyMeta, key);
    EXPECT_TRUE(result);
    for (int8_t i = 0; i < randomKey.size(); i++) {
        EXPECT_EQ(randomKey[i], key[i]);
    }
}

/**
* @tc.name: UpdatePassword001
* @tc.desc: The data is unencrypted.
* @tc.type: FUNC
* @tc.require:
* @tc.author: yanhui
*/
HWTEST_F(CryptoManagerTest, UpdatePassword001, TestSize.Level0)
{
    StoreMetaData metaData;
    std::vector<uint8_t> key;
    EXPECT_FALSE(CryptoManager::GetInstance().UpdateSecretKey(metaData, key));
}

/**
* @tc.name: UpdatePassword002
* @tc.desc: The data is encrypted.
* @tc.type: FUNC
* @tc.require:
* @tc.author: yanhui
*/
HWTEST_F(CryptoManagerTest, UpdatePassword002, TestSize.Level0)
{
    StoreMetaData metaData;
    metaData.isEncrypt = true;
    metaData.area = DEFAULT_ENCRYPTION_LEVEL;
    // MetaDataManager not initialized
    EXPECT_FALSE(CryptoManager::GetInstance().UpdateSecretKey(metaData, randomKey));
    EXPECT_FALSE(CryptoManager::GetInstance().UpdateSecretKey(metaData, randomKey, CryptoManager::CLONE_SECRET_KEY));
}
} // namespace DistributedDataTest
} // namespace OHOS::Test
