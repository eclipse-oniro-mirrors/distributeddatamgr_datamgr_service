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
#define LOG_TAG "AccountDelegateDefaultImpl"

#include "account_delegate_default_impl.h"

#include "log_print.h"

namespace OHOS {
namespace DistributedData {
namespace {
constexpr const char *DEFAULT_OHOS_ACCOUNT_UID = ""; // default UID
}
__attribute__((used)) static bool g_isInit = AccountDelegateDefaultImpl::Init();

std::string AccountDelegateDefaultImpl::GetCurrentAccountId() const
{
    ZLOGD("no account part, return default.");
    return DEFAULT_OHOS_ACCOUNT_UID;
}

int32_t AccountDelegateDefaultImpl::GetUserByToken(uint32_t tokenId) const
{
    (void)tokenId;
    return 0;
}

bool AccountDelegateDefaultImpl::QueryUsers(std::vector<int> &users)
{
    ZLOGD("no account part.");
    users = {0}; // default user
    return true;
}

bool AccountDelegateDefaultImpl::QueryForegroundUsers(std::vector<int> &users)
{
    ZLOGD("no account part.");
    users = {0}; // default user
    return true;
}

bool AccountDelegateDefaultImpl::IsLoginAccount()
{
    ZLOGD("no account login.");
    return false;
}

bool AccountDelegateDefaultImpl::IsVerified(int userId)
{
    ZLOGD("no account part.");
    return true;
}

bool AccountDelegateDefaultImpl::IsDeactivating(int userId)
{
    ZLOGD("no account part.");
    return false;
}

void AccountDelegateDefaultImpl::SubscribeAccountEvent()
{
    ZLOGD("no account part.");
}

void AccountDelegateDefaultImpl::UnsubscribeAccountEvent()
{
    ZLOGD("no account part.");
}

AccountDelegateDefaultImpl::~AccountDelegateDefaultImpl()
{
    ZLOGD("destruct");
}

void AccountDelegateDefaultImpl::BindExecutor(std::shared_ptr<ExecutorPool> executors)
{
    ZLOGD("no account part");
}

bool AccountDelegateDefaultImpl::Init()
{
    static AccountDelegateDefaultImpl defaultAccountDelegate;
    static std::once_flag onceFlag;
    std::call_once(onceFlag, [&]() { AccountDelegate::RegisterAccountInstance(&defaultAccountDelegate); });
    return true;
}
} // namespace DistributedData
} // namespace OHOS