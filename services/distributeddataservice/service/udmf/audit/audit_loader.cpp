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
#define LOG_TAG "AuditLoader"

#include "audit_loader.h"

#include <dlfcn.h>

#include <string>

#include <parameter.h>

#include "log_print.h"

namespace OHOS {
namespace UDMF {

constexpr const char *IS_ENTERPRISE_DEVICE = "const.edm.is_enterprise_device";
constexpr const char *ENTERPRISE_DEVICE_FALSE = "false";
constexpr const char *ENTERPRISE_DEVICE_TRUE = "true";

using Creator = std::shared_ptr<OHOS::UDMF::IAuditHelper> (*)();

AuditLoader &AuditLoader::GetInstance()
{
    static AuditLoader loader;
    return loader;
}

bool AuditLoader::IsEnterpriseDevice()
{
    char isEnterpriseDeviceValue[PARAM_VALUE_LEN_MAX] = {0};
    GetParameter(IS_ENTERPRISE_DEVICE, ENTERPRISE_DEVICE_FALSE, isEnterpriseDeviceValue, PARAM_VALUE_LEN_MAX);
    return std::string(isEnterpriseDeviceValue) == ENTERPRISE_DEVICE_TRUE;
}

std::shared_ptr<IAuditHelper> AuditLoader::GetAuditHelper()
{
    if (!IsEnterpriseDevice()) {
        return nullptr;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    if (auditHelper_ != nullptr) {
        return auditHelper_;
    }
    void *handler = dlopen("libudmf_audit.z.so", RTLD_LAZY);
    if (handler == nullptr) {
        const char *dlopenError = dlerror();
        ZLOGE("dlopen failed: %{public}s", dlopenError ? dlopenError : "unknown error");
        return nullptr;
    }
    (void)dlerror();
    auto creator = reinterpret_cast<Creator>(dlsym(handler, "CreateAuditHelper"));
    if (creator == nullptr) {
        ZLOGE("dlsym failed, %{public}s", dlerror());
        dlclose(handler);
        return nullptr;
    }
    auditHelper_ = creator();
    return auditHelper_;
}

void AuditLoader::ReportDragAuditEvent(const UnifiedData &unifiedData, int32_t userId, uint32_t tokenId)
{
    auto helper = GetAuditHelper();
    if (helper == nullptr) {
        ZLOGW("audit helper is nullptr");
        return;
    }
    helper->ReportDragAuditEvent(unifiedData, userId, tokenId);
}
} // namespace UDMF
} // namespace OHOS
