/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#define LOG_TAG "TemplateData"
#include "template_data.h"
#include "log_print.h"
namespace OHOS::DataShare {
bool TemplateNode::Marshal(DistributedData::Serializable::json &node) const
{
    bool ret = SetValue(node[GET_NAME(predicates)], predicates);
    ret = ret && SetValue(node[GET_NAME(scheduler)], scheduler);
    return ret;
}

bool TemplateNode::Unmarshal(const DistributedData::Serializable::json &node)
{
    bool ret = GetValue(node, GET_NAME(predicates), predicates);
    return ret && GetValue(node, GET_NAME(scheduler), scheduler);
}

TemplateNode::TemplateNode(const Template &tpl) : scheduler(tpl.scheduler_)
{
    for (auto &item:tpl.predicates_) {
        predicates.emplace_back(item.key_, item.selectSql_);
    }
}

Template TemplateNode::ToTemplate() const
{
    std::vector<PredicateTemplateNode> nodes;
    for (const auto &predicate: predicates) {
        nodes.emplace_back(predicate.key, predicate.selectSql);
    }
    return Template(nodes, scheduler);
}

bool TemplateRootNode::Marshal(DistributedData::Serializable::json &node) const
{
    bool ret = SetValue(node[GET_NAME(uri)], uri);
    ret = ret && SetValue(node[GET_NAME(bundleName)], bundleName);
    ret = ret && SetValue(node[GET_NAME(subscriberId)], subscriberId);
    ret = ret && SetValue(node[GET_NAME(templat)], tpl);
    return ret;
}

bool TemplateRootNode::Unmarshal(const DistributedData::Serializable::json &node)
{
    bool ret = GetValue(node, GET_NAME(uri), uri);
    ret = ret && GetValue(node, GET_NAME(bundleName), bundleName);
    ret = ret && GetValue(node, GET_NAME(subscriberId), subscriberId);
    ret = ret && GetValue(node, GET_NAME(templat), tpl);
    return ret;
}

TemplateRootNode::TemplateRootNode(
    const std::string &uri, const std::string &bundleName, int64_t subscriberId, const Template &tpl)
    : uri(uri), bundleName(bundleName), subscriberId(subscriberId), tpl(tpl)
{
}

bool TemplateData::HasVersion() const
{
    return false;
}

std::string TemplateData::GetValue() const
{
    return DistributedData::Serializable::Marshall(value);
}

TemplateData::TemplateData(
    const std::string &uri, const std::string &bundleName, int64_t subscriberId, const Template &tpl)
    :KvData(Id(GenId(uri, bundleName, subscriberId))), value(uri, bundleName, subscriberId, tpl)
{
}

int TemplateData::GetVersion() const
{
    return 0;
}

std::string TemplateData::GenId(const std::string &uri, const std::string &bundleName, int64_t subscriberId)
{
    return uri + "_" + std::to_string(subscriberId) + "_" + bundleName;
}

int32_t TemplateData::Query(const std::string &filter, Template &aTemplate)
{
    auto delegate = KvDBDelegate::GetInstance();
    if (delegate == nullptr) {
        ZLOGE("db open failed");
        return E_ERROR;
    }
    std::string queryResult;
    int32_t status = delegate->Get(KvDBDelegate::TEMPLATE_TABLE, filter, "{}", queryResult);
    if (status != E_OK) {
        ZLOGE("db Get failed, %{public}s %{public}d", filter.c_str(), status);
        return status;
    }
    TemplateRootNode data;
    if (!DistributedData::Serializable::Unmarshall(queryResult, data)) {
        ZLOGE("Unmarshall failed, %{private}s", queryResult.c_str());
        return E_ERROR;
    }
    aTemplate = data.ToTemplate();
    return E_OK;
}

Template TemplateRootNode::ToTemplate() const
{
    return tpl.ToTemplate();
}

PredicatesNode::PredicatesNode(const std::string &key, const std::string &selectSql) : key(key), selectSql(selectSql)
{
}
bool PredicatesNode::Marshal(DistributedData::Serializable::json &node) const
{
    bool ret = SetValue(node[GET_NAME(key)], key);
    ret = ret && SetValue(node[GET_NAME(selectSql)], selectSql);
    return ret;
}
bool PredicatesNode::Unmarshal(const DistributedData::Serializable::json &node)
{
    bool ret = GetValue(node, GET_NAME(key), key);
    ret = ret && GetValue(node, GET_NAME(selectSql), selectSql);
    return ret;
}
} // namespace OHOS::DataShare