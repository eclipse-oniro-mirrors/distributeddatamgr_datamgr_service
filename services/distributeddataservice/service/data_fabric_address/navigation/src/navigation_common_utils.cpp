/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "navigation_common_utils.h"

#include <cmath>

#include "data_fabric_address_api_helper.h"
#include "location.h"
#include "locator_impl.h"
#include "log_print.h"

#undef LOG_TAG
#define LOG_TAG "NavigationCommonUtil"

namespace OHOS {
namespace DataFabricAddress {
using namespace DistributedData;

constexpr double COORD_TRANSFORM_A = 6378245.0; // Semi-major axis of the GCJ02 coordinate transform (unit: m)
// Square of the eccentricity of the GCJ02 coordinate system
constexpr double COORD_TRANSFORM_EE = 0.00669342162296594323;
constexpr double COORD_TRANSFORM_LNG_OFFSET = 105.0; // Longitude reference offset of the coordinate transform
constexpr double COORD_TRANSFORM_LAT_OFFSET = 35.0; // Latitude reference offset of the coordinate transform
constexpr double COORD_TRANSFORM_DEGREE = 180.0; // Degree-to-radian conversion coefficient
constexpr double COORD_TRANSFORM_SINE_SCALE_FACTOR = 2.0 / 3.0; // Amplitude correction coefficient of the sine term
constexpr double COORD_TRANSFORM_SINE_BASE_AMPLITUDE = 20.0; // Base amplitude of the sine term
constexpr double COORD_TRANSFORM_SINE_MID_AMPLITUDE = 40.0; // Mid-frequency amplitude of the sine term
constexpr double COORD_TRANSFORM_SINE_FREQUENCY_6X = 6.0; // 6x angular frequency of the sine term
constexpr double COORD_TRANSFORM_SINE_FREQUENCY_2X = 2.0; // 2x angular frequency of the sine term
constexpr double COORD_TRANSFORM_SINE_FREQUENCY_DIV_3 = 3.0; // 1/3x angular frequency of the sine term
constexpr double COORD_TRANSFORM_SINE_FREQUENCY_DIV_12 = 12.0; // 1/12x angular frequency of the sine term
constexpr double COORD_TRANSFORM_SINE_FREQUENCY_DIV_30 = 30.0; // 1/30x angular frequency of the sine term
constexpr double COORD_TRANSFORM_LAT_POLY_BASE = -100.0; // Constant term of the latitude offset polynomial
constexpr double COORD_TRANSFORM_LNG_POLY_BASE = 300.0; // Constant term of the longitude offset polynomial
constexpr double COORD_TRANSFORM_LINEAR_COEFF = 2.0; // Coefficient of the linear term of the polynomial
// Latitude coefficient of the linear term of the latitude offset
constexpr double COORD_TRANSFORM_LAT_LINEAR_Y_COEFF = 3.0;
// Coefficient of the cross (longitude-latitude) term of the polynomial
constexpr double COORD_TRANSFORM_CROSS_COEFF = 0.1;
// Coefficient of the quadratic and square-root terms of the latitude offset
constexpr double COORD_TRANSFORM_LAT_SQUARE_SQRT_COEFF = 0.2;
// Coefficient of the quadratic and square-root terms of the longitude offset
constexpr double COORD_TRANSFORM_LNG_SQUARE_SQRT_COEFF = 0.1;
// Amplitude of the slowly varying sine term of the latitude offset (1/12 angular frequency)
constexpr double COORD_TRANSFORM_SINE_LAT_SLOW1_AMPLITUDE = 160.0;
// Amplitude of the slowly varying sine term of the latitude offset (1/30 angular frequency)
constexpr double COORD_TRANSFORM_SINE_LAT_SLOW2_AMPLITUDE = 320.0;
// Amplitude of the slowly varying sine term of the longitude offset (1/12 angular frequency)
constexpr double COORD_TRANSFORM_SINE_LNG_SLOW1_AMPLITUDE = 150.0;
// Amplitude of the slowly varying sine term of the longitude offset (1/30 angular frequency)
constexpr double COORD_TRANSFORM_SINE_LNG_SLOW2_AMPLITUDE = 300.0;
constexpr double PI_NUM = 3.14159265358979323846;

bool NavigationCommonUtil::GetDistance(const NativePreferences::LocationPoint& startPoint,
    const NativePreferences::LocationPoint& endPoint, double& distance)
{
    if (!NativePreferences::DataFabricAddressApiHelper::IsValidLatLng(startPoint.latitude, startPoint.longitude) ||
        !NativePreferences::DataFabricAddressApiHelper::IsValidLatLng(endPoint.latitude, endPoint.longitude)) {
        ZLOGE("Get distance failed, the input latitude or longitude is invalid.");
        return false;
    }

    Location::Location locSrc;
    Location::Location locTar;
    locSrc.SetLongitude(startPoint.longitude);
    locSrc.SetLatitude(startPoint.latitude);
    locTar.SetLongitude(endPoint.longitude);
    locTar.SetLatitude(endPoint.latitude);
    auto locRet = Location::LocatorImpl::GetInstance()->GetDistanceBetweenLocations(locSrc, locTar, distance);
    if (locRet != Location::LocationErrCode::ERRCODE_SUCCESS) {
        ZLOGE("Get the distance between locations failed, errCode:%{public}d", locRet);
        return false;
    }
    return true;
}

bool NavigationCommonUtil::Gcj02ToWgs84(const NativePreferences::LocationPoint& gcj02Point,
    NativePreferences::LocationPoint& wgs84Point)
{
    if (!NativePreferences::DataFabricAddressApiHelper::IsValidLatLng(gcj02Point.latitude, gcj02Point.longitude)) {
        ZLOGE("Transform coordinate from gcj02 to wgs84 failed, the input latitude or longitude is invalid.");
        return false;
    }

    double dlng = 0.0;
    double dlat = 0.0;
    if (!CalculateGcj02Delta(gcj02Point.longitude, gcj02Point.latitude, dlng, dlat)) {
        ZLOGE("Failed to calculate gcj02 delta.");
        return false;
    }
    wgs84Point.latitude = gcj02Point.latitude - dlat;
    wgs84Point.longitude = gcj02Point.longitude - dlng;
    return true;
}

double NavigationCommonUtil::TransformLat(double lng, double lat)
{
    double ret = COORD_TRANSFORM_LAT_POLY_BASE + COORD_TRANSFORM_LINEAR_COEFF * lng +
        COORD_TRANSFORM_LAT_LINEAR_Y_COEFF * lat + COORD_TRANSFORM_LAT_SQUARE_SQRT_COEFF * lat * lat +
        COORD_TRANSFORM_CROSS_COEFF * lng * lat;
    ret += COORD_TRANSFORM_LAT_SQUARE_SQRT_COEFF * std::sqrt(std::abs(lng));
    ret += (COORD_TRANSFORM_SINE_BASE_AMPLITUDE * std::sin(COORD_TRANSFORM_SINE_FREQUENCY_6X * lng * PI_NUM) +
        COORD_TRANSFORM_SINE_BASE_AMPLITUDE * std::sin(COORD_TRANSFORM_SINE_FREQUENCY_2X * lng * PI_NUM)) *
        COORD_TRANSFORM_SINE_SCALE_FACTOR;
    ret += (COORD_TRANSFORM_SINE_BASE_AMPLITUDE * std::sin(lat * PI_NUM) +
        COORD_TRANSFORM_SINE_MID_AMPLITUDE * std::sin(lat / COORD_TRANSFORM_SINE_FREQUENCY_DIV_3 * PI_NUM)) *
        COORD_TRANSFORM_SINE_SCALE_FACTOR;
    ret += (COORD_TRANSFORM_SINE_LAT_SLOW1_AMPLITUDE *
        std::sin(lat / COORD_TRANSFORM_SINE_FREQUENCY_DIV_12 * PI_NUM) +
        COORD_TRANSFORM_SINE_LAT_SLOW2_AMPLITUDE * std::sin(lat * PI_NUM / COORD_TRANSFORM_SINE_FREQUENCY_DIV_30)) *
        COORD_TRANSFORM_SINE_SCALE_FACTOR;
    return ret;
}

double NavigationCommonUtil::TransformLng(double lng, double lat)
{
    double ret = COORD_TRANSFORM_LNG_POLY_BASE + lng + COORD_TRANSFORM_LINEAR_COEFF * lat +
        COORD_TRANSFORM_LNG_SQUARE_SQRT_COEFF * lng * lng + COORD_TRANSFORM_CROSS_COEFF * lng * lat +
        COORD_TRANSFORM_LNG_SQUARE_SQRT_COEFF * std::sqrt(std::abs(lng));
    ret += (COORD_TRANSFORM_SINE_BASE_AMPLITUDE * std::sin(COORD_TRANSFORM_SINE_FREQUENCY_6X * lng * PI_NUM) +
        COORD_TRANSFORM_SINE_BASE_AMPLITUDE * std::sin(COORD_TRANSFORM_SINE_FREQUENCY_2X * lng * PI_NUM)) *
        COORD_TRANSFORM_SINE_SCALE_FACTOR;
    ret += (COORD_TRANSFORM_SINE_BASE_AMPLITUDE * std::sin(lng * PI_NUM) +
        COORD_TRANSFORM_SINE_MID_AMPLITUDE * std::sin(lng / COORD_TRANSFORM_SINE_FREQUENCY_DIV_3 * PI_NUM)) *
        COORD_TRANSFORM_SINE_SCALE_FACTOR;
    ret += (COORD_TRANSFORM_SINE_LNG_SLOW1_AMPLITUDE *
        std::sin(lng / COORD_TRANSFORM_SINE_FREQUENCY_DIV_12 * PI_NUM) +
        COORD_TRANSFORM_SINE_LNG_SLOW2_AMPLITUDE * std::sin(lng / COORD_TRANSFORM_SINE_FREQUENCY_DIV_30 * PI_NUM)) *
        COORD_TRANSFORM_SINE_SCALE_FACTOR;
    return ret;
}

bool NavigationCommonUtil::CalculateGcj02Delta(double lng, double lat, double& dlng, double& dlat)
{
    double dLat = TransformLat(lng - COORD_TRANSFORM_LNG_OFFSET, lat - COORD_TRANSFORM_LAT_OFFSET);
    double dLng = TransformLng(lng - COORD_TRANSFORM_LNG_OFFSET, lat - COORD_TRANSFORM_LAT_OFFSET);
    double radLat = lat / COORD_TRANSFORM_DEGREE * PI_NUM;
    double magic = std::sin(radLat);
    magic = 1 - COORD_TRANSFORM_EE * magic * magic;
    double sqrtMagic = std::sqrt(magic);
    if (sqrtMagic == 0) {
        ZLOGE("The magic or sqrtMagic can not be zero.");
        dlat = 0;
        dlng = 0;
        return false;
    }
    dlat = (dLat * COORD_TRANSFORM_DEGREE) / ((COORD_TRANSFORM_A *
        (1 - COORD_TRANSFORM_EE)) / (magic * sqrtMagic) * PI_NUM);
    dlng = (dLng * COORD_TRANSFORM_DEGREE) / (COORD_TRANSFORM_A / sqrtMagic * std::cos(radLat) * PI_NUM);
    return true;
}
} // End of namespace DataFabricAddress
} // End of namespace OHOS
