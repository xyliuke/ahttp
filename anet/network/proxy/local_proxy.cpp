//
// Created by ke liu on 19/01/2018.
// Copyright (c) 2018 ke liu. All rights reserved.
//

#include "local_proxy.h"

#ifdef __APPLE__

#endif

#ifdef _WIN32
//define something for Windows (32-bit and 64-bit, this part is common)
static std::shared_ptr<std::map<std::string, std::string>> get_local_proxy() {
    auto ret = std::make_shared<std::map<std::string, std::string>>();
    return ret;
};
   #ifdef _WIN64
      //define something for Windows (64-bit only)
   #else
      //define something for Windows (32-bit only)
   #endif
#elif __APPLE__
#include <CFNetwork/CFProxySupport.h>
#include <CoreFoundation/CFDictionary.h>
#include <CoreFoundation/CFNumber.h>
#include <CoreFoundation/CFString.h>
#include <sstream>

static std::string get_string_value(CFDictionaryRef dic, std::string key);

static int get_int_value(CFDictionaryRef dic, std::string key) {
    const char* k = key.c_str();
    CFStringRef str = CFStringCreateWithCString(NULL, k, kCFStringEncodingUTF8);
    const void* value = CFDictionaryGetValue(dic, str);
    int ret = 0;
    if (value != NULL) {
        if (CFGetTypeID(value) == CFNumberGetTypeID()) {
            CFNumberGetValue((CFNumberRef)value, kCFNumberSInt32Type, &ret);
        } else if (CFGetTypeID(value) == CFStringGetTypeID()){
            std::string v = get_string_value(dic, key);
            return atoi(v.c_str());
        }
    }
    return ret;
}
static std::string get_string_value(CFDictionaryRef dic, std::string key) {
    const char* k = key.c_str();
    CFStringRef str = CFStringCreateWithCString(NULL, k, kCFStringEncodingUTF8);
    const void* value = CFDictionaryGetValue(dic, str);
    if (value != NULL) {
        if (CFGetTypeID(value) == CFStringGetTypeID()) {
            char buf[100];
            CFStringGetCString((CFStringRef)value, buf, 100, kCFStringEncodingUTF8);
            return std::string(buf);
        } else if (CFGetTypeID(value) == CFNumberGetTypeID()){
            int num = get_int_value(dic, key);
            std::stringstream ss;
            ss << num;
            return ss.str();
        }
    }
    return "";
}

static std::shared_ptr<std::map<std::string, std::string>> get_local_proxy() {
    auto ret = std::make_shared<std::map<std::string, std::string>>();
    CFDictionaryRef dic = CFNetworkCopySystemProxySettings();

    int httpEnable = get_int_value(dic, "HTTPEnable");
    if (httpEnable == 1) {
        (*ret)["HTTPProxy"] = get_string_value(dic, "HTTPProxy");
        (*ret)["HTTPPort"] = get_string_value(dic, "HTTPPort");
    }

    int httpsEnable = get_int_value(dic, "HTTPSEnable");
    if (httpsEnable == 1) {
        (*ret)["HTTPSProxy"] = get_string_value(dic, "HTTPSProxy");
        (*ret)["HTTPSPort"] = get_string_value(dic, "HTTPSPort");
    }

    return ret;
};

//#include "TargetConditionals.h"
//#if TARGET_IPHONE_SIMULATOR
// iOS Simulator
//#elif TARGET_OS_IPHONE
// iOS device
//#elif TARGET_OS_MAC
// Other kinds of Mac OS
//#else
//# error "Unknown Apple platform"
//#endif
#elif __ANDROID__
// android
static std::shared_ptr<std::map<std::string, std::string>> get_local_proxy() {
    auto ret = std::make_shared<std::map<std::string, std::string>>();
    return ret;
};
#elif __linux__
    // linux
#elif __unix__ // all unices not caught above
    // Unix
#elif defined(_POSIX_VERSION)
    // POSIX
#else
# error "Unknown compiler"
#endif

namespace plan9
{
    void local_proxy::get_proxy(std::function<void(std::shared_ptr<std::map<std::string, std::string>>)> callback) {
        if (callback) {
            callback(get_local_proxy());
        }
    }
}