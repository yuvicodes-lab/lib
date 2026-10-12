#include <jni.h>
#include <string.h>
#include <android/log.h>
#include <string>
#include <vector>
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <unistd.h>
#include "dobby.h"
#include "xor.h"
#include "config.h"  // server config shared (hook.cpp wala hi URL yahan bhi)

// NOTE: ye file + hook.cpp dono ek hi lib me chalte hain.
// Replace URL dono ke liye EK HI hai — server se aata hai (g_cfg.replaceUrl).
// libcurl nahi hai (AIDE/NDK me milta nahi) — networking config.cpp me hai.

#define LOGTAG XOR("JNI_HOOK")

// ============================================
// LOGGING CONTROL
// ============================================
#define ENABLE_LOGS false

#if ENABLE_LOGS
    #define WRITE_LOG(text) writeLog(text)
#else
    #define WRITE_LOG(text) ((void)0)
#endif

// ============================================
// ORIGINAL FUNCTION POINTERS
// ============================================
jstring (*orig_NewStringUTF)(JNIEnv*, const char*);
const char* (*orig_GetStringUTFChars)(JNIEnv*, jstring, jboolean*);

// ============================================
// GLOBAL VARIABLES (server se bhare jate hain — koi hardcode nahi)
// ============================================
static std::string GLOBAL_REPLACE_URL = "";
static bool HOOK_ENABLED = false;

// Hot-path cache
static std::string g_jniHttp;
static std::string g_jniLogPath;

// ============================================
// FILE LOGGING
// ============================================
void writeLog(const char* text) {
    #if ENABLE_LOGS
    FILE *f = fopen(g_jniLogPath.empty() ? XOR("/sdcard/Download/string-hook.log") : g_jniLogPath.c_str(), "a");
    if (f != nullptr) {
        fprintf(f, XOR("[%d] %s\n"), getpid(), text);
        fflush(f);
        fclose(f);
    }
    #endif
}

// ============================================
// CHECK IF URL SHOULD BE REPLACED (server endpoints se)
// ============================================
bool shouldReplaceURL(const std::string& url) {
    if (g_cfg.endpoints.empty()) return false;  // FIND-ONLY mode: replace nahi
    for (size_t i = 0; i < g_cfg.endpoints.size(); i++) {
        if (!g_cfg.endpoints[i].empty() && url.find(g_cfg.endpoints[i]) != std::string::npos) {
            return true;
        }
    }
    return false;
}

// ============================================
// JSON PARSER (server response ke liye — testable)
// ============================================
bool parse_json_response(const std::string& json, bool& status, std::string& url) {
    std::string s_true1 = XOR("\"status\":true");
    std::string s_true2 = XOR("\"status\": true");
    if (json.find(s_true1) != std::string::npos || json.find(s_true2) != std::string::npos) {
        status = true;
    } else {
        status = false;
    }

    std::string url_key = XOR("\"url\":");
    size_t url_pos = json.find(url_key);
    if (url_pos != std::string::npos) {
        size_t start_quote = json.find('"', url_pos + url_key.length());
        size_t end_quote = (start_quote == std::string::npos) ? std::string::npos : json.find('"', start_quote + 1);
        if (start_quote != std::string::npos && end_quote != std::string::npos) {
            url = json.substr(start_quote + 1, end_quote - start_quote - 1);
        }
    }
    return true;
}

// ============================================
// HOOKS
// ============================================
jstring my_NewStringUTF(JNIEnv* env, const char* utf) {
    if (utf != nullptr && HOOK_ENABLED && !GLOBAL_REPLACE_URL.empty() && !g_jniHttp.empty()) {
        std::string str(utf);
        if (str.find(g_jniHttp) != std::string::npos) {
            char buf[1024];
            snprintf(buf, sizeof(buf), XOR("[NewStringUTF] URL Found: %s"), utf);
            WRITE_LOG(buf);

            if (shouldReplaceURL(str)) {
                snprintf(buf, sizeof(buf), XOR("[NewStringUTF] REPLACED: %s -> %s"), utf, GLOBAL_REPLACE_URL.c_str());
                WRITE_LOG(buf);
                return orig_NewStringUTF(env, GLOBAL_REPLACE_URL.c_str());
            }
        }
    }
    return orig_NewStringUTF(env, utf);
}

const char* my_GetStringUTFChars(JNIEnv* env, jstring string, jboolean* isCopy) {
    const char* utf = orig_GetStringUTFChars(env, string, isCopy);

    if (utf != nullptr && HOOK_ENABLED && !GLOBAL_REPLACE_URL.empty() && !g_jniHttp.empty()) {
        std::string str(utf);
        if (str.find(g_jniHttp) != std::string::npos) {
            char buf[1024];
            snprintf(buf, sizeof(buf), XOR("[GetStringUTFChars] URL Found: %s"), utf);
            WRITE_LOG(buf);

            if (shouldReplaceURL(str)) {
                snprintf(buf, sizeof(buf), XOR("[GetStringUTFChars] REPLACED: %s -> %s"), utf, GLOBAL_REPLACE_URL.c_str());
                WRITE_LOG(buf);
                // WARNING: JVM is buffer ko us jstring ka maan kar ReleaseStringUTFChars
                // me wapas dega. Sirf tab replace hota hai jab endpoint match ho.
                return GLOBAL_REPLACE_URL.c_str();
            }
        }
    }
    return utf;
}

// ============================================
// APPLY HOOKS
// ============================================
void apply_jni_hook(JNIEnv* env) {
    WRITE_LOG(XOR("[HOOK] Applying JNI hooks..."));

    if (env == nullptr) {
        WRITE_LOG(XOR("ERROR: JNIEnv is NULL!"));
        return;
    }

    void* addr_NewStringUTF = (void*)env->functions->NewStringUTF;
    void* addr_GetStringUTFChars = (void*)env->functions->GetStringUTFChars;

    if (addr_NewStringUTF != nullptr) {
        int result = DobbyHook(addr_NewStringUTF, (void*)my_NewStringUTF, (void**)&orig_NewStringUTF);
        if (result == 0) WRITE_LOG(XOR("[HOOK] NewStringUTF hooked!"));
    }

    if (addr_GetStringUTFChars != nullptr) {
        int result = DobbyHook(addr_GetStringUTFChars, (void*)my_GetStringUTFChars, (void**)&orig_GetStringUTFChars);
        if (result == 0) WRITE_LOG(XOR("[HOOK] GetStringUTFChars hooked!"));
    }

    WRITE_LOG(XOR("=== HOOK APPLICATION COMPLETED ==="));
}

// ============================================
// JNI_OnLoad — server se config, dono hooks ke liye ek hi URL
// ============================================
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved) {
    WRITE_LOG(XOR("=== JNI_OnLoad START ==="));

    JNIEnv* env = nullptr;
    if (vm->GetEnv((void**)&env, JNI_VERSION_1_6) != JNI_OK || env == nullptr) {
        return JNI_VERSION_1_6;
    }

    g_jniHttp = XOR("http");
    g_jniLogPath = XOR("/sdcard/Download/string-hook.log");

    // Server se config (pkg → kaun sa user → uska URL). Thread-safe, ek hi baar.
    bool cfg_ok = EnsureServerConfig();
    if (cfg_ok && g_cfg.enabled && !g_cfg.replaceUrl.empty()) {
        GLOBAL_REPLACE_URL = g_cfg.replaceUrl;
        HOOK_ENABLED = true;
        WRITE_LOG(XOR("[SERVER] Authorized, hooks enabling..."));
    } else if (cfg_ok && g_cfg.enabled) {
        WRITE_LOG(XOR("[SERVER] Authorized but no URL — FIND-ONLY mode."));
    } else {
        WRITE_LOG(XOR("[SERVER] Validation failed — hooks NOT applied."));
    }

    if (HOOK_ENABLED) {
        apply_jni_hook(env);
    }

    WRITE_LOG(XOR("=== JNI_OnLoad COMPLETED ==="));
    return JNI_VERSION_1_6;
}

// ============================================
// CONSTRUCTOR
// ============================================
__attribute__((constructor))
void init_jnihook() {
    WRITE_LOG(XOR("=== LIBRARY CONSTRUCTOR CALLED ==="));
}
