#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <dlfcn.h>
#include <android/log.h>
#include <string>
#include <vector>
#include <mutex>
#include <chrono>
#include <ctime>
#include <cstring>
#include <cinttypes>
#include <cctype>

#include "dobby.h"
#include "xor.h"
#include "config.h"

// ============================================================
// CrackLib UNIVERSAL — kisi bhi target APK me chalegi.
// - Koi hardcoded target lib / domain / endpoint NAHI.
// - Har load par panel se config: {enabled, replaceUrl, endpoints,
//   targetModule} — wahi URL + wahi endpoints dono hooks use karte hain.
// - Server na mile ya allow na kare → sirf FIND/LOG mode (koi replace nahi).
// - Target stripped ho ya na ho: pehle symbol try, warna OPCODE SCAN.
// - Replace NO-PATCH: nayi URL orig function ko pass hoti hai.
// Saare strings XOR encrypted — plaintext .so me nahi dikhega.
// ============================================================

#define LOG_TAG XOR("CrackLib")
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

#define LOG_PATH_CFG XOR("/storage/emulated/0/Download/logs.txt")

static std::string g_logPath;
static std::string g_sep;         // "://" (generic, server-independent)
static std::string g_httpsP;      // "https://"
static std::string g_httpP;       // "http://"
static bool g_downgradeHttps = true;

static std::mutex g_log_mutex;
static std::vector<uintptr_t> g_hookedTargets;  // double-hook guard

// -----------------------------------------------------------------------------
// Safe File Logger
// -----------------------------------------------------------------------------
void WriteLog(const char* type, const char* data) {
    if (!type || !data) return;

    std::lock_guard<std::mutex> lock(g_log_mutex);
    LOGI(XOR("[%s] %s"), type, data);

    FILE* fp = fopen(g_logPath.empty() ? LOG_PATH_CFG : g_logPath.c_str(), "a+");
    if (fp) {
        auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
        char time_str[64];
        std::strftime(time_str, sizeof(time_str), XOR("%Y-%m-%d %H:%M:%S"), std::localtime(&now));

        fputs(XOR("====================================================\n"), fp);
        fprintf(fp, XOR("[TIME]: %s\n"), time_str);
        fprintf(fp, XOR("[TYPE]: %s\n"), type);
        fprintf(fp, XOR("[DATA]:\n%s\n"), data);
        fputs(XOR("====================================================\n\n"), fp);
        fflush(fp);
        fclose(fp);
    }
}

// -----------------------------------------------------------------------------
// Safe String Validator
// -----------------------------------------------------------------------------
bool IsValidPointer(const void* ptr) {
    return ptr != nullptr && ((uintptr_t)ptr > 0x10000);
}

// Struct for dumping curl header linked list
struct curl_slist {
    char *data;
    struct curl_slist *next;
};

// -----------------------------------------------------------------------------
// URL Replacer — server config se. Config empty/disabled → original wapas
// (FIND-ONLY mode). curl string ko internally copy karta hai, isliye local
// std::string ka c_str() pass karna safe hai. Koi memory patch nahi.
// -----------------------------------------------------------------------------
static bool CanReplace() {
    return g_cfg.enabled && !g_cfg.replaceUrl.empty() && !g_cfg.endpoints.empty();
}

static std::string TryReplaceCurlUrl(const char* url) {
    if (!url) return "";
    std::string u(url);
    if (!CanReplace()) return u;
    bool hit = false;
    for (size_t i = 0; i < g_cfg.endpoints.size(); i++) {
        if (!g_cfg.endpoints[i].empty() && u.find(g_cfg.endpoints[i]) != std::string::npos) {
            hit = true;
            break;
        }
    }
    if (!hit) return u;
    if (g_sep.empty()) return u;
    size_t p = u.find(g_sep);
    if (p == std::string::npos) return u;
    size_t ds = p + g_sep.length();
    size_t pe = u.find('/', ds);
    std::string path = (pe == std::string::npos) ? "" : u.substr(pe);
    std::string nu = u.substr(0, ds) + g_cfg.replaceUrl + path;
    if (g_downgradeHttps && !g_httpsP.empty() && !g_httpP.empty() &&
        nu.compare(0, g_httpsP.length(), g_httpsP) == 0) {
        nu.replace(0, g_httpsP.length(), g_httpP);
    }
    return nu;
}

// -----------------------------------------------------------------------------
// Hook: curl_easy_setopt (URL=10002, POSTFIELDS=10015,
// CUSTOMREQUEST=10036, HTTPHEADER=10023)
// -----------------------------------------------------------------------------
typedef int (*curl_easy_setopt_t)(void *curl, int option, void *param);
static curl_easy_setopt_t orig_curl_easy_setopt = nullptr;

int hooked_curl_easy_setopt(void *curl, int option, void *param) {
    if (IsValidPointer(param)) {
        if (option == 10002) {
            const char* origUrl = (const char*)param;
            WriteLog(XOR("FULL_TARGET_URL"), origUrl);
            std::string nu = TryReplaceCurlUrl(origUrl);
            if (!nu.empty() && nu != origUrl) {
                std::string disp = std::string(origUrl) + XOR(" -> ") + nu;
                WriteLog(XOR("URL_REPLACED"), disp.c_str());
                return orig_curl_easy_setopt(curl, option, (void*)nu.c_str());
            }
        }
        else if (option == 10015) {
            WriteLog(XOR("POST_BODY_DATA"), (const char*)param);
        }
        else if (option == 10036) {
            WriteLog(XOR("HTTP_METHOD"), (const char*)param);
        }
        else if (option == 10023) {
            struct curl_slist* list = (struct curl_slist*)param;
            std::string all_headers = "";
            while (list && IsValidPointer(list->data)) {
                all_headers += list->data;
                all_headers += "\n";
                list = list->next;
            }
            if (!all_headers.empty()) {
                WriteLog(XOR("HTTP_HEADERS"), all_headers.c_str());
            }
        }
    }
    return orig_curl_easy_setopt(curl, option, param);
}

// -----------------------------------------------------------------------------
// Hook: libc getaddrinfo (DNS — host discovery, sirf log, no patch)
// -----------------------------------------------------------------------------
static int (*orig_getaddrinfo)(const char *node, const char *service,
                              const struct addrinfo *hints, struct addrinfo **res) = nullptr;
int hooked_getaddrinfo(const char *node, const char *service,
                      const struct addrinfo *hints, struct addrinfo **res) {
    if (node) {
        char buffer[256];
        snprintf(buffer, sizeof(buffer), XOR("Host: %s | Port: %s"), node, service ? service : XOR("N/A"));
        WriteLog(XOR("DNS_REQUEST"), buffer);
    }
    return orig_getaddrinfo(node, service, hints, res);
}

// -----------------------------------------------------------------------------
// Module Segment Locator (sirf READ — /proc/self/maps se r-x segments)
// -----------------------------------------------------------------------------
struct ModuleSegment {
    uintptr_t start;
    uintptr_t end;
    char perms[5];
    std::string path;
};

static std::string GetSelfPath() {
    Dl_info info;
    memset(&info, 0, sizeof(info));
    if (dladdr((void*)GetSelfPath, &info) && info.dli_fname) return info.dli_fname;
    return "";
}

std::vector<ModuleSegment> GetSegments(const char* module_name) {
    std::vector<ModuleSegment> segments;
    FILE* fp = fopen(XOR("/proc/self/maps"), "rt");
    if (!fp) return segments;

    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, module_name)) {
            uintptr_t start, end;
            char perms[5];
            if (sscanf(line, "%" SCNxPTR "-%" SCNxPTR " %4s", &start, &end, perms) == 3) {
                if (perms[0] != 'r' || perms[2] != 'x') continue;
                ModuleSegment s;
                s.start = start; s.end = end;
                s.perms[0] = perms[0]; s.perms[1] = perms[1];
                s.perms[2] = perms[2]; s.perms[3] = perms[3]; s.perms[4] = '\0';
                const char* sp = strchr(line, '/');
                s.path = sp ? sp : "";
                size_t nl = s.path.find('\n');
                if (nl != std::string::npos) s.path = s.path.substr(0, nl);
                segments.push_back(s);
            }
        }
    }
    fclose(fp);
    return segments;
}

// Saare APP libs ke r-x segments (system/apex/vendor + khud ki lib excluded).
// Target APK alag-alag ho to bhi kaam karega — naam ki need nahi.
std::vector<ModuleSegment> GetAllAppSegments() {
    std::vector<ModuleSegment> out;
    std::string self = GetSelfPath();
    FILE* fp = fopen(XOR("/proc/self/maps"), "rt");
    if (!fp) return out;

    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        const char* sp = strchr(line, '/');
        if (!sp) continue;
        if (!strstr(sp, ".so")) continue;
        if (strncmp(sp, "/system/", 8) == 0) continue;
        if (strncmp(sp, "/apex/", 6) == 0) continue;
        if (strncmp(sp, "/vendor/", 8) == 0) continue;
        if (!self.empty() && strstr(sp, self.c_str())) continue;
        // sirf app-private libs: /data/app ya /data/data ke andar
        if (!strstr(sp, "/data/app/") && !strstr(sp, "/data/data/")) continue;

        uintptr_t start, end;
        char perms[5];
        if (sscanf(line, "%" SCNxPTR "-%" SCNxPTR " %4s", &start, &end, perms) == 3) {
            if (perms[0] != 'r' || perms[2] != 'x') continue;
            ModuleSegment s;
            s.start = start; s.end = end;
            s.perms[0] = perms[0]; s.perms[1] = perms[1];
            s.perms[2] = perms[2]; s.perms[3] = perms[3]; s.perms[4] = '\0';
            s.path = sp;
            size_t nl = s.path.find('\n');
            if (nl != std::string::npos) s.path = s.path.substr(0, nl);
            out.push_back(s);
        }
    }
    fclose(fp);
    return out;
}

// -----------------------------------------------------------------------------
// Opcode Scanner — STRIPPED lib ke liye (symbol ki jarurat nahi).
// "MOV W1/X1, #10002" (CURLOPT_URL) ke baad wala BL hi setopt ka call hai.
// -----------------------------------------------------------------------------
static bool AlreadyHooked(uintptr_t addr) {
    for (size_t i = 0; i < g_hookedTargets.size(); i++) {
        if (g_hookedTargets[i] == addr) return true;
    }
    return false;
}

static bool ScanSegmentsForCurl(const std::vector<ModuleSegment>& segments) {
    bool any = false;
    for (size_t s = 0; s < segments.size(); s++) {
        const ModuleSegment& seg = segments[s];
        if (seg.end <= seg.start) continue;
        if (seg.end - seg.start > (64u * 1024u * 1024u)) continue;  // pagal segment skip
        uint32_t* code = (uint32_t*)seg.start;
        size_t count = (seg.end - seg.start) / 4;

        for (size_t i = 0; i + 4 < count; ++i) {
            // MOV W1, #10002 (0x2712) or MOV X1, #10002
            if (code[i] == 0x5284e241 || code[i] == 0xd284e241) {
                for (size_t j = 1; j <= 4; ++j) {
                    uint32_t next_insn = code[i + j];
                    if ((next_insn & 0xFC000000) == 0x94000000) { // BL instruction
                        int32_t imm26 = (int32_t)(next_insn & 0x03FFFFFF);
                        if (imm26 & 0x02000000) {
                            imm26 |= 0xFC000000;
                        }
                        uintptr_t target_func = (uintptr_t)(&code[i + j]) + (imm26 * 4);
                        if (AlreadyHooked(target_func)) { any = true; break; }

                        char log_buf[192];
                        snprintf(log_buf, sizeof(log_buf), XOR("Hooking curl_easy_setopt at 0x%lx in %s"),
                                 (unsigned long)target_func, seg.path.c_str());
                        WriteLog(XOR("HOOK_SUCCESS"), log_buf);

                        if (DobbyHook((void*)target_func, (void*)hooked_curl_easy_setopt,
                                      (void**)&orig_curl_easy_setopt) == 0) {
                            g_hookedTargets.push_back(target_func);
                            any = true;
                        }
                        break;
                    }
                }
            }
        }
    }
    return any;
}

bool HookCurlByOpcode(const char* module_name) {
    return ScanSegmentsForCurl(GetSegments(module_name));
}

bool HookCurlScanAll() {
    return ScanSegmentsForCurl(GetAllAppSegments());
}

// -----------------------------------------------------------------------------
// Monitor Thread
// -----------------------------------------------------------------------------
void* MonitorThread(void*) {
    g_logPath = LOG_PATH_CFG;
    g_sep     = XOR("://");
    g_httpsP  = XOR("https://");
    g_httpP   = XOR("http://");

    bool cfg_ok = EnsureServerConfig();
    if (cfg_ok && g_cfg.enabled && !g_cfg.replaceUrl.empty()) {
        WriteLog(XOR("SYSTEM"), XOR("Universal lib started — REPLACE mode"));
    } else if (cfg_ok && g_cfg.enabled) {
        WriteLog(XOR("SYSTEM"), XOR("Universal lib started — FIND-ONLY mode (no URL from server)"));
    } else {
        WriteLog(XOR("SYSTEM"), XOR("Server unreachable/blocked — FIND-ONLY mode"));
    }

    // Hook DNS (libc stripped nahi hota → symbol mil jayega)
    void* p_getaddrinfo = DobbySymbolResolver(nullptr, XOR("getaddrinfo"));
    if (p_getaddrinfo) {
        DobbyHook(p_getaddrinfo, (void*)hooked_getaddrinfo, (void**)&orig_getaddrinfo);
    }

    // curl hook: pehle symbol try, warna opcode scan. Target APK koi bhi ho —
    // server ne exact module bheja ho to wahi, warna saare app libs.
    bool hooked = false;
    void* p_curl = DobbySymbolResolver(nullptr, XOR("curl_easy_setopt"));
    if (p_curl) {
        WriteLog(XOR("HOOK_SUCCESS"), XOR("Hooking curl_easy_setopt via symbol"));
        if (DobbyHook(p_curl, (void*)hooked_curl_easy_setopt,
                      (void**)&orig_curl_easy_setopt) == 0) {
            g_hookedTargets.push_back((uintptr_t)p_curl);
            hooked = true;
        }
    }

    if (!g_cfg.targetModule.empty()) {
        WriteLog(XOR("SYSTEM"), XOR("Waiting for server-specified module..."));
        int waits = 0;
        while (!hooked && waits < 120) {  // ~2 min tak naye module ka wait
            auto segs = GetSegments(g_cfg.targetModule.c_str());
            if (!segs.empty()) hooked = HookCurlByOpcode(g_cfg.targetModule.c_str());
            if (!hooked) { usleep(1000000); waits++; }
        }
    } else {
        int sweeps = 0;
        while (!hooked && sweeps < 24) {  // ~2 min tak retry (late dlopen ke liye)
            hooked = HookCurlScanAll();
            if (!hooked) { usleep(5000000); sweeps++; }
        }
        if (hooked) {  // der se load hone wali libs ke liye ek aur sweep
            usleep(30000000);
            HookCurlScanAll();
        }
    }

    if (!hooked) WriteLog(XOR("SYSTEM"), XOR("curl hook NOT installed (pattern not found)"));
    return nullptr;
}

__attribute__((constructor)) void InitCrackLib() {
    pthread_t thread;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_create(&thread, &attr, MonitorThread, nullptr);
    pthread_attr_destroy(&attr);
}
