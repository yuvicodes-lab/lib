#include "config.h"
#include "xor.h"

#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <ctime>
#include <mutex>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

ServerConfig g_cfg;
std::string g_cfgError;
static std::mutex g_cfgMutex;
static bool g_cfgFetched = false;

// ---------------- crypt (XOR + HEX) ----------------
std::string xor_crypt(const std::string& data, const std::string& key) {
    if (key.empty() || data.empty()) return data;
    std::string result = data;
    for (size_t i = 0; i < data.size(); ++i) {
        result[i] = data[i] ^ key[i % key.size()];
    }
    return result;
}

std::string to_hex(const std::string& data) {
    std::string hex;
    char buf[3];
    for (unsigned char c : data) {
        snprintf(buf, sizeof(buf), XOR("%02x"), c);
        hex += buf;
    }
    return hex;
}

std::string from_hex(const std::string& hex) {
    std::string data;
    for (size_t i = 0; i + 1 < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        char byte = (char) strtol(byteString.c_str(), NULL, 16);
        data.push_back(byte);
    }
    return data;
}

std::string encrypt_data(const std::string& data) {
    std::string key = XOR("MySecretKey2026_VIP");
    return to_hex(xor_crypt(data, key));
}

std::string decrypt_data(const std::string& hex_data) {
    std::string key = XOR("MySecretKey2026_VIP");
    return xor_crypt(from_hex(hex_data), key);
}

// ---------------- raw socket HTTP POST (sirf http://) ----------------
static bool send_all(int sock, const char* buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(sock, buf + sent, len - sent, 0);
        if (n <= 0) return false;
        sent += (size_t)n;
    }
    return true;
}

std::string http_post(const std::string& url_str, const std::string& post_data) {
    std::string http_pre = XOR("http://");
    if (url_str.compare(0, http_pre.length(), http_pre) != 0) return "ERROR";
    std::string rest = url_str.substr(http_pre.length());
    size_t slash = rest.find('/');
    std::string hostport = (slash == std::string::npos) ? rest : rest.substr(0, slash);
    std::string path = (slash == std::string::npos) ? "/" : rest.substr(slash);
    std::string host = hostport;
    int port = 80;
    size_t colon = hostport.find(':');
    if (colon != std::string::npos) {
        host = hostport.substr(0, colon);
        port = atoi(hostport.substr(colon + 1).c_str());
        if (port <= 0 || port > 65535) port = 80;
    }
    if (host.empty()) return "ERROR";

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo* res = nullptr;
    if (getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0 || !res) return "ERROR";

    int sock = -1;
    for (struct addrinfo* rp = res; rp != nullptr; rp = rp->ai_next) {
        if (rp->ai_family == AF_INET) {
            ((struct sockaddr_in*)rp->ai_addr)->sin_port = htons((uint16_t)port);
        } else if (rp->ai_family == AF_INET6) {
            ((struct sockaddr_in6*)rp->ai_addr)->sin6_port = htons((uint16_t)port);
        } else {
            continue;
        }
        sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock < 0) continue;
        struct timeval tv;
        tv.tv_sec = 10; tv.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        if (connect(sock, rp->ai_addr, rp->ai_addrlen) == 0) break;
        close(sock);
        sock = -1;
    }
    freeaddrinfo(res);
    if (sock < 0) return "ERROR";

    std::string req;
    req += XOR("POST ");
    req += path;
    req += XOR(" HTTP/1.1\r\nHost: ");
    req += hostport;
    req += XOR("\r\nUser-Agent: Mozilla/5.0 (Linux; Android) CrackLib/3.0\r\n");
    req += XOR("Content-Type: application/x-www-form-urlencoded\r\n");
    char cl[64];
    snprintf(cl, sizeof(cl), XOR("Content-Length: %zu\r\n"), post_data.length());
    req += cl;
    req += XOR("Connection: close\r\n\r\n");
    req += post_data;

    std::string response = "ERROR";
    if (send_all(sock, req.c_str(), req.length())) {
        std::string raw;
        char tmp[4096];
        ssize_t n;
        while ((n = recv(sock, tmp, sizeof(tmp), 0)) > 0) {
            raw.append(tmp, (size_t)n);
        }
        size_t hdr_end = raw.find("\r\n\r\n");
        if (hdr_end != std::string::npos) {
            response = raw.substr(hdr_end + 4);
        } else if (!raw.empty()) {
            response = raw;
        }
    }
    close(sock);
    return response;
}

// ---------------- package name ----------------
std::string GetOwnPkg() {
    char cmdline[256] = {0};
    FILE* fp = fopen(XOR("/proc/self/cmdline"), "r");
    if (fp) {
        fread(cmdline, 1, sizeof(cmdline) - 1, fp);
        fclose(fp);
        std::string pkg(cmdline);
        size_t pos = pkg.find(':');
        if (pos != std::string::npos) pkg = pkg.substr(0, pos);
        return pkg;
    }
    return "";
}

// ---------------- response parse ----------------
static std::string parse_quoted_after(const std::string& json, const std::string& key) {
    size_t kp = json.find(key);
    if (kp == std::string::npos) return "";
    size_t q1 = json.find('"', kp + key.length());
    if (q1 == std::string::npos) return "";
    size_t q2 = json.find('"', q1 + 1);
    if (q2 == std::string::npos) return "";
    return json.substr(q1 + 1, q2 - q1 - 1);
}

static bool ApplyValidateJson(const std::string& json) {
    std::string k_true = XOR("\"status\":true");
    if (json.find(k_true) == std::string::npos) {
        g_cfgError = "server status != true";
        return false;
    }
    std::string k_url = XOR("\"url\":");
    std::string k_eps = XOR("\"endpoints\":");
    std::string k_tgt = XOR("\"target\":");
    std::string k_ref = XOR("\"refresh\":");
    std::string k_mode = XOR("\"mode\":");

    g_cfg.enabled = true;
    g_cfg.replaceUrl = parse_quoted_after(json, k_url);
    g_cfg.targetModule = parse_quoted_after(json, k_tgt);

    g_cfg.endpoints.clear();
    size_t ep = json.find(k_eps);
    if (ep != std::string::npos) {
        size_t b1 = json.find('[', ep + k_eps.length());
        size_t b2 = (b1 == std::string::npos) ? std::string::npos : json.find(']', b1 + 1);
        if (b1 != std::string::npos && b2 != std::string::npos) {
            size_t p = b1 + 1;
            while (p < b2) {
                size_t q1 = json.find('"', p);
                if (q1 == std::string::npos || q1 >= b2) break;
                size_t q2 = json.find('"', q1 + 1);
                if (q2 == std::string::npos || q2 > b2) break;
                g_cfg.endpoints.push_back(json.substr(q1 + 1, q2 - q1 - 1));
                p = q2 + 1;
            }
        }
    }

    std::string mode = parse_quoted_after(json, k_mode);
    if (mode == "log") g_cfg.replaceUrl.clear();  // find-only mode

    size_t rp = json.find(k_ref);
    if (rp != std::string::npos) {
        size_t c = json.find(':', rp + k_ref.length() - 1);
        if (c != std::string::npos) {
            int v = atoi(json.c_str() + c + 1);
            if (v > 0) g_cfg.refreshSec = v;
        }
    }
    return true;
}

bool FetchServerConfigFrom(const std::string& validateUrl, const std::string& pkg) {
    if (pkg.empty()) {
        g_cfgError = "empty pkg";
        return false;
    }
    char ts[32];
    snprintf(ts, sizeof(ts), XOR("%lld"), (long long)time(nullptr));
    std::string payload = pkg + "|" + LIB_VERSION + "|" + ts;
    std::string post_data = std::string(XOR("data=")) + encrypt_data(payload);

    std::string resp = http_post(validateUrl, post_data);
    if (resp.empty() || resp == "ERROR") {
        g_cfgError = "network error";
        return false;
    }
    std::string dec = decrypt_data(resp);
    if (dec.empty()) {
        g_cfgError = "decrypt failed";
        return false;
    }
    return ApplyValidateJson(dec);
}

bool EnsureServerConfig() {
    std::lock_guard<std::mutex> lock(g_cfgMutex);
    if (g_cfgFetched) return g_cfg.enabled;
    g_cfgFetched = true;
    std::string url = BOOTSTRAP_VALIDATE_URL;
    std::string pkg = GetOwnPkg();
    return FetchServerConfigFrom(url, pkg);
}
