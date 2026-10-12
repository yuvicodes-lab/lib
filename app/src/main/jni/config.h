#pragma once
// Shared server-driven config — dono hooks (curl + JNI) ek hi config use karte hain.
// Lib me koi user-specific data hardcode NAHI hai: har load par panel se aata hai.
// Isliye lib ek baar build hone ke baad kabhi rebuild nahi mangti.
//
// Protocol (panel/Worker ko ye follow karna hai, detail README me):
//   POST <BOOTSTRAP_VALIDATE_URL>  body: data=<HEX(XOR(pkg|libver|ts))>
//   RESP body: HEX(XOR(json))  json: {"status":true,"url":"...","endpoints":[...],
//                                     "target":"","refresh":300,"mode":"replace"}

#include <string>
#include <vector>

#define LIB_VERSION "3.0"

// !! Pehli build se PEHLE apna panel domain yahan set karo.
// Ye lib me eklauti one-time setting hai — iske baad rebuild ki need nahi.
#define BOOTSTRAP_VALIDATE_URL XOR("http://panel.example.com/api/validate")

struct ServerConfig {
  bool enabled = false;                // server ne allow kiya ya nahi
  std::string replaceUrl;              // user ka URL (empty = sirf find/log mode)
  std::vector<std::string> endpoints;  // match list (empty = koi replace nahi)
  std::string targetModule;            // optional exact .so (empty = saare app libs scan)
  int refreshSec = 300;
};

extern ServerConfig g_cfg;
extern std::string g_cfgError;

// Thread-safe one-time fetch. true = server ne enable kiya.
bool EnsureServerConfig();

// Direct fetch (test / manual refresh ke liye)
bool FetchServerConfigFrom(const std::string& validateUrl, const std::string& pkg);

// Shared protocol helpers
std::string xor_crypt(const std::string& data, const std::string& key);
std::string to_hex(const std::string& data);
std::string from_hex(const std::string& hex);
std::string encrypt_data(const std::string& data);
std::string decrypt_data(const std::string& hex_data);
std::string http_post(const std::string& url_str, const std::string& post_data);
std::string GetOwnPkg();
