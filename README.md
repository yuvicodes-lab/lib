# CrackLib — Universal URL Hook (build once, configure forever)

Ek hi `libCrackLib.so` kisi bhi target APK me chalti hai. Lib me **koi
user-specific ya target-specific data hardcode nahi hai** — har load par
panel (server) se config aati hai: kaun sa user, uska URL, match endpoints.

- Target APK alag-alag ho to bhi chalega (module ka naam fix nahi hai)
- Target lib **stripped** ho to bhi chalega (opcode scan, symbol ki need nahi)
- Replace **bina memory patch** ke hota hai (nayi string orig function ko milti hai)
- Server allow na kare / unreachable ho → **find-only mode** (sirf log, koi replace nahi)
- Saari strings `XOR()` encrypted — `strings libCrackLib.so` me kuch nahi dikhta

## Project structure

```
app/src/main/jni/
├── hook.cpp        # curl hook (opcode scan) + DNS hook, NO strlen, NO patch
├── jnihook.cpp     # JNI string hooks (NewStringUTF / GetStringUTFChars)
├── config.cpp/h    # shared server config: validate protocol + HTTP + crypt
├── xor.h           # string obfuscation header (per-string, per-build keys)
├── Android.mk      # module CrackLib (hook.cpp jnihook.cpp config.cpp)
├── Application.mk  # arm64-v8a, android-21, --strip-all
└── Dobby/          # dobby.h + libdobby.a (hooking engine)
```

Dono hooks ke liye **ek hi replace URL** hota hai — server se aata hai
(`g_cfg.replaceUrl`). Curl hook aur JNI hook dono wahi use karte hain.

## Pehli build se PEHLE (eklauta one-time setting)

`config.h` me apna panel domain set karo. Ye lib me eklauti fixed setting
hai — iske baad **kabhi rebuild ki need nahi**:

```c
#define BOOTSTRAP_VALIDATE_URL XOR("http://panel.example.com/api/validate")
```

## AIDE me build

1. Project kholo → **Build / Run** dabao (ndk-build `Android.mk` se hota hai).
2. Output: `libs/arm64-v8a/libCrackLib.so` (stripped, release).
3. Is `.so` ko target APK me daalo — bas, har user / har game ke liye **same file**.

## Kaam kaise karta hai

```
load → pkg bhejo → panel: pkg → user → uska URL → hooks on
```

1. **Validate.** Load par lib apna package name (`/proc/self/cmdline` se) +
   lib version + timestamp panel ko bhejti hai (XOR+HEX encrypted POST).
2. **Config.** Panel jawab deta hai: `{enabled, replaceUrl, endpoints[],
   targetModule, refresh, mode}`. Dono hooks wahi URL + endpoints use karte hain.
3. **Curl hook.** `curl_easy_setopt` ko pehle symbol se, na mile to opcode
   scan se dhoondhta hai (`MOV W1/X1, #10002` ke baad wala `BL`).
   `CURLOPT_URL` match hone par domain badal kar nayi URL orig ko de deta hai
   (curl usko copy karta hai — purana buffer untouched, `https→http` downgrade).
   `POSTFIELDS / METHOD / HEADERS / DNS` sirf log hote hain.
4. **JNI hook.** `NewStringUTF` / `GetStringUTFChars` me `http` + endpoint
   mile to server wali URL se replace.
5. **Server mana kare** (`status:false`, block, ya network fail) → hooks off /
   find-only. Panel se URL badlo → next load par lib khud naya utha legi.

## Panel API spec (Worker/backend banane walo ke liye)

Request:

```
POST /api/validate
body: data=<HEX>( XOR( "pkg|libver|unix_ts", key="MySecretKey2026_VIP" ) )
```

Response body: same key se `HEX(XOR(json))`, json:

```json
{
  "status": true,
  "url": "http://user-panel.example.com/prefix",
  "endpoints": ["/connect", "/server", "/api/verify"],
  "target": "",
  "refresh": 300,
  "mode": "replace"
}
```

- `url` empty ya `mode:"log"` → find-only (koi replace nahi).
- `target` me exact `.so` naam do to sirf wahi scan hoga, warna **saare app
  libs** scan hote hain (kisi bhi APK ke liye).
- `status:false` → lib hooks nahi lagati.

## Verify (release .so par)

```bash
strings libCrackLib.so | grep -E "panel|FULL_TARGET|NewStringUTF|/proc/self"
# kuch nahi milna chahiye (libc imports jaise socket/getaddrinfo normal hain —
# wo har native lib me hote hain, leak nahi)
```

## Notes / limits (honest)

- Pehchan **pkg-name based** hai (build-once ka tradeoff). Mass-share rokne ke
  liye panel me **per-user device-ID limit + hit logs + block button** rakho.
- `GetStringUTFChars` replace par JVM ko dusra buffer milta hai — sirf
  endpoint-match par hota hai (code me WARNING comment dekho).
- Logging default OFF hai (`ENABLE_LOGS false` dono files me). URL dekhne ke
  liye testing me `true` karo, release me wapas `false`.
- Validation transport `http://` hai (lib me TLS stack nahi, taaki koi extra
  dependency na ho). Payload waise bhi XOR+HEX encrypted hai.
