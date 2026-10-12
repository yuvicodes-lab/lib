# CrackLib Panel — deploy guide (Cloudflare Workers + D1)

## Files

| File | Kaam |
|---|---|
| `worker.js` | Poora backend + website (single file, zero dependency) |
| `wrangler.toml` | Worker config + D1 binding (`crack` DB already filled) |
| `schema.sql` | Tables: users, user_urls, pkgs, hits |

## Deploy (5 min)

```bash
cd panel
npm i -g wrangler
wrangler login

# 1. Tables banao (database_id already wrangler.toml me hai)
wrangler d1 execute crack --file=schema.sql

# 2. Secrets set karo (zaroori)
wrangler secret put SESSION_SECRET   # koi lambi random string
wrangler secret put ADMIN_USER       # tumhara admin username
wrangler secret put ADMIN_PASS       # tumhara admin password

# 3. Deploy
wrangler deploy
```

Domain lagana ho to: Cloudflare dashboard → Workers → custom domain add karo.

## URLs

| URL | Kaun |
|---|---|
| `domain.com/` | Landing + user login |
| `domain.com/register?ref=CODE` | Register (code auto-fill) |
| `domain.com/{username}/` | Us user ka personal panel |
| `domain.com/admin` | Sirf tumhara login + full control |

## Lib ko panel se jodna

1. Panel live hone ke baad `app/src/main/jni/config.h` me:
   ```c
   #define BOOTSTRAP_VALIDATE_URL XOR("http://tumhara-domain.com/api/validate")
   ```
   (http hi rakho — payload waise bhi encrypted hai, aur lib me TLS stack nahi.)
2. AIDE me ek baar build karo → wahi `libCrackLib.so` sab users sab APKs me.
3. User flow: register → apne panel me **URL + package names** save → same lib
   target APK me → lib pkg bhejegi → panel us user ka URL dega.

## Admin kaam (domain.com/admin se, code me kuch nahi)

- Users: search, block/unblock, URL+pkgs edit, delete
- Unclaimed PKGs: lib ne bheja par kisi se juda nahi → user id daal ke assign
- Hits: kaun sa user, kaun sa pkg, kab, kis IP se
- Referral: har user ka code + uske joins, register link copy karke baanto

## Notes

- Passwords PBKDF2-SHA256 (100k) + salt se hash hote hain, plain kabhi store nahi.
- Lib protocol detail: `CRACK LIB/README.md` me "Panel API spec" dekho.
- 200+ users D1 free limits me aaram se (hits row chhoti hai; purana data
  kabhi saaf karna ho to D1 me `DELETE FROM hits WHERE created_at < ...`).
