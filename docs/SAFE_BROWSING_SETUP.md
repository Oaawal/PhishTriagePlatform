# Google Safe Browsing link check: setup

When a scanned message contains links, the API asks Google Safe Browsing
whether any of them is a known phishing or malware site. A match adds the
signal "Google Safe Browsing lists this link as dangerous" and makes the
result High risk. Without a key, scans still work with the rules only.

## 1. Create the key (about 5 minutes)

1. Open https://console.cloud.google.com and sign in.
2. Top bar: **project picker > New Project**. Name it `phishtriage`, click **Create**, then select it.
3. Left menu: **APIs & Services > Library**. Search **Safe Browsing API**, open it, click **Enable**.
4. Left menu: **APIs & Services > Credentials > + Create credentials > API key**. Copy the key.
5. On the new key, click **Edit API key**. Under **API restrictions** choose **Restrict key**,
   tick only **Safe Browsing API**, and click **Save**.

The key is only used by the server. Never put it in the mobile app.

## 2. Add it to the server

Render: **phishtriageplatform > Environment > Add Environment Variable**

| Key | Value |
|---|---|
| `SAFE_BROWSING_API_KEY` | the key from step 1 |

Save. Render redeploys automatically.

## 3. Check it works

```bash
curl https://phishtriageplatform.onrender.com/health
# expect "safe_browsing_enabled": true

curl -X POST https://phishtriageplatform.onrender.com/analyze \
  -H 'Content-Type: application/json' \
  -d '{"message":"Check this http://testsafebrowsing.appspot.com/s/phishing.html"}'
# expect "dangerous_links": 1 and "risk": "High"
```

`testsafebrowsing.appspot.com` is Google's official test page for this purpose.

## Notes

- **Privacy:** only the links are sent to Google, never the message text.
- **Limits:** Google gives a free daily quota (see APIs & Services > Safe Browsing API > Quotas).
  Results are cached for 30 minutes, and at most 10 links per message are checked.
- **Failures:** if Google is slow (over 5 seconds) or down, the scan still returns
  the rules result, with `link_check.status` set to `error`.
- **Commercial use:** Google provides the Safe Browsing API for non-commercial use.
  If PhishTriage starts charging (for example for the partner feed), switch to
  Google's **Web Risk API**, which is the commercial version of the same lookup.
