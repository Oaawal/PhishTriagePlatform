# WhatsApp bot setup (Meta WhatsApp Cloud API)

The bot lets anyone forward a suspicious message to a WhatsApp number and get
a verdict. No app install needed.

## 1. Create the Meta app

1. Go to developers.facebook.com > **My Apps > Create App**, choose the
   **Business** type, and add the **WhatsApp** product.
2. In **WhatsApp > API Setup** you get a test phone number, a temporary
   access token and the **Phone number ID**.
3. In **App settings > Basic**, copy the **App Secret**.

## 2. Set environment variables on the API server

| Variable | Where it comes from |
|---|---|
| `WHATSAPP_TOKEN` | Access token. For production create a **System User** in Meta Business Settings with the `whatsapp_business_messaging` permission and generate a permanent token |
| `WHATSAPP_PHONE_NUMBER_ID` | WhatsApp > API Setup |
| `WHATSAPP_APP_SECRET` | App settings > Basic. Used to verify that webhook calls really come from Meta |
| `WHATSAPP_VERIFY_TOKEN` | Any random string you choose |

## 3. Connect the webhook

1. In **WhatsApp > Configuration > Webhook**, set:
   - Callback URL: `https://<your-api-host>/webhooks/whatsapp`
   - Verify token: the same value as `WHATSAPP_VERIFY_TOKEN`
2. Click **Verify and save**, then subscribe to the **messages** field.

## 4. Test

Send "hi" from your phone to the test number (add your phone as a test
recipient first). Then forward a scam message. You should get a verdict.

## 5. Go live

- Add a real business phone number and complete **Business Verification** in
  Meta Business Settings.
- Replies to a user's message within 24 hours are "service" conversations.
  Check Meta's current WhatsApp pricing for your region before launch.
- Publish the number on your website and social media: "Forward any
  suspicious message to +234 … on WhatsApp".

## Bot commands

| User sends | Bot replies |
|---|---|
| any forwarded message | risk level, reasons, advice |
| `check 0803 123 4567` | phone number reputation |
| `account 0123456789 opay` | bank account reputation |
| `official gtbank` | verified official numbers, SMS names and websites |
| `official 0700...` or `official GTBank` | is this number / sender / website official? |
| `alerts` | scam warnings going round now |
| `SCAM` / `SAFE` (after a verdict) | shares that message anonymously for training |
| `scammed` | recovery menu |
| `recover transfer` / `otp` / `loan` / `invest` / `hacked` | step-by-step recovery plan |
| `hi` / `help` | menu |
