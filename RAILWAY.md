# اجرا روی Railway

۱. پوشه را در یک ریپوی خصوصی GitHub بگذار (Dockerfile کنار app.py است).
۲. در Railway: New Project ← Deploy from GitHub repo.
۳. در Variables این‌ها را بساز:

    ADMIN_USER = نام کاربری دلخواه
    ADMIN_PASS = رمز قوی (بدون ' " \)
    TLS_DOMAIN = www.google.com
    PROXY_PORT = 8443

۴. Settings ← Networking: یک Public Domain برای خود پنل بساز (HTTPS).
   همان‌جا TCP Proxy بساز و Application port را 8443 بگذار. Railway یک دامنه و پورت می‌دهد، مثلاً `xxx.proxy.rlwy.net:12345`.
۵. دو متغیر دیگر اضافه کن و Redeploy بزن:

    SERVER_HOST = xxx.proxy.rlwy.net
    PUBLIC_PROXY_PORT = 12345

۶. یک Volume بساز و Mount path را /data بگذار. بدون Volume با هر دیپلوی کاربرها پاک می‌شوند.
۷. وارد پنل شو و کاربر بساز. لینک‌ها خودکار با دامنه و پورت TCP Proxy ساخته می‌شوند.
