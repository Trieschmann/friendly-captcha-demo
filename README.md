# Friendly Captcha Demo

Ein einfaches Flask-Webprojekt mit Login und Friendly Captcha Integration. Bereit zum Deployment auf Render.

## Deployment (Render)

1. Forke dieses Repo oder lade es auf deinen GitHub-Account.
2. Gehe zu [https://render.com](https://render.com) und logge dich ein.
3. Erstelle einen neuen **Web Service**.
4. Wähle dieses Repo aus.
5. Setze Build Command: `pip install -r requirements.txt`
6. Setze Start Command: `python backend/app.py`
7. Unter Environment Variables:
   - Key: `FRIENDLY_CAPTCHA_SECRET`
   - Value: dein geheimer Schlüssel von https://friendlycaptcha.com

Fertig!
