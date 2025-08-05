from flask import Flask, request
import requests
import os

app = Flask(__name__)

FRIENDLY_CAPTCHA_SECRET = os.getenv("FRIENDLY_CAPTCHA_SECRET")

@app.route('/')
def index():
    return open("frontend/index.html").read()

@app.route('/submit', methods=['POST'])
def submit():
    username = request.form.get('username')
    password = request.form.get('password')
    solution = request.form.get('frc-captcha-solution')

    captcha_response = requests.post(
        "https://api.friendlycaptcha.com/api/v1/siteverify",
        data={
            "solution": solution,
            "secret": FRIENDLY_CAPTCHA_SECRET
        },
        timeout=5
    )

    result = captcha_response.json()
    if result.get("success"):
        return f"<h3>Login erfolgreich: {username}</h3>"
    else:
        return "<h3>Captcha fehlgeschlagen</h3>"

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
