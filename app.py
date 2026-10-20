from flask import Flask, render_template, request
import pandas as pd
import joblib
import re
from urllib.parse import urlparse

app = Flask(__name__)
# Load the trained model
saved_data = joblib.load("phishing_url_model.pkl")

model = saved_data["model"]
feature_columns = saved_data["feature_columns"]


def extract_url_features(url):
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    path = parsed.path or ""

    return {
        "URLLength": len(url),
        "HostnameLength": len(hostname),
        "PathLength": len(path),
        "NoOfDots": url.count("."),
        "NoOfHyphens": url.count("-"),
        "NoOfAt": url.count("@"),
        "NoOfDigits": sum(c.isdigit() for c in url),
        "NoOfSubdirectories": path.count("/"),
        "UsesHTTPS": int(parsed.scheme == "https"),
        "HasIPAddress": int(
            bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", hostname))
        ),
        "HasAtSymbol": int("@" in url),
        "HasSuspiciousWord": int(
            any(
                word in url.lower()
                for word in [
                    "login", "verify", "update", "secure", "account"
                ]
            )
        )
    }


@app.route("/", methods=["GET", "POST"])
def home():
    result = None
    submitted_url = ""
    error = None

    if request.method == "POST":
        submitted_url = request.form.get("url", "").strip()

        if not submitted_url:
            error = "Please enter a URL."
        else:
            try:
                features = extract_url_features(submitted_url)
                input_data = pd.DataFrame([features])[feature_columns]

                prediction = int(model.predict(input_data)[0])

                if prediction == 0:
                    result = "Potentially Phishing"
                else:
                    result = "Likely Legitimate"

            except Exception:
                error = "Unable to analyse this input. Please check the URL."

    return render_template(
        "index.html",
        result=result,
        submitted_url=submitted_url,
        error=error
    )


if __name__ == "__main__":
    app.run(debug=True)