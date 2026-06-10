from flask import Flask, render_template, request, jsonify
from kiro import scan_url

app = Flask(__name__)

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json()

    url = data.get("url", "")

    verdict, reasons = scan_url(url)

    return jsonify({
        "verdict": verdict,
        "reasons": reasons
    })

if __name__ == "__main__":
    app.run(debug=True)
