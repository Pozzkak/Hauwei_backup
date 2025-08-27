from flask import Flask, render_template, jsonify
import huawei_backup

app = Flask(__name__)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/run-backup", methods=["POST"])
def run_backup_route():
    results = huawei_backup.run_backup()
    return jsonify(results)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
