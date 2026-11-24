import hmac
import os

from flask import Flask, abort, render_template, request, send_from_directory

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 1024

HINTS = [
    "The .bin file is a PNG. List its chunks: plMb is a custom chunk containing zlib data; decompress it to recover the device ID. Also inspect the appended data after IEND.",
    "The PNG's compressed Comment contains the appended archive password. Open the archive and export the HTTP objects from relay_capture.pcap. The manifest confirms the handle hidden in the image's blue-channel LSBs; other objects contain communications, a fight report, and decoys.",
    "The packet capture points to the sightings account. The [SEALED] log entries use repeating-key Vigenere with a surname associated with the crater; the second flag fragment is encoded in zero-width characters in the account's posts.",
]


@app.get("/")
def index():
    return render_template("index.html", hints=HINTS, result=None)


@app.get("/blackbox.bin")
def download_artifact():
    return send_from_directory(app.root_path, "blackbox.bin", as_attachment=True)


@app.post("/submit")
def submit():
    expected_flag = os.environ.get("FLAG")
    if not expected_flag:
        abort(503, description="Flag checking is not configured yet.")

    submitted_flag = request.form.get("flag", "").strip()
    if not submitted_flag:
        result = ("empty", "Enter a flag before submitting.")
    elif hmac.compare_digest(submitted_flag, expected_flag):
        result = ("correct", "Correct flag. Mission record recovered.")
    else:
        result = ("incorrect", "That flag is not correct. Check the recovered record and try again.")

    return render_template("index.html", hints=HINTS, result=result)
