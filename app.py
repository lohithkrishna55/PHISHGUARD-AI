from flask import Flask, render_template, request
import sqlite3
from pathlib import Path
from detector import analyze_url
from flask import Flask, render_template, request, redirect, url_for
app = Flask(__name__)

app.secret_key = "phishguard-demo-secret"

# Database location
DB = Path(__file__).with_name("database.db")


# Connect to SQLite database
def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


# Create database table
def initialize_db():
    conn = get_db()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            score INTEGER NOT NULL,
            status TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


# Home page and URL scanner
@app.route("/", methods=["GET", "POST"])
def home():

    result = None
    scanned_url = ""

    if request.method == "POST":

        scanned_url = request.form.get("url", "").strip()

        # Analyze submitted URL
        result = analyze_url(scanned_url)

        # Save valid scan results
        if result["status"] != "Invalid URL":

            conn = get_db()

            conn.execute("""
                INSERT INTO scans (url, score, status)
                VALUES (?, ?, ?)
            """, (
                scanned_url,
                result["score"],
                result["status"]
            ))

            conn.commit()
            conn.close()

    # Get recent scan history
    conn = get_db()

    history = conn.execute("""
        SELECT * FROM scans
        ORDER BY id DESC
        LIMIT 10
    """).fetchall()

    conn.close()

    return render_template(
        "index.html",
        result=result,
        scanned_url=scanned_url,
        history=history
    )
@app.route("/clear-history", methods=["POST"])
def clear_history():
    conn = get_db()
    conn.execute("DELETE FROM scans")
    conn.commit()
    conn.close()
    return redirect(url_for("home"))

# Run Flask application
initialize_db()

if __name__ == "__main__":
    app.run(debug=True)
