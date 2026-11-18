"""Deliberately vulnerable demo app used by VulnScan's tests. Do not deploy."""
import os
import sqlite3
import subprocess

from flask import Flask, request
from openai import OpenAI

app = Flask(__name__)
client = OpenAI()
DB_PASSWORD = "Pr0d-Db-Passw0rd-2024!"
api_key = "a8f5f167f44f4964e6c998dee827110c4b3e7f1a9c"


@app.route("/user")
def user():
    uid = request.args.get("id")
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = '%s'" % uid)
    return str(cur.fetchall())


@app.route("/ping")
def ping():
    host = request.args.get("host")
    return subprocess.check_output("ping -c 1 " + host, shell=True)


@app.route("/ask")
def ask():
    q = request.args.get("q")
    resp = client.chat.completions.create(model="gpt-4o-mini", messages=[
        {"role": "system", "content": "You are a calculator. " + q},
        {"role": "user", "content": q}])
    return str(eval(resp.choices[0].message.content))


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")
