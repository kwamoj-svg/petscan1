"""
Petscan – Veterinärradiologie SaaS
Backend-Server (Flask + Anthropic)

Umgebungsvariablen die gesetzt werden müssen:
  ANTHROPIC_API_KEY  – dein Anthropic API Key (von platform.anthropic.com)
  SECRET_KEY         – beliebiger langer zufälliger String für Sessions
"""

from flask import Flask, request, jsonify, send_from_directory, abort
from flask_cors import CORS
import anthropic
import os
import json
import base64
import hashlib
import time
from functools import wraps

app = Flask(__name__, static_folder=".", static_url_path="")
CORS(app, origins=["https://petscan.de", "https://www.petscan.de"])

# ── ANTHROPIC CLIENT ──
client = anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY", ""))

# ── SIMPLE RATE LIMITER (pro IP, 20 Analysen pro Stunde) ──
rate_store = {}

def rate_limit(max_calls=20, window=3600):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            ip = request.remote_addr or "unknown"
            now = time.time()
            calls = rate_store.get(ip, [])
            # Alte Einträge entfernen
            calls = [t for t in calls if now - t < window]
            if len(calls) >= max_calls:
                return jsonify({"error": "Zu viele Anfragen. Bitte in einer Stunde erneut versuchen."}), 429
            calls.append(now)
            rate_store[ip] = calls
            return f(*args, **kwargs)
        return wrapper
    return decorator


# ── SEITEN AUSLIEFERN ──
@app.route("/")
def index():
    return send_from_directory(".", "index.html")

@app.route("/<path:filename>")
def static_files(filename):
    if filename.endswith(".html") or filename.endswith(".css") or filename.endswith(".js"):
        return send_from_directory(".", filename)
    abort(404)


# ── KI-ANALYSE API ──
@app.route("/api/analyse", methods=["POST"])
@rate_limit(max_calls=20, window=3600)
def analyse():
    """
    Empfängt Bild(er) + Prompt, leitet an Anthropic weiter.
    Der API-Key bleibt auf dem Server – niemals im Browser sichtbar.
    """
    if not client.api_key:
        return jsonify({"error": "API-Key nicht konfiguriert. Bitte ANTHROPIC_API_KEY setzen."}), 500

    data = request.get_json()
    if not data:
        return jsonify({"error": "Kein JSON empfangen"}), 400

    system_prompt = data.get("system", "")
    messages = data.get("messages", [])

    if not messages:
        return jsonify({"error": "Keine Nachrichten"}), 400

    try:
        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=2200,
            system=system_prompt,
            messages=messages
        )

        text = response.content[0].text if response.content else ""
        return jsonify({
            "content": [{"type": "text", "text": text}],
            "usage": {
                "input_tokens": response.usage.input_tokens,
                "output_tokens": response.usage.output_tokens
            }
        })

    except anthropic.AuthenticationError:
        return jsonify({"error": "Ungültiger API-Key. Bitte ANTHROPIC_API_KEY prüfen."}), 401
    except anthropic.RateLimitError:
        return jsonify({"error": "Anthropic Rate Limit erreicht. Bitte kurz warten."}), 429
    except anthropic.BadRequestError as e:
        return jsonify({"error": f"Anfragefehler: {str(e)}"}), 400
    except Exception as e:
        app.logger.error(f"Analyse-Fehler: {e}")
        return jsonify({"error": "Interner Serverfehler"}), 500


# ── HEALTH CHECK (für Railway/Render) ──
@app.route("/health")
def health():
    return jsonify({
        "status": "ok",
        "api_key_set": bool(client.api_key),
        "version": "1.0.0"
    })


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_ENV") == "development"
    app.run(host="0.0.0.0", port=port, debug=debug)
