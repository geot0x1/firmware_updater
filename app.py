#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Comprehensive Firmware Management Web App
Frontend (Flask templates + JS) and Backend TCP firmware server.

Run:
  python app.py
Then open http://127.0.0.1:5000

Config is at the top of this file.
"""

import os
import json
import socket
import threading
import time
import uuid
import struct
import hashlib
from datetime import datetime
from flask import Flask, request, jsonify, render_template, send_file, abort

# ========================== CONFIG ==========================
TCP_HOST = "0.0.0.0"
TCP_PORT = 9090
CHUNK_SIZE = 4096
MAGIC1 = 0xDEADBEEF
MAGIC2 = 0xCAFEF00D
MAGIC3 = 0xBABEFACE
IO_TIMEOUT_SEC = 5.0
ALLOWED_CONSEC_TIMEOUTS = 3

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FIRMWARE_DIR = os.path.join(BASE_DIR, "firmware_files")
METADATA_PATH = os.path.join(BASE_DIR, "firmware_metadata.json")

# ========================== APP STATE ==========================
app = Flask(__name__)

# Thread-safe status map
current_downloads = {}
downloads_lock = threading.Lock()

# Metadata map: firmwareId -> { "stored_path": str, "original_name": str, "size": int }
metadata_lock = threading.Lock()
if not os.path.isdir(FIRMWARE_DIR):
    os.makedirs(FIRMWARE_DIR, exist_ok=True)

if not os.path.exists(METADATA_PATH):
    with open(METADATA_PATH, "w", encoding="utf-8") as f:
        json.dump({}, f, indent=2)

with open(METADATA_PATH, "r", encoding="utf-8") as f:
    try:
        firmware_metadata = json.load(f)
    except json.JSONDecodeError:
        firmware_metadata = {}
        with open(METADATA_PATH, "w", encoding="utf-8") as wf:
            json.dump(firmware_metadata, wf, indent=2)

# ========================== HELPERS ==========================
def now_iso():
    return datetime.utcnow().isoformat() + "Z"

def update_download(connection_id, **fields):
    with downloads_lock:
        rec = current_downloads.get(connection_id, {})
        rec.update(fields)
        current_downloads[connection_id] = rec

def remove_download(connection_id):
    with downloads_lock:
        current_downloads.pop(connection_id, None)

def load_firmware_by_id(firmware_id):
    with metadata_lock:
        entry = firmware_metadata.get(f"{firmware_id}")
        if not entry:
            return None, None, None
        stored_path = entry.get("stored_path")
        original_name = entry.get("original_name")
        try:
            size = os.path.getsize(stored_path)
        except OSError:
            size = entry.get("size", 0)
        return stored_path, original_name, size

def compute_sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1<<20), b""):
            h.update(chunk)
    return h.digest()

def recv_until(sock, needle: bytes, maxlen: int = 1024):
    """Receive until 'needle' is found or maxlen reached. Returns bytes or None on timeout/error."""
    data = b""
    sock.settimeout(IO_TIMEOUT_SEC)
    try:
        while needle not in data and len(data) < maxlen:
            ch = sock.recv(1)
            if not ch:
                break
            data += ch
    except (socket.timeout, OSError):
        return None
    return data

def recv_fixed(sock, nbytes: int):
    """Receive exactly nbytes or return None on timeout/error."""
    buf = bytearray()
    sock.settimeout(IO_TIMEOUT_SEC)
    try:
        while len(buf) < nbytes:
            chunk = sock.recv(nbytes - len(buf))
            if not chunk:
                return None
            buf.extend(chunk)
    except (socket.timeout, OSError):
        return None
    return bytes(buf)

def send_all(sock, payload: bytes):
    """Send all or return False on timeout/error."""
    total_sent = 0
    sock.settimeout(IO_TIMEOUT_SEC)
    try:
        while total_sent < len(payload):
            sent = sock.send(payload[total_sent:])
            if sent == 0:
                return False
            total_sent += sent
    except (socket.timeout, OSError):
        return False
    return True

# ========================== TCP SERVER ==========================
def handle_client(conn, addr):
    ip = addr[0]
    connection_id = f"{ip}-{uuid.uuid4().hex[:8]}"
    print(connection_id)
    start_ts = time.time()

    update_download(connection_id,
                    connection_id=connection_id,
                    firmwareId="",
                    ip=ip,
                    status="Connecting",
                    progress=0,
                    bytes_sent=0,
                    total_bytes=0,
                    start_time=now_iso())

    try:
        # 1) Expect request like: b'ID=fw_v1.0.0\n' or b'ID=...'
        # Read up to newline or 128 bytes.
        req = recv_until(conn, b"\n", maxlen=128)
        if not req:
            update_download(connection_id, status="Failed: Invalid Request")
            return
        req = req.strip().decode(errors="ignore")
        if not req.startswith("ID="):
            update_download(connection_id, status="Failed: Invalid Request")
            return

        firmware_id = req.split("=", 1)[1].strip()
        update_download(connection_id, firmwareId=firmware_id, status="Resolving Firmware")

        # 2) Lookup firmware
        path, orig_name, fsize = load_firmware_by_id(firmware_id)
        if not path or not os.path.isfile(path):
            update_download(connection_id, status="Failed: Unknown FirmwareID")
            return

        # 3) Load and prepare transfer
        total_bytes = fsize
        sha = compute_sha256(path)

        update_download(connection_id, status="Preparing Header", total_bytes=total_bytes)

        header = struct.pack("!LLLL", MAGIC1, MAGIC2, MAGIC3, total_bytes) + sha  # 4*4 + 32 = 48 bytes
        assert len(header) == 48

        # 4) Send header
        status = "Downloading Header"
        update_download(connection_id, status=status)
        consec_timeouts = 0

        if not send_all(conn, header):
            consec_timeouts += 1
            if consec_timeouts >= ALLOWED_CONSEC_TIMEOUTS:
                update_download(connection_id, status="Failed: Timeout")
                return
        else:
            consec_timeouts = 0

        # 5) Wait for "DATA OK"
        update_download(connection_id, status="Waiting for DATA OK")
        a = recv_fixed(conn, len(b"DATA OK"))
        if a is None or a != b"DATA OK":
            update_download(connection_id, status="Failed: No ACK After Header")
            return

        # 6) Send chunks with handshake
        sent_bytes = 0
        nchunks = (total_bytes + CHUNK_SIZE - 1) // CHUNK_SIZE

        with open(path, "rb") as f:
            for i in range(nchunks):
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    chunk = b""
                if len(chunk) < CHUNK_SIZE:
                    chunk = chunk + b"\xFF" * (CHUNK_SIZE - len(chunk))

                # Send chunk
                update_download(connection_id, status=f"Sending Chunk {i+1}/{nchunks}")
                if not send_all(conn, chunk):
                    consec_timeouts += 1
                    if consec_timeouts >= ALLOWED_CONSEC_TIMEOUTS:
                        update_download(connection_id, status="Failed: Timeout")
                        return
                else:
                    consec_timeouts = 0

                # Wait for ACK
                update_download(connection_id, status="Waiting for DATA OK")
                a = recv_fixed(conn, len(b"DATA OK"))
                if a is None or a != b"DATA OK":
                    update_download(connection_id, status="Failed: No ACK")
                    return

                # Update progress
                sent_bytes = min((i+1) * CHUNK_SIZE, total_bytes)
                pct = int((sent_bytes / total_bytes) * 100) if total_bytes else 0
                update_download(connection_id,
                                bytes_sent=sent_bytes,
                                progress=pct,
                                status=f"Downloading Chunk {i+1}/{nchunks}")

        update_download(connection_id, progress=100, status="Completed")

    except Exception as e:
        update_download(connection_id, status=f"Failed: {type(e).__name__}")
    finally:
        try:
            conn.close()
        except Exception:
            pass
        # keep completed/failed entries visible for a short time
        time.sleep(2)
        remove_download(connection_id)

def tcp_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((TCP_HOST, TCP_PORT))
    s.listen(128)
    while True:
        try:
            conn, addr = s.accept()
        except OSError:
            break
        t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
        t.start()

# ========================== FLASK ROUTES ==========================
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/downloads_status")
def api_downloads_status():
    with downloads_lock:
        # shallow copy to avoid race in jsonify
        snapshot = list(current_downloads.values())
    return jsonify(snapshot)

@app.route("/api/firmwares")
def api_firmwares():
    with metadata_lock:
        items = [{"firmwareId": k,
                  "original_name": v.get("original_name"),
                  "stored_path": v.get("stored_path"),
                  "size": v.get("size", 0)} for k, v in firmware_metadata.items()]
    return jsonify(items)

@app.route("/download/<firmware_id>")
def download_firmware(firmware_id):
    path, orig, size = load_firmware_by_id(firmware_id)
    if not path or not os.path.isfile(path):
        abort(404)
    return send_file(path, as_attachment=True, download_name=orig or os.path.basename(path))

@app.route("/upload", methods=["POST"])
def upload():
    if "file" not in request.files:
        return jsonify({"ok": False, "error": "No file"}), 400
    file = request.files["file"]
    firmware_id = request.form.get("firmwareId", "").strip()
    if not firmware_id:
        return jsonify({"ok": False, "error": "Missing firmwareId"}), 400
    if file.filename == "":
        return jsonify({"ok": False, "error": "Empty filename"}), 400

    # Save file to firmware_files/<firmwareId>.bin
    safe_name = f"{firmware_id}.bin"
    dest_path = os.path.join(FIRMWARE_DIR, safe_name)

    try:
        file.save(dest_path)
        size = os.path.getsize(dest_path)
        with metadata_lock:
            firmware_metadata[firmware_id] = {
                "stored_path": dest_path,
                "original_name": file.filename,
                "size": size
            }
            with open(METADATA_PATH, "w", encoding="utf-8") as f:
                json.dump(firmware_metadata, f, indent=2)
        return jsonify({"ok": True, "firmwareId": firmware_id, "size": size})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

# ========================== MAIN ==========================
if __name__ == "__main__":
    # Start TCP server in background
    t = threading.Thread(target=tcp_server, daemon=True)
    t.start()
    print(f"[TCP] Listening on {TCP_HOST}:{TCP_PORT}")
    # Start Flask
    app.run(host="0.0.0.0", port=5000, debug=True)
