from flask import Flask, request, jsonify
import asyncio
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf.json_format import MessageToJson  # (kept for minimal change)
import binascii
import aiohttp
import requests
import json
import like_pb2
import like_count_pb2
import uid_generator_pb2
from google.protobuf.message import DecodeError

app = Flask(__name__)

# ------------ helpers ------------
def load_tokens(server_name: str):
    """
    Load tokens JSON depending on server. Returns a list (possibly empty) or None on fatal error.
    """
    try:
        if server_name == "IND":
            fname = "token_ind.json"
        elif server_name in {"BR", "US", "SAC", "NA"}:
            fname = "token_br.json"
        else:
            fname = "token_bd.json"

        with open(fname, "r") as f:
            tokens = json.load(f)
        if not isinstance(tokens, list):
            app.logger.error(f"Token file {fname} must contain a list.")
            return []
        return tokens
    except Exception as e:
        app.logger.error(f"Error loading tokens for server {server_name}: {e}")
        return None

def encrypt_message(plaintext: bytes):
    """
    AES-CBC encrypt bytes and return hex string.
    """
    try:
        if not isinstance(plaintext, (bytes, bytearray)):
            raise TypeError("encrypt_message expects bytes.")
        key = b'Yg&tc%DEuh6%Zc^8'  # 16 bytes
        iv = b'6oyZDr22E3ychjM%'   # 16 bytes
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded = pad(plaintext, AES.block_size)
        encrypted = cipher.encrypt(padded)
        return binascii.hexlify(encrypted).decode('utf-8')
    except Exception as e:
        app.logger.error(f"Error encrypting message: {e}")
        return None

def create_protobuf_message(user_id: str, region: str):
    """
    Build like_pb2.like() -> bytes
    """
    try:
        msg = like_pb2.like()
        msg.uid = int(user_id)
        msg.region = region
        return msg.SerializeToString()
    except Exception as e:
        app.logger.error(f"Error creating protobuf message: {e}")
        return None

async def send_request(encrypted_hex: str, token: str, url: str):
    """
    POST the encrypted payload to the LikeProfile endpoint.
    """
    try:
        edata = bytes.fromhex(encrypted_hex)
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB50",
        }
        timeout = aiohttp.ClientTimeout(total=10)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(url, data=edata, headers=headers) as resp:
                # return status for visibility; don't raise to keep the batch running
                if resp.status != 200:
                    app.logger.warning(f"Like request failed: HTTP {resp.status}")
                    return resp.status
                # Many of these endpoints return binary protobuf or empty body. Just return status 200.
                return 200
    except Exception as e:
        app.logger.error(f"Exception in send_request: {e}")
        return None

async def send_multiple_requests(uid: str, server_name: str, url: str):
    """
    Fire off multiple like requests using rotating tokens.
    """
    try:
        proto = create_protobuf_message(uid, server_name)
        if proto is None:
            app.logger.error("Failed to create protobuf message.")
            return None

        encrypted_uid = encrypt_message(proto)
        if encrypted_uid is None:
            app.logger.error("Encryption failed.")
            return None

        tokens = load_tokens(server_name)
        if tokens is None:
            app.logger.error("Failed to load tokens.")
            return None
        if len(tokens) == 0:
            app.logger.error("Token list is empty.")
            return None

        tasks = []
        for i in range(100):
            token = tokens[i % len(tokens)].get("token")
            if not token:
                app.logger.warning(f"Missing 'token' field in tokens[{i % len(tokens)}]")
                continue
            tasks.append(send_request(encrypted_uid, token, url))

        if not tasks:
            app.logger.error("No valid tokens available to send requests.")
            return None

        results = await asyncio.gather(*tasks, return_exceptions=True)
        return results
    except Exception as e:
        app.logger.error(f"Exception in send_multiple_requests: {e}")
        return None

def create_uid_protobuf(uid: str):
    try:
        msg = uid_generator_pb2.uid_generator()
        msg.saturn_ = int(uid)  # Field name assumed from your .proto
        msg.garena = 1
        return msg.SerializeToString()
    except Exception as e:
        app.logger.error(f"Error creating uid protobuf: {e}")
        return None

def enc(uid: str):
    data = create_uid_protobuf(uid)
    if data is None:
        return None
    return encrypt_message(data)

def _personal_show_url(server_name: str) -> str:
    if server_name == "IND":
        return "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"
    elif server_name in {"BR", "US", "SAC", "NA"}:
        return "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
    else:
        return "https://clientbp.ggblueshark.com/GetPlayerPersonalShow"

def _like_profile_url(server_name: str) -> str:
    if server_name == "IND":
        return "https://client.ind.freefiremobile.com/LikeProfile"
    elif server_name in {"BR", "US", "SAC", "NA"}:
        return "https://client.us.freefiremobile.com/LikeProfile"
    else:
        return "https://clientbp.ggblueshark.com/LikeProfile"

def make_request(encrypted_hex: str, server_name: str, token: str):
    """
    Calls GetPlayerPersonalShow and decodes like_count_pb2.Info.
    """
    try:
        if not encrypted_hex:
            raise ValueError("Encrypted payload is empty.")
        url = _personal_show_url(server_name)
        edata = bytes.fromhex(encrypted_hex)
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB50",
        }
        resp = requests.post(url, data=edata, headers=headers, timeout=10, verify=False)
        resp.raise_for_status()
        # The response is protobuf binary
        return decode_protobuf(resp.content)
    except Exception as e:
        app.logger.error(f"Error in make_request: {e}")
        return None

def decode_protobuf(binary: bytes):
    try:
        info = like_count_pb2.Info()
        info.ParseFromString(binary)
        return info
    except DecodeError as e:
        app.logger.error(f"Error decoding Protobuf data: {e}")
        return None
    except Exception as e:
        app.logger.error(f"Unexpected error during protobuf decoding: {e}")
        return None

def fetch_player_info(uid: str):
    """
    Best-effort metadata for region/level/version; falls back to NA/NA/NA.
    """
    try:
        url = f"https://nr-codex-info.vercel.app/get?uid={uid}"
        r = requests.get(url, timeout=5)
        if r.status_code == 200:
            data = r.json()
            acc = data.get("AccountInfo", {}) or {}
            return {
                "Level": acc.get("AccountLevel", "NA"),
                "Region": acc.get("AccountRegion", "NA"),
                "ReleaseVersion": acc.get("ReleaseVersion", "NA"),
            }
        app.logger.error(f"Player info API failed with status code: {r.status_code}")
        return {"Level": "NA", "Region": "NA", "ReleaseVersion": "NA"}
    except Exception as e:
        app.logger.error(f"Error fetching player info from API: {e}")
        return {"Level": "NA", "Region": "NA", "ReleaseVersion": "NA"}

def run_async(coro):
    """
    Safely run async code from a Flask route (avoids 'asyncio.run() from a running loop' errors).
    """
    try:
        return asyncio.run(coro)
    except RuntimeError:
        loop = asyncio.new_event_loop()
        try:
            asyncio.set_event_loop(loop)
            return loop.run_until_complete(coro)
        finally:
            try:
                loop.close()
            except Exception:
                pass

# ------------ routes ------------
@app.route('/like', methods=['GET'])
def handle_requests():
    uid = request.args.get("uid", "").strip()
    server_name = request.args.get("server_name", "").strip().upper()
    key = request.args.get('key')

    if key != 'NS':
        return jsonify({'error': 'Invalid or missing API key'}), 401
    if not uid.isdigit():
        return jsonify({"error": "UID must be a numeric string"}), 400
    if not server_name:
        return jsonify({"error": "server_name is required"}), 400

    try:
        # --- Player info & region sanity ---
        player_info = fetch_player_info(uid)
        region = player_info["Region"]
        level = player_info["Level"]
        release_version = player_info["ReleaseVersion"]

        # If API returns a concrete region (not "NA"), prefer it
        server_name_used = region if region != "NA" else server_name

        tokens = load_tokens(server_name_used)
        if tokens is None:
            return jsonify({"error": "Failed to load tokens"}), 500
        if len(tokens) == 0:
            return jsonify({"error": "No tokens available"}), 500

        token0 = tokens[0].get('token')
        if not token0:
            return jsonify({"error": "First token missing 'token' field"}), 500

        encrypted_uid = enc(uid)
        if encrypted_uid is None:
            return jsonify({"error": "Encryption of UID failed"}), 500

        # --- BEFORE ---
        before_msg = make_request(encrypted_uid, server_name_used, token0)
        if before_msg is None:
            return jsonify({"error": "Failed to retrieve initial player info"}), 502

        try:
            before_json = json.loads(MessageToJson(before_msg))
        except Exception as e:
            return jsonify({"error": f"Error converting 'before' protobuf to JSON: {e}"}), 500

        before_like_raw = (before_json.get('AccountInfo') or {}).get('Likes', 0)
        try:
            before_like = int(before_like_raw)
        except Exception:
            before_like = 0
        app.logger.info(f"Likes before command: {before_like}")

        # --- SEND LIKE BURST ---
        like_url = _like_profile_url(server_name_used)
        run_async(send_multiple_requests(uid, server_name_used, like_url))

        # --- AFTER ---
        after_msg = make_request(encrypted_uid, server_name_used, token0)
        if after_msg is None:
            return jsonify({"error": "Failed to retrieve player info after like requests"}), 502

        try:
            after_json = json.loads(MessageToJson(after_msg))
        except Exception as e:
            return jsonify({"error": f"Error converting 'after' protobuf to JSON: {e}"}), 500

        after_like_raw = (after_json.get('AccountInfo') or {}).get('Likes', 0)
        try:
            after_like = int(after_like_raw)
        except Exception:
            after_like = before_like  # if invalid, assume unchanged

        player_uid = int((after_json.get('AccountInfo') or {}).get('UID', 0) or 0)
        player_name = str((after_json.get('AccountInfo') or {}).get('PlayerNickname', '') or '')

        like_given = max(0, after_like - before_like)
        status = 1 if like_given != 0 else 2

        result = {
            "LikesGivenByAPI": like_given,
            "LikesafterCommand": after_like,
            "LikesbeforeCommand": before_like,
            "PlayerNickname": player_name,
            "Region": region,
            "Level": level,
            "UID": player_uid,
            "ReleaseVersion": release_version,
            "status": status
        }
        return jsonify(result)
    except Exception as e:
        app.logger.error(f"Error processing request: {e}")
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    # Consider putting behind a proper WSGI server in production
    app.run(host="0.0.0.0", port=5000, debug=True, use_reloader=False)
