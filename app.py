from flask import Flask, request, jsonify
import my_pb2
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import requests
from key_iv import AES_KEY, AES_IV

import warnings
warnings.filterwarnings("ignore", message="Unverified HTTPS request")

app = Flask(__name__)

DECODE_API = "https://team-x-ujjaiwal.vercel.app/decode_jwt"
TOKEN_API = "https://100067.vercel.app/token"  # JWT token generation API

HEADERS_TEMPLATE = {
    'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
    'Connection': "Keep-Alive",
    'Accept-Encoding': "gzip",
    'Content-Type': "application/octet-stream",
    'Expect': "100-continue",
    'X-Unity-Version': "2018.4.11f1",
    'X-GA': "v1 1",
    'ReleaseVersion': "OB50",
}

session = requests.Session()

def encrypt_message(key, iv, plaintext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(plaintext, AES.block_size)
    return cipher.encrypt(padded_message)

def get_user_info_from_api(token):
    try:
        res = requests.get(DECODE_API, params={"jwt_token": token}, timeout=5)
        data = res.json()
        decoded = data.get("data", {})

        return {
            "uid": decoded.get("account_id", "Unknown"),
            "region": decoded.get("lock_region", "Unknown"),
            "nickname": decoded.get("nickname", "Unknown")
        }
    except Exception as e:
        return {
            "uid": "Error",
            "region": "Error",
            "nickname": f"Error: {str(e)}"
        }

def get_jwt_token(uid, password):
    try:
        params = {
            "uid": uid,
            "password": password
        }
        res = requests.get(TOKEN_API, params=params, timeout=10)
        data = res.json()
        
        if "token" in data:
            return data["token"], data.get("lock_region", "IND")
        else:
            return None, "IND"
    except Exception as e:
        print(f"Error getting JWT token: {str(e)}")
        return None, "IND"

def get_url(server_name: str) -> str:
    server_name = server_name.upper()

    if server_name == "IND":
        return "https://client.ind.freefiremobile.com/UpdateSocialBasicInfo"
    elif server_name in {"BR", "US", "SAC", "NA"}:
        return "https://client.us.freefiremobile.com/UpdateSocialBasicInfo"
    else:
        # fallback for other regions (EU, ME, etc.)
        return "https://clientbp.ggblueshark.com/UpdateSocialBasicInfo"

def update_bio_with_token(token, user_bio, region):
    headers = HEADERS_TEMPLATE.copy()
    headers['Authorization'] = f"Bearer {token}"

    api_url = get_url(region)

    message = my_pb2.Signature()
    message.field2 = 9
    message.field8 = user_bio
    message.field9 = 1

    encrypted_data = encrypt_message(AES_KEY, AES_IV, message.SerializeToString())
    response = session.post(api_url, data=encrypted_data, headers=headers, verify=False)

    try:
        response_text = response.content.decode('utf-8')
    except UnicodeDecodeError:
        response_text = response.content.decode('latin1')

    return response.status_code, response_text

@app.route('/updatebio', methods=['GET'])
def api_update_bio():
    token = request.args.get('token')
    bio = request.args.get('bio')

    if not token or not bio:
        return jsonify({
            "status": "error",
            "message": "Missing token or bio!"
        }), 400

    user_info = get_user_info_from_api(token)
    region = user_info.get("region", "IND")
    status_code, response_text = update_bio_with_token(token, bio, region)

    return jsonify({
        "status": "success" if status_code == 200 else "fail",
        "http_status": status_code,
        "message": "✅ Bio updated successfully!" if status_code == 200 else "❌ Bio update failed!",
        "bio_sent": bio,
        "uid": user_info["uid"],
        "region": region,
        "nickname": user_info["nickname"],
        "raw_response": response_text
    })

@app.route('/changebio', methods=['GET'])
def change_bio():
    uid = request.args.get('uid')
    password = request.args.get('password')
    newbio = request.args.get('newbio')
    region = request.args.get('region', 'IND')  # Default to IND if not provided

    if not uid or not password or not newbio:
        return jsonify({
            "status": "error",
            "message": "Missing parameters! Required: uid, password, newbio"
        }), 400

    # Get JWT token first
    token, token_region = get_jwt_token(uid, password)
    
    if not token:
        return jsonify({
            "status": "error",
            "message": "Failed to get JWT token. Check uid and password."
        }), 401

    # Use region from token if not explicitly provided
    if region == "IND" and token_region != "IND":
        region = token_region

    # Update bio with the obtained token
    status_code, response_text = update_bio_with_token(token, newbio, region)
    
    # Get user info for response
    user_info = get_user_info_from_api(token)

    return jsonify({
        "token": token,
        "newBio": newbio,
        "message": "✅ Bio updated successfully!" if status_code == 200 else "❌ Bio update failed!",
        "nickname": user_info["nickname"],
        "response": response_text,
        "region": region,
        "status": "success" if status_code == 200 else "fail",
        "uid": uid
    })

@app.route('/')
def home():
    return "🛡️ API Update Bio\nUsage: /updatebio?token=<TOKEN>&bio=<BIO>\n/changebio?uid={uid}&password={password}&newbio={newbio}&region={region}"

if __name__ == '__main__':
    app.run(debug=True, port=5000, host="0.0.0.0")