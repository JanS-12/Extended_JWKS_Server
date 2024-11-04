from cryptography.hazmat.primitives.serialization import load_pem_private_key
from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime
import sqlite3
import os

hostName = "localhost"
serverPort = 8080

# For easier readability
db_file = "totally_not_my_privateKeys.db"

# Initialize Database
db = sqlite3.connect(db_file)
db.execute(''' 
    CREATE TABLE IF NOT EXISTS keys (
        kid INTEGER PRIMARY KEY AUTOINCREMENT,
        key BLOB NOT NULL,
        exp INTEGER NOT NULL
    ) 
    ''')
    
# Keep using the private and expired keys provided
private_key = rsa.generate_private_key(
    public_exponent = 65537,
    key_size = 2048,
)

expired_key = rsa.generate_private_key(
    public_exponent = 65537,
    key_size = 2048,
)

pem = private_key.private_bytes(
    encoding = serialization.Encoding.PEM,
    format = serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm = serialization.NoEncryption()
)

expired_pem = expired_key.private_bytes(
    encoding = serialization.Encoding.PEM,
    format = serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm = serialization.NoEncryption()
)

# Keep using the conversion provided
def int_to_base64(value):
    """Convert an integer to a Base64URL-encoded string"""
    value_hex = format(value, 'x')
    # Ensure even length
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')

# Insert a key into the DB    
def store_key(priv_key_pem, exp):
    with db:
        db.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (priv_key_pem, exp))  

# Retrieve key from DB    
def get_keys(expired=False):
    with db:
        if expired: # If key expired
            result = db.execute("SELECT (key, exp) FROM keys WHERE exp <= ?", (int(datetime.datetime.now(datetime.UTC).timestamp()),))
        else:       # Otherwise
            result = db.execute("SELECT (key, exp) FROM keys WHERE exp > ?", (int(datetime.datetime.now(datetime.UTC).timestamp()),))
        
        rows = result.fetchall()  
        return rows    

# Save valid private key to the DB
store_key(pem.decode(), int((datetime.datetime.now(datetime.UTC) + datetime.timedelta(hours=2)).timestamp())) 

# Save an expired key by 1 day
store_key(expired_pem.decode(), int((datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=1)).timestamp()))

def check_db_contents():
    with db:
        result = db.execute("SELECT kid, exp FROM keys")
        rows = result.fetchall()
        print("Database contents:")
        for row in rows:
            exp_time = datetime.datetime.utcfromtimestamp(row[1]).strftime('%Y-%m-%d %H:%M:%S')
            print(f"KID: {row[0]}, Exp: {exp_time}")

# Debugging: Check the database contents after saving keys
check_db_contents()

class MyServer(BaseHTTPRequestHandler):
    
    def not_supported_methods(self):
        self.send_response(405)
        self.end_headers()
        return
    
    # To simplify unused methods
    do_PUT = do_HEAD = do_DELETE = do_PATCH = not_supported_methods
    
    # POST Request (/auth)
    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)
            
        if parsed_path.path == "/auth":
            exp = 'expired' in params      
            rows = get_keys(exp) # Get all valid or expired keys
                
            if rows:
                # Get the first key
                key = rows[0]
                key_pem = key[0]    
                
                headers = {
                    "kid": "expiredKID" if exp else "goodKid"
                }
                token_payload = {
                    "user": "username",
                    "exp": datetime.datetime.now(datetime.UTC) + datetime.timedelta(hours=-1) if exp else    # If expired
                        datetime.datetime.now(datetime.UTC) + datetime.timedelta(hours=1)                    # If Valid
                } 
                
                encoded_jwt = jwt.encode(token_payload, key_pem, algorithm  = "RS256", headers=headers)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(bytes(encoded_jwt, "utf-8"))
            else:
                self.not_supported_methods() # Key not found
                
        return

    # GET Request: /.well-known/jwks.json
    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
           
            # Get valid keys 
            rows = get_keys(False)
            keys = {"keys": []}
            
            for row in rows:
                priv_key = load_pem_private_key(row[1], password=None)
                numbers = priv_key.private_numbers()
                
                jwk = {
                    "alg": "RS256",
                    "kty": "RSA",
                    "use": "sig",
                    "kid": "goodKID",
                    "n": int_to_base64(numbers.public_numbers.n),
                    "e": int_to_base64(numbers.public_numbers.e),
                }
                
                keys["keys"].append(jwk)
                self.wfile.write(bytes(json.dumps(keys).encode(), "utf-8"))
        else:
            self.not_supported_methods()
                
        return

# Keep server running until interruption occurs. 
if __name__ == "__main__":
    webServer = HTTPServer((hostName, serverPort), MyServer)
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        # Only for debugging purposes
        #db.execute("""DROP TABLE IF EXISTS keys;""")
        db.close()
        pass



webServer.server_close()

    
