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

numbers = private_key.private_numbers()

# Initialize Database
def init_db():
    db = sqlite3.connect(db_file)
    db.execute(''' 
        CREATE TABLE IF NOT EXISTS keys (
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        ) 
        ''')

# Insert a key into the DB    
def store_key(priv_key_pem, exp):
    with sqlite3.connect(db_file) as db:
        db.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (priv_key_pem, exp))  

# Retrieve key from DB    
def get_key(expired=False):
    with sqlite3.connect(db_file) as db:
        if expired: # If key expired
            result = db.execute("SELECT key, exp, FROM keys WHERE exp <= ?", (int(datetime.datetime.now(datetime.UTC).timestamp()),))
        else:       # otherwise
            result = db.execute("SELECT key, exp, FROM keys WHERE exp > ?", (int(datetime.datetime.now(datetime.UTC).timestamp()),))
        
        row = result.fetchone()  
        return row    
        
# Call the function to create table, if it doesn't exist    
init_db() 

# Save valid private key to the DB
store_key(pem.decode(), int((datetime.datetime.now(datetime.UTC) + datetime.timedelta(hours=1)).timestamp())) 

# Save an expired key by 1 day
store_key(expired_pem.decode(), int((datetime.datetime.now(datetime.UTC) -  datetime.timedelta(days=1)).timestamp()))

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
            key_row = get_key(exp)
                
            if key_row:
                key_pem = key_row[0]
                    
                headers = {
                    "kid": "expiredKID" if exp else "goodKid"
                }
                token_payload = {
                    "user": "username",
                    "exp": datetime.datetime.now(datetime.UTC) + datetime.timedelta(hours=-1) if exp else    
                        datetime.datetime.now(datetime.UTC) + datetime.timedelta(hours=1)
                } 
                
                encoded_jwt = jwt.encode(token_payload, key_pem, algorithm  = "RS256", headers=headers)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(bytes(encoded_jwt, "utf-8"))
            else:
                self.not_supported_methods() # Key not found
                
        return

    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            
            # Get valid keys 
            v_keys = get_key(False)
            keys = {"keys": []}
            
            if v_keys:
                key_pem = v_keys[0]
                priv_key = serialization.load_pem_private_key(key_pem.encode(), password=None)
                
                numbers = priv_key.private_numbers()  
                jwk = {
                    "keys": [
                        {
                            "alg": "RS256",
                            "kty": "RSA",
                            "use": "sig",
                            "kid": "goodKID",
                            "n": int_to_base64(numbers.public_numbers.n),
                            "e": int_to_base64(numbers.public_numbers.e),
                        }
                    ]
                }
                keys["keys"].append(jwk)
                self.wfile.write(bytes(json.dumps(keys), "utf-8"))
        else:
            self.not_supported_methods()
                
        return

# Keep server running until interruption occurs. 
if __name__ == "__main__":
    webServer = HTTPServer((hostName, serverPort), MyServer)
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
    
