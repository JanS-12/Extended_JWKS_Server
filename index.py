# Name: Jan Smith  
# EUID: js2019
# Student ID: 11536897
# Course: CSCE 3550

from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from urllib.parse import urlparse, parse_qs
import datetime
import sqlite3
import base64
import json
import jwt

hostName = "localhost"
serverPort = 8080

# Database file
db_file = "totally_not_my_privateKeys.db"

# Connect to DB and create a table
db = sqlite3.connect(db_file)
db.execute(
    '''CREATE TABLE IF NOT EXISTS keys(
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL)''')

# Re-using given code for key generation
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

expired_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

expired_pem = expired_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

# Re-using code for integer conversion to Base64URL
def int_to_base64(value):
    """Convert an integer to a Base64URL-encoded string"""
    value_hex = format(value, 'x')
    # Ensure even length
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')

numbers = private_key.private_numbers()

# Save the keys to DB
def store_key(k_pem, exp):
    with db:
        db.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (k_pem, exp))
        
# Function to get a key from the database (expired or valid)
def get_key(expired=False):
    with db:
        if expired:
            result = db.execute("SELECT key, exp FROM keys WHERE exp <= ?", (int(datetime.datetime.now(datetime.UTC).timestamp()),))
        else:
            result = db.execute("SELECT key, exp FROM keys WHERE exp > ?", (int(datetime.datetime.now(datetime.UTC).timestamp()),))
             
        row = result.fetchone()
         
        return row
    
# Store valid key
store_key(pem.decode(), int((datetime.datetime.now(datetime.UTC) + datetime.timedelta(hours=1)).timestamp()))  

# Store expired key (by 5 hours)
store_key(expired_pem.decode(), int((datetime.datetime.now(datetime.UTC) - datetime.timedelta(hours=5)).timestamp()))    

# HTTP Server logic remains unchanged
class MyServer(BaseHTTPRequestHandler):
    # For unsupported methods --> Key Not Found 
    def not_supported_methods(self):
        self.send_response(404)
        self.end_headers()
    
    # Simplificaiton for unused methods          
    do_PUT = do_DELETE = do_HEAD = do_PATCH = not_supported_methods

    # POST Request (/auth)
    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)

        if parsed_path.path == "/auth":
            exp = 'expired' in params
            row = get_key(exp)            

            if row:
                k_pem = row[0]      # Index 0 is pem, Index 1 is exp
                headers = {"kid": "expiredKID" if exp else "goodKID"}

                token_payload = {
                    "user": "username",
                    "exp": datetime.datetime.now(datetime.UTC) + (datetime.timedelta(hours=-2) if exp else datetime.timedelta(hours=2))
                }

                encoded_jwt = jwt.encode(
                    token_payload, 
                    k_pem.encode(), 
                    algorithm = "RS256", 
                    headers = headers)
                
                self.send_response(200)
                self.end_headers()
                self.wfile.write(bytes(encoded_jwt, "utf-8"))
            else:
                self.not_supported_methods() # Key not found
        return

    #GET Request (/.well-known/jwks.json)
    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()

            # Get valid key 
            valid_key = get_key(False)              
            jwks = {"keys": []}  #Key Set

            if valid_key:
                k_pem = valid_key[0]
                key = serialization.load_pem_private_key(k_pem.encode(), password = None)

                numbers = key.private_numbers()
                
                jwk = {
                    "alg": "RS256",
                    "kty": "RSA",
                    "use": "sig",
                    "kid": "goodKID",
                    "n": int_to_base64(numbers.public_numbers.n),
                    "e": int_to_base64(numbers.public_numbers.e),
                }
                
                jwks["keys"].append(jwk)

            self.wfile.write(bytes(json.dumps(jwks), "utf-8"))
        else:
            self.not_supported_methods() # Not found
            
        return

print("Starting server on port 8080!")

if __name__ == "__main__":
    webServer = HTTPServer((hostName, serverPort), MyServer)
    
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        #db.execute("""DROP TABLE IF EXISTS keys""") # Only for debugging purposes
        db.close()
        pass

    webServer.server_close()


    
