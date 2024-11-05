# Name: Jan Smith  
# EUID: js2019
# Student ID: 11536897
# Course: CSCE 3550

import unittest
import sqlite3
import requests
import os

# Host for JWKS Server
host = "http://localhost:8080"
db_file = "totally_not_my_privateKeys.db"

class Test_JWKS_Server(unittest.TestCase):
    
    @classmethod
    def test_server(self):
        """ Check if server is running """
        server_response = requests.get(host, timeout=3)
        self.assertTrue(server_response.status_code, 200) # Checking for 'OK'
        
    def test_DB(self):
        """ Check if database is up and running """
        db_exists = os.path.exists("./totally_not_my_privateKeys.db")
        self.assertTrue(db_exists, "The database file should exist") # Checking for 'OK'
    
    def test_db_insertion(self):
        """ Test if keys are inserted """
        db = sqlite3.connect(db_file)
        cursor = db.cursor()
        
        cursor.execute("SELECT * FROM keys")
        rows = cursor.fetchall()
        
        self.assertGreaterEqual(len(rows), 2, "There should be at least 2 keys") # Checking for 'OK'
    
    def test_get_auth_request(self):
        response = requests.get(url="http://localhost:8080/auth", auth=("userABC", "password123"))
        self.assertEqual(response.status_code, 404)  # Checking for 'Method Not Allowed'

    def test_valid_auth_request(self):
        response = requests.post(url="http://localhost:8080/auth", auth=("userABC", "password123"))
        self.assertEqual(response.status_code, 200)  # Checking for 'OK'
       
    def test_auth_expired_request(self):
        response = requests.post(url="http://localhost:8080/auth?expired=true", auth=("userABC", "password123"))   
        self.assertTrue(response.status_code, 200)    # Checking for 'OK'    

    def test_not_supported_methods(self):
        for method in [requests.patch, requests.put, requests.delete, requests.head]:
            response = method(url="http://localhost:8080/auth")
            self.assertEqual(response.status_code, 404)  # Checking for 'Method Not Allowed'        
    
    def test_valid_well_known(self):
        response = requests.get(url="http://localhost:8080/.well-known/jwks.json")
        self.assertTrue(response.status_code, 200)  # Checking for 'OK'    
            
    def test_jwks(self):
        response = requests.get(url="http://localhost:8080/.well-known/jwks.json")
        self.assertTrue(response.status_code, 200) 
        
        keys = response.json()
        self.assertIn("keys", keys, "The key set should contains keys in it.")
        self.assertGreaterEqual(len(keys["keys"]), 1, "There should be at least one valid key. ")
        # Checking for 'OK', there should be at least one key in JWKS.
     

            
if __name__ == "__main__":
    unittest.main()