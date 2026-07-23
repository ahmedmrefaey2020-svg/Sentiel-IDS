from gradio_client import Client
import os
from dotenv import load_dotenv

load_dotenv()
token = os.getenv("HF_TOKEN")
print("Token found:", bool(token))

try:
    client = Client("AhmedMahmoud165/Deep-learning", hf_token=token)
    print("Connected successfully!")
except Exception as e:
    print("Connection failed:", e)