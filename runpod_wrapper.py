import runpod
from typing import Any, TypedDict
import requests
import sys

import base64
import hashlib
import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

key_endpoint = os.environ.get('KEY_ENDPOINT')

def derive_key(password: str) -> bytes:
    return hashlib.sha256(password.encode('utf-8')).digest()

def encode_text(text: str, private_key: str) -> str:
    key = derive_key(private_key)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(text.encode('utf-8')) + encryptor.finalize()
    auth_tag = encryptor.tag
    encrypted_data = iv + auth_tag + ciphertext
    return base64.b64encode(encrypted_data).decode('utf-8')

def decode_text(encoded_text: str, private_key: str) -> str:
    key = derive_key(private_key)
    encrypted_data = base64.b64decode(encoded_text.encode('utf-8'))
    iv = encrypted_data[:16]
    auth_tag = encrypted_data[16:32]
    ciphertext = encrypted_data[32:]
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, auth_tag), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext.decode('utf-8')

class HandlerInput(TypedDict):
    """The data for calling the Ollama service."""

    method_name: str
    """The url endpoint of the Ollama service to make a post request to."""

    input: Any
    """The body of the post request to the Ollama service."""


class HandlerJob(TypedDict):
    input: HandlerInput


def handler(job: HandlerJob):
    base_url = "http://0.0.0.0:11434"

    input = job["input"]

    #key = requests.get(key_endpoint, allow_redirects=True).text

    # streaming is not supported in serverless mode
    input["input"]["stream"] = False
    print(sys.argv)
    model = sys.argv[1]
    input["input"]["model"] = model

    response = requests.post(
        url=f"{base_url}/{input['method_name']}",
        headers={"Content-Type": "application/json"},
        json=input["input"],
    )
    response.encoding = "utf-8"

    # TODO: handle errors
    return response.json()


runpod.serverless.start({"handler": handler})
