import hashlib
import requests

def calculate_sha256_from_network(url):
    sha256_hash = hashlib.sha256()
    
    response = requests.get(url, stream=True)
    if response.status_code == 200:
        for byte_block in response.iter_content(4096):
            sha256_hash.update(byte_block)
    else:
        raise Exception(f"Failed to retrieve the file from {url}")

    return sha256_hash.hexdigest()

file_url = "https://www.instagram.com/"
hash_value = calculate_sha256_from_network(file_url)
print(f"SHA-256 hash of {file_url}: {hash_value}")