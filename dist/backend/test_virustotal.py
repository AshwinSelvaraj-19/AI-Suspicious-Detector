from hash_engine import calculate_sha256
from virustotal import lookup_hash

file_path = r"C:\Windows\System32\notepad.exe"

hash_value = calculate_sha256(file_path)

print("SHA256:", hash_value)

result = lookup_hash(hash_value)

print(result)