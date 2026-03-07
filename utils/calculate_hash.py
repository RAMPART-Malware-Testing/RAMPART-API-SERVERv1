import hashlib

CHUNK_SIZE = 1024 * 1024

def calculate_hash_from_chunks(chunks_data):
    md5_hash = hashlib.md5()
    sha1_hash = hashlib.sha1()
    sha256_hash = hashlib.sha256()

    for chunk in chunks_data:
        md5_hash.update(chunk)
        sha1_hash.update(chunk)
        sha256_hash.update(chunk)

    return {
        'md5': md5_hash.hexdigest(),
        'sha1': sha1_hash.hexdigest(),
        'sha256': sha256_hash.hexdigest()
    }



