import hashlib
import hmac
import os
from datetime import datetime

def generate_all(text):
    """Generate all hash types for given text."""
    if not text:
        return {'error': 'No text provided'}

    encoded = text.encode('utf-8')

    return {
        'input': text,
        'md5':       hashlib.md5(encoded).hexdigest(),
        'sha1':      hashlib.sha1(encoded).hexdigest(),
        'sha224':    hashlib.sha224(encoded).hexdigest(),
        'sha256':    hashlib.sha256(encoded).hexdigest(),
        'sha384':    hashlib.sha384(encoded).hexdigest(),
        'sha512':    hashlib.sha512(encoded).hexdigest(),
        'sha3_256':  hashlib.sha3_256(encoded).hexdigest(),
        'sha3_512':  hashlib.sha3_512(encoded).hexdigest(),
        'blake2b':   hashlib.blake2b(encoded).hexdigest(),
        'blake2s':   hashlib.blake2s(encoded).hexdigest(),
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }

def verify(text, hash_value):
    """Verify text against a hash - auto detects algorithm."""
    if not text or not hash_value:
        return {'error': 'Text and hash are required'}

    encoded = text.encode('utf-8')
    hash_value = hash_value.strip().lower()
    hash_len = len(hash_value)

    # Map hash length to algorithm
    algo_map = {
        32:  [('MD5',      hashlib.md5(encoded).hexdigest())],
        40:  [('SHA-1',    hashlib.sha1(encoded).hexdigest())],
        56:  [('SHA-224',  hashlib.sha224(encoded).hexdigest())],
        64:  [('SHA-256',  hashlib.sha256(encoded).hexdigest()),
               ('SHA3-256',hashlib.sha3_256(encoded).hexdigest()),
               ('BLAKE2s', hashlib.blake2s(encoded).hexdigest())],
        96:  [('SHA-384',  hashlib.sha384(encoded).hexdigest())],
        128: [('SHA-512',  hashlib.sha512(encoded).hexdigest()),
               ('SHA3-512',hashlib.sha3_512(encoded).hexdigest()),
               ('BLAKE2b', hashlib.blake2b(encoded).hexdigest())],
    }

    candidates = algo_map.get(hash_len, [])

    for algo_name, computed in candidates:
        if hmac.compare_digest(computed, hash_value):
            return {
                'match': True,
                'algorithm': algo_name,
                'message': f'✅ MATCH — Hash verified using {algo_name}',
                'input': text,
                'hash': hash_value,
            }

    return {
        'match': False,
        'algorithm': 'Unknown',
        'message': '❌ NO MATCH — Hash does not match any algorithm',
        'input': text,
        'hash': hash_value,
    }

def generate_hmac(text, key, algorithm='sha256'):
    """Generate HMAC for given text and key."""
    if not text or not key:
        return {'error': 'Text and key are required'}

    algo_map = {
        'md5':    hashlib.md5,
        'sha1':   hashlib.sha1,
        'sha256': hashlib.sha256,
        'sha512': hashlib.sha512,
    }

    algo = algo_map.get(algorithm.lower(), hashlib.sha256)
    result = hmac.new(
        key.encode('utf-8'),
        text.encode('utf-8'),
        algo
    ).hexdigest()

    return {
        'input': text,
        'key': key,
        'algorithm': f'HMAC-{algorithm.upper()}',
        'hmac': result,
    }