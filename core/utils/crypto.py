import json
import logging
from pathlib import Path
from typing import Optional, Union, Literal

from base58 import b58encode
from nacl.signing import SigningKey
from nacl.secret import SecretBox
import mnemonic
import hashlib

WalletFormat = Literal["json", "base58", "mnemonic", "keystore"]

def get_public_key_from_private_bytes(pv_bytes: bytes) -> str:
    """
    Convert private key bytes to Solana public key (base58 encoded)
    """
    pv = SigningKey(pv_bytes)
    pb_bytes = bytes(pv.verify_key)
    return b58encode(pb_bytes).decode()

def private_key_to_base58(pv_bytes: bytes) -> str:
    """
    Convert private key bytes to base58 format
    """
    return b58encode(pv_bytes).decode()

def private_key_to_mnemonic(pv_bytes: bytes) -> str:
    """
    Convert private key bytes to BIP39 mnemonic (seed phrase)
    """
    m = mnemonic.Mnemonic('english')
    entropy = hashlib.sha256(pv_bytes).digest()[:32]  # Use first 32 bytes
    return m.to_mnemonic(entropy)

def create_keystore(pv_bytes: bytes, password: str) -> dict:
    """
    Create an encrypted keystore from private key bytes
    """
    salt = hashlib.sha256(password.encode()).digest()
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    box = SecretBox(key)
    encrypted = box.encrypt(pv_bytes)
    
    return {
        'version': 1,
        'salt': b58encode(salt).decode(),
        'data': b58encode(encrypted).decode()
    }

def save_keypair(
    pv_bytes: bytes, 
    output_dir: str, 
    format: WalletFormat = "json",
    password: Optional[str] = None
) -> str:
    """
    Save private key in specified format, return public key
    
    Args:
        pv_bytes: Private key bytes
        output_dir: Directory to save the wallet file
        format: Wallet format ('json', 'base58', 'mnemonic', or 'keystore')
        password: Password for keystore format (required if format='keystore')
    
    Returns:
        str: The public key (base58 encoded)
    """
    pv = SigningKey(pv_bytes)
    pb_bytes = bytes(pv.verify_key)
    pubkey = b58encode(pb_bytes).decode()
    
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    
    if format == "json":
        # Original Solana CLI format
        file_path = Path(output_dir) / f"{pubkey}.json"
        file_path.write_text(json.dumps(list(pv_bytes + pb_bytes)))
    
    elif format == "base58":
        # Raw base58 private key
        file_path = Path(output_dir) / f"{pubkey}.key"
        file_path.write_text(private_key_to_base58(pv_bytes))
    
    elif format == "mnemonic":
        # BIP39 mnemonic phrase
        file_path = Path(output_dir) / f"{pubkey}.phrase"
        file_path.write_text(private_key_to_mnemonic(pv_bytes))
    
    elif format == "keystore":
        if not password:
            raise ValueError("Password required for keystore format")
        # Encrypted keystore
        file_path = Path(output_dir) / f"{pubkey}.keystore"
        keystore = create_keystore(pv_bytes, password)
        file_path.write_text(json.dumps(keystore, indent=2))
    
    else:
        raise ValueError(f"Unsupported format: {format}")

    logging.info(f"Found: {pubkey}")
    logging.info(f"Saved as {format} format to: {file_path}")
    return pubkey
