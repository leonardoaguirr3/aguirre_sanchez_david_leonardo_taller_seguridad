"""Cadena didáctica HKDF; borrado lógico, no borrado físico de RAM."""
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def kdf(material, info, salt=None):
    """Deriva 64 bytes con HKDF-SHA256 y separación de dominio."""
    return HKDF(algorithm=hashes.SHA256(), length=64, salt=salt, info=info).derive(material)


def derivar_clave(cadena, indice):
    """Retorna (siguiente_cadena, clave_mensaje); reemplazar cadena anterior."""
    if len(cadena) != 32 or indice < 0:
        raise ValueError('Cadena de 32 bytes e índice no negativo requeridos')
    salida = kdf(cadena, b'A1/cadena/' + indice.to_bytes(8, 'big'))
    return salida[:32], salida[32:]


def cifrar(clave, texto):
    """Cifra UTF-8 con AES-256-GCM; retorna nonce seguido del ciphertext/tag."""
    nonce = os.urandom(12)
    return nonce + AESGCM(clave).encrypt(nonce, texto.encode('utf-8'), None)


def descifrar(clave, paquete):
    """Verifica autenticidad y devuelve texto UTF-8 o lanza InvalidTag."""
    return AESGCM(clave).decrypt(paquete[:12], paquete[12:], None).decode('utf-8')
