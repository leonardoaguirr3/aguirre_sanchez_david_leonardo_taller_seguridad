"""Double Ratchet clásico reducido: entrega estrictamente ordenada, sin red."""
import copy
import os
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from a1_cadena import kdf, derivar_clave


def publica(privada):
    return privada.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


class Ratchet:
    """Estado de un participante; no guarda claves de mensajes ni plaintexts."""
    def __init__(self, raiz, privada, remota):
        self.raiz, self.privada, self.remota = raiz, privada, remota
        self.envio = self.recepcion = None
        self.ns = self.nr = 0
        self.vistas = set()

    def _raiz(self, privada, remota):
        salida = kdf(privada.exchange(X25519PublicKey.from_public_bytes(remota)),
                     b'A2/raiz', self.raiz)
        self.raiz = salida[:32]
        return salida[32:]

    def cambiar_direccion(self):
        """Genera un par X25519 nuevo y una cadena de envío desde DH."""
        self.privada = X25519PrivateKey.generate()
        self.envio = self._raiz(self.privada, self.remota)
        self.ns = 0

    def enviar(self, texto):
        """Deriva y consume una clave; autentica también pública e índice."""
        if self.envio is None:
            self.cambiar_direccion()
        siguiente, clave = derivar_clave(self.envio, self.ns)
        pub, n, nonce = publica(self.privada), self.ns, os.urandom(12)
        ct = AESGCM(clave).encrypt(nonce, texto.encode(), pub + n.to_bytes(8, 'big'))
        self.envio, self.ns = siguiente, n + 1
        del clave
        return {'publica': pub, 'indice': n, 'nonce': nonce, 'ciphertext': ct}

    def recibir(self, paquete):
        """Rechaza repetición/desorden; confirma cambios solo tras autenticar."""
        pub, n = paquete['publica'], paquete['indice']
        identidad = (pub, n)
        if identidad in self.vistas:
            raise ValueError('Repetición')
        candidato = copy.copy(self)
        if pub != self.remota:
            candidato.recepcion = candidato._raiz(candidato.privada, pub)
            candidato.remota, candidato.nr = pub, 0
            candidato.envio = None  # Generación diferida hasta responder.
        if n != candidato.nr or candidato.recepcion is None:
            raise ValueError('Mensaje fuera de orden o cadena inexistente')
        siguiente, clave = derivar_clave(candidato.recepcion, n)
        texto = AESGCM(clave).decrypt(paquete['nonce'], paquete['ciphertext'],
                                     pub + n.to_bytes(8, 'big')).decode()
        candidato.recepcion, candidato.nr = siguiente, n + 1
        candidato.vistas = self.vistas | {identidad}
        self.__dict__.update(candidato.__dict__)
        del clave
        return texto


def pareja():
    """Secreto precompartido confiable simulado; NO implementa X3DH."""
    raiz = os.urandom(32)
    a, b = X25519PrivateKey.generate(), X25519PrivateKey.generate()
    alice, bob = Ratchet(raiz, a, publica(b)), Ratchet(raiz, b, publica(a))
    alice.cambiar_direccion()
    return alice, bob
