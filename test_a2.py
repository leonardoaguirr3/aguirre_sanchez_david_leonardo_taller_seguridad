import copy
import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from a1_cadena import derivar_clave
from a2_ratchet import pareja, publica


def tres():
    a, b = pareja()
    paquetes = []
    for i in range(3):
        p = a.enviar(f'Mensaje {i + 1}')
        assert b.recibir(p) == f'Mensaje {i + 1}'
        paquetes.append(p)
    return a, b, paquetes


def test_A2_01():
    a, b, _ = tres()
    anterior = publica(b.privada)
    b.cambiar_direccion()
    assert publica(b.privada) != anterior
    for i in range(3, 6):
        assert a.recibir(b.enviar(f'Mensaje {i + 1}')) == f'Mensaje {i + 1}'


def test_A2_02():
    a, b = pareja()
    p = a.enviar('Original')
    malo = dict(p)
    malo['ciphertext'] = bytes([p['ciphertext'][0] ^ 1]) + p['ciphertext'][1:]
    with pytest.raises(InvalidTag):
        b.recibir(malo)
    assert b.recibir(p) == 'Original'  # Ataque no desincroniza el estado.


def test_A2_03():
    a, b = pareja()
    p = a.enviar('Una vez')
    assert b.recibir(p) == 'Una vez'
    with pytest.raises(ValueError, match='Repetición'):
        b.recibir(p)


def test_A2_04():
    a, b, paquetes = tres()
    robado = copy.copy(b)
    p = paquetes[0]
    # Evita confundir protección antirrepetición con forward secrecy.
    _, intento = derivar_clave(robado.recepcion, 0)
    with pytest.raises(InvalidTag):
        AESGCM(intento).decrypt(p['nonce'], p['ciphertext'],
                               p['publica'] + p['indice'].to_bytes(8, 'big'))


def test_A2_05():
    a, b, _ = tres()
    # Robo completo de Bob ANTES de que Bob genere su nueva privada.
    robado = copy.copy(b)
    control = a.enviar('Control conocido por atacante')
    assert robado.recibir(control) == 'Control conocido por atacante'
    assert b.recibir(control) == 'Control conocido por atacante'
    b.cambiar_direccion()
    p = b.enviar('Nuevo secreto')
    assert a.recibir(p) == 'Nuevo secreto'
    # Atacante intenta DH con su privada antigua y pública de Alice.
    cadena = robado._raiz(robado.privada, robado.remota)
    _, intento = derivar_clave(cadena, 0)
    with pytest.raises(InvalidTag):
        AESGCM(intento).decrypt(p['nonce'], p['ciphertext'], p['publica'] + bytes(8))
