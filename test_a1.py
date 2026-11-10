import os
import pytest
from cryptography.exceptions import InvalidTag
from a1_cadena import derivar_clave, cifrar, descifrar


def test_A1_01():
    c = os.urandom(32)
    assert derivar_clave(c, 0) == derivar_clave(c, 0)


def test_A1_02():
    c, claves = os.urandom(32), []
    for i in range(10):
        c, k = derivar_clave(c, i)
        claves.append(k)
    assert len(set(claves)) == 10


def test_A1_03():
    emisor = receptor = os.urandom(32)
    for i in range(10):
        emisor, k = derivar_clave(emisor, i)
        p = cifrar(k, f'Mensaje {i}')
        del k
        receptor, k = derivar_clave(receptor, i)
        assert descifrar(k, p) == f'Mensaje {i}'
        del k


def test_A1_04():
    c = os.urandom(32)
    c, k = derivar_clave(c, 0)
    p = cifrar(k, 'Pasado')
    del k
    # Solo queda la cadena avanzada: reusar el índice no reconstruye la clave.
    _, intento = derivar_clave(c, 0)
    with pytest.raises(InvalidTag):
        descifrar(intento, p)
