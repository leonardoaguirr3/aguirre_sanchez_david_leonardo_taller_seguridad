# Seguridad en mensajería: cadena de claves y Double Ratchet reducido

**Autor:** David Leonardo Aguirre Sanchez  
**Asignatura:** Sistemas distribuidos

## Objetivo

Investigar el cifrado extremo a extremo y el secreto hacia adelante (*forward secrecy*), implementar dos mecanismos simplificados de gestión de claves y contrastar su comportamiento mediante pruebas automatizadas.

El proyecto se ejecuta localmente, en un único proceso y en memoria. No utiliza red, servidores, cuentas de terceros ni datos reales de usuarios.

## Implementación

- **A1 — Cadena de claves simétrica:** utiliza HKDF-SHA256 para derivar una clave por mensaje y el siguiente estado de la cadena. Los mensajes se cifran con AES-256-GCM y las referencias a las claves consumidas se descartan.
- **A2 — Double Ratchet reducido:** combina cadenas simétricas con actualizaciones Diffie-Hellman mediante X25519. El escenario principal comprende seis mensajes: tres de Alice a Bob y tres de Bob a Alice. El cambio de dirección genera un nuevo par de claves X25519.

Las primitivas criptográficas proceden de la biblioteca `cryptography`. `pytest` ejecuta las pruebas y `conftest.py` exporta sus resultados.

## Requisitos

- Python 3.11.
- `pip` y soporte para entornos virtuales mediante `venv`.
- Dependencias especificadas en `requirements.txt`.

La instalación de dependencias requiere acceso a internet. Las pruebas se ejecutan sin conexiones de red.

## Instalación

Desde el directorio raíz del proyecto, en macOS o Linux:

```bash
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

## Ejecución de las pruebas

Con el entorno virtual activo y desde la raíz del proyecto:

```bash
python -m pytest -q
```

El comando ejecuta las nueve pruebas y genera o reemplaza los siguientes archivos:

- `resultados.csv`: resultados comparados con los valores esperados, con estados `OK` o `FALLA` y comentarios.
- `log_pruebas.json`: registro de cada prueba con los campos `prueba`, `esperado`, `obtenido` y `estado`.

Los resultados se obtienen de la ejecución de las aserciones, sin edición manual. Las claves y los nonces varían entre ejecuciones y no se incluyen en los registros.

## Pruebas incluidas

| Identificador | Propiedad evaluada |
| --- | --- |
| A1-01 | Determinismo de la derivación para una misma cadena e índice. |
| A1-02 | Generación de diez claves de mensaje distintas. |
| A1-03 | Cifrado y descifrado correcto de diez mensajes. |
| A1-04 | Rechazo del intento de recuperar una clave anterior desde la cadena avanzada, bajo un modelo de borrado lógico. |
| A2-01 | Descifrado correcto de los seis mensajes y renovación del par X25519. |
| A2-02 | Rechazo de un ciphertext alterado sin desincronizar el receptor. |
| A2-03 | Rechazo de un mensaje repetido. |
| A2-04 | Rechazo del intento de descifrar el primer mensaje desde el estado robado tras el tercero. |
| A2-05 | Rechazo del intento de descifrar un mensaje posterior a la renovación de Bob usando su estado anterior comprometido. |

Las funciones usan nombres como `test_A1_01`, ya que Python no admite guiones en identificadores. El exportador los convierte a los identificadores del enunciado, como `A1-01`.

A2-05 utiliza un escenario independiente con un mensaje de control adicional: comprueba que el estado robado permite descifrar antes de la renovación. El escenario principal A2-01 conserva exactamente seis mensajes.

## Estructura del proyecto

| Archivo | Contenido |
| --- | --- |
| `ficha.md` | Definición, amenaza, mecanismo y fuentes primarias. |
| `a1_cadena.py` | Derivación de claves y cifrado simétrico de A1. |
| `a2_ratchet.py` | Participantes y operaciones del Double Ratchet reducido. |
| `test_a1.py` | Cuatro pruebas de A1. |
| `test_a2.py` | Cinco pruebas de A2. |
| `conftest.py` | Exportación automática de resultados de pytest. |
| `resultados.csv` | Tabla de las nueve pruebas. |
| `log_pruebas.json` | Registro estructurado de resultados. |
| `informe.md` | Implementación, diferencias y limitaciones. |
| `requirements.txt` | Versiones de las dependencias. |
| `validacion.txt` | Entorno y resultado de la verificación realizada. |
| `README.md` | Descripción e instrucciones de reproducción. |

## Validación

La ejecución realizada con CPython 3.11.18 en Linux produjo **9 pruebas aprobadas**, con nueve filas `OK` en el CSV y nueve entradas `OK` en el JSON. La ejecución en macOS no forma parte de esta verificación.

## Alcance y limitaciones

- El borrado de claves es lógico: eliminar referencias en Python no garantiza la eliminación física de todas sus copias en memoria.
- La inicialización supone un secreto precompartido confiable. No se implementa X3DH ni autenticación de identidades.
- La recuperación tras un compromiso se evalúa para un robo puntual del estado de Bob antes de que genere su nueva clave privada, con un atacante pasivo sin acceso posterior al dispositivo. No implica recuperación inmediata para cualquier estado comprometido.
- Se exige entrega ordenada; no se gestionan mensajes retrasados, persistencia, recuperación tras reinicios ni extensiones poscuánticas.
- Las pruebas aportan evidencia funcional de los escenarios implementados; no constituyen una demostración formal de seguridad ni una auditoría criptográfica.

El proyecto tiene finalidad académica y no está diseñado para proteger comunicaciones reales.
