# Informe del taller de seguridad en mensajería
**Estudiante:** David Leonardo Aguirre Sanchez  
**Asignatura:** Sistemas distribuidos

## Qué se implementó
A1 deriva con HKDF-SHA256 dos valores de 32 bytes: la cadena siguiente y la clave del mensaje. AES-256-GCM cifra y autentica el texto; el nonce aleatorio tiene 12 bytes. Se reemplaza la cadena y se elimina la referencia a la clave consumida.

A2 mantiene raíz, par X25519 local, pública remota, cadenas de envío/recepción y contadores. El escenario principal transmite mensajes 1–3 de Alice a Bob y 4–6 de Bob a Alice. Al responder, Bob genera un par X25519 nuevo; ambos calculan el mismo secreto DH y actualizan la raíz. La cabecera (pública e índice) se autentica como datos asociados. Recibir verifica sobre un estado provisional y solo confirma cambios si el tag es válido.

Las nueve pruebas se ejecutan con pytest y generan automáticamente resultados.csv y log_pruebas.json. A2-05 es un escenario independiente: añade un mensaje de control anterior al cambio para demostrar que el estado robado sí podía descifrar antes de la renovación. El escenario A2-01 mantiene exactamente seis mensajes.

## Diferencias
Los resultados concretos están en resultados.csv: cada OK representa aserciones ejecutadas, no una estimación. A1-04 interpreta «no recuperable» como ausencia de una clave antigua en el estado lógico y rechazo de un intento derivado de la cadena avanzada; no demuestra imposibilidad matemática ni borrado físico de RAM.

El enunciado solicita nombres de funciones iguales a identificadores como A1-01. Python no permite guiones en identificadores: se usa test_A1_01 y el exportador lo transforma inequívocamente a A1-01. El CSV conserva exactamente los identificadores y el encabezado pedidos.

El Double Ratchet reducido difiere de un cliente Signal: usa un secreto inicial compartido de forma confiable en memoria, entrega ordenada y generación DH diferida hasta responder. No implementa X3DH, almacenamiento de claves para mensajes retrasados, cifrado de cabeceras ni extensiones poscuánticas.

## Limitaciones
Las pruebas son evidencia funcional de escenarios concretos, no una auditoría ni una prueba formal de seguridad. No se implementa criptografía desde cero: las primitivas proceden de cryptography. No hay red, servidores, cuentas ni datos reales.

En A2-04 se intenta descifrar criptográficamente desde la cadena avanzada, evitando obtener un falso éxito por el filtro de repetición. En A2-05 se roba el estado de Bob antes de generar su nueva privada. Si se roba el estado de Alice y Bob responde usando la pública de Alice aún comprometida, ese primer cambio no basta para recuperar seguridad. Tampoco se protege frente a un atacante que mantiene acceso al dispositivo o manipula activamente el establecimiento de claves.

Python no ofrece garantía de borrado seguro de bytes ni de las privadas administradas por la biblioteca. La prueba de borrado modela eliminación lógica de referencias. Se rechazan mensajes fuera de orden; no hay persistencia ni recuperación tras reinicios. El conjunto de identificadores vistos crece con la sesión. Esta implementación es educativa y no debe utilizarse para comunicaciones reales.
