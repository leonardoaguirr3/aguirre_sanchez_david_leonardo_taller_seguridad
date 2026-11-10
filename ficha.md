# Cifrado extremo a extremo y secreto hacia adelante
David Leonardo Aguirre Sanchez · Sistemas distribuidos

## Definición
El cifrado extremo a extremo (E2EE) permite que el contenido sea descifrado por los extremos autorizados. Un intermediario que transporta mensajes no necesita sus claves. No protege el texto ya visible en un dispositivo comprometido, capturas del destinatario ni, por sí solo, los metadatos de comunicación. La autenticación de las identidades y la protección del dispositivo siguen siendo necesarias: X3DH separa el establecimiento autenticado del secreto del protocolo posterior [2].

## Amenaza
El secreto hacia adelante protege mensajes anteriores ante el robo posterior del estado criptográfico, siempre que se hayan eliminado las claves antiguas. El atacante puede guardar ciphertexts y obtener después las claves actuales. Esto no garantiza seguridad futura: recuperar seguridad tras un compromiso requiere secretos nuevos que el atacante desconozca [1].

## Mecanismo
En el Double Ratchet clásico, las cadenas simétricas producen claves individuales y avanzan descartando el estado anterior. La raíz incorpora resultados Diffie-Hellman para renovar las cadenas. El taller reproduce esa separación con HKDF y X25519, sin implementar el establecimiento X3DH. Su borrado es lógico; Python puede conservar copias en memoria. La recuperación ensayada supone un robo puntual y un atacante pasivo, sin acceso a la nueva clave privada [1].

## Fuentes
[1] Perrin, Marlinspike y Schmidt. *The Double Ratchet Algorithm*. Signal, revisión 4, 2025-11-04. Secciones 2, 3 y 8. https://signal.org/docs/specifications/doubleratchet/

[2] Marlinspike y Perrin. *The X3DH Key Agreement Protocol*. Signal, revisión 1, 2016-11-04. Secciones 1 y 4. https://signal.org/docs/specifications/x3dh/

Fuentes primarias consultadas para esta entrega. Se estudia el Double Ratchet clásico; no las extensiones poscuánticas de la especificación actual.
