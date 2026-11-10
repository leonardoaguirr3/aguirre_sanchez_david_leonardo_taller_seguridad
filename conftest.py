"""Exporta resultados de pytest, incluso ante fallos o pruebas omitidas."""
import csv
import json
from pathlib import Path

CASOS = [
('A1-01','A1','determinismo','Misma cadena e índice producen la misma clave','misma clave'),
('A1-02','A1','unicidad','10 claves de mensaje distintas','10 claves distintas'),
('A1-03','A1','cifrado','Cifrar y descifrar 10 mensajes','10/10 correctos'),
('A1-04','A1','borrado','Clave usada y luego borrada no se recupera','no recuperable'),
('A2-01','A2','descifrado','Descifrar los 6 mensajes','6/6 correctos'),
('A2-02','A2','integridad','Un byte alterado del ciphertext','rechazado'),
('A2-03','A2','repetición','Mensaje reenviado','rechazado'),
('A2-04','A2','forward secrecy','Estado robado tras mensaje 3 no descifra mensaje 1','no descifrable'),
('A2-05','A2','post-compromise','Estado robado antes del cambio de dirección no descifra tras él','no descifrable')]
REPORTES = {}


def pytest_runtest_logreport(report):
    nombre = report.nodeid.split('::')[-1]
    identificador = nombre.removeprefix('test_').replace('_', '-')
    if report.when == 'call' or report.failed or report.skipped:
        previo = REPORTES.get(identificador)
        if previo is None or not previo.failed:
            REPORTES[identificador] = report


def pytest_sessionfinish(session, exitstatus):
    filas, registro = [], []
    for ident, alg, prop, desc, esperado in CASOS:
        r = REPORTES.get(ident)
        ok = r is not None and r.passed
        obtenido = esperado if ok else ('no ejecutada' if r is None else r.outcome)
        comentario = 'Aserciones verificadas' if ok else (str(r.longrepr) if r else 'Sin reporte')
        if ok and ident == 'A1-04':
            comentario = 'Borrado lógico; intento con cadena avanzada falla. No demuestra borrado físico.'
        if ok and ident == 'A2-05':
            comentario = 'Compromiso puntual de Bob; nueva privada de Bob posterior al robo; atacante pasivo.'
        estado = 'OK' if ok else 'FALLA'
        filas.append([ident, alg, prop, desc, esperado, obtenido, estado, comentario])
        registro.append(dict(prueba=ident, esperado=esperado, obtenido=obtenido, estado=estado))
    base = Path(__file__).parent
    with (base / 'resultados.csv').open('w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow('id_prueba,algoritmo,propiedad,descripcion,esperado,obtenido,estado,comentario'.split(','))
        w.writerows(filas)
    (base / 'log_pruebas.json').write_text(json.dumps(registro, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
