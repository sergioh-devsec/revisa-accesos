# Auth Log Analyzer · CyberSerchMX

Herramienta terminada de clasificación local de eventos. No conecta servicios ni escanea sistemas. Python 3.10 o posterior, sin dependencias.

## Problema y resultado reproducible

Leer eventos uno por uno oculta los orígenes que acumulan rechazos. El programa valida hora, estado e IPv4, agrupa los rechazos y señala los que alcanzan el umbral. La muestra ficticia `sample.log` contiene 5 eventos, 4 rechazos y un origen con 3 rechazos: `192.0.2.14`.

```sh
python analyzer.py sample.log
python analyzer.py sample.log --threshold 3 --output report.json
python -m unittest -v
```

Formato: `HH:MM:SS ACCEPT|DENY IPv4`, un evento por línea. Salida JSON con total, válidos, aceptados, rechazados, líneas inválidas y hallazgos. El informe nunca sobrescribe un archivo existente. Límite de entrada: 2 MB. Código de salida 2 para errores de entrada o escritura.

## Límites y privacidad

Cuenta todo el archivo; no calcula ventanas temporales, autenticación real ni correlación. Una IP compartida puede representar usuarios diferentes. Un hallazgo requiere revisión humana y no demuestra un ataque. No es Wazuh, un SIEM ni una auditoría. Usa registros propios o autorizados y no publiques registros de clientes en issues.

La demostración web relacionada está en https://sergioh-devsec.github.io/#laboratory. Este repositorio contiene la versión CLI en Python.
