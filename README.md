# Revisa accesos

Soy Serch. Quise convertir una lista de accesos en una primera señal que pudiera revisar sin leer línea por línea.

## Por qué y para qué
Desde mis conocimientos de redes y ciberseguridad empecé por un formato acotado: hora, decisión e IPv4. Separé validación, agrupación e informe; elegí biblioteca estándar de Python para que se pueda repetir sin instalar un entorno grande.

Lo estoy incorporando a mi laboratorio como parte de mi práctica profesional y mi curiosidad por construir herramientas útiles. Esta es una herramienta de muestra, no una historia de resultados de clientes.

## Pruébalo
Python 3.10 o posterior, sin dependencias externas. Desde esta carpeta:

    python analyzer.py sample.log --threshold 3
    python -m unittest -v

También puedes usar la [versión ligera en el navegador](https://sergioh-devsec.github.io/herramientas.html#logs), sin enviar el archivo a un servidor.

## Proceso
1. Definí la entrada y sus límites antes de programar.
2. Separé lógica de procesamiento y argumentos de la terminal.
3. Preparé una muestra ficticia y pruebas de entradas válidas e inválidas.
4. Añadí exportación y mensajes de error que permiten revisar el resultado.

## Alcance honesto
La muestra contiene cinco eventos válidos, cuatro rechazos y un origen con tres rechazos. El umbral marca una señal, no demuestra un ataque. No hay ventana temporal ni compatibilidad universal con logs de productos. Límite de entrada: 2 MB.

El archivo original no se modifica. No se recoge telemetría ni se envían datos. No publiques registros reales en incidencias. El próximo paso es ampliar formatos conservando las validaciones.

— Serch · CyberSerchMX
