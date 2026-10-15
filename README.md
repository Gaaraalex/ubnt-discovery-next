# Ubiquiti Discovery (sin Java)

Reemplazo moderno de la herramienta **Ubiquiti Discovery Utility v2.5.1**, que está
descontinuada y solo funciona con una versión antigua y vulnerable de Java 8.

Esta versión hace lo mismo que la original, pero sin Java: está hecha con
[Electron](https://www.electronjs.org/) y Node.js, y se distribuye como un
instalador o un ejecutable portable para Windows.

## Funciones

- **Búsqueda de equipos** airOS / UISP y **UniFi** en la red local (UDP 10001),
  con el mismo protocolo que la herramienta original (consultas v1 y v2).
- Tabla con **producto, IP, MAC, nombre del sistema y firmware**, con búsqueda
  (admite comodines `*` y `?`) y orden por columnas.
- **Detalles** del equipo: direcciones de red, versión, build, tiempo activo,
  SSID y dirección IPv6 de rescate.
- **Web UI**: abre la interfaz web del equipo en el navegador.
- **Reboot**: reinicia el equipo con el mismo mecanismo de desafío/respuesta
  del original (crypt DES / MD5 / SHA-512 + SHA-256).
- **Rescue Web UI**: abre un túnel SSH por IPv6 link-local cuando la interfaz
  web no es accesible por IPv4.
- **Copiar** filas al portapapeles (Ctrl+C).
- **8 temas**: Sistema, Claro, Oscuro, Medianoche, Azul Ubiquiti, Terminal verde,
  Arena y Alto contraste.

## Requisitos

- Windows 10 u 11 de 64 bits.
- Estar en la misma red local que los equipos.
- Permitir la aplicación en el Firewall de Windows (redes privadas) la primera vez.

## Compilar desde el código

Necesitas [Node.js](https://nodejs.org/) 22 o superior.

```bash
npm install
npm test          # pruebas del protocolo y del cifrado
npm start         # abre la aplicación en modo desarrollo
npm run dist      # genera el instalador y el portable en dist/
```

### Herramientas de prueba

- `node scripts/fake-device.js` simula un NanoStation y un UniFi AP en tu propio
  PC, para probar la búsqueda y el reinicio sin hardware real
  (usuario `ubnt`, contraseña `ubnt`).
- `node scripts/scan-cli.js` hace una búsqueda de 10 segundos desde la consola.
- `node scripts/make-icon.js` vuelve a generar el icono de la aplicación.

## Cómo funciona el protocolo

| Consulta | Bytes | Destino |
| --- | --- | --- |
| v1 | `01 00 00 00` | UDP 10001 a `255.255.255.255` y `233.89.188.1` |
| v2 (UniFi) | `02 08 00 00` | igual |

Los equipos responden con `versión, comando, longitud` seguido de registros TLV
(tipo de 1 byte, longitud de 2 bytes, datos). Los tipos están en
[`src/lib/protocol.js`](src/lib/protocol.js).

## Aviso

Proyecto independiente, **sin relación con Ubiquiti Inc.** "Ubiquiti", "UniFi" y
"airOS" son marcas de sus respectivos propietarios. El protocolo se reconstruyó
para dar interoperabilidad a una herramienta descontinuada, y no incluye código
ni imágenes de Ubiquiti. Úsalo solo con equipos que te pertenezcan o que estés
autorizado a administrar.

## Licencia

[MIT](LICENSE)
