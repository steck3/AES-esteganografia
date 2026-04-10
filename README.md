# encripta

Herramienta de línea de comandos para **cifrado de archivos** y **esteganografía en imágenes PNG**, construida sobre Node.js nativo.

Combina dos técnicas de seguridad:
- **AES-256-GCM** — cifrado simétrico moderno con autenticación integrada
- **LSB (Least Significant Bit)** — esteganografía para ocultar texto cifrado dentro de imágenes PNG sin alteración visible

---

## Características

- Cifra y descifra cualquier archivo directamente (el archivo original es reemplazado)
- Oculta texto cifrado dentro de imágenes PNG usando esteganografía LSB
- Dos modos de protección: **clave hexadecimal** generada automáticamente o **contraseña** derivada con PBKDF2
- Detecta manipulación de archivos gracias al tag de autenticación GCM
- Sin dependencias externas para cifrado de archivos (usa el módulo `crypto` nativo de Node.js)
- Instalación global: disponible como comando `encripta` desde cualquier directorio

---

## Requisitos

- Node.js v16 o superior
- npm

Para el modo esteganografía se requiere además:

```bash
npm install -g jimp
```

> Si `jimp` no está instalado globalmente, el script intentará instalarlo automáticamente la primera vez que uses `ocultar` o `revelar`.

---

## Instalación

```bash
# Clonar el repositorio
git clone https://github.com/tu-usuario/encripta.git
cd encripta

# Instalar como comando global
sudo cp encripta.js /usr/local/bin/encripta
sudo chmod +x /usr/local/bin/encripta

# Instalar dependencia para esteganografía
npm install -g jimp
```

Verificar instalación:

```bash
encripta --ayuda
```

---

## Uso

### Cifrado de archivos

```bash
# Cifrar un archivo (genera clave automáticamente)
encripta cifrar documento.txt

# Cifrar con contraseña
encripta cifrar documento.txt -p

# Cifrar con una clave existente
encripta cifrar documento.txt -k <clave_hex>

# Descifrar con clave
encripta descifrar documento.txt -k <clave_hex>

# Descifrar con contraseña
encripta descifrar documento.txt -p

# Ver información del archivo cifrado sin abrirlo
encripta info documento.txt
```

> El archivo original es **reemplazado** por su versión cifrada. Al descifrar, el mismo archivo vuelve a su contenido original.

---

### Esteganografía en imágenes

```bash
# Ocultar texto cifrado en una imagen PNG (genera clave automáticamente)
encripta ocultar foto.png "mensaje secreto" foto_salida.png

# Ocultar con contraseña
encripta ocultar foto.png "mensaje secreto" foto_salida.png -p

# Extraer y descifrar el mensaje de una imagen
encripta revelar foto_salida.png -k <clave_hex>

# Extraer usando contraseña
encripta revelar foto_salida.png -p
```

> Solo se admiten imágenes **PNG**. El formato JPG usa compresión con pérdida que destruye los bits ocultos.

---

## Cómo funciona

### Cifrado de archivos

```
archivo original
      │
      ▼
  AES-256-GCM
  (clave 256 bits, IV aleatorio 96 bits, tag 128 bits)
      │
      ▼
archivo cifrado (reemplaza al original)
```

El archivo cifrado tiene la siguiente estructura interna:

```
[ 4 bytes: longitud de metadatos ]
[ metadatos JSON: nombre, tamaño, fecha ]
[ metadatos de cifrado: modo, fecha ]
[ sal PBKDF2: 16 bytes ]  ← solo en modo contraseña
[ IV: 12 bytes ]
[ Tag GCM: 16 bytes ]
[ datos cifrados ]
```

### Esteganografía LSB

```
texto plano
      │
      ▼
  AES-256-GCM  →  base64
      │
      ▼
  bits del payload
      │
      ▼
  LSB de canales R, G, B de cada píxel
      │
      ▼
  imagen PNG (visualmente idéntica)
```

Cada píxel almacena 3 bits (uno por canal de color). El cambio en cada canal es de ±1 valor, imperceptible al ojo humano. Una imagen de 300×300 px tiene capacidad para ~33,750 bytes de datos cifrados.

---

## Seguridad

| Característica | Detalle |
|---|---|
| Algoritmo de cifrado | AES-256-GCM |
| Longitud de clave | 256 bits generados con `crypto.randomBytes` |
| IV | 96 bits aleatorios por operación |
| Autenticación | Tag GCM de 128 bits (detecta cualquier alteración) |
| Derivación desde contraseña | PBKDF2-SHA256, 100,000 iteraciones, sal aleatoria de 128 bits |
| Esteganografía | LSB sobre canales R, G, B en imágenes PNG sin pérdida |

> **Importante:** guarda la clave hexadecimal en un lugar seguro. Sin ella es matemáticamente imposible recuperar el archivo o el mensaje oculto.

---

## Ejemplos de sesión

```bash
# Cifrar un contrato y guardar la clave
$ encripta cifrar contrato.pdf

Archivo cifrado : contrato.pdf
Tamaño          : 48.23 KB
Algoritmo       : AES-256-GCM

CLAVE (guardala en un lugar seguro):
-------------------------------------
9de75ccbd0c1a39d62a743dbc89acb15254e9417b35bb103e9ca20920217ff4a
-------------------------------------
Sin esta clave no podras recuperar el archivo.

# Más tarde, descifrar
$ encripta descifrar contrato.pdf -k 9de75ccbd0c1a39d62a743dbc89acb15254e9417b35bb103e9ca20920217ff4a

Archivo descifrado : contrato.pdf
Tamaño             : 47.10 KB
Cifrado el         : 10/4/2026, 21:30:00
```

```bash
# Ocultar un mensaje en el logo de la empresa
$ encripta ocultar logo.png "eochoa@empresa.mx" logo_enviado.png

Texto ocultado en imagen
------------------------------
Imagen original  : logo.png
Imagen salida    : logo_enviado.png
Texto            : "eochoa@empresa.mx"
Capacidad usada  : 0.21%
Algoritmo        : AES-256-GCM + LSB

CLAVE:
-------------------------------------
69e16e696dd60abdc4699f7c5cc1700d53c75bdb9adca3dcd2f07d826e5c6d71
-------------------------------------

# Extraer el mensaje
$ encripta revelar logo_enviado.png -k 69e16e696dd60abdc4699f7c5cc1700d53c75bdb9adca3dcd2f07d826e5c6d71

Mensaje encontrado y descifrado
------------------------------
Imagen   : logo_enviado.png
Mensaje  : "eochoa@empresa.mx"
```

---

## Estructura del proyecto

```
encripta/
├── encripta.js     # Script principal (CLI unificado)
└── README.md       # Este archivo
```

---

## Limitaciones

- Las imágenes de entrada para esteganografía deben estar en formato **PNG**
- El mensaje a ocultar no puede superar la capacidad de la imagen (3 bits por píxel)
- El cifrado de archivos reemplaza el original — se recomienda hacer respaldo antes si es un archivo crítico
- Probado en Linux y macOS; en Windows puede requerir ajustes en la lectura de contraseñas

---

## Licencia

MIT
