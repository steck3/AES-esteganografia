#!/usr/bin/env node

const crypto = require("crypto");
const fs     = require("fs");
const path   = require("path");

// ─────────────────────────────────────────────
//  CONFIGURACION
// ─────────────────────────────────────────────
const ALGORITMO    = "aes-256-gcm";
const LONGITUD_IV  = 12;
const LONGITUD_TAG = 16;
const SEPARADOR    = "\x00\x00\xFF"; // marcador fin de mensaje en imagen

// ─────────────────────────────────────────────
//  AYUDA
// ─────────────────────────────────────────────
function mostrarAyuda() {
  console.log(`
ENCRIPTADOR AES-256-GCM + ESTEGANOGRAFIA LSB
=============================================

-- ARCHIVOS --
  encripta cifrar   <archivo>              Cifra el archivo con clave generada
  encripta cifrar   <archivo> -p           Cifra el archivo con contrasena
  encripta cifrar   <archivo> -k <clave>   Cifra el archivo con clave existente
  encripta descifrar <archivo> -k <clave>  Descifra el archivo con clave
  encripta descifrar <archivo> -p          Descifra el archivo con contrasena
  encripta info     <archivo>              Ver info de archivo cifrado

-- IMAGENES (esteganografia + cifrado) --
  encripta ocultar  <imagen.png> "<texto>" <salida.png>
                                           Cifra el texto y lo oculta en la imagen
  encripta ocultar  <imagen.png> "<texto>" <salida.png> -p
                                           Igual pero protegido con contrasena
  encripta revelar  <imagen.png> -k <clave>
                                           Extrae y descifra el texto de la imagen
  encripta revelar  <imagen.png> -p        Extrae y descifra usando contrasena

  encripta --ayuda                         Mostrar esta ayuda

EJEMPLOS:
  encripta cifrar documento.txt
  encripta descifrar documento.txt -k 3a9f...
  encripta ocultar foto.png "mensaje secreto" foto_salida.png
  encripta revelar foto_salida.png -k 3a9f...

NOTA:
  Las imagenes deben ser PNG. JPG destruye los datos ocultos por su compresion.
`);
}

// ─────────────────────────────────────────────
//  UTILIDADES GENERALES
// ─────────────────────────────────────────────
function leerPassword(prompt) {
  const { execSync } = require("child_process");
  process.stdout.write(prompt);
  try {
    const pass = execSync("bash -c 'read -s PASS && echo $PASS'", {
      stdio: ["inherit", "pipe", "inherit"],
    });
    process.stdout.write("\n");
    return pass.toString().trim();
  } catch {
    console.error("Error: no se pudo leer la contrasena.");
    process.exit(1);
  }
}

function derivarClave(password, sal) {
  return crypto.pbkdf2Sync(password, sal, 100_000, 32, "sha256");
}

function formatearTamano(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 ** 2) return `${(bytes / 1024).toFixed(2)} KB`;
  return `${(bytes / 1024 ** 2).toFixed(2)} MB`;
}

// ─────────────────────────────────────────────
//  AES: CIFRAR datos (devuelve Buffer)
// ─────────────────────────────────────────────
function cifrarDatos(datos, opciones = {}) {
  let clave, sal, claveHex;

  if (opciones.password) {
    sal   = crypto.randomBytes(16);
    clave = derivarClave(opciones.password, sal);
  } else {
    claveHex = opciones.claveHex || crypto.randomBytes(32).toString("hex");
    clave    = Buffer.from(claveHex, "hex");
    sal      = null;
  }

  const iv      = crypto.randomBytes(LONGITUD_IV);
  const cipher  = crypto.createCipheriv(ALGORITMO, clave, iv);
  const cifrado = Buffer.concat([cipher.update(datos), cipher.final()]);
  const tag     = cipher.getAuthTag();

  const meta    = Buffer.from(JSON.stringify({
    modo:  opciones.password ? "password" : "clave",
    fecha: new Date().toISOString(),
  }));
  const metaLen = Buffer.alloc(4);
  metaLen.writeUInt32BE(meta.length, 0);

  const partes = sal
    ? [metaLen, meta, sal, iv, tag, cifrado]
    : [metaLen, meta, iv, tag, cifrado];

  return { buffer: Buffer.concat(partes), claveHex };
}

// ─────────────────────────────────────────────
//  AES: DESCIFRAR datos desde Buffer
// ─────────────────────────────────────────────
function descifrarDatos(buffer, opciones = {}) {
  let offset = 0;

  const metaLen = buffer.readUInt32BE(offset); offset += 4;
  let meta;
  try {
    meta = JSON.parse(buffer.subarray(offset, offset + metaLen).toString());
  } catch {
    throw new Error("Datos no reconocidos o corruptos.");
  }
  offset += metaLen;

  let clave;
  if (meta.modo === "password") {
    if (!opciones.password) throw new Error("Se requiere contrasena (-p).");
    const sal = buffer.subarray(offset, offset + 16); offset += 16;
    clave     = derivarClave(opciones.password, sal);
  } else {
    if (!opciones.claveHex) throw new Error("Se requiere clave (-k <clave>).");
    clave = Buffer.from(opciones.claveHex, "hex");
  }

  const iv      = buffer.subarray(offset, offset + LONGITUD_IV);  offset += LONGITUD_IV;
  const tag     = buffer.subarray(offset, offset + LONGITUD_TAG); offset += LONGITUD_TAG;
  const cifrado = buffer.subarray(offset);

  const decipher = crypto.createDecipheriv(ALGORITMO, clave, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(cifrado), decipher.final()]);
}

// ─────────────────────────────────────────────
//  LSB: TEXTO -> BITS
// ─────────────────────────────────────────────
function aBits(buffer) {
  const bits = [];
  for (const byte of buffer) {
    for (let i = 7; i >= 0; i--) bits.push((byte >> i) & 1);
  }
  return bits;
}

// ─────────────────────────────────────────────
//  LSB: BITS -> BUFFER
// ─────────────────────────────────────────────
function aBuffer(bits) {
  const bytes = [];
  for (let i = 0; i + 7 < bits.length; i += 8) {
    let byte = 0;
    for (let j = 0; j < 8; j++) byte = (byte << 1) | bits[i + j];
    bytes.push(byte);
  }
  return Buffer.from(bytes);
}

// ─────────────────────────────────────────────
//  LSB: INCRUSTAR bits en imagen
// ─────────────────────────────────────────────
function incrustarBits(img, bits, Jimp) {
  const { intToRGBA, rgbaToInt } = Jimp;
  let idx = 0;

  for (let y = 0; y < img.height && idx < bits.length; y++) {
    for (let x = 0; x < img.width && idx < bits.length; x++) {
      let { r, g, b, a } = intToRGBA(img.getPixelColor(x, y));
      if (idx < bits.length) r = (r & 0xFE) | bits[idx++];
      if (idx < bits.length) g = (g & 0xFE) | bits[idx++];
      if (idx < bits.length) b = (b & 0xFE) | bits[idx++];
      img.setPixelColor(rgbaToInt(r, g, b, a), x, y);
    }
  }
}

// ─────────────────────────────────────────────
//  LSB: EXTRAER bits de imagen
// ─────────────────────────────────────────────
function extraerBits(img, Jimp) {
  const { intToRGBA } = Jimp;
  const bits = [];

  for (let y = 0; y < img.height; y++) {
    for (let x = 0; x < img.width; x++) {
      const { r, g, b } = intToRGBA(img.getPixelColor(x, y));
      bits.push(r & 1, g & 1, b & 1);
    }
  }
  return bits;
}

// ─────────────────────────────────────────────
//  CARGAR JIMP (instalarlo si falta)
// ─────────────────────────────────────────────
async function cargarJimp() {
  const { execSync } = require("child_process");

  // Intentar carga directa primero
  try { return require("jimp"); } catch {}

  // Buscar en rutas globales de npm
  const rutas = [];
  try {
    const globalRoot = execSync("npm root -g").toString().trim();
    rutas.push(path.join(globalRoot, "jimp"));
  } catch {}

  // Rutas comunes en distintos sistemas
  const home = process.env.HOME || "";
  rutas.push(
    "/usr/lib/node_modules/jimp",
    "/usr/local/lib/node_modules/jimp",
    path.join(home, ".npm-global/lib/node_modules/jimp"),
    path.join(home, ".nvm/versions/node", process.version, "lib/node_modules/jimp"),
  );

  for (const ruta of rutas) {
    try { return require(ruta); } catch {}
  }

  // No se encontró: instalar globalmente
  console.log("Instalando jimp globalmente...");
  try {
    execSync("npm install -g jimp", { stdio: "inherit" });
  } catch {
    execSync("sudo npm install -g jimp", { stdio: "inherit" });
  }

  // Reintentar después de instalar
  const globalRoot = execSync("npm root -g").toString().trim();
  return require(path.join(globalRoot, "jimp"));
}

// ─────────────────────────────────────────────
//  COMANDO: cifrar archivo
// ─────────────────────────────────────────────
function cifrarArchivo(archivo, opciones = {}) {
  if (!fs.existsSync(archivo)) {
    console.error(`Error: archivo no encontrado: ${archivo}`);
    process.exit(1);
  }

  const datos = fs.readFileSync(archivo);
  let password = null;

  if (opciones.password) {
    password        = leerPassword("Ingresa contrasena: ");
    const confirmar = leerPassword("Confirma contrasena: ");
    if (password !== confirmar) {
      console.error("Error: las contrasenas no coinciden.");
      process.exit(1);
    }
  }

  const meta    = Buffer.from(JSON.stringify({
    nombre: path.basename(archivo),
    tamano: datos.length,
    fecha:  new Date().toISOString(),
  }));
  const metaLen = Buffer.alloc(4);
  metaLen.writeUInt32BE(meta.length, 0);

  const { buffer, claveHex } = cifrarDatos(datos, {
    password,
    claveHex: opciones.claveHex,
  });

  fs.writeFileSync(archivo, Buffer.concat([metaLen, meta, buffer]));

  console.log(`\nArchivo cifrado : ${archivo}`);
  console.log(`Tamano          : ${formatearTamano(fs.statSync(archivo).size)}`);
  console.log(`Algoritmo       : AES-256-GCM`);

  if (!password) {
    console.log(`\nCLAVE (guardala en un lugar seguro):\n-------------------------------------\n${claveHex}\n-------------------------------------\nSin esta clave no podras recuperar el archivo.\n`);
  } else {
    console.log(`Modo: contrasena (PBKDF2 x100,000)\n`);
  }
}

// ─────────────────────────────────────────────
//  COMANDO: descifrar archivo
// ─────────────────────────────────────────────
function descifrarArchivo(archivo, opciones = {}) {
  if (!fs.existsSync(archivo)) {
    console.error(`Error: archivo no encontrado: ${archivo}`);
    process.exit(1);
  }

  const raw    = fs.readFileSync(archivo);
  let offset   = 0;
  const mLen   = raw.readUInt32BE(offset); offset += 4;
  const meta   = JSON.parse(raw.subarray(offset, offset + mLen).toString()); offset += mLen;
  const buffer = raw.subarray(offset);

  let password = null;
  if (opciones.password) password = leerPassword("Ingresa contrasena: ");

  let datos;
  try {
    datos = descifrarDatos(buffer, { password, claveHex: opciones.claveHex });
  } catch (e) {
    console.error(`Error: ${e.message}`);
    process.exit(1);
  }

  fs.writeFileSync(archivo, datos);
  console.log(`\nArchivo descifrado : ${archivo}`);
  console.log(`Tamano             : ${formatearTamano(datos.length)}`);
  console.log(`Cifrado el         : ${new Date(meta.fecha).toLocaleString()}\n`);
}

// ─────────────────────────────────────────────
//  COMANDO: info archivo
// ─────────────────────────────────────────────
function infoArchivo(archivo) {
  if (!fs.existsSync(archivo)) {
    console.error(`Error: archivo no encontrado: ${archivo}`);
    process.exit(1);
  }
  try {
    const raw    = fs.readFileSync(archivo);
    const mLen   = raw.readUInt32BE(0);
    const meta   = JSON.parse(raw.subarray(4, 4 + mLen).toString());
    const inner  = raw.subarray(4 + mLen + 4);
    let innerMeta = {};
    try {
      const iLen = raw.readUInt32BE(4 + mLen);
      innerMeta  = JSON.parse(raw.subarray(4 + mLen + 4, 4 + mLen + 4 + iLen).toString());
    } catch {}
    console.log(`\nINFO DEL ARCHIVO CIFRADO\n-----------------------------------------`);
    console.log(`Nombre original  : ${meta.nombre}`);
    console.log(`Tamano original  : ${formatearTamano(meta.tamano)}`);
    console.log(`Fecha de cifrado : ${new Date(meta.fecha).toLocaleString()}`);
    console.log(`Modo             : ${innerMeta.modo === "password" ? "Contrasena (PBKDF2)" : "Clave hexadecimal"}`);
    console.log(`Tamano actual    : ${formatearTamano(fs.statSync(archivo).size)}\n`);
  } catch {
    console.error("Error: no se pudo leer la informacion.");
    process.exit(1);
  }
}

// ─────────────────────────────────────────────
//  COMANDO: ocultar texto cifrado en imagen
// ─────────────────────────────────────────────
async function ocultarEnImagen(imagenEntrada, texto, imagenSalida, opciones = {}) {
  if (!fs.existsSync(imagenEntrada)) {
    console.error(`Error: imagen no encontrada: ${imagenEntrada}`);
    process.exit(1);
  }
  if (!imagenEntrada.toLowerCase().endsWith(".png")) {
    console.error("Error: solo se admiten imagenes PNG.");
    process.exit(1);
  }

  const JimpMod = await cargarJimp();
  const { Jimp, intToRGBA, rgbaToInt } = JimpMod;

  let password = null;
  if (opciones.password) {
    password        = leerPassword("Ingresa contrasena: ");
    const confirmar = leerPassword("Confirma contrasena: ");
    if (password !== confirmar) {
      console.error("Error: las contrasenas no coinciden.");
      process.exit(1);
    }
  }

  // 1. Cifrar el texto con AES-256
  const { buffer: datosCifrados, claveHex } = cifrarDatos(
    Buffer.from(texto, "utf8"),
    { password, claveHex: opciones.claveHex }
  );

  // 2. Convertir a base64 + separador de fin
  const payload = Buffer.from(datosCifrados.toString("base64") + SEPARADOR, "utf8");
  const bits    = aBits(payload);

  // 3. Leer imagen y verificar capacidad
  const img        = await Jimp.read(imagenEntrada);
  const capacidad  = img.width * img.height * 3;

  if (bits.length > capacidad) {
    console.error(`Error: texto demasiado largo para esta imagen.`);
    console.error(`  Se necesitan : ${bits.length} bits`);
    console.error(`  Disponibles  : ${capacidad} bits`);
    process.exit(1);
  }

  // 4. Incrustar bits en los LSB de los pixeles
  incrustarBits(img, bits, { intToRGBA, rgbaToInt });

  // 5. Guardar imagen
  await img.write(imagenSalida);

  const porcUsado = ((bits.length / capacidad) * 100).toFixed(2);
  console.log(`\nTexto ocultado en imagen`);
  console.log(`------------------------------`);
  console.log(`Imagen original  : ${imagenEntrada}`);
  console.log(`Imagen salida    : ${imagenSalida}`);
  console.log(`Texto            : "${texto}"`);
  console.log(`Capacidad usada  : ${porcUsado}%`);
  console.log(`Algoritmo        : AES-256-GCM + LSB`);

  if (!password) {
    console.log(`\nCLAVE (guardala en un lugar seguro):\n-------------------------------------\n${claveHex}\n-------------------------------------\nNecesitaras esta clave para revelar el mensaje.\n`);
  } else {
    console.log(`Modo: contrasena (PBKDF2 x100,000)\n`);
  }
}

// ─────────────────────────────────────────────
//  COMANDO: revelar texto cifrado de imagen
// ─────────────────────────────────────────────
async function revelarDeImagen(imagenEntrada, opciones = {}) {
  if (!fs.existsSync(imagenEntrada)) {
    console.error(`Error: imagen no encontrada: ${imagenEntrada}`);
    process.exit(1);
  }

  const JimpMod = await cargarJimp();
  const { Jimp, intToRGBA } = JimpMod;

  let password = null;
  if (opciones.password) password = leerPassword("Ingresa contrasena: ");

  // 1. Leer imagen y extraer bits LSB
  const img  = await Jimp.read(imagenEntrada);
  const bits = extraerBits(img, { intToRGBA });

  // 2. Convertir bits a bytes y buscar separador
  const rawBytes = aBuffer(bits);
  const rawStr   = rawBytes.toString("utf8");
  const idxSep   = rawStr.indexOf(SEPARADOR);

  if (idxSep === -1) {
    console.log("\nNo se encontro ningun mensaje oculto en la imagen.\n");
    return;
  }

  const base64Cifrado = rawStr.slice(0, idxSep);

  // 3. Descifrar con AES-256
  let textOriginal;
  try {
    const bufCifrado = Buffer.from(base64Cifrado, "base64");
    const descifrado = descifrarDatos(bufCifrado, { password, claveHex: opciones.claveHex });
    textOriginal     = descifrado.toString("utf8");
  } catch (e) {
    console.error(`Error: ${e.message}`);
    process.exit(1);
  }

  console.log(`\nMensaje encontrado y descifrado`);
  console.log(`------------------------------`);
  console.log(`Imagen   : ${imagenEntrada}`);
  console.log(`Mensaje  : "${textOriginal}"\n`);
}

// ─────────────────────────────────────────────
//  PARSER DE ARGUMENTOS
// ─────────────────────────────────────────────
const args    = process.argv.slice(2);
const comando = args[0];

if (!comando || args.includes("--ayuda") || args.includes("-h")) {
  mostrarAyuda();
  process.exit(0);
}

const archivo = args[1];

// -- ARCHIVOS --
if (comando === "cifrar") {
  if (!archivo) { console.error("Error: falta el archivo."); process.exit(1); }
  cifrarArchivo(archivo, {
    password: args.includes("-p"),
    claveHex: args.includes("-k") ? args[args.indexOf("-k") + 1] : null,
  });

} else if (comando === "descifrar") {
  if (!archivo) { console.error("Error: falta el archivo."); process.exit(1); }
  descifrarArchivo(archivo, {
    password: args.includes("-p"),
    claveHex: args.includes("-k") ? args[args.indexOf("-k") + 1] : null,
  });

} else if (comando === "info") {
  if (!archivo) { console.error("Error: falta el archivo."); process.exit(1); }
  infoArchivo(archivo);

// -- IMAGENES --
} else if (comando === "ocultar") {
  const texto        = args[2];
  const imagenSalida = args[3];
  if (!archivo || !texto || !imagenSalida) {
    console.error("Error: uso -> encripta ocultar <imagen.png> \"<texto>\" <salida.png>");
    process.exit(1);
  }
  ocultarEnImagen(archivo, texto, imagenSalida, {
    password: args.includes("-p"),
    claveHex: args.includes("-k") ? args[args.indexOf("-k") + 1] : null,
  });

} else if (comando === "revelar") {
  if (!archivo) { console.error("Error: falta la imagen."); process.exit(1); }
  revelarDeImagen(archivo, {
    password: args.includes("-p"),
    claveHex: args.includes("-k") ? args[args.indexOf("-k") + 1] : null,
  });

} else {
  console.error(`Error: comando desconocido "${comando}"`);
  mostrarAyuda();
  process.exit(1);
}
