// Descifrado del sitio en el navegador. Lo usan la página de entrada y el service worker.
// Formato (lo genera .tools/cifrar.mjs):
//   c/m.bin      índice: 8 bytes de prefijo del nonce seguidos del JSON cifrado
//   c/<id>.bin   cada fichero del sitio, cifrado
// Todo se cifra con AES-256-GCM en bloques de 1 MiB, para poder servir rangos de un vídeo.
// Bloque i de n: nonce = prefijo (8 bytes) + i (uint32 big-endian), datos adicionales = "<id>:<i>:<n>".
(() => {
  const BLOQUE = 1 << 20;
  const ETIQUETA = 16;
  const CIFRADO = BLOQUE + ETIQUETA;
  // Tras abrir el enlace, el navegador recuerda el acceso durante 24 horas; después hay que volver a abrirlo.
  const DURACION = 24 * 60 * 60 * 1000;
  const utf8 = new TextEncoder();
  const formato = /^[A-Za-z0-9_-]{43}$/;

  function decodificar(base64url) {
    const base64 = base64url.replace(/-/g, "+").replace(/_/g, "/");
    return Uint8Array.from(atob(base64 + "=".repeat((4 - (base64.length % 4)) % 4)), (c) => c.charCodeAt(0));
  }

  async function derivarClave(clave) {
    const maestra = await crypto.subtle.importKey("raw", decodificar(clave), "HKDF", false, ["deriveKey"]);
    return crypto.subtle.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: utf8.encode("web-cifrada/v1/aes") },
      maestra,
      { name: "AES-GCM", length: 256 },
      false,
      ["decrypt"],
    );
  }

  async function descifrarBloque(aes, id, prefijo, i, n, datos) {
    const iv = new Uint8Array(12);
    iv.set(prefijo);
    new DataView(iv.buffer).setUint32(8, i);
    const plano = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv, additionalData: utf8.encode(`${id}:${i}:${n}`) },
      aes,
      datos,
    );
    return new Uint8Array(plano);
  }

  // Un error de descifrado (clave que no corresponde) es un DOMException "OperationError";
  // los fallos de red llegan como TypeError o como Error con el estado HTTP.
  async function cargarIndice(base, aes, { revalidar = false } = {}) {
    const respuesta = await fetch(new URL("c/m.bin", base), { cache: revalidar ? "no-cache" : "default" });
    if (!respuesta.ok) throw new Error(`c/m.bin: ${respuesta.status}`);
    const datos = new Uint8Array(await respuesta.arrayBuffer());
    const prefijo = datos.subarray(0, 8);
    const cuerpo = datos.subarray(8);
    const n = Math.max(1, Math.ceil(cuerpo.length / CIFRADO));
    const partes = [];
    for (let i = 0; i < n; i++)
      partes.push(await descifrarBloque(aes, "m", prefijo, i, n, cuerpo.subarray(i * CIFRADO, (i + 1) * CIFRADO)));
    return JSON.parse(new TextDecoder().decode(await new Blob(partes).arrayBuffer()));
  }

  // Lee del cuerpo de una respuesta exactamente los bytes que se piden.
  function lectorExacto(cuerpo) {
    let resto = new Uint8Array(0);
    async function siguiente() {
      const { value, done } = await cuerpo.read();
      if (done) throw new Error("El fichero cifrado está incompleto.");
      return value;
    }
    return {
      async saltar(n) {
        while (resto.length < n) {
          n -= resto.length;
          resto = await siguiente();
        }
        resto = resto.subarray(n);
      },
      async leer(n) {
        const salida = new Uint8Array(n);
        for (let lleno = 0; lleno < n; ) {
          if (!resto.length) resto = await siguiente();
          const trozo = resto.subarray(0, n - lleno);
          salida.set(trozo, lleno);
          lleno += trozo.length;
          resto = resto.subarray(trozo.length);
        }
        return salida;
      },
    };
  }

  // Bytes [inicio, fin] de un fichero, descifrados bloque a bloque a medida que llegan.
  // entrada = [id, tamaño, tipo, prefijo] tal como aparece en el índice; el fichero no puede estar vacío.
  function flujo(base, aes, [id, tamano, , prefijo], inicio, fin) {
    const nonce = decodificar(prefijo);
    const n = Math.max(1, Math.ceil(tamano / BLOQUE));
    const primero = Math.floor(inicio / BLOQUE);
    const ultimo = Math.floor(fin / BLOQUE);
    const desde = primero * CIFRADO;
    const hasta = Math.min((ultimo + 1) * CIFRADO, tamano + n * ETIQUETA) - 1;
    let cuerpo;
    let lector;
    let i = primero;
    return new ReadableStream({
      async start() {
        const respuesta = await fetch(new URL(`c/${id}.bin`, base), { headers: { Range: `bytes=${desde}-${hasta}` } });
        if (!respuesta.ok) throw new Error(`c/${id}.bin: ${respuesta.status}`);
        cuerpo = respuesta.body.getReader();
        lector = lectorExacto(cuerpo);
        // Si el servidor ignora el rango, llega el fichero entero.
        if (respuesta.status !== 206) await lector.saltar(desde);
      },
      async pull(control) {
        const largo = Math.min(BLOQUE, tamano - i * BLOQUE) + ETIQUETA;
        const plano = await descifrarBloque(aes, id, nonce, i, n, await lector.leer(largo));
        const desdeAqui = i === primero ? inicio - i * BLOQUE : 0;
        const hastaAqui = i === ultimo ? fin - i * BLOQUE + 1 : plano.length;
        control.enqueue(plano.subarray(desdeAqui, hastaAqui));
        if (i++ === ultimo) {
          control.close();
          cuerpo.cancel().catch(() => {});
        }
      },
      cancel() {
        return cuerpo?.cancel();
      },
    });
  }

  async function descifrarTodo(base, aes, entrada) {
    if (!entrada[1]) return new Uint8Array(0);
    return new Uint8Array(await new Response(flujo(base, aes, entrada, 0, entrada[1] - 1)).arrayBuffer());
  }

  // En IndexedDB (que comparten la página de entrada y el service worker) solo se guarda la clave AES
  // derivada, como CryptoKey no exportable, junto con su caducidad: sirve para descifrar en este
  // navegador, pero de ella no se puede sacar la clave del enlace ni sus bytes.
  function almacen(modo, accion) {
    return new Promise((resolver, rechazar) => {
      const apertura = indexedDB.open("web-cifrada", 1);
      apertura.onupgradeneeded = () => apertura.result.createObjectStore("acceso");
      apertura.onerror = () => rechazar(apertura.error);
      apertura.onsuccess = () => {
        const db = apertura.result;
        const transaccion = db.transaction("acceso", modo);
        const peticion = accion(transaccion.objectStore("acceso"));
        transaccion.oncomplete = () => {
          db.close();
          resolver(peticion.result);
        };
        transaccion.onerror = transaccion.onabort = () => {
          db.close();
          rechazar(transaccion.error);
        };
      };
    });
  }

  self.WebCifrada = {
    formato,
    derivarClave,
    cargarIndice,
    flujo,
    descifrarTodo,
    // { estado: "vigente", aes, caduca } | { estado: "caducado" } | { estado: "sin-acceso" }.
    // Leer no borra: así la página de entrada sabe que caducó, lo dice y entonces lo borra.
    async leerAcceso() {
      const guardado = await almacen("readonly", (s) => s.get("acceso"));
      if (!guardado) return { estado: "sin-acceso" };
      if (!(guardado.caduca > Date.now())) return { estado: "caducado" };
      return { estado: "vigente", aes: guardado.aes, caduca: guardado.caduca };
    },
    // "aes" es donde se guardaba antes la clave, sin caducidad: se elimina al guardar o borrar.
    guardarAcceso: (aes) =>
      almacen("readwrite", (s) => {
        s.delete("aes");
        return s.put({ aes, caduca: Date.now() + DURACION }, "acceso");
      }),
    borrarAcceso: () =>
      almacen("readwrite", (s) => {
        s.delete("aes");
        return s.delete("acceso");
      }),
  };
})();
