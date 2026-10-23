// Service worker del sitio cifrado: cada fichero que pide una página se descarga cifrado de c/
// y se descifra aquí, así las demos funcionan sin saber nada del cifrado.
importScripts("cripto.js?v=b9cf85f19d");

const { leerAcceso, cargarIndice, flujo, descifrarTodo } = self.WebCifrada;
const base = self.registration.scope;
const raiz = new URL(base).pathname;
// Ficheros en claro de la propia capa de cifrado: los sirve el servidor tal cual.
const propios = new Set(["sw.js", "cripto.js", "entrada.js", "robots.txt"]);

// Se inyecta al principio de cada página descifrada: quita la clave de la barra de direcciones
// si se abrió (o se pegó) un enlace con #k=…. Las páginas no tienen ningún acceso a la clave.
const acceso =
  `<script>(() => { const quitar = () => { if (/^#k=/.test(location.hash)) history.replaceState(history.state, "", location.pathname + location.search); }; quitar(); addEventListener("hashchange", quitar); })();</script>`;

self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (evento) => evento.waitUntil(self.clients.claim()));

async function abrir(revalidar) {
  const { estado, aes, caduca } = await leerAcceso();
  if (estado !== "vigente") return null;
  return { aes, caduca, indice: await cargarIndice(base, aes, { revalidar }) };
}

// Cada navegación vuelve a leer el acceso y revalida el índice, por si se ha publicado una versión nueva.
// Un fallo no se recuerda: la siguiente petición lo vuelve a intentar.
let sitio = null;
function sitioActual(navegacion) {
  if (navegacion || !sitio) {
    const intento = abrir(navegacion).catch(() => null);
    sitio = intento;
    intento.then((abierto) => {
      if (!abierto && sitio === intento) sitio = null;
    });
  }
  return sitio;
}

self.addEventListener("fetch", (evento) => {
  const peticion = evento.request;
  if (peticion.method !== "GET" || !peticion.url.startsWith(base)) return;
  const url = new URL(peticion.url);
  let ruta;
  try {
    ruta = decodeURIComponent(url.pathname.slice(raiz.length));
  } catch {
    return;
  }
  if (propios.has(ruta) || ruta.startsWith("c/")) return;
  evento.respondWith(responder(peticion, url, ruta));
});

async function responder(peticion, url, ruta) {
  const navegacion = peticion.mode === "navigate";
  const abierto = await sitioActual(navegacion);
  // Sin acceso vigente, el servidor devuelve la página de entrada, que pide el enlace.
  // La caducidad se comprueba en cada petición, también con una página que lleva tiempo abierta.
  if (!abierto || abierto.caduca <= Date.now()) {
    sitio = null;
    return fetch(peticion);
  }
  const { archivos } = abierto.indice;
  const entrada = archivos[ruta === "" || ruta.endsWith("/") ? `${ruta}index.html` : ruta];
  if (!entrada) {
    if (archivos[`${ruta}/index.html`]) return Response.redirect(new URL(`${url.pathname}/${url.search}`, url).href, 301);
    return noEncontrado(navegacion);
  }
  try {
    return await servir(peticion, abierto.aes, entrada);
  } catch {
    return new Response("No se ha podido descifrar este fichero.", { status: 500 });
  }
}

async function servir(peticion, aes, entrada) {
  const [, tamano, tipo] = entrada;
  const cabeceras = { "Content-Type": tipo, "Accept-Ranges": "bytes", "X-Content-Type-Options": "nosniff" };
  if (tipo.startsWith("text/html")) {
    const html = new TextDecoder().decode(await descifrarTodo(base, aes, entrada));
    return new Response(conAcceso(html), { headers: cabeceras });
  }
  const rango = leerRango(peticion.headers.get("Range"), tamano);
  if (rango === false) return new Response(null, { status: 416, headers: { "Content-Range": `bytes */${tamano}` } });
  if (!tamano) return new Response(null, { headers: { ...cabeceras, "Content-Length": "0" } });
  const [inicio, fin] = rango ?? [0, tamano - 1];
  const cuerpo = flujo(base, aes, entrada, inicio, fin);
  if (!rango) return new Response(cuerpo, { headers: { ...cabeceras, "Content-Length": String(tamano) } });
  return new Response(cuerpo, {
    status: 206,
    headers: { ...cabeceras, "Content-Length": String(fin - inicio + 1), "Content-Range": `bytes ${inicio}-${fin}/${tamano}` },
  });
}

// null: sin rango (se sirve entero); false: rango imposible (416).
function leerRango(cabecera, tamano) {
  const partes = /^bytes=(\d*)-(\d*)$/.exec(cabecera ?? "");
  if (!partes || (!partes[1] && !partes[2])) return null;
  const inicio = partes[1] ? Number(partes[1]) : Math.max(0, tamano - Number(partes[2]));
  const fin = partes[1] && partes[2] ? Math.min(Number(partes[2]), tamano - 1) : tamano - 1;
  return inicio > fin ? false : [inicio, fin];
}

// El script va dentro de <head> para no sacar la página del modo estándar.
function conAcceso(html) {
  for (const etiqueta of [/<head(\s[^>]*)?>/i, /<html(\s[^>]*)?>/i, /<!doctype[^>]*>/i]) {
    const encontrada = etiqueta.exec(html);
    if (encontrada) {
      const fin = encontrada.index + encontrada[0].length;
      return html.slice(0, fin) + acceso + html.slice(fin);
    }
  }
  return acceso + html;
}

function noEncontrado(navegacion) {
  if (!navegacion) return new Response(null, { status: 404 });
  const pagina = `<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Página no encontrada</title><style>body{margin:0;min-height:100vh;display:grid;place-items:center;padding:24px;box-sizing:border-box;background:#161a4b;color:#eef0fb;font:500 1rem/1.6 system-ui,sans-serif}a{color:#3fd6c6}</style></head><body><main><h1>Página no encontrada</h1><p><a href="${raiz}">Volver al inicio</a></p></main></body></html>`;
  return new Response(pagina, { status: 404, headers: { "Content-Type": "text/html; charset=utf-8" } });
}
