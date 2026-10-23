// Página de entrada: lee la clave del enlace (#k=…), la quita de la barra de direcciones,
// comprueba que abre el índice cifrado, guarda la clave AES derivada (no exportable) durante 24 horas,
// instala el service worker y recarga: a partir de ahí, el service worker sirve el sitio descifrado.
// La clave del enlace no se guarda en ningún sitio.
(async () => {
  const { formato, derivarClave, cargarIndice, leerAcceso, guardarAcceso, borrarAcceso } = self.WebCifrada;
  const base = new URL("/", location.origin);

  function mostrar(estado) {
    for (const seccion of document.querySelectorAll("[data-estado]")) seccion.hidden = seccion.dataset.estado !== estado;
  }
  // Pegar el enlace en esta misma pestaña solo cambia el #: se vuelve a empezar con la clave nueva.
  addEventListener("hashchange", () => {
    if (/^#k=/.test(location.hash)) location.reload();
  });

  const delEnlace = /^#k=([^&]*)/.exec(location.hash)?.[1];
  if (delEnlace !== undefined) history.replaceState(null, "", location.pathname + location.search);
  if (!("serviceWorker" in navigator) || !self.crypto?.subtle || !self.indexedDB) return mostrar("sin-soporte");

  let aes;
  try {
    if (delEnlace !== undefined) {
      if (!formato.test(delEnlace)) return mostrar("no-valida");
      aes = await derivarClave(delEnlace);
    } else {
      const acceso = await leerAcceso();
      if (acceso.estado === "caducado") {
        await borrarAcceso().catch(() => {});
        return mostrar("caducado");
      }
      if (acceso.estado !== "vigente") return mostrar("sin-clave");
      aes = acceso.aes;
    }
  } catch {
    return mostrar("sin-soporte");
  }

  try {
    await cargarIndice(base, aes, { revalidar: true });
  } catch (error) {
    if (error?.name !== "OperationError") return mostrar("error");
    if (delEnlace !== undefined) return mostrar("no-valida");
    await borrarAcceso().catch(() => {});
    return mostrar("cambiada");
  }

  try {
    await guardarAcceso(aes);
    await navigator.serviceWorker.register("/sw.js", { scope: "/" });
    await navigator.serviceWorker.ready;
    if (!navigator.serviceWorker.controller)
      await new Promise((listo) => {
        navigator.serviceWorker.addEventListener("controllerchange", listo, { once: true });
        setTimeout(listo, 3000);
      });
  } catch {
    return mostrar("sin-soporte");
  }

  // Si después de recargar se vuelve a esta página, el service worker no puede servir el sitio:
  // se avisa en vez de recargar en bucle.
  try {
    if (Date.now() - Number(sessionStorage.getItem("web-cifrada-recarga")) < 15000) return mostrar("error");
    sessionStorage.setItem("web-cifrada-recarga", String(Date.now()));
  } catch {}
  location.reload();
})();
