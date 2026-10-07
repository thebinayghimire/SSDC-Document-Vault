import * as pdfjs from '../vendor/pdfjs/pdf.mjs';

pdfjs.GlobalWorkerOptions.workerSrc = new URL('../vendor/pdfjs/pdf.worker.mjs', import.meta.url).href;
const viewer = document.querySelector('#viewer');
const stage = document.querySelector('#preview-stage');
const surface = document.querySelector('#page-surface');
const canvas = document.querySelector('#pdf-canvas');
const image = document.querySelector('#image-preview');
const message = document.querySelector('#viewer-message');
const number = document.querySelector('#page-number');
let documentPdf, current = 1, scale = 1, task, busy = false, pending = false;
const isPdf = viewer.dataset.kind === 'application/pdf';

function error() { message.textContent = 'Preview unavailable. Your session may have expired. Return to the library and try again.'; message.hidden = false; }
function updateControls() {
  number.value = current;
  document.querySelector('#zoom-label').textContent = `${Math.round(scale * 100)}%`;
  document.querySelector('#previous').disabled = current <= 1;
  document.querySelector('#next').disabled = !documentPdf || current >= documentPdf.numPages;
}
async function render() {
  updateControls();
  if (!isPdf) {
    const width = Math.round(image.naturalWidth * scale);
    const height = Math.round(image.naturalHeight * scale);
    surface.style.width = `${width}px`; surface.style.height = `${height}px`;
    image.style.width = `${width}px`; image.style.height = `${height}px`;
    return;
  }
  if (busy) { pending = true; if (task) task.cancel(); return; }
  busy = true;
  try {
    const page = await documentPdf.getPage(current);
    const viewport = page.getViewport({ scale });
    const ratio = Math.min(window.devicePixelRatio || 1, 2);
    const cap = Math.min(1, Math.sqrt(16000000 / (viewport.width * viewport.height * ratio * ratio)));
    const pixelRatio = ratio * cap;
    canvas.width = Math.ceil(viewport.width * pixelRatio); canvas.height = Math.ceil(viewport.height * pixelRatio);
    surface.style.width = `${viewport.width}px`; surface.style.height = `${viewport.height}px`;
    canvas.style.width = `${viewport.width}px`; canvas.style.height = `${viewport.height}px`;
    task = page.render({ canvasContext: canvas.getContext('2d'), viewport, transform: [pixelRatio, 0, 0, pixelRatio, 0, 0] });
    await task.promise;
    message.hidden = true;
    canvas.dataset.rendered = 'true';
  } catch (exception) {
    if (exception.name !== 'RenderingCancelledException') error();
  } finally {
    busy = false; task = null;
    if (pending) { pending = false; render(); }
  }
}
async function fit() {
  const width = isPdf ? (await documentPdf.getPage(current)).getViewport({ scale: 1 }).width : image.naturalWidth;
  scale = Math.min(3, Math.max(0.1, (stage.clientWidth - 64) / width));
  await render();
}
try {
  if (isPdf) {
    documentPdf = await pdfjs.getDocument({
      url: viewer.dataset.url, withCredentials: true, isEvalSupported: false,
      cMapUrl: new URL('../vendor/pdfjs/cmaps/', import.meta.url).href, cMapPacked: true,
      standardFontDataUrl: new URL('../vendor/pdfjs/standard_fonts/', import.meta.url).href,
      wasmUrl: new URL('../vendor/pdfjs/wasm/', import.meta.url).href,
      maxImageSize: 20000000, disableAutoFetch: true,
    }).promise;
    document.querySelector('#page-count').textContent = documentPdf.numPages;
    number.max = documentPdf.numPages;
    await fit();
  } else {
    canvas.hidden = true; image.hidden = false;
    image.src = viewer.dataset.url;
    await image.decode(); message.hidden = true; await fit();
  }
} catch { error(); }
document.querySelector('#previous').addEventListener('click', () => { if (current > 1) { current--; render(); } });
document.querySelector('#next').addEventListener('click', () => { if (documentPdf && current < documentPdf.numPages) { current++; render(); } });
number.addEventListener('change', () => { if (documentPdf) { current = Math.max(1, Math.min(documentPdf.numPages, Number(number.value) || 1)); render(); } });
document.querySelector('#zoom-in').addEventListener('click', () => { scale = Math.min(3, scale + 0.15); render(); });
document.querySelector('#zoom-out').addEventListener('click', () => { scale = Math.max(0.1, scale - 0.15); render(); });
document.querySelector('#fit').addEventListener('click', fit);
viewer.addEventListener('contextmenu', event => event.preventDefault());
viewer.addEventListener('dragstart', event => event.preventDefault());
viewer.addEventListener('copy', event => event.preventDefault());
document.addEventListener('keydown', event => {
  if (event.target.matches('input, textarea, select')) return;
  if (event.key === 'ArrowLeft') document.querySelector('#previous').click();
  if (event.key === 'ArrowRight') document.querySelector('#next').click();
});
