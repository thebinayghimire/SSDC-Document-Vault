import * as pdfjs from '../vendor/pdfjs/pdf.mjs';

pdfjs.GlobalWorkerOptions.workerSrc = new URL('../vendor/pdfjs/pdf.worker.mjs', import.meta.url).href;
const viewer = document.querySelector('#viewer');
const stage = document.querySelector('#preview-stage');
const surface = document.querySelector('#page-surface');
const canvas = document.querySelector('#pdf-canvas');
const image = document.querySelector('#image-preview');
const message = document.querySelector('#viewer-message');
const number = document.querySelector('#page-number');
const skeleton = document.querySelector('#preview-skeleton');
const pageText = document.createElement('div');
pageText.className = 'sr-only';
pageText.setAttribute('role', 'document');
viewer.append(pageText);
let documentPdf, current = 1, scale = 0.89, task, busy = false, pending = false;
let ready = false, fitMode = false;
const isPdf = viewer.dataset.kind === 'application/pdf';

function error() {
  ready = false;
  pending = false;
  if (task) task.cancel();
  delete canvas.dataset.rendered;
  canvas.width = 0;
  pageText.textContent = '';
  surface.hidden = true;
  updateControls();
  message.textContent = 'Preview unavailable. Your session may have expired. ';
  const link = document.createElement('a');
  link.href = '/';
  link.textContent = 'Return to the library and try again.';
  message.append(link);
  message.dataset.error = 'true';
  message.hidden = false;
  skeleton.hidden = true;
  viewer.setAttribute('aria-busy', 'false');
}
function reveal() {
  message.hidden = true;
  delete message.dataset.error;
  skeleton.hidden = true;
  surface.hidden = false;
  viewer.setAttribute('aria-busy', 'false');
}
function updateControls() {
  number.value = current;
  document.querySelector('#zoom-label').textContent = `${Math.round(scale * 100)}%`;
  document.querySelector('#previous').disabled = !ready || current <= 1;
  document.querySelector('#next').disabled = !ready || !documentPdf || current >= documentPdf.numPages;
  document.querySelector('#zoom-out').disabled = !ready || scale <= 0.1;
  document.querySelector('#zoom-in').disabled = !ready || scale >= 3;
  document.querySelector('#fit').disabled = !ready;
  number.disabled = !ready;
}
async function render() {
  if (!ready) return;
  delete canvas.dataset.rendered;
  pageText.textContent = '';
  updateControls();
  if (!isPdf) {
    const width = Math.round(image.naturalWidth * scale);
    const height = Math.round(image.naturalHeight * scale);
    surface.style.width = `${width}px`; surface.style.height = `${height}px`;
    image.style.width = `${width}px`; image.style.height = `${height}px`;
    reveal();
    return;
  }
  if (busy) { pending = true; if (task) task.cancel(); return; }
  busy = true;
  const requestedPage = current, requestedScale = scale;
  viewer.setAttribute('aria-busy', 'true');
  try {
    const page = await documentPdf.getPage(requestedPage);
    const viewport = page.getViewport({ scale: requestedScale });
    const ratio = Math.min(window.devicePixelRatio || 1, 2);
    const cap = Math.min(1, Math.sqrt(16000000 / (viewport.width * viewport.height * ratio * ratio)));
    const pixelRatio = ratio * cap;
    canvas.width = Math.ceil(viewport.width * pixelRatio); canvas.height = Math.ceil(viewport.height * pixelRatio);
    surface.style.width = `${viewport.width}px`; surface.style.height = `${viewport.height}px`;
    canvas.style.width = `${viewport.width}px`; canvas.style.height = `${viewport.height}px`;
    task = page.render({ canvasContext: canvas.getContext('2d'), viewport, transform: [pixelRatio, 0, 0, pixelRatio, 0, 0] });
    await task.promise;
    if (!ready) return;
    if (requestedPage !== current || requestedScale !== scale) { pending = true; return; }
    reveal();
    canvas.setAttribute('aria-label', `Document page ${current} of ${documentPdf.numPages}`);
    const text = await page.getTextContent();
    if (!ready) return;
    if (requestedPage !== current || requestedScale !== scale) { pending = true; return; }
    pageText.setAttribute('aria-label', `Page ${requestedPage} text`);
    pageText.textContent = text.items.map(item => item.str).join(' ') || 'This page has no extractable text. Contact your document administrator for an accessible copy.';
    canvas.dataset.rendered = 'true';
    canvas.dataset.page = String(requestedPage);
  } catch (exception) {
    if (exception.name !== 'RenderingCancelledException') error();
  } finally {
    busy = false; task = null;
    if (pending && ready) { pending = false; render().catch(error); }
  }
}
async function fit() {
  if (!ready) return;
  const width = isPdf ? (await documentPdf.getPage(current)).getViewport({ scale: 1 }).width : image.naturalWidth;
  const style = getComputedStyle(stage);
  const padding = parseFloat(style.paddingLeft) + parseFloat(style.paddingRight);
  scale = Math.min(3, Math.max(0.1, (stage.clientWidth - padding) / width));
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
    ready = true;
    await render();
  } else {
    canvas.hidden = true; image.hidden = false;
    image.src = viewer.dataset.url;
    await image.decode(); ready = true; await render();
  }
} catch { error(); }
document.querySelector('#previous').addEventListener('click', () => { if (ready && current > 1) { current--; render().catch(error); } });
document.querySelector('#next').addEventListener('click', () => { if (ready && documentPdf && current < documentPdf.numPages) { current++; render().catch(error); } });
number.addEventListener('change', () => { if (ready && documentPdf) { current = Math.max(1, Math.min(documentPdf.numPages, Math.trunc(Number(number.value)) || 1)); render().catch(error); } });
document.querySelector('#zoom-in').addEventListener('click', () => { if (!ready) return; fitMode = false; scale = Math.min(3, scale + 0.15); render().catch(error); });
document.querySelector('#zoom-out').addEventListener('click', () => { if (!ready) return; fitMode = false; scale = Math.max(0.1, scale - 0.15); render().catch(error); });
document.querySelector('#fit').addEventListener('click', () => { fitMode = true; fit().catch(error); });
let stageWidth = stage.clientWidth;
new ResizeObserver(() => {
  if (stage.clientWidth === stageWidth) return;
  stageWidth = stage.clientWidth;
  if (ready && fitMode) fit().catch(error);
}).observe(stage);
viewer.addEventListener('contextmenu', event => event.preventDefault());
viewer.addEventListener('dragstart', event => event.preventDefault());
viewer.addEventListener('copy', event => event.preventDefault());
document.addEventListener('keydown', event => {
  if (!isPdf || !ready || event.target.matches('input, textarea, select') || document.querySelector('dialog[open]')) return;
  if (!viewer.contains(event.target) && event.target !== document.body) return;
  if (event.key === 'ArrowLeft') { event.preventDefault(); document.querySelector('#previous').click(); }
  if (event.key === 'ArrowRight') { event.preventDefault(); document.querySelector('#next').click(); }
});
