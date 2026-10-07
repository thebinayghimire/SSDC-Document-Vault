import { cp, mkdir } from 'node:fs/promises';

const destination = 'static/vendor/pdfjs';
await mkdir(destination, { recursive: true });
for (const file of ['pdf.mjs', 'pdf.worker.mjs']) {
  await cp(`node_modules/pdfjs-dist/build/${file}`, `${destination}/${file}`);
}
for (const directory of ['cmaps', 'standard_fonts', 'wasm']) {
  await cp(`node_modules/pdfjs-dist/${directory}`, `${destination}/${directory}`, { recursive: true });
}
await cp('node_modules/pdfjs-dist/LICENSE', `${destination}/LICENSE`);
