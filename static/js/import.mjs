const panel = document.querySelector('[data-import]');
const form = panel?.querySelector('[data-import-form]');
if (form) initializeImporter();

function initializeImporter() {
  const find = selector => panel.querySelector(selector);
  const filesInput = find('#import-files');
  const folderInput = find('[data-folder-input]');
  const destination = find('#import-folder');
  const dropzone = find('[data-dropzone]');
  const feedback = find('[data-feedback]');
  const list = find('[data-file-list]');
  const start = find('[data-start]');
  const maxBytes = Number(panel.dataset.maxBytes);
  const maxFiles = 50;
  let queue = [], busy = false, reading = false, nextId = 0;

  filesInput.multiple = true;
  filesInput.required = false;
  filesInput.hidden = true;
  find('#import-title').required = false;
  find('[data-fallback]').hidden = true;
  panel.querySelectorAll('[data-enhanced]').forEach(element => { element.hidden = false; });
  if (!('webkitdirectory' in folderInput)) find('[data-choose-folder]').hidden = true;
  const pasteKey = /Mac|iPhone|iPad/.test(navigator.platform) ? '⌘ + V' : 'Ctrl + V';
  find('[data-paste-key]').textContent = pasteKey;

  function say(message, error = false) {
    feedback.textContent = message;
    feedback.toggleAttribute('data-error', error);
  }
  function size(bytes) {
    return bytes < 1024 * 1024 ? `${Math.ceil(bytes / 1024)} KB` : `${(bytes / 1024 / 1024).toFixed(1)} MB`;
  }
  function element(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }
  function update() {
    find('[data-queue]').hidden = queue.length === 0;
    find('[data-count]').textContent = `(${queue.length})`;
    const pending = queue.filter(item => ['queued', 'failed'].includes(item.state)).length;
    start.disabled = busy || reading || !pending || !destination.value;
    start.textContent = busy ? 'Importing documents…' : `Import ${pending || ''} document${pending === 1 ? '' : 's'}`;
    destination.disabled = busy;
    panel.querySelectorAll('[data-choose-files], [data-choose-folder], [data-paste], [data-clear]').forEach(button => { button.disabled = busy || reading; });
    queue.forEach(item => { item.title.disabled = busy || !['queued', 'failed'].includes(item.state); item.remove.disabled = busy || reading; });
  }
  function state(item, value, message) {
    item.state = value;
    item.row.dataset.state = value;
    item.status.textContent = message;
  }
  function addFiles(files) {
    if (busy) return;
    let added = 0, duplicate = 0, unsupported = 0, oversized = 0, empty = 0, excess = 0;
    for (const file of files) {
      if (!/\.(pdf|jpe?g|png|webp)$/i.test(file.name)) { unsupported++; continue; }
      if (file.size > maxBytes) { oversized++; continue; }
      if (!file.size) { empty++; continue; }
      const path = file.webkitRelativePath || file.name;
      const key = `${path}:${file.size}:${file.lastModified}`;
      if (queue.some(item => item.key === key)) { duplicate++; continue; }
      if (queue.length >= maxFiles) { excess++; continue; }
      const row = element('li', 'import-file-row');
      const mark = element('span', 'import-file-mark', /\.pdf$/i.test(file.name) ? 'PDF' : 'IMG');
      mark.setAttribute('aria-hidden', 'true');
      const details = element('div', 'import-file-details');
      const title = element('input');
      title.id = `queued-title-${++nextId}`;
      title.maxLength = 200;
      title.required = true;
      title.value = file.name.replace(/\.[^.]+$/, '').slice(0, 200);
      const label = element('label', 'sr-only', `Document title for ${file.name}`);
      label.htmlFor = title.id;
      const info = element('small', '', `${path} · ${size(file.size)}`);
      const progress = element('progress');
      progress.max = 100;
      progress.value = 0;
      progress.hidden = true;
      progress.setAttribute('aria-label', `Upload progress for ${file.name}`);
      const status = element('div', 'import-file-status', 'Ready to upload');
      const remove = element('button', 'icon-button import-remove', '×');
      remove.type = 'button';
      remove.setAttribute('aria-label', `Remove ${file.name}`);
      const item = {file, key, row, title, progress, status, remove, state: 'queued'};
      row.dataset.state = 'queued';
      remove.addEventListener('click', () => {
        if (busy || reading) return;
        queue = queue.filter(candidate => candidate !== item);
        row.remove(); update(); say(`${file.name} removed from the queue.`);
        start.disabled ? find('[data-choose-files]').focus() : start.focus();
      });
      details.append(label, title, info, progress, status);
      row.append(mark, details, remove);
      list.append(row); queue.push(item); added++;
    }
    const notes = [];
    if (duplicate) notes.push(`${duplicate} already queued`);
    if (unsupported) notes.push(`${unsupported} unsupported file${unsupported === 1 ? '' : 's'}`);
    if (oversized) notes.push(`${oversized} over the ${size(maxBytes)} limit`);
    if (empty) notes.push(`${empty} empty file${empty === 1 ? '' : 's'}`);
    if (excess) notes.push(`${excess} beyond the 50-file batch limit`);
    say(`${added} file${added === 1 ? '' : 's'} added.${notes.length ? ` Skipped: ${notes.join('; ')}.` : ''}${!destination.value ? ' Choose a destination folder to continue.' : ''}`, !added && notes.length > 0);
    update();
  }

  find('[data-choose-files]').addEventListener('click', () => filesInput.click());
  find('[data-choose-folder]').addEventListener('click', () => folderInput.click());
  for (const input of [filesInput, folderInput]) input.addEventListener('change', () => { addFiles(input.files); input.value = ''; });
  destination.addEventListener('change', update);
  find('[data-clear]').addEventListener('click', () => {
    queue = queue.filter(item => {
      if (['done', 'stored', 'rejected'].includes(item.state)) { item.row.remove(); return false; }
      return true;
    });
    update(); say('Finished files cleared.');
  });

  // Capture directory entries during the drop event; browsers discard access afterward.
  async function readEntries(entries) {
    const files = [];
    let visited = 0;
    async function walk(entry) {
      if (!entry || files.length >= 1000 || ++visited > 2000) return;
      if (entry.isFile) files.push(await new Promise((resolve, reject) => entry.file(resolve, reject)));
      else if (entry.isDirectory) {
        const reader = entry.createReader();
        let children;
        do {
          children = await new Promise((resolve, reject) => reader.readEntries(resolve, reject));
          for (const child of children) await walk(child);
        } while (children.length && visited <= 2000 && files.length < 1000);
      }
    }
    for (const entry of entries) await walk(entry);
    return {files, limited: files.length >= 1000 || visited > 2000};
  }
  let dragDepth = 0;
  const fileDrag = event => [...(event.dataTransfer?.types || [])].includes('Files');
  dropzone.addEventListener('dragenter', event => {
    if (!fileDrag(event)) return;
    event.preventDefault(); dragDepth++;
    if (!busy && !reading) dropzone.classList.add('is-dragging');
  });
  dropzone.addEventListener('dragover', event => {
    if (!fileDrag(event)) return;
    event.preventDefault(); event.dataTransfer.dropEffect = busy || reading ? 'none' : 'copy';
  });
  dropzone.addEventListener('dragleave', event => {
    event.preventDefault();
    if (--dragDepth <= 0) { dragDepth = 0; dropzone.classList.remove('is-dragging'); }
  });
  dropzone.addEventListener('drop', async event => {
    event.preventDefault(); dragDepth = 0; dropzone.classList.remove('is-dragging');
    if (busy || reading) return;
    const files = [...event.dataTransfer.files];
    const entries = [...event.dataTransfer.items].map(item => item.webkitGetAsEntry?.()).filter(Boolean);
    if (!entries.some(entry => entry.isDirectory)) { addFiles(files); return; }
    reading = true; update(); say('Reading your folder…');
    try {
      const result = await readEntries(entries);
      addFiles(result.files);
      if (result.limited) say('This folder is too large to read completely. Review the queued files and import smaller folders next.', true);
    } catch {
      say('Could not read this folder. Try the Import folder button instead.', true);
    } finally { reading = false; update(); }
  });
  // Prevent an accidental file drop outside the target from navigating away.
  for (const name of ['dragover', 'drop']) document.addEventListener(name, event => { if (fileDrag(event)) event.preventDefault(); });
  document.addEventListener('paste', event => {
    if (busy || reading || event.target.closest('input, textarea, [contenteditable="true"]')) return;
    const files = [...(event.clipboardData?.files || [])];
    if (files.length) { event.preventDefault(); addFiles(files); }
    else if (dropzone.contains(event.target)) say(`Your browser did not provide a file. Try Choose files, or copy a file and press ${pasteKey} here.`, true);
  });
  find('[data-paste]').addEventListener('click', async () => {
    dropzone.focus();
    if (!navigator.clipboard?.read) { say(`Press ${pasteKey} here to paste copied files. If your browser does not expose them, use Choose files.`); return; }
    reading = true; update();
    try {
      const items = await navigator.clipboard.read();
      const files = [];
      for (const item of items) {
        const type = item.types.find(value => ['image/png', 'image/jpeg', 'image/webp', 'application/pdf'].includes(value));
        if (!type) continue;
        const blob = await item.getType(type);
        const extension = {'image/png': 'png', 'image/jpeg': 'jpg', 'image/webp': 'webp', 'application/pdf': 'pdf'}[type];
        files.push(new File([blob], `Pasted document ${Date.now()}-${files.length + 1}.${extension}`, {type}));
      }
      if (files.length) addFiles(files);
      else say(`Press ${pasteKey} to paste a copied file. If your browser does not expose the file, use Choose files.`);
    } catch { say(`Press ${pasteKey} here to paste copied files, or use Choose files.`); }
    finally { reading = false; update(); }
  });

  function upload(item, folder) {
    return new Promise(resolve => {
      const xhr = new XMLHttpRequest();
      xhr.open('POST', form.action);
      xhr.setRequestHeader('Accept', 'application/json');
      xhr.timeout = 180000;
      const data = new FormData();
      data.append('csrfmiddlewaretoken', find('[name="csrfmiddlewaretoken"]').value);
      data.append('folder', folder);
      data.append('title', item.title.value.trim());
      data.append('file', item.file);
      item.progress.hidden = false;
      item.progress.value = 0;
      state(item, 'uploading', 'Uploading…');
      xhr.upload.addEventListener('progress', event => {
        if (event.lengthComputable) item.progress.value = Math.round(event.loaded / event.total * 100);
      });
      xhr.upload.addEventListener('load', () => {
        item.progress.removeAttribute('value');
        state(item, 'uploading', 'Uploaded · Checking document…');
      });
      const connectionError = () => {
        state(item, 'failed', 'Connection interrupted. Check Manage documents before retrying; the file may have arrived.');
        item.progress.hidden = true; resolve({stop: true});
      };
      xhr.addEventListener('error', connectionError);
      xhr.addEventListener('timeout', connectionError);
      xhr.addEventListener('load', () => {
        item.progress.hidden = true;
        let response;
        try { response = JSON.parse(xhr.responseText); } catch { response = {}; }
        if (xhr.status === 201 && response.manage_url) {
          const ready = response.status === 'ready';
          const rejected = response.status === 'rejected';
          state(item, ready ? 'done' : rejected ? 'rejected' : 'stored', ready ? 'Added to library' : rejected ? 'Rejected during checking' : 'Saved · Awaiting checks');
          const link = element('a', '', 'View details');
          link.href = response.manage_url;
          item.status.append(link);
          if (response.note) item.status.append(element('small', '', response.note));
          resolve({}); return;
        }
        const errors = Object.values(response.errors || {}).flat().map(error => error.message);
        let message = response.error || errors.join(' ') || 'Upload failed. Try again shortly.';
        if (xhr.status === 429) message = 'Upload limit reached. Wait one minute, then continue.';
        if (xhr.status === 413) message = 'This file exceeds the server upload limit.';
        if (xhr.status === 403 && !response.error) message = 'Your session or upload access changed. Refresh the page and sign in again.';
        if (xhr.status === 200 && !response.manage_url) message = 'Your session expired. Sign in again in a new tab, then continue here.';
        if (response.reauth_url || xhr.status === 200) {
          const link = find('[data-reauth]');
          link.href = response.reauth_url || '/accounts/login/'; link.hidden = false;
        }
        state(item, 'failed', message);
        resolve({stop: [200, 401, 403, 429].includes(xhr.status) || xhr.status >= 500});
      });
      xhr.send(data);
    });
  }
  form.addEventListener('submit', async event => {
    event.preventDefault();
    if (busy || reading || !destination.value) return;
    const pending = queue.filter(item => ['queued', 'failed'].includes(item.state));
    if (!pending.length || !form.reportValidity()) return;
    busy = true; find('[data-reauth]').hidden = true;
    form.setAttribute('aria-busy', 'true'); update();
    // Signing in in a second tab rotates CSRF. Refresh it without losing queued files.
    try {
      const response = await fetch(form.action, {headers: {Accept: 'application/json'}});
      const session = await response.json();
      if (!response.ok || !session.csrf_token) throw new Error('Session unavailable');
      find('[name="csrfmiddlewaretoken"]').value = session.csrf_token;
    } catch {
      busy = false; form.removeAttribute('aria-busy'); update();
      const link = find('[data-reauth]');
      link.href = '/accounts/login/'; link.hidden = false;
      say('Could not verify your session. Check your connection or sign in in a new tab, then continue here.', true);
      return;
    }
    const folder = destination.value;
    for (let index = 0; index < pending.length; index++) {
      say(`Importing ${index + 1} of ${pending.length}: ${pending[index].file.name}`);
      const result = await upload(pending[index], folder);
      if (result.stop) break;
    }
    busy = false; form.removeAttribute('aria-busy'); update();
    const added = queue.filter(item => item.state === 'done').length;
    const checking = queue.filter(item => item.state === 'stored').length;
    const rejected = queue.filter(item => item.state === 'rejected').length;
    const remaining = queue.filter(item => ['queued', 'failed'].includes(item.state)).length;
    say(`${added} added to library. ${checking ? `${checking} awaiting checks. ` : ''}${rejected ? `${rejected} rejected. ` : ''}${remaining ? `${remaining} still need attention. Review the file messages before continuing.` : 'You can add more files or return to your library.'}`, remaining > 0 || rejected > 0);
  });
  window.addEventListener('beforeunload', event => { if (busy || reading) { event.preventDefault(); event.returnValue = ''; } });
  update();
}
