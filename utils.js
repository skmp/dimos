export const $ = (sel) => document.querySelector(sel);
export const $$ = (sel) => Array.from(document.querySelectorAll(sel));
export const enc = new TextEncoder();
export const dec = new TextDecoder();

export function b64u(buf) {
  const b = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let str = '';
  for (let i = 0; i < b.length; i++) str += String.fromCharCode(b[i]);
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function b64uToBytes(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  const pad = s.length % 4 === 2 ? '==' : s.length % 4 === 3 ? '=' : '';
  const bin = atob(s + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function hex(buf) {
  return [...new Uint8Array(buf)].map(x => x.toString(16).padStart(2, '0')).join('');
}

export async function sha256(bytes) {
  const h = await crypto.subtle.digest('SHA-256', bytes);
  return new Uint8Array(h);
}

export function downloadBlob(name, blob) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

export async function listAll(store) {
  const items = [];
  await store.iterate((value, key) => { items.push({ key, value }); });
  return items;
}

export function drawToCanvas(img, canvas) {
  const ctx = canvas.getContext('2d');
  const maxW = 1600, maxH = 1600;
  let w = img.naturalWidth || img.videoWidth || img.width;
  let h = img.naturalHeight || img.videoHeight || img.height;
  const scale = Math.min(1, maxW / w, maxH / h);
  w = Math.max(1, Math.round(w * scale));
  h = Math.max(1, Math.round(h * scale));
  canvas.width = w;
  canvas.height = h;
  ctx.drawImage(img, 0, 0, w, h);
}

function placeRect(w, h, percent, corner) {
  const s = Math.round(Math.min(w, h) * (percent / 100));
  const pad = Math.round(s * 0.08);
  const size = s;
  let x = 0, y = 0;
  if (corner === 'TR') { x = w - size - pad; y = pad; }
  if (corner === 'TL') { x = pad; y = pad; }
  if (corner === 'BR') { x = w - size - pad; y = h - size - pad; }
  if (corner === 'BL') { x = pad; y = h - size - pad; }
  return { x, y, size };
}

export async function canvasToPngBytes(canvas) {
  const url = canvas.toDataURL('image/png');
  const bin = atob(url.split(',')[1]);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

export async function computeHashWithBlackSquare(imgCanvas, corner, percent) {
  const c = document.createElement('canvas');
  c.width = imgCanvas.width;
  c.height = imgCanvas.height;
  const ctx = c.getContext('2d');
  ctx.drawImage(imgCanvas, 0, 0);
  const r = placeRect(c.width, c.height, percent, corner);
  ctx.fillStyle = '#000';
  ctx.fillRect(r.x, r.y, r.size, r.size);
  const bytes = await canvasToPngBytes(c);
  return { hash: await sha256(bytes), bytes, rect: r };
}

export async function drawQR(canvas, text, rect) {
  const temp = document.createElement('canvas');
  temp.width = rect.size;
  temp.height = rect.size;
  await QRCode.toCanvas(temp, text, { errorCorrectionLevel: 'M', margin: 1, width: rect.size });
  const ctx = canvas.getContext('2d');
  ctx.drawImage(temp, rect.x, rect.y);
}
