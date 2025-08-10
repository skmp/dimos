import {
  $, $$, enc, b64u, b64uToBytes, downloadBlob, listAll,
  drawToCanvas, computeHashWithBlackSquare, canvasToPngBytes, drawQR
} from './utils.js';

// ---------- Storage (IndexedDB via localForage) ----------
const db = {
  ids: localforage.createInstance({ name: 'photo-signer', storeName: 'identities' }),
  contacts: localforage.createInstance({ name: 'photo-signer', storeName: 'contacts' }),
  captures: localforage.createInstance({ name: 'photo-signer', storeName: 'captures' }),
};

// ---------- Crypto: WebCrypto only ----------
async function importPubKey(rawOrJwk) {
  if (typeof rawOrJwk === 'string') {
    try { rawOrJwk = JSON.parse(rawOrJwk); } catch {}
  }
  if (rawOrJwk.kty === 'OKP' && rawOrJwk.crv === 'Ed25519' && rawOrJwk.x) {
    const raw = b64uToBytes(rawOrJwk.x);
    return await crypto.subtle.importKey('raw', raw, { name: 'Ed25519' }, true, ['verify']);
  }
  const raw = typeof rawOrJwk === 'string' ? b64uToBytes(rawOrJwk) : new Uint8Array(rawOrJwk);
  return await crypto.subtle.importKey('raw', raw, { name: 'Ed25519' }, true, ['verify']);
}

async function genKey() {
  const key = await crypto.subtle.generateKey(
    { name: 'Ed25519', namedCurve: 'Ed25519' },
    false,
    ['sign', 'verify']
  );
  const pubRaw = new Uint8Array(await crypto.subtle.exportKey('raw', key.publicKey));
  const pubJwk = await crypto.subtle.exportKey('jwk', key.publicKey);
  return { algo: 'Ed25519', key, pubRaw, pubJwk };
}

async function signBytes(idRec, bytes) {
  const sig = await crypto.subtle.sign({ name: 'Ed25519' }, idRec.key.privateKey, bytes);
  return new Uint8Array(sig);
}

async function verifySig(pubKey, bytes, sig) {
  return await crypto.subtle.verify({ name: 'Ed25519' }, pubKey, sig, bytes);
}

// ---------- UI Tabs ----------
const tabs = $$('.tab');
$$('nav button').forEach(btn => btn.addEventListener('click', () => {
  switchTab(btn.dataset.tab);
  if (window.innerWidth <= 700) document.body.classList.remove('nav-open');
}));
$('#menu-btn').addEventListener('click', () => {
  document.body.classList.toggle('nav-open');
});
function switchTab(id) {
  document.querySelector('nav button.active')?.classList.remove('active');
  $(`nav button[data-tab="${id}"]`).classList.add('active');
  tabs.forEach(t => t.style.display = (t.id === id ? '' : 'none'));
}

// ---------- Identity management ----------
async function refreshIdentities() {
  const list = await listAll(db.ids);
  const cont = $('#identity-list'); cont.innerHTML = '';
  const sel = $('#sign-identity'); sel.innerHTML = '';
  list.forEach(({key, value}) => {
    const div = document.createElement('div');
    div.className='card';
    div.innerHTML = `
        <div><strong>${value.name}</strong> <span class="pill">${value.algo}</span></div>
        <div class="mono muted">pk: ${b64u(value.pubRaw)}</div>
        <div style="margin-top:6px" class="row">
          <button class="btn" data-share="${key}">Share</button>
          <button class="btn warn" data-del="${key}">Delete</button>
        </div>
      `;
    cont.appendChild(div);
    const opt = document.createElement('option');
    opt.value = key; opt.textContent = `${value.name} (${value.algo})`;
    sel.appendChild(opt);
  });
  if (!list.length) {
    $('#identity-list').innerHTML = '<div class="muted">No identities yet.</div>';
  }
}

$('#btn-create-id').addEventListener('click', async () => {
  const name = $('#id-name').value.trim() || 'Unnamed';
  const k = await genKey();
  const rec = { name, algo: 'Ed25519', ...k };
  const id = crypto.randomUUID();
  await db.ids.setItem(id, rec);
  await refreshIdentities();
  alert('Identity created');
});

$('#identity-list').addEventListener('click', async (e) => {
  const t = e.target;
  if (t.dataset.share) {
    const id = t.dataset.share; const rec = await db.ids.getItem(id);
    const payload = { displayName: rec.name, algo: rec.algo, publicJwk: rec.pubJwk };
    await QRCode.toCanvas($('#share-qr'), JSON.stringify(payload), { errorCorrectionLevel: 'M', margin: 1, width: 256 });
    $('#share-name').textContent = rec.name;
    $('#share-modal').style.display = 'flex';
  } else if (t.dataset.del) {
    if (!confirm('Delete identity?')) return;
    await db.ids.removeItem(t.dataset.del);
    await refreshIdentities();
  }
});

$('#share-close').addEventListener('click', () => {
  $('#share-modal').style.display = 'none';
});

// ---------- Contacts ----------
async function refreshContacts() {
  const list = await listAll(db.contacts);
  const cont = $('#contact-list'); cont.innerHTML='';
  list.forEach(({key, value}) => {
    const div = document.createElement('div');
    div.className='card';
    div.innerHTML = `
        <div><strong>${value.displayName}</strong> <span class="pill">${value.algo}</span></div>
        <div class="mono muted">pk: ${typeof value.publicJwk === 'string' ? value.publicJwk : (value.publicJwk.x || JSON.stringify(value.publicJwk))}</div>
        <div style="margin-top:6px" class="row">
          <button class="btn warn" data-del="${key}">Delete</button>
        </div>
      `;
    cont.appendChild(div);
  });
  if (!list.length) cont.innerHTML = '<div class="muted">No contacts yet.</div>';
}

$('#btn-add-contact').addEventListener('click', async () => {
  const displayName = $('#contact-name').value.trim();
  let publicJwk = $('#contact-pub').value.trim();
  try { publicJwk = JSON.parse(publicJwk); } catch {}
  const id = crypto.randomUUID();
  await db.contacts.setItem(id, { displayName, algo: 'Ed25519', publicJwk });
  await refreshContacts();
  alert('Contact saved');
});

$('#contact-list').addEventListener('click', async (e) => {
  const t = e.target;
  if (t.dataset.del) { await db.contacts.removeItem(t.dataset.del); await refreshContacts(); }
});

// QR scanning for contacts (expects JSON {displayName, algo, publicJwk|raw})
let scanTimer; let stream;
$('#btn-start-scan').addEventListener('click', async () => {
  if (scanTimer) { clearInterval(scanTimer); scanTimer = null; }
  if (stream) { stream.getTracks().forEach(t => t.stop()); }
  const video = $('#qr-video');
  stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode:'environment' } });
  video.srcObject = stream; await video.play();
  $('#scan-status').textContent = 'Scanning...';
  const canvas = document.createElement('canvas'); const ctx = canvas.getContext('2d');
  scanTimer = setInterval(async () => {
    canvas.width = video.videoWidth; canvas.height = video.videoHeight;
    ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
    const img = ctx.getImageData(0,0,canvas.width, canvas.height);
    const code = jsQR(img.data, img.width, img.height);
    if (code) {
      try {
        const obj = JSON.parse(code.data);
        const id = crypto.randomUUID();
        await db.contacts.setItem(id, obj);
        await refreshContacts();
        $('#scan-status').textContent = 'Contact added';
        clearInterval(scanTimer); scanTimer=null; if (stream) stream.getTracks().forEach(t=>t.stop());
      } catch { $('#scan-status').textContent = 'Invalid QR'; }
    }
  }, 300);
});

// ---------- Capture/Sign flow ----------
let currentCanvas = $('#canvas');
let currentImageBytes = null;

$('#file-input').addEventListener('change', async (e) => {
  const f = e.target.files[0]; if (!f) return;
  const img = new Image(); img.onload = () => { drawToCanvas(img, currentCanvas); }; img.src = URL.createObjectURL(f);
});

let camStream;
$('#btn-open-camera').addEventListener('click', async () => {
  try {
    camStream = await navigator.mediaDevices.getUserMedia({ video: { facingMode:'environment' }, audio:false });
    const v = $('#cam'); v.srcObject = camStream; await v.play();
    $('#capture-status').textContent = 'Camera ready';
  } catch (e) { $('#capture-status').textContent = 'Camera error: ' + e.message; }
});

$('#btn-capture').addEventListener('click', async () => {
  if (!camStream) return;
  const v = $('#cam');
  drawToCanvas(v, currentCanvas);
  $('#capture-status').textContent = 'Captured';
});

$('#btn-sign').addEventListener('click', async () => {
  const id = $('#sign-identity').value; if (!id) return alert('Select identity');
  const rec = await db.ids.getItem(id); if (!rec) return alert('Invalid identity');
  const corner = $('#qr-corner').value;
  let percent = parseInt($('#qr-size').value, 10);
  try {
    const shortSide = Math.min(currentCanvas.width, currentCanvas.height);
    let payload, sig, token, hash, rect;
    while (true) {
      ({ hash, rect } = await computeHashWithBlackSquare(currentCanvas, corner, percent));
      payload = {
        version:1,
        algo:rec.algo,
        imageHash: b64u(hash),
        signerPub: b64u(rec.pubRaw),
        timestamp: new Date().toISOString(),
        corner,
        percent,
        optional: { note: $('#sign-note').value || undefined }
      };
      const payloadBytes = enc.encode(JSON.stringify(payload));
      sig = await signBytes(rec, payloadBytes);
      token = JSON.stringify({ v:1, alg:payload.algo, pk:payload.signerPub, ts:payload.timestamp, ih:payload.imageHash, c:payload.corner, p:payload.percent, n:payload.optional.note, sig:b64u(sig) });
      const qrObj = QRCode.create(token, { errorCorrectionLevel: 'M' });
      const minSize = qrObj.modules.size * 3;
      if (rect.size >= minSize) break;
      percent = Math.ceil((minSize / shortSide) * 100);
    }
    await drawQR(currentCanvas, token, rect);

    const ok = await verifyFromCanvas(currentCanvas);
    $('#payload-view').textContent = JSON.stringify(payload, null, 2) + "\n\nSignature (b64u):\n" + b64u(sig);
    $('#self-verify').textContent = JSON.stringify(ok, null, 2);
    alert('Signed and QR embedded');
  } catch (e) { alert('Sign failed: ' + e.message); }
});

$('#btn-download').addEventListener('click', async () => {
  const bytes = await canvasToPngBytes(currentCanvas);
  downloadBlob('signed.png', new Blob([bytes], { type:'image/png' }));
});

// ---------- Verification ----------
async function verifyFromCanvas(canvas) {
  const ctx = canvas.getContext('2d');
  const img = ctx.getImageData(0,0,canvas.width, canvas.height);
  const code = jsQR(img.data, img.width, img.height);
  if (!code) return { verified:false, reason:'No QR found' };
  let token; try { token = JSON.parse(code.data); } catch { return { verified:false, reason:'QR not JSON' }; }
  const { v, alg, pk, ts, ih, c, p, n, sig } = token;
  if (alg !== 'Ed25519') return { verified:false, reason:'Unsupported algorithm', details:{ alg } };
  const { hash } = await computeHashWithBlackSquare(canvas, c, p);
  const hashB64 = b64u(hash);
  const payload = { version:1, algo:alg, imageHash:hashB64, signerPub:pk, timestamp:ts, corner:c, percent:p, optional:{ note:n } };
  const payloadBytes = enc.encode(JSON.stringify(payload));
  let pub;
  try { pub = await importPubKey({ kty:'OKP', crv:'Ed25519', x: pk }); }
  catch { pub = await importPubKey(pk); }
  const ok = await verifySig(pub, payloadBytes, b64uToBytes(sig));
  return {
    verified: ok && (hashB64 === ih),
    reason: ok ? (hashB64===ih? 'OK':'Hash mismatch') : 'Bad signature',
    details: { alg, publicKey: pk, timestamp: ts, note:n, imageHashComputed: hashB64, imageHashQR: ih }
  };
}

async function drawBytesToCanvas(bytes, canvas) {
  return new Promise((resolve,reject)=>{
    const blob = new Blob([bytes], { type:'image/png' });
    const url = URL.createObjectURL(blob);
    const img = new Image(); img.onload = () => { drawToCanvas(img, canvas); URL.revokeObjectURL(url); resolve(); };
    img.onerror = (e)=>{ URL.revokeObjectURL(url); reject(e); };
    img.src = url;
  });
}

$('#verify-file').addEventListener('change', async (e) => {
  const f = e.target.files[0]; if (!f) return;
  const img = new Image(); img.onload = async () => { drawToCanvas(img, $('#verify-canvas')); const rep = await verifyFromCanvas($('#verify-canvas')); $('#verify-report').textContent = JSON.stringify(rep, null, 2); }; img.src = URL.createObjectURL(f);
});

$('#btn-verify-url').addEventListener('click', async () => {
  const url = $('#verify-url').value.trim(); if (!url) return;
  try {
    const res = await fetch(url, { mode:'cors' });
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const buf = new Uint8Array(await res.arrayBuffer());
    await drawBytesToCanvas(buf, $('#verify-canvas'));
    const rep = await verifyFromCanvas($('#verify-canvas'));
    $('#verify-report').textContent = JSON.stringify(rep, null, 2);
  } catch (e) {
    $('#verify-report').textContent = JSON.stringify({ verified:false, reason:'Fetch failed or CORS blocked', error:e.message }, null, 2);
  }
});

// ---------- Init ----------
(async function init(){
  await refreshIdentities(); await refreshContacts();
})();

