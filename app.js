import {
  $, $$, enc, dec, b64u, b64uToBytes, downloadBlob, listAll,
  drawToCanvas, computeHashWithBlackSquare, canvasToPngBytes, drawQR
} from './utils.js';

// ---------- Storage (IndexedDB via localForage) ----------
const db = {
  ids: localforage.createInstance({ name: 'photo-signer', storeName: 'identities' }),
  contacts: localforage.createInstance({ name: 'photo-signer', storeName: 'contacts' }),
  captures: localforage.createInstance({ name: 'photo-signer', storeName: 'captures' }),
};

// ---------- Crypto: WebCrypto + noble fallback ----------
const hasEd25519 = (() => {
  try {
    crypto.subtle.generateKey({ name: 'Ed25519', namedCurve: 'Ed25519' }, false, ['sign', 'verify']);
    return true;
  } catch { return false; }
})();

async function importPubKey(algo, rawOrJwk) {
  if (typeof rawOrJwk === 'string') {
    try { rawOrJwk = JSON.parse(rawOrJwk); } catch {}
  }
  if (algo === 'Ed25519') {
    if (rawOrJwk.kty === 'OKP' && rawOrJwk.crv === 'Ed25519' && rawOrJwk.x) {
      const raw = b64uToBytes(rawOrJwk.x);
      try {
        return await crypto.subtle.importKey('raw', raw, { name:'Ed25519' }, true, ['verify']);
      } catch (e) {
        return { noble:true, algo:'Ed25519', raw };
      }
    } else {
      const raw = typeof rawOrJwk === 'string' ? b64uToBytes(rawOrJwk) : new Uint8Array(rawOrJwk);
      try { return await crypto.subtle.importKey('raw', raw, { name:'Ed25519' }, true, ['verify']); }
      catch { return { noble:true, algo:'Ed25519', raw }; }
    }
  } else if (algo === 'P-256') {
    if (rawOrJwk.kty) {
      return await crypto.subtle.importKey('jwk', rawOrJwk, { name:'ECDSA', namedCurve:'P-256' }, true, ['verify']);
    } else {
      throw new Error('Provide P-256 public key as JWK');
    }
  }
  throw new Error('Unsupported algo');
}

async function genKey(algo) {
  if (algo === 'Ed25519') {
    try {
      const key = await crypto.subtle.generateKey({ name:'Ed25519', namedCurve:'Ed25519' }, true, ['sign','verify']);
      const pubRaw = new Uint8Array(await crypto.subtle.exportKey('raw', key.publicKey));
      const pubJwk = await crypto.subtle.exportKey('jwk', key.publicKey);
      return { algo, key, pubRaw, pubJwk };
    } catch (e) {
      const priv = nobleEd25519.utils.randomPrivateKey();
      const pubRaw = await nobleEd25519.getPublicKeyAsync(priv);
      return { algo, noble:true, priv, pubRaw, pubJwk: { kty:'OKP', crv:'Ed25519', x: b64u(pubRaw) } };
    }
  } else if (algo === 'P-256') {
    const key = await crypto.subtle.generateKey({ name:'ECDSA', namedCurve:'P-256' }, true, ['sign','verify']);
    const pubJwk = await crypto.subtle.exportKey('jwk', key.publicKey);
    const x = pubJwk.x;
    return { algo, key, pubRaw: b64uToBytes(x), pubJwk };
  }
  throw new Error('Unsupported algo');
}

async function exportPrivateEncrypted(idRec, passphrase) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const keyMat = await crypto.subtle.importKey('raw', enc.encode(passphrase || ''), 'PBKDF2', false, ['deriveKey']);
  const aesKey = await crypto.subtle.deriveKey({ name:'PBKDF2', salt, iterations: 200_000, hash:'SHA-256' }, keyMat, { name:'AES-GCM', length:256 }, false, ['encrypt']);

  let privBytes, privJwk;
  if (idRec.noble) {
    privBytes = idRec.priv;
    privJwk = { kty:'OKP', crv:'Ed25519', d: b64u(privBytes), x: b64u(idRec.pubRaw) };
  } else {
    privJwk = await crypto.subtle.exportKey('jwk', idRec.key.privateKey);
    privBytes = enc.encode(JSON.stringify(privJwk));
  }
  const plaintext = idRec.noble ? enc.encode(JSON.stringify(privJwk)) : privBytes;
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name:'AES-GCM', iv }, aesKey, plaintext));
  return {
    name: idRec.name,
    algo: idRec.algo,
    salt: b64u(salt), iv: b64u(iv), ct: b64u(ciphertext)
  };
}

async function importPrivateEncrypted(payload, passphrase) {
  const salt = b64uToBytes(payload.salt); const iv = b64uToBytes(payload.iv); const ct = b64uToBytes(payload.ct);
  const keyMat = await crypto.subtle.importKey('raw', enc.encode(passphrase || ''), 'PBKDF2', false, ['deriveKey']);
  const aesKey = await crypto.subtle.deriveKey({ name:'PBKDF2', salt, iterations: 200_000, hash:'SHA-256' }, keyMat, { name:'AES-GCM', length:256 }, false, ['decrypt']);
  const plain = new Uint8Array(await crypto.subtle.decrypt({ name:'AES-GCM', iv }, aesKey, ct));
  const jwk = JSON.parse(dec.decode(plain));
  if (payload.algo === 'Ed25519') {
    try {
      const priv = await crypto.subtle.importKey('jwk', jwk, { name:'Ed25519', namedCurve:'Ed25519' }, true, ['sign']);
      const pub = await crypto.subtle.importKey('jwk', { kty:'OKP', crv:'Ed25519', x:jwk.x }, { name:'Ed25519' }, true, ['verify']);
      const pubRaw = new Uint8Array(await crypto.subtle.exportKey('raw', pub));
      return { name: payload.name, algo:'Ed25519', key: { privateKey: priv, publicKey: pub }, pubRaw, pubJwk: { kty:'OKP', crv:'Ed25519', x:jwk.x } };
    } catch (e) {
      const priv = b64uToBytes(jwk.d);
      const pubRaw = await nobleEd25519.getPublicKeyAsync(priv);
      return { name: payload.name, algo:'Ed25519', noble:true, priv, pubRaw, pubJwk:{ kty:'OKP', crv:'Ed25519', x:b64u(pubRaw) } };
    }
  } else if (payload.algo === 'P-256') {
    const priv = await crypto.subtle.importKey('jwk', jwk, { name:'ECDSA', namedCurve:'P-256' }, true, ['sign']);
    const pub = await crypto.subtle.importKey('jwk', { ...jwk, d: undefined }, { name:'ECDSA', namedCurve:'P-256' }, true, ['verify']);
    const pubJwk = await crypto.subtle.exportKey('jwk', pub);
    return { name: payload.name, algo:'P-256', key: { privateKey: priv, publicKey: pub }, pubRaw: b64uToBytes(pubJwk.x), pubJwk };
  }
  throw new Error('Unsupported');
}

async function signBytes(idRec, bytes) {
  if (idRec.algo === 'Ed25519') {
    if (idRec.noble) {
      const sig = await nobleEd25519.signAsync(bytes, idRec.priv);
      return new Uint8Array(sig);
    } else {
      const sig = await crypto.subtle.sign({ name:'Ed25519' }, idRec.key.privateKey, bytes);
      return new Uint8Array(sig);
    }
  } else if (idRec.algo === 'P-256') {
    const sig = await crypto.subtle.sign({ name:'ECDSA', hash: 'SHA-256' }, idRec.key.privateKey, bytes);
    return new Uint8Array(sig);
  }
  throw new Error('Unsupported algo');
}

async function verifySig(algo, pubKey, bytes, sig) {
  if (algo === 'Ed25519') {
    if (pubKey && pubKey.noble) {
      return await nobleEd25519.verifyAsync(sig, bytes, pubKey.raw);
    }
    try {
      return await crypto.subtle.verify({ name:'Ed25519' }, pubKey, sig, bytes);
    } catch (e) {
      if (pubKey && pubKey.raw) return await nobleEd25519.verifyAsync(sig, bytes, pubKey.raw);
      throw e;
    }
  } else if (algo === 'P-256') {
    return await crypto.subtle.verify({ name:'ECDSA', hash:'SHA-256' }, pubKey, sig, bytes);
  }
  throw new Error('Unsupported algo');
}

// ---------- UI Tabs ----------
const tabs = $$('.tab');
$$('nav button').forEach(btn => btn.addEventListener('click', () => switchTab(btn.dataset.tab)));
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
          <button class="btn" data-export="${key}">Export Private (encrypted)</button>
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
  const algo = $('#id-algo').value;
  const k = await genKey(algo);
  const rec = { name, algo, ...k };
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
  } else if (t.dataset.export) {
    const id = t.dataset.export; const rec = await db.ids.getItem(id);
    const pass = $('#id-pass').value || prompt('Passphrase to encrypt private key export:');
    if (!pass) return;
    const payload = await exportPrivateEncrypted(rec, pass);
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type:'application/json' });
    downloadBlob(`identity-${rec.name}.priv.enc.json`, blob);
  } else if (t.dataset.del) {
    if (!confirm('Delete identity?')) return;
    await db.ids.removeItem(t.dataset.del);
    await refreshIdentities();
  }
});

$('#share-close').addEventListener('click', () => {
  $('#share-modal').style.display = 'none';
});

$('#btn-import-id').addEventListener('click', async () => {
  try {
    const json = JSON.parse($('#id-import-json').value);
    const pass = $('#id-import-pass').value;
    const rec = await importPrivateEncrypted(json, pass);
    const id = crypto.randomUUID();
    await db.ids.setItem(id, rec);
    await refreshIdentities();
    alert('Imported identity');
  } catch (e) { alert('Import failed: ' + e.message); }
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
  const algo = $('#contact-algo').value;
  let publicJwk = $('#contact-pub').value.trim();
  try { publicJwk = JSON.parse(publicJwk); } catch {}
  const id = crypto.randomUUID();
  await db.contacts.setItem(id, { displayName, algo, publicJwk });
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
  const percent = parseInt($('#qr-size').value, 10);
  const comment = $('#sign-comment')?.value?.trim();
  try {
    const { hash, rect } = await computeHashWithBlackSquare(currentCanvas, corner, percent);
    const payload = {
      version:1,
      algo:rec.algo,
      imageHash: b64u(hash),
      signerPub: b64u(rec.pubRaw),
      timestamp: new Date().toISOString(),
      corner,
      percent
    };
    if (comment) payload.comment = comment;
    const payloadBytes = enc.encode(JSON.stringify(payload));
    const sig = await signBytes(rec, payloadBytes);
    const tokenObj = { v:1, alg:payload.algo, pk:payload.signerPub, ts:payload.timestamp, ih:payload.imageHash, c:payload.corner, p:payload.percent, sig:b64u(sig) };
    if (comment) tokenObj.cm = comment;
    const token = JSON.stringify(tokenObj);
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
  const { v, alg, pk, ts, ih, c, p, sig, cm } = token;
  const { hash } = await computeHashWithBlackSquare(canvas, c, p);
  const hashB64 = b64u(hash);
  const payload = { version:1, algo:alg, imageHash:hashB64, signerPub:pk, timestamp:ts, corner:c, percent:p };
  if (cm) payload.comment = cm;
  const payloadBytes = enc.encode(JSON.stringify(payload));
  let pub;
  try { pub = await importPubKey(alg, { kty:'OKP', crv:'Ed25519', x: pk }); }
  catch { try { pub = await importPubKey(alg, pk); } catch (e) { pub = { noble:true, raw: b64uToBytes(pk) }; } }
  const ok = await verifySig(alg, pub, payloadBytes, b64uToBytes(sig));
  return {
    verified: ok && (hashB64 === ih),
    reason: ok ? (hashB64===ih? 'OK':'Hash mismatch') : 'Bad signature',
    details: { alg, publicKey: pk, timestamp: ts, comment: cm, imageHashComputed: hashB64, imageHashQR: ih }
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

// ---------- Backup/Restore ----------
$('#btn-backup').addEventListener('click', async () => {
  const pass = $('#backup-pass').value || prompt('Passphrase to encrypt private keys in backup:');
  const ids = await listAll(db.ids);
  const contacts = await listAll(db.contacts);
  const out = { version:1, when:new Date().toISOString(), identities:[], contacts: contacts.map(x=>x.value) };
  for (const { value } of ids) out.identities.push(await exportPrivateEncrypted(value, pass));
  downloadBlob('photosigner-backup.json', new Blob([JSON.stringify(out, null, 2)], { type:'application/json' }));
});

$('#btn-restore').addEventListener('click', async () => {
  try {
    const json = JSON.parse($('#restore-json').value);
    const pass = $('#restore-pass').value || prompt('Backup passphrase:');
    if (json.contacts) {
      for (const c of json.contacts) await db.contacts.setItem(crypto.randomUUID(), c);
    }
    if (json.identities) {
      for (const i of json.identities) {
        const rec = await importPrivateEncrypted(i, pass);
        await db.ids.setItem(crypto.randomUUID(), rec);
      }
    }
    await refreshIdentities(); await refreshContacts();
    alert('Restore complete');
  } catch (e) { alert('Restore failed: '+e.message); }
});

// ---------- Init ----------
(async function init(){
  await refreshIdentities(); await refreshContacts();
})();

