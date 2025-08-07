const state = JSON.parse(localStorage.getItem('dimos-state') || '{"identities":[],"contacts":[],"photos":[]}')

function saveState(){
  localStorage.setItem('dimos-state', JSON.stringify(state));
}

function bytesToBase64(bytes){
  let binary='';
  const len=bytes.length;
  for(let i=0;i<len;i++) binary+=String.fromCharCode(bytes[i]);
  return btoa(binary);
}
function base64ToBytes(b64){
  const binary=atob(b64);
  const len=binary.length;
  const bytes=new Uint8Array(len);
  for(let i=0;i<len;i++) bytes[i]=binary.charCodeAt(i);
  return bytes;
}

function renderIdentities(){
  const list=document.getElementById('identityList');
  const select=document.getElementById('signIdentity');
  list.innerHTML='';
  select.innerHTML='<option value="">--select--</option>';
  state.identities.forEach(id=>{
    const li=document.createElement('li');
    li.textContent=id.name;
    const share=document.createElement('button'); share.textContent='Share';
    share.onclick=()=>shareIdentity(id);
    const del=document.createElement('button'); del.textContent='Delete';
    del.onclick=()=>{state.identities=state.identities.filter(i=>i.id!==id.id); saveState(); renderIdentities();};
    li.append(' ',share,' ',del);
    list.appendChild(li);
    const opt=document.createElement('option'); opt.value=id.id; opt.textContent=id.name; select.appendChild(opt);
  });
}

function shareIdentity(identity){
  const data=JSON.stringify({name:identity.name, publicKey:identity.publicKey});
  const modal=document.getElementById('qrModal');
  const out=document.getElementById('qrOutput');
  out.innerHTML='';
  new QRCode(out, {text:data, width:200, height:200});
  modal.style.display='flex';
}

document.getElementById('closeQR').onclick=()=>{document.getElementById('qrModal').style.display='none'; document.getElementById('qrOutput').innerHTML='';};

function renderContacts(){
  const list=document.getElementById('contactList');
  list.innerHTML='';
  state.contacts.forEach(ct=>{
    const li=document.createElement('li');
    li.textContent=ct.name;
    const del=document.createElement('button'); del.textContent='Delete';
    del.onclick=()=>{state.contacts=state.contacts.filter(c=>c.id!==ct.id); saveState(); renderContacts();};
    li.append(' ',del);
    list.appendChild(li);
  });
}

function addContactFromText(){
  try{
    const txt=document.getElementById('contactText').value;
    const obj=JSON.parse(txt);
    if(!obj.name || !obj.publicKey) throw new Error('invalid');
    state.contacts.push({id:Date.now().toString(), name:obj.name, publicKey:obj.publicKey});
    saveState(); renderContacts(); document.getElementById('contactText').value='';
  }catch(e){ alert('Invalid contact text'); }
}

async function addContactFromQR(){
  const file=document.getElementById('contactQR').files[0];
  if(!file) return;
  const img=await loadImage(file);
  const canvas=document.getElementById('workCanvas');
  const ctx=canvas.getContext('2d');
  canvas.width=img.width; canvas.height=img.height; ctx.drawImage(img,0,0);
  const imgData=ctx.getImageData(0,0,canvas.width,canvas.height);
  const qr=jsQR(imgData.data, imgData.width, imgData.height);
  if(qr){
    try{
      const obj=JSON.parse(qr.data);
      if(!obj.name || !obj.publicKey) throw new Error('invalid');
      state.contacts.push({id:Date.now().toString(), name:obj.name, publicKey:obj.publicKey});
      saveState(); renderContacts();
    }catch(e){ alert('Invalid QR data'); }
  } else {
    alert('QR code not found');
  }
  document.getElementById('contactQR').value='';
}

document.getElementById('createId').onclick=()=>{
  const name=document.getElementById('idName').value.trim();
  if(!name) return;
  const kp=nacl.sign.keyPair();
  state.identities.push({id:Date.now().toString(), name, publicKey:bytesToBase64(kp.publicKey), privateKey:bytesToBase64(kp.secretKey), createdAt:new Date().toISOString()});
  saveState(); renderIdentities(); document.getElementById('idName').value='';
};

document.getElementById('addContactText').onclick=addContactFromText;
document.getElementById('addContactQR').onclick=addContactFromQR;

async function canvasHash(canvas){
  return new Promise(res=>canvas.toBlob(async blob=>{
    const buf=await blob.arrayBuffer();
    const hashBuf=await crypto.subtle.digest('SHA-256', buf);
    res(bytesToBase64(new Uint8Array(hashBuf)));
  }));
}

function cornerPosition(corner,w,h,size){
  switch(corner){
    case 'tr': return {x:w-size, y:0};
    case 'bl': return {x:0,y:h-size};
    case 'br': return {x:w-size,y:h-size};
    default: return {x:0,y:0};
  }
}

async function signPhoto(){
  const idVal=document.getElementById('signIdentity').value;
  const file=document.getElementById('photoInput').files[0];
  const corner=document.getElementById('qrCorner').value;
  if(!idVal || !file) return;
  const identity=state.identities.find(i=>i.id===idVal);
  const img=await loadImage(file);
  const canvas=document.getElementById('workCanvas');
  const ctx=canvas.getContext('2d');
  canvas.width=img.width; canvas.height=img.height; ctx.drawImage(img,0,0);
  const qrSize=Math.floor(Math.min(canvas.width,canvas.height)*0.25);
  const pos=cornerPosition(corner,canvas.width,canvas.height,qrSize);
  ctx.fillStyle='black'; ctx.fillRect(pos.x,pos.y,qrSize,qrSize);
  const hash=await canvasHash(canvas);
  const sig=nacl.sign.detached(base64ToBytes(hash), base64ToBytes(identity.privateKey));
  const qrData=JSON.stringify({hash, signature:bytesToBase64(sig), publicKey:identity.publicKey});
  const tmp=document.createElement('div');
  new QRCode(tmp,{text:qrData,width:qrSize,height:qrSize});
  const qrCanvas=tmp.querySelector('canvas');
  ctx.drawImage(qrCanvas,pos.x,pos.y,qrSize,qrSize);
  const url=canvas.toDataURL('image/png');
  document.getElementById('downloadLink').href=url; document.getElementById('downloadLink').style.display='inline';
  state.photos.push({id:Date.now().toString(), imageURI:url, hash, signature:bytesToBase64(sig), publicKey:identity.publicKey, qrCorner:corner, createdAt:new Date().toISOString()});
  saveState();
  document.getElementById('photoInput').value='';
}

document.getElementById('signBtn').onclick=signPhoto;

async function verifyPhoto(){
  const file=document.getElementById('verifyInput').files[0];
  if(!file) return;
  const img=await loadImage(file);
  const canvas=document.getElementById('workCanvas');
  const ctx=canvas.getContext('2d');
  canvas.width=img.width; canvas.height=img.height; ctx.drawImage(img,0,0);
  const imgData=ctx.getImageData(0,0,canvas.width,canvas.height);
  const qr=jsQR(imgData.data,imgData.width,imgData.height);
  if(!qr){ document.getElementById('verifyResult').textContent='QR not found'; return; }
  let data; try{ data=JSON.parse(qr.data); } catch(e){ document.getElementById('verifyResult').textContent='Invalid QR data'; return; }
  const left=Math.min(qr.location.topLeftCorner.x, qr.location.bottomLeftCorner.x);
  const right=Math.max(qr.location.topRightCorner.x, qr.location.bottomRightCorner.x);
  const top=Math.min(qr.location.topLeftCorner.y, qr.location.topRightCorner.y);
  const bottom=Math.max(qr.location.bottomLeftCorner.y, qr.location.bottomRightCorner.y);
  ctx.fillStyle='black'; ctx.fillRect(left,top,right-left,bottom-top);
  const hash=await canvasHash(canvas);
  const okHash = hash===data.hash;
  const sigOk = nacl.sign.detached.verify(base64ToBytes(data.hash), base64ToBytes(data.signature), base64ToBytes(data.publicKey));
  document.getElementById('verifyResult').textContent = okHash && sigOk ? 'Valid photo' : 'Invalid photo';
  document.getElementById('verifyInput').value='';
}

document.getElementById('verifyBtn').onclick=verifyPhoto;

function loadImage(file){
  return new Promise((res,rej)=>{
    const url=URL.createObjectURL(file);
    const img=new Image();
    img.onload=()=>{URL.revokeObjectURL(url); res(img);};
    img.onerror=rej;
    img.src=url;
  });
}

renderIdentities();
renderContacts();
