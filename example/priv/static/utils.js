function base64UrlEncode(buffer) {
  const bytes = new Uint8Array(buffer);
  let str = '';
  for (const byte of bytes) {
    str += String.fromCharCode(byte);
  }
  return btoa(str)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function base64UrlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) {
    str += '=';
  }
  const binary = atob(str);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

function checkWebAuthn() {
  if (!window.PublicKeyCredential) {
    const main = document.querySelector('main');
    const article = document.createElement('article');
    const header = document.createElement('header');
    const h2 = document.createElement('h2');
    h2.textContent = 'WebAuthn Not Supported';
    header.appendChild(h2);
    const p = document.createElement('p');
    p.textContent = 'Your browser does not support WebAuthn. Please use a modern browser.';
    article.appendChild(header);
    article.appendChild(p);
    main.replaceChildren(article);
    return false;
  }
  return true;
}
