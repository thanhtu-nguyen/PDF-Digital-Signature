/* ===================================================================== i18n */
let LANG = localStorage.getItem('lang') || 'en';
const UI = {
  math: { en: 'Show math', vi: 'Hiện toán' },
  footer: { en: 'All values are computed live by SecureSign, the project code and the audited cryptography library',
            vi: 'Mọi giá trị đều được tính trực tiếp bởi SecureSign, code của nhóm và thư viện cryptography đã kiểm định' },
  back: { en: '← Back to SecureSign', vi: '← Về SecureSign' },
  login: { en: 'Please sign in to SecureSign first. The lab keeps its keys per account and uses the same session and CSRF protection as the rest of the API.',
           vi: 'Hãy đăng nhập SecureSign trước. Lab lưu khóa riêng cho từng tài khoản và dùng cùng cơ chế phiên đăng nhập + CSRF như toàn bộ API.' },
  loginBtn: { en: 'Open SecureSign and sign in', vi: 'Mở SecureSign để đăng nhập' },
  files: { en: 'Download to re-check offline:', vi: 'Tải về để tự kiểm tra:' },
  restart: { en: '↺ Restart this scene', vi: '↺ Làm lại cảnh này' },
  keys: { en: 'Press <kbd>→</kbd> or <kbd>Space</kbd> for the next step', vi: 'Bấm <kbd>→</kbd> hoặc <kbd>Space</kbd> để sang bước tiếp' },
  step: { en: 'Step', vi: 'Bước' }, of: { en: 'of', vi: '/' },
  start: { en: 'Start ▶', vi: 'Bắt đầu ▶' },
  clickReveal: { en: 'click to reveal', vi: 'bấm để xem' },
  sig: { en: 'signature', vi: 'chữ ký' },
};
const t = o => (o && typeof o === 'object' && !Array.isArray(o) && ('en' in o)) ? o[LANG] : o;
function fill(s, vars = {}) { return String(s).replace(/\{(\w+)\}/g, (_, k) => vars[k] ?? ''); }

/* ===================================================================== helpers */
const $ = id => document.getElementById(id);
const esc = s => String(s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
function toast(m) { const e = $('toast'); e.textContent = m; e.style.display = 'block'; clearTimeout(e._t); e._t = setTimeout(() => e.style.display = 'none', 4000); }
function cookie(name) {
  return document.cookie.split('; ').find(x => x.startsWith(name + '='))?.split('=').slice(1).join('=') || '';
}
/* Every lab call is an authenticated SecureSign API call: session cookie + double-submit CSRF token. */
async function api(path, body = {}) {
  const r = await fetch('/api/lab/' + path.replace(/^\/api\//, ''), {
    method: 'POST', credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': decodeURIComponent(cookie('securesign_csrf')) },
    body: JSON.stringify(body),
  });
  const j = await r.json().catch(() => ({}));
  if (r.status === 401) { showLogin(); throw new Error(t(UI.login)); }
  if (!r.ok) throw new Error(j.detail || r.statusText);
  return j;
}
function showLogin() {
  $('main').innerHTML = `<div class="hero"><h1>🔐 SecureSign Security Lab</h1><p>${t(UI.login)}</p>
    <a class="next" style="display:inline-block;min-width:260px;text-decoration:none;margin-top:14px" href="/">${t(UI.loginBtn)}</a></div>`;
}
const sleep = ms => new Promise(r => setTimeout(r, ms));
/* fingerprint: the first bytes of a value shown as coloured blocks, so equal values are easy to spot */
function fp(hex, cls = '', secret = false) {
  hex = hex.replace(/^0x/, '');
  let sq = '';
  for (let i = 0; i < 12; i += 2) { const b = parseInt(hex.slice(i, i + 2) || '0', 16); sq += `<i style="background:hsl(${Math.round(b * 1.41)},70%,${45 + (b % 4) * 6}%)"></i>`; }
  const txt = hex.length > 14 ? hex.slice(0, 6) + '…' + hex.slice(-4) : hex;
  return `<span class="fp ${cls} ${secret ? 'secret' : ''}" ${secret ? `data-action="reveal" title="${t(UI.clickReveal)}"` : ''}><span class="sq">${sq}</span><code>${txt}</code></span>`;
}

/* ===================================================================== actors */
const ACTORS = {
  correct: [
    { id: 'alice', cls: 'c-alice', av: '👩‍💼', name: 'Alice', role: { en: 'Signer: owns the private key', vi: 'Người ký: giữ khóa bí mật' } },
    { id: 'net', cls: 'c-net', av: '🌐', name: 'Internet', role: { en: 'Public channel: everyone can see', vi: 'Kênh công khai: ai cũng thấy' } },
    { id: 'eve', cls: 'c-eve', av: '🦹', name: 'Eve', role: { en: 'Attacker', vi: 'Kẻ tấn công' } },
    { id: 'bob', cls: 'c-bob', av: '👨‍💼', name: 'Bob', role: { en: 'Verifier: has Alice\'s public key', vi: 'Người kiểm tra: có khóa công khai của Alice' } },
  ],
  lab: [
    { id: 'alice', cls: 'c-alice', av: '🏢', name: { en: 'Invoice service', vi: 'Dịch vụ hóa đơn' }, role: { en: 'Signs invoice PDFs with ECDSA P-256', vi: 'Ký hóa đơn PDF bằng ECDSA P-256' } },
    { id: 'net', cls: 'c-net', av: '🌐', name: 'Internet', role: { en: 'Signed invoice PDFs are public', vi: 'Hóa đơn PDF đã ký là công khai' } },
    { id: 'eve', cls: 'c-eve', av: '🦹', name: 'Eve', role: { en: 'Attacker: sees only public data', vi: 'Kẻ tấn công: chỉ thấy dữ liệu công khai' } },
    { id: 'bob', cls: 'c-bob', av: '🏦', name: { en: 'Bank', vi: 'Ngân hàng' }, role: { en: 'Pays invoices with a valid signature', vi: 'Thanh toán hóa đơn có chữ ký hợp lệ' } },
  ],
};
ACTORS.rsa = ACTORS.correct;
ACTORS.evidence = [
  { id: 'alice', cls: 'c-alice', av: '👩‍💼', name: 'Alice', role: { en: 'Signed a contract, now wants to deny it', vi: 'Đã ký hợp đồng, giờ muốn chối' } },
  { id: 'net', cls: 'c-net', av: '⛓', name: { en: 'Evidence log', vi: 'Sổ bằng chứng' }, role: { en: 'SecureSign: hash chain + server signature', vi: 'SecureSign: chuỗi băm + chữ ký máy chủ' } },
  { id: 'eve', cls: 'c-eve', av: '🕵️', name: 'Mallory', role: { en: 'Insider with database access', vi: 'Người nội bộ có quyền sửa database' } },
  { id: 'bob', cls: 'c-bob', av: '⚖️', name: { en: 'Judge', vi: 'Trọng tài' }, role: { en: 'Checks Bob\'s receipt and the log', vi: 'Kiểm tra biên nhận của Bob và sổ' } },
];
ACTORS.keysub = [
  { id: 'alice', cls: 'c-alice', av: '👩‍💼', name: 'Alice', role: { en: 'Owns her RSA key pair', vi: 'Sở hữu cặp khóa RSA' } },
  { id: 'net', cls: 'c-net', av: '📇', name: { en: 'Key directory', vi: 'Danh bạ khóa' }, role: { en: 'Public keys are public', vi: 'Khóa công khai ai cũng xem được' } },
  { id: 'eve', cls: 'c-eve', av: '🦹', name: 'Eve', role: { en: 'Has only Alice\'s PUBLIC key', vi: 'Chỉ có khóa CÔNG KHAI của Alice' } },
  { id: 'bob', cls: 'c-bob', av: '👨‍💼', name: 'Bob', role: { en: 'Asks the directory: who signed this PDF?', vi: 'Hỏi danh bạ: ai đã ký PDF này?' } },
];

/* ===================================================================== card renderers */
function cardHTML(c, isNew) {
  const n = isNew ? ' new' : '';
  if (c.type === 'verdict') return `<div class="verdict ${c.tone}${n}"><div class="big">${c.icon}</div><b>${t(c.title)}</b><span>${t(c.sub) || ''}</span>${c.math ? `<div class="math">${c.math}</div>` : ''}</div>`;
  if (c.type === 'note') return `<div class="note ${c.tone || ''}${n}">${t(c.text)}</div>`;
  let h = `<div class="item ${c.evil ? 'evil' : ''}${n}"><div class="h">${c.icon || ''} ${t(c.title)} ${c.tag ? `<span class="tagx ${c.tag.tone}">${t(c.tag.text)}</span>` : ''}</div>`;
  if (c.doc) h += `<div class="doc">${c.doc}</div>`;
  for (const r of c.rows || []) h += `<div class="row"><span class="lbl">${t(r.label)}</span>${r.html || fp(r.hex, r.cls, r.secret)}${r.after ? ' ' + t(r.after) : ''}</div>`;
  if (c.hint) h += `<div class="secret-hint">${t(c.hint)}</div>`;
  if (c.math) h += `<div class="math">${c.math}</div>`;
  return h + '</div>';
}

/* ===================================================================== scenes */
const ALICE_MSG = 'CONTRACT #2026-11: Alice agrees to pay Bob 1,000 USD on 30/11/2026.';
const pdfLabel = { en: 'PDF SHA-256', vi: 'SHA-256 của PDF' };
const TAMPERED = ALICE_MSG.replace('1,000', '9,000');
const INV1 = 'Invoice #1001: pay 100 USD to Supplier A';
const INV2 = 'Invoice #1002: pay 250 USD to Supplier B';
const EVIL = "Invoice #6666: pay 1,000,000 USD to Eve's account";
const docHL = (s, word) => esc(s).replace(esc(word), `<mark>${esc(word)}</mark>`);

const SCENES = {};

/* ---------- 1. correct use ---------- */
SCENES.correct = {
  tab: { en: '1 · How it works', vi: '1 · Cách hoạt động' }, actors: 'correct',
  kicker: { en: 'Scene 1 · Correct use', vi: 'Cảnh 1 · Dùng đúng cách' },
  title: { en: 'How does a digital signature protect a document?', vi: 'Chữ ký số bảo vệ tài liệu như thế nào?' },
  text: { en: 'Alice sends Bob a <b>contract PDF</b>. Bob must be sure that <b>it really comes from Alice</b> and that <b>nobody changed it</b> on the way. We sign the PDF bytes with <b>RSA-2048 (PSS)</b>, exactly like SecureSign does, and with <b>ECDSA P-256</b>.',
          vi: 'Alice gửi cho Bob một <b>hợp đồng PDF</b>. Bob cần chắc chắn <b>hợp đồng đúng là của Alice</b> và <b>không ai sửa nó</b> trên đường đi. Ta ký các byte của PDF bằng <b>RSA-2048 (PSS)</b> giống hệt SecureSign, và bằng <b>ECDSA P-256</b>.' },
  steps: [
    { btn: { en: '🔑 Alice creates her key pair', vi: '🔑 Alice tạo cặp khóa' },
      title: { en: 'Alice now has two keys', vi: 'Alice có hai chiếc khóa' },
      text: { en: 'The <b>private key 🔑</b> stays secret with Alice and is used to <b>sign</b>. The <b>public key 🔓</b> is given to everyone, so Bob can <b>verify</b>.',
              vi: '<b>Khóa bí mật 🔑</b> chỉ Alice giữ, dùng để <b>ký</b>. <b>Khóa công khai 🔓</b> được đưa cho mọi người, để Bob <b>kiểm tra</b>.' },
      run: async S => {
        const j = await api('/api/demo1/keygen'); S.keys = j;
        S.add('alice', { icon: '🔑', title: { en: 'Private key (secret)', vi: 'Khóa bí mật' }, rows: [{ label: 'ECDSA d', hex: j.ec_d, secret: true }],
          hint: { en: 'Never leaves Alice. Click to reveal.', vi: 'Không bao giờ rời khỏi Alice. Bấm để xem.' } });
        S.add('bob', { icon: '🔓', title: { en: 'Alice\'s public key', vi: 'Khóa công khai của Alice' }, rows: [{ label: 'ECDSA Q', hex: j.ec_qx }, { label: 'RSA n', hex: j.rsa_n }],
          math: `RSA: n = ${j.rsa_bits} bits, e = ${j.rsa_e}<br>ECDSA: Q = d·G on P-256<br>Qx = ${j.ec_qx}` });
      } },
    { btn: { en: '✍️ Alice signs the contract and sends it', vi: '✍️ Alice ký hợp đồng và gửi đi' },
      title: { en: 'The contract travels with its signature', vi: 'Hợp đồng được gửi kèm chữ ký' },
      text: { en: 'Alice computes a <b>SHA-256 fingerprint</b> of the contract and signs that fingerprint with her <b>private key</b>. The signature is a short number that only Alice could produce.',
              vi: 'Alice tính <b>dấu vân tay SHA-256</b> của hợp đồng rồi ký dấu vân tay đó bằng <b>khóa bí mật</b>. Chữ ký là một con số mà chỉ Alice mới tạo ra được.' },
      run: async S => {
        const j = await api('/api/demo1/sign', { message: ALICE_MSG }); S.sig = j;
        S.add('net', { icon: '📄', title: { en: 'Signed contract PDF', vi: 'Hợp đồng PDF đã ký' }, doc: esc(ALICE_MSG),
          rows: [{ label: pdfLabel, hex: j.hash }, { label: 'RSA ' + t(UI.sig), hex: j.rsa_sig }, { label: 'ECDSA ' + t(UI.sig), hex: j.ec_sig }],
          math: `PDF: ${j.pdf_bytes} bytes, SHA-256 = ${j.hash}<br>RSA-PSS signature: ${j.rsa_len} bytes (same as the .sig file SecureSign produces)<br>ECDSA signature: ${j.ec_len} bytes (about 4× smaller)` });
      } },
    { btn: { en: '🔍 Bob verifies the signature', vi: '🔍 Bob kiểm tra chữ ký' },
      title: { en: 'Valid: Bob can trust the contract', vi: 'Hợp lệ: Bob tin được hợp đồng' },
      text: { en: 'Bob uses <b>Alice\'s public key</b>. Both signatures match the contract, so it <b>comes from Alice</b> and <b>was not changed</b>. The RSA check is the same <code>verify_signature()</code> the SecureSign server runs on every uploaded PDF.',
              vi: 'Bob dùng <b>khóa công khai của Alice</b>. Cả hai chữ ký đều khớp với hợp đồng, vậy hợp đồng <b>đúng là của Alice</b> và <b>không bị sửa</b>. Phép kiểm tra RSA chính là hàm <code>verify_signature()</code> mà máy chủ SecureSign chạy với mọi PDF tải lên.' },
      run: async S => {
        const j = await api('/api/demo1/verify', { message: ALICE_MSG });
        S.add('bob', { type: 'verdict', tone: 'good', icon: '✅', title: { en: 'VALID: contract accepted', vi: 'HỢP LỆ: chấp nhận hợp đồng' },
          sub: `RSA-PSS ${j.rsa_ok ? '✓' : '✗'} · ECDSA ${j.ec_ok ? '✓' : '✗'}` });
      } },
    { btn: { en: '🦹 Eve changes 1,000 USD → 9,000 USD', vi: '🦹 Eve sửa 1,000 USD → 9,000 USD' },
      title: { en: 'Tampering is detected', vi: 'Bị sửa là phát hiện ngay' },
      text: { en: 'Eve changed <b>one character</b> in the PDF, but that changed <b>{bits} of the 256 bits</b> of the fingerprint. The old signature no longer matches, so Bob <b>rejects</b> it. This is <b>integrity</b>.',
              vi: 'Eve chỉ sửa <b>một ký tự</b>, nhưng dấu vân tay thay đổi tới <b>{bits}/256 bit</b>. Chữ ký cũ không còn khớp nên Bob <b>từ chối</b>. Đó là tính <b>toàn vẹn</b>.' },
      run: async S => {
        const j = await api('/api/demo1/verify', { message: TAMPERED }); S.vars.bits = j.bits_changed;
        S.add('eve', { icon: '✏️', evil: true, title: { en: 'Eve edits the contract', vi: 'Eve sửa hợp đồng' }, doc: docHL(TAMPERED, '9,000'),
          rows: [{ label: { en: 'old fingerprint', vi: 'vân tay cũ' }, hex: j.hash_signed }, { label: { en: 'new fingerprint', vi: 'vân tay mới' }, hex: j.hash_now, cls: 'same' }] });
        S.add('bob', { type: 'verdict', tone: 'good', icon: '🛡️', title: { en: 'INVALID: tampered contract rejected', vi: 'KHÔNG HỢP LỆ: từ chối hợp đồng bị sửa' },
          sub: `RSA-PSS ${j.rsa_ok ? '✓' : '✗'} · ECDSA ${j.ec_ok ? '✓' : '✗'}`, math: `SHA-256 before: ${j.hash_signed}<br>SHA-256 after:&nbsp; ${j.hash_now}<br>SecureSign server: ${esc(j.server_message)}` });
      } },
    { btn: { en: '🦹 Eve signs with her own key, pretending to be Alice', vi: '🦹 Eve tự ký bằng khóa của mình, giả làm Alice' },
      title: { en: 'Impersonation is detected', vi: 'Giả danh cũng bị phát hiện' },
      text: { en: 'Eve does not have Alice\'s private key, so her signature does not match <b>Alice\'s public key</b>. This is <b>authentication</b>. Since only Alice can make a valid signature, she cannot later deny signing: <b>non-repudiation</b>.',
              vi: 'Eve không có khóa bí mật của Alice nên chữ ký của Eve không khớp với <b>khóa công khai của Alice</b>. Đó là tính <b>xác thực</b>. Và vì chỉ Alice tạo được chữ ký hợp lệ, Alice không thể chối là mình đã ký: <b>chống chối bỏ</b>.' },
      run: async S => {
        const j = await api('/api/demo1/eve_sign', { message: TAMPERED });
        S.add('eve', { icon: '🔑', evil: true, title: { en: 'Eve signs with HER key', vi: 'Eve ký bằng khóa CỦA EVE' }, rows: [{ label: 'ECDSA ' + t(UI.sig), hex: j.ec_sig }] });
        S.add('bob', { type: 'verdict', tone: 'good', icon: '🛡️', title: { en: 'INVALID: not signed by Alice', vi: 'KHÔNG HỢP LỆ: không phải Alice ký' },
          sub: `RSA-PSS ${j.rsa_ok ? '✓' : '✗'} · ECDSA ${j.ec_ok ? '✓' : '✗'}` });
      } },
  ],
  end: { title: { en: 'Used correctly, digital signatures work', vi: 'Dùng đúng cách thì chữ ký số rất an toàn' },
         text: { en: 'Valid signatures are accepted; tampering and impersonation are rejected. <b>But what if the signing software has a bug?</b>',
                 vi: 'Chữ ký đúng được chấp nhận; sửa nội dung hay giả danh đều bị từ chối. <b>Nhưng nếu phần mềm ký có lỗi thì sao?</b>' },
         next: 'attack', btn: { en: 'Next: the attack ▶', vi: 'Tiếp: cuộc tấn công ▶' } },
};

/* ---------- 2/3. nonce-reuse lab ---------- */
function labScene(mode) {
  const V = mode === 'vulnerable';
  return {
    tab: V ? { en: '2 · The attack', vi: '2 · Tấn công' } : { en: '3 · The fix', vi: '3 · Bản vá' }, actors: 'lab',
    kicker: V ? { en: 'Scene 2 · Attack: ECDSA nonce reuse', vi: 'Cảnh 2 · Tấn công: dùng lại số k' } : { en: 'Scene 3 · Defense: RFC 6979', vi: 'Cảnh 3 · Phòng thủ: RFC 6979' },
    title: V ? { en: 'One small bug, and the private key leaks', vi: 'Một lỗi nhỏ làm lộ cả khóa bí mật' }
             : { en: 'Same attack, after the fix', vi: 'Cùng cuộc tấn công, sau khi vá' },
    text: V ? { en: 'An invoice service signs its <b>invoice PDFs</b> with ECDSA. ECDSA needs a <b>new secret random number k</b> for every signature, but the developer made a mistake: <b>k is created once and reused</b>. Eve only sees the public invoices.',
                vi: 'Một dịch vụ hóa đơn ký các <b>hóa đơn PDF</b> bằng ECDSA. ECDSA cần một <b>số ngẫu nhiên bí mật k MỚI</b> cho mỗi chữ ký, nhưng lập trình viên mắc lỗi: <b>k chỉ tạo một lần rồi dùng lại</b>. Eve chỉ thấy các hóa đơn công khai.' }
            : { en: 'Only one thing changes: k is now computed with <b>RFC 6979</b>, k = HMAC(private key, fingerprint of the message). <b>Every message gets its own k</b>, and nobody can predict it. Eve runs exactly the same attack.',
                vi: 'Chỉ thay đổi một điều: k được tính bằng <b>RFC 6979</b>, k = HMAC(khóa bí mật, vân tay của thông điệp). <b>Mỗi thông điệp có k riêng</b> và không ai đoán được. Eve chạy y hệt cuộc tấn công cũ.' },
    steps: [
      { btn: { en: '🏢 Start the invoice signing service', vi: '🏢 Khởi động dịch vụ ký hóa đơn' },
        title: { en: 'The service is running', vi: 'Dịch vụ đã chạy' },
        text: V ? { en: 'It has a strong private key, but a <b>bug</b>: it picks k only once. The bank only knows the <b>public key</b>. The private key is blurred; we reveal it at the end to compare.',
                    vi: 'Dịch vụ có khóa bí mật mạnh, nhưng có <b>lỗi</b>: chỉ chọn k một lần. Ngân hàng chỉ biết <b>khóa công khai</b>. Khóa bí mật đang bị che; cuối cùng ta sẽ mở ra để so sánh.' }
                : { en: 'Same strong private key, but now with the <b>RFC 6979 fix</b>. The bank only knows the <b>public key</b>.',
                    vi: 'Vẫn khóa bí mật mạnh, nhưng giờ đã có <b>bản vá RFC 6979</b>. Ngân hàng chỉ biết <b>khóa công khai</b>.' },
        run: async S => {
          const j = await api('/api/ecdsa/start', { mode }); S.lab = j;
          S.add('alice', { icon: '🔑', title: { en: 'Private key d', vi: 'Khóa bí mật d' }, rows: [{ label: 'd', hex: j.d, secret: true }],
            tag: V ? { tone: 'bad', text: { en: 'bug: k reused', vi: 'lỗi: dùng lại k' } } : { tone: 'good', text: { en: 'fixed: RFC 6979', vi: 'đã vá: RFC 6979' } },
            hint: { en: 'Click to reveal', vi: 'Bấm để xem' },
            math: V ? 'self._k = random()   # only ONCE  ← BUG<br>sign(m) = ecdsa_sign(m, d, self._k)' : 'k = rfc6979_nonce(d, m)   # new k per message<br>sign(m) = ecdsa_sign(m, d, k)' });
          S.add('bob', { icon: '🔓', title: { en: 'Service public key', vi: 'Khóa công khai của dịch vụ' }, rows: [{ label: 'Q', hex: j.qx }] });
        } },
      { btn: { en: '📄 Sign invoice #1001', vi: '📄 Ký hóa đơn #1001' },
        title: { en: 'An ECDSA signature has two parts: r and s', vi: 'Chữ ký ECDSA gồm hai phần: r và s' },
        text: { en: 'The first part <b>r</b> comes directly from the secret number k. <b>Same k → same r.</b> The bank checks the invoice: valid.',
                vi: 'Phần đầu <b>r</b> được tính trực tiếp từ số bí mật k. <b>Cùng k → cùng r.</b> Ngân hàng kiểm tra hóa đơn: hợp lệ.' },
        run: async S => {
          const j = await api('/api/ecdsa/sign', { message: INV1 }); S.s1 = j;
          S.add('net', { id: 'inv1', icon: '📄', title: { en: 'Invoice #1001 (PDF)', vi: 'Hóa đơn #1001 (PDF)' }, doc: esc(INV1), rows: [{ label: 'r', hex: j.r }, { label: 's', hex: j.s }],
            math: `PDF ${j.pdf_bytes} bytes, SHA-256 = ${j.pdf_sha256}` });
          S.add('bob', { icon: '✅', title: { en: 'Invoice #1001 is valid', vi: 'Hóa đơn #1001 hợp lệ' } });
        } },
      { btn: { en: '📄 Sign invoice #1002', vi: '📄 Ký hóa đơn #1002' },
        title: V ? { en: 'Look at r: it is the same in both!', vi: 'Nhìn r: hai chữ ký giống hệt nhau!' } : { en: 'r is different in each signature', vi: 'r khác nhau ở mỗi chữ ký' },
        text: V ? { en: 'Different invoices, but the <b>same r</b> (same colours). That proves the service <b>reused k</b>. Anyone on the Internet can see this.',
                    vi: 'Hai hóa đơn khác nhau nhưng <b>r giống nhau</b> (cùng màu). Điều đó chứng tỏ dịch vụ đã <b>dùng lại k</b>. Ai trên Internet cũng thấy được.' }
                : { en: 'Each invoice got its <b>own k</b>, so the r values are <b>different</b>. Nothing repeats, nothing leaks.',
                    vi: 'Mỗi hóa đơn có <b>k riêng</b>, nên các giá trị r <b>khác nhau</b>. Không có gì lặp lại, không có gì bị lộ.' },
        run: async S => {
          const j = await api('/api/ecdsa/sign', { message: INV2 }); S.s2 = j;
          const same = j.r === S.s1.r, cls = same ? 'same' : 'diff';
          S.update('inv1', c => { c.rows[0].cls = cls; });
          S.add('net', { icon: '📄', title: { en: 'Invoice #1002 (PDF)', vi: 'Hóa đơn #1002 (PDF)' }, doc: esc(INV2), rows: [{ label: 'r', hex: j.r, cls }, { label: 's', hex: j.s }],
            math: `PDF ${j.pdf_bytes} bytes, SHA-256 = ${j.pdf_sha256}`,
            tag: same ? { tone: 'bad', text: { en: 'same r!', vi: 'trùng r!' } } : { tone: 'good', text: { en: 'different r', vi: 'r khác' } } });
          S.add('bob', { icon: '✅', title: { en: 'Invoice #1002 is valid', vi: 'Hóa đơn #1002 hợp lệ' } });
        } },
      { btn: { en: '🦹 Eve tries to compute the private key', vi: '🦹 Eve thử tính khóa bí mật' },
        title: V ? { en: 'Eve recovered the private key!', vi: 'Eve đã tìm ra khóa bí mật!' } : { en: 'The attack fails', vi: 'Cuộc tấn công thất bại' },
        text: V ? { en: 'With the same k, Eve has <b>2 equations and 2 unknowns</b> (k and d). Subtracting them gives k, then k gives d. It took <b>{ms} ms</b>. Reveal the service\'s key: <b>it is identical</b>.',
                    vi: 'Vì cùng k, Eve có <b>2 phương trình, 2 ẩn</b> (k và d). Trừ hai phương trình ra k, rồi từ k ra d. Mất <b>{ms} ms</b>. Mở khóa của dịch vụ ra xem: <b>giống hệt</b>.' }
                : { en: 'The r values differ, so Eve has <b>more unknowns than equations</b>. Forcing the formula anyway gives a <b>wrong key</b> that does not match the public key.',
                    vi: 'Các giá trị r khác nhau nên Eve có <b>nhiều ẩn hơn số phương trình</b>. Cố tính theo công thức thì ra một <b>khóa sai</b>, không khớp với khóa công khai.' },
        run: async S => {
          const j = await api('/api/ecdsa/attack'); S.vars.ms = j.ms;
          const ok = j.matches;
          const math = j.reused
            ? `<span class="eq">s1 − s2 = k⁻¹(h1 − h2)  ⇒  k = (h1 − h2)/(s1 − s2) mod n</span><br>k = ${j.k}<br><span class="eq">s1·k = h1 + r·d  ⇒  d = (s1·k − h1)/r mod n</span><br>d = ${j.d}`
            : `recover_nonce(): ${esc(j.refused || '')}<br>forced guess d′ = ${j.d}`;
          S.add('eve', { icon: '🧮', evil: true, title: { en: 'Eve\'s calculation', vi: 'Eve tính toán' },
            rows: [{ label: { en: 'found key', vi: 'khóa tìm được' }, hex: j.d, cls: ok ? 'same' : 'diff' }],
            tag: ok ? { tone: 'bad', text: { en: 'matches public key', vi: 'khớp khóa công khai' } } : { tone: 'good', text: { en: 'wrong key', vi: 'khóa sai' } }, math });
          if (ok) {
            S.update('alice0', c => { c.rows[0].secret = false; c.rows[0].cls = 'same'; });
            S.add('eve', { type: 'note', text: { en: '☠️ d·G = Q: this <b>is</b> the service\'s private key.', vi: '☠️ d·G = Q: đây <b>chính là</b> khóa bí mật của dịch vụ.' } });
          } else {
            S.update('alice0', c => { c.rows[0].secret = false; c.rows[0].cls = 'diff'; });
            S.add('eve', { type: 'note', tone: 'good', text: { en: '🛡️ d′·G ≠ Q: the key was <b>not</b> recovered.', vi: '🛡️ d′·G ≠ Q: <b>không</b> tìm được khóa.' } });
          }
        } },
      { btn: { en: '💸 Eve forges an invoice for 1,000,000 USD', vi: '💸 Eve làm giả hóa đơn 1,000,000 USD' },
        title: V ? { en: 'The bank is fooled', vi: 'Ngân hàng bị lừa' } : { en: 'The bank rejects the forgery', vi: 'Ngân hàng từ chối hóa đơn giả' },
        text: V ? { en: 'Eve signs her invoice with the stolen key. The bank checks it with the <b>real public key</b> and an <b>audited library</b>, and it says <b>VALID</b>. Integrity, authentication and non-repudiation are all broken.',
                    vi: 'Eve ký hóa đơn giả bằng khóa đã đánh cắp. Ngân hàng kiểm tra bằng <b>khóa công khai thật</b> và <b>thư viện đã kiểm định</b>, kết quả: <b>HỢP LỆ</b>. Toàn vẹn, xác thực và chống chối bỏ đều bị phá vỡ.' }
                : { en: 'Eve\'s signature, made with a wrong key, does not match the real public key. The <b>fix works</b>: the same attack code now achieves nothing.',
                    vi: 'Chữ ký của Eve được tạo bằng khóa sai nên không khớp với khóa công khai thật. <b>Bản vá hiệu quả</b>: cùng một đoạn code tấn công giờ vô dụng.' },
        run: async S => {
          const j = await api('/api/ecdsa/forge', { message: EVIL });
          const files = `${t(UI.files)} <a href="/api/lab/ecdsa/files/forged.pdf">forged.pdf</a> · <a href="/api/lab/ecdsa/files/forged.sig">forged.sig</a> · <a href="/api/lab/ecdsa/files/public.pem">public.pem</a><br><code>openssl dgst -sha256 -verify lab-public.pem -signature lab-forged.sig lab-forged.pdf</code>`;
          S.add('eve', { icon: '💸', evil: true, title: { en: 'Forged invoice PDF', vi: 'Hóa đơn PDF giả' }, doc: docHL(EVIL, '1,000,000 USD'), rows: [{ label: pdfLabel, hex: j.pdf_sha256 }, { label: 'r', hex: j.r }, { label: 's', hex: j.s }] });
          S.add('bob', j.accepted
            ? { type: 'verdict', tone: 'bad', icon: '💥', title: { en: 'VALID: 1,000,000 USD paid to Eve', vi: 'HỢP LỆ: đã trả 1,000,000 USD cho Eve' }, sub: { en: 'The forgery cannot be told apart from a real signature.', vi: 'Không thể phân biệt chữ ký giả với chữ ký thật.' }, math: files }
            : { type: 'verdict', tone: 'good', icon: '🛡️', title: { en: 'INVALID: forgery rejected', vi: 'KHÔNG HỢP LỆ: từ chối hóa đơn giả' }, sub: { en: 'No money lost.', vi: 'Không mất tiền.' } });
        } },
      ...(V ? [] : [{
        btn: { en: '🔁 Compare with the audited library', vi: '🔁 So sánh với thư viện đã kiểm định' },
        title: { en: 'Our fix matches the standard exactly', vi: 'Bản vá khớp chính xác với chuẩn' },
        text: { en: 'We signed invoice #1001 with our RFC 6979 code and with the <b>cryptography</b> library (deterministic mode). The two signatures are <b>byte-for-byte identical</b>.',
                vi: 'Ta ký hóa đơn #1001 bằng code RFC 6979 của nhóm và bằng thư viện <b>cryptography</b> (chế độ deterministic). Hai chữ ký <b>giống nhau đến từng byte</b>.' },
        run: async S => {
          const j = await api('/api/ecdsa/crosscheck', { message: INV1 });
          S.add('alice', { icon: '🔁', title: { en: 'Cross-check', vi: 'Đối chiếu' },
            rows: [{ label: { en: 'our r', vi: 'r của nhóm' }, hex: j.ours_r, cls: 'diff' }, { label: { en: 'library r', vi: 'r thư viện' }, hex: j.lib_r, cls: 'diff' }],
            tag: j.identical ? { tone: 'good', text: { en: 'identical', vi: 'giống hệt' } } : { tone: 'bad', text: { en: 'different', vi: 'khác' } } });
        } }]),
    ],
    end: V ? { title: { en: 'The math was never broken, the implementation was', vi: 'Toán học không bị phá, mà là cách cài đặt' },
               text: { en: 'ECDSA itself is secure. One reused number was enough to leak the key (the same bug leaked Sony\'s PS3 signing key in 2010). <b>How do we fix it?</b>',
                       vi: 'Bản thân ECDSA vẫn an toàn. Chỉ một con số bị dùng lại là đủ lộ khóa (lỗi này từng làm lộ khóa ký PS3 của Sony năm 2010). <b>Vá thế nào?</b>' },
               next: 'defense', btn: { en: 'Next: the fix ▶', vi: 'Tiếp: bản vá ▶' } }
             : { title: { en: 'RFC 6979 stops nonce reuse', vi: 'RFC 6979 chặn lỗi dùng lại k' },
                 text: { en: 'Each message gets a unique, unpredictable k without needing a random generator. <b>Bonus:</b> why RSA also needs padding.',
                         vi: 'Mỗi thông điệp có k riêng, không đoán được, và không cần bộ sinh số ngẫu nhiên. <b>Phần thêm:</b> vì sao RSA cũng cần padding.' },
                 next: 'rsa', btn: { en: 'Bonus: RSA ▶', vi: 'Phần thêm: RSA ▶' } },
  };
}
SCENES.attack = labScene('vulnerable');
SCENES.defense = labScene('patched');

/* ---------- 4. textbook RSA vs PSS ---------- */
SCENES.rsa = {
  tab: { en: '4 · RSA padding', vi: '4 · Padding RSA' }, actors: 'rsa',
  kicker: { en: 'Scene 4 · Bonus', vi: 'Cảnh 4 · Phần thêm' },
  title: { en: 'Why RSA needs padding (PSS)', vi: 'Vì sao RSA cần padding (PSS)' },
  text: { en: '"Textbook" RSA signs a number directly: sign(m) = m<sup>d</sup> mod n. It has a dangerous property: <b>sign(a) × sign(b) = sign(a × b)</b>.',
          vi: 'RSA "sách giáo khoa" ký thẳng con số: sign(m) = m<sup>d</sup> mod n. Nó có tính chất nguy hiểm: <b>sign(a) × sign(b) = sign(a × b)</b>.' },
  steps: [
    { btn: { en: '✍️ Alice signs 100 and 50 (textbook RSA)', vi: '✍️ Alice ký số 100 và 50 (RSA sách giáo khoa)' },
      title: { en: 'Two harmless signed amounts', vi: 'Hai số tiền vô hại đã được ký' },
      text: { en: 'Alice approves payments of <b>100</b> and <b>50</b>. Eve sees both signatures on the Internet.',
              vi: 'Alice duyệt hai khoản <b>100</b> và <b>50</b>. Eve nhìn thấy cả hai chữ ký trên Internet.' },
      run: async S => {
        const j = await api('/api/rsa/run', { m1: 100, m2: 50 }); S.rsa = j;
        S.add('net', { icon: '📄', title: { en: 'Amount 100', vi: 'Số tiền 100' }, rows: [{ label: t(UI.sig), hex: j.s1 }] });
        S.add('net', { icon: '📄', title: { en: 'Amount 50', vi: 'Số tiền 50' }, rows: [{ label: t(UI.sig), hex: j.s2 }] });
      } },
    { btn: { en: '🦹 Eve multiplies the two signatures', vi: '🦹 Eve nhân hai chữ ký với nhau' },
      title: { en: 'Eve made a valid signature for 5,000', vi: 'Eve tạo được chữ ký hợp lệ cho 5,000' },
      text: { en: 'Without the private key, Eve computes sign(100) × sign(50) and gets a signature that Bob accepts for <b>5,000 = 100 × 50</b>.',
              vi: 'Không cần khóa bí mật, Eve tính sign(100) × sign(50) và được chữ ký mà Bob chấp nhận cho <b>5,000 = 100 × 50</b>.' },
      run: async S => {
        const j = S.rsa;
        S.add('eve', { icon: '✖️', evil: true, title: { en: 'Multiply', vi: 'Phép nhân' }, doc: '<div class="bigeq">100 × 50 = <em>5,000</em></div>', rows: [{ label: t(UI.sig), hex: j.forged_s }],
          math: 's = s1 · s2 mod n<br>s^e mod n = 100^(de) · 50^(de) = 5000' });
        S.add('bob', j.textbook_ok
          ? { type: 'verdict', tone: 'bad', icon: '💥', title: { en: 'VALID: 5,000 accepted', vi: 'HỢP LỆ: chấp nhận 5,000' }, sub: { en: 'Textbook RSA is forgeable.', vi: 'RSA sách giáo khoa bị giả mạo được.' } }
          : { type: 'verdict', tone: 'good', icon: '🛡️', title: { en: 'Rejected', vi: 'Bị từ chối' } });
      } },
    { btn: { en: '🔐 Try the same trick against RSA-PSS', vi: '🔐 Thử lại mánh đó với RSA-PSS' },
      title: { en: 'PSS blocks the trick', vi: 'PSS chặn được mánh này' },
      text: { en: 'PSS signs a <b>hashed and randomly salted</b> version of the message, not the raw number. Multiplying two PSS signatures produces garbage, and Bob <b>rejects</b> it.',
              vi: 'PSS ký phiên bản <b>đã băm và thêm muối ngẫu nhiên</b> của thông điệp, không ký số thô. Nhân hai chữ ký PSS chỉ ra rác, Bob <b>từ chối</b>.' },
      run: async S => {
        const j = S.rsa;
        S.add('eve', { icon: '✖️', evil: true, title: { en: 'Multiply PSS signatures', vi: 'Nhân chữ ký PSS' }, rows: [{ label: t(UI.sig), hex: j.pss_forged }] });
        S.add('bob', j.pss_ok
          ? { type: 'verdict', tone: 'bad', icon: '💥', title: { en: 'Accepted (unexpected)', vi: 'Được chấp nhận (bất thường)' } }
          : { type: 'verdict', tone: 'good', icon: '🛡️', title: { en: 'INVALID: PSS rejects 5,000', vi: 'KHÔNG HỢP LỆ: PSS từ chối 5,000' }, sub: { en: 'Padding protects RSA.', vi: 'Padding bảo vệ RSA.' } });
      } },
  ],
  end: { title: { en: 'Padding is not optional', vi: 'Padding là bắt buộc' },
         text: { en: 'SecureSign only accepts RSA-PSS with SHA-256. <b>Last question:</b> the math is right, but how does Bob know <b>whose</b> public key it is?',
                 vi: 'SecureSign chỉ chấp nhận RSA-PSS với SHA-256. <b>Câu hỏi cuối:</b> toán học đúng rồi, nhưng làm sao Bob biết khóa công khai đó là <b>của ai</b>?' },
         next: 'keysub', btn: { en: 'Next: key substitution ▶', vi: 'Tiếp: đánh tráo khóa ▶' } },
};

/* ---------- 5. key substitution vs proof-of-possession (SecureSign key registry) ---------- */
SCENES.keysub = {
  tab: { en: '5 · Key registry', vi: '5 · Đăng ký khóa' }, actors: 'keysub',
  kicker: { en: 'Scene 5 · Attack on the key registry', vi: 'Cảnh 5 · Tấn công danh bạ khóa' },
  title: { en: 'Stealing a signature without stealing a key', vi: 'Cướp chữ ký mà không cần cướp khóa' },
  text: { en: 'A signature proves "the holder of <b>this public key</b> signed". Bob learns <b>who</b> that is from the key directory. Eve copies Alice\'s <b>public</b> key (it is public!) and registers it under her own account.',
          vi: 'Chữ ký chứng minh "người giữ <b>khóa công khai này</b> đã ký". Bob biết đó là <b>ai</b> nhờ danh bạ khóa. Eve sao chép khóa <b>công khai</b> của Alice (vốn công khai!) và đăng ký nó dưới tài khoản của mình.' },
  steps: [
    { btn: { en: '✍️ Alice signs a contract PDF and registers her key', vi: '✍️ Alice ký hợp đồng PDF và đăng ký khóa' },
      title: { en: 'Alice proves she owns her key', vi: 'Alice chứng minh mình sở hữu khóa' },
      text: { en: 'SecureSign sends Alice a <b>one-time random challenge</b>. She signs it with her private key (RSA-PSS) in the browser, and the server checks the proof before linking the key to her account.',
              vi: 'SecureSign gửi cho Alice một <b>challenge ngẫu nhiên dùng một lần</b>. Alice ký nó bằng khóa bí mật (RSA-PSS) ngay trong trình duyệt, máy chủ kiểm tra bằng chứng rồi mới gắn khóa với tài khoản của cô.' },
      run: async S => {
        const j = await api('keysub/setup', { message: ALICE_MSG }); S.ks = j;
        S.add('alice', { icon: '📄', title: { en: 'Signed contract PDF', vi: 'Hợp đồng PDF đã ký' }, doc: esc(ALICE_MSG), rows: [{ label: pdfLabel, hex: j.pdf_sha256 }, { label: 'RSA ' + t(UI.sig), hex: j.sig }] });
        S.add('net', { icon: '🔓', title: { en: 'Alice\'s public key', vi: 'Khóa công khai của Alice' }, rows: [{ label: 'fingerprint', hex: j.fingerprint, cls: 'same' }],
          tag: { tone: 'good', text: { en: 'owner: Alice', vi: 'chủ: Alice' } }, math: `challenge = ${esc(j.challenge)}<br>proof = RSA-PSS-sign(d_Alice, challenge) → ${j.alice_proof_ok ? 'valid' : 'invalid'}` });
      } },
    { btn: { en: '🦹 Eve registers Alice\'s key in a registry WITHOUT proof', vi: '🦹 Eve đăng ký khóa của Alice ở danh bạ KHÔNG kiểm tra' },
      title: { en: 'Without proof-of-possession, Eve "owns" Alice\'s signatures', vi: 'Không có proof-of-possession, Eve "sở hữu" chữ ký của Alice' },
      text: { en: 'A naive registry only stores (public key → owner). Eve uploads Alice\'s key first. Alice\'s PDF still verifies <b>mathematically</b>, but the directory now says it was <b>signed by Eve</b>. Eve can claim Alice\'s contracts, and Alice can deny them: <b>authentication and non-repudiation are broken</b>, with no key ever leaked.',
              vi: 'Một danh bạ ngây thơ chỉ lưu (khóa công khai → chủ sở hữu). Eve tải khóa của Alice lên trước. Về <b>toán học</b> PDF của Alice vẫn hợp lệ, nhưng danh bạ giờ báo là <b>Eve đã ký</b>. Eve có thể nhận vơ hợp đồng của Alice, còn Alice có thể chối: <b>xác thực và chống chối bỏ bị phá</b>, dù không có khóa nào bị lộ.' },
      run: async S => {
        const j = await api('keysub/legacy');
        S.add('eve', { icon: '📋', evil: true, title: { en: 'Copies the public key', vi: 'Sao chép khóa công khai' }, rows: [{ label: 'fingerprint', hex: j.fingerprint, cls: 'same' }],
          tag: { tone: 'bad', text: { en: 'registered as Eve', vi: 'đăng ký là Eve' } } });
        S.add('bob', { type: 'verdict', tone: 'bad', icon: '💥', title: { en: 'VALID signature, "signed by Eve"', vi: 'Chữ ký HỢP LỆ, "do Eve ký"' },
          sub: { en: 'The math is right, the identity is wrong.', vi: 'Toán đúng, danh tính sai.' } });
      } },
    { btn: { en: '🛡️ Eve tries the same against SecureSign', vi: '🛡️ Eve thử lại với SecureSign' },
      title: { en: 'SecureSign rejects the registration', vi: 'SecureSign từ chối đăng ký' },
      text: { en: 'SecureSign asks Eve to sign a <b>fresh challenge</b> with the private key of the key she uploads. She can only sign with <b>her own</b> key, so <code>verify_proof_of_possession()</code> fails, and an old proof cannot be replayed because each challenge is used once. The same check is required by real PKIs (a CSR is self-signed for this reason).',
              vi: 'SecureSign yêu cầu Eve ký một <b>challenge mới</b> bằng khóa bí mật tương ứng với khóa cô tải lên. Eve chỉ ký được bằng khóa <b>của mình</b>, nên <code>verify_proof_of_possession()</code> thất bại, và không thể dùng lại bằng chứng cũ vì mỗi challenge chỉ dùng một lần. PKI thật cũng bắt buộc bước này (CSR được tự ký chính vì lý do đó).' },
      run: async S => {
        const j = await api('keysub/secure');
        S.add('eve', { icon: '✍️', evil: true, title: { en: 'Proof signed with Eve\'s key', vi: 'Bằng chứng ký bằng khóa của Eve' }, rows: [{ label: 'proof', hex: j.eve_proof }],
          math: `challenge = ${esc(j.challenge)}` });
        S.add('bob', j.accepted
          ? { type: 'verdict', tone: 'bad', icon: '💥', title: { en: 'Accepted (unexpected)', vi: 'Được chấp nhận (bất thường)' } }
          : { type: 'verdict', tone: 'good', icon: '🛡️', title: { en: 'REJECTED: Eve cannot prove ownership', vi: 'TỪ CHỐI: Eve không chứng minh được quyền sở hữu' },
              sub: { en: 'Alice\'s PDFs stay attributed to Alice.', vi: 'PDF của Alice vẫn đứng tên Alice.' } });
      } },
  ],
  end: { title: { en: 'Identity is part of the signature', vi: 'Danh tính là một phần của chữ ký' },
         text: { en: 'A key registry must check ownership. <b>Last question:</b> once Alice has really signed, can she still deny it, or can someone rewrite the history?',
                 vi: 'Danh bạ khóa phải kiểm tra quyền sở hữu. <b>Câu hỏi cuối:</b> khi Alice đã thực sự ký, cô ấy còn chối được không, hay ai đó có thể viết lại lịch sử?' },
         next: 'evidence', btn: { en: 'Next: non-repudiation ▶', vi: 'Tiếp: chống chối bỏ ▶' } },
};

/* ---------- 6. non-repudiation: signed receipts + hash-chained evidence log ---------- */
SCENES.evidence = {
  tab: { en: '6 · Non-repudiation', vi: '6 · Chống chối bỏ' }, actors: 'evidence',
  kicker: { en: 'Scene 6 · Repudiation and log tampering', vi: 'Cảnh 6 · Chối bỏ và sửa nhật ký' },
  title: { en: '"I never signed that", and the log that cannot be rewritten', vi: '"Tôi chưa từng ký", và cuốn sổ không thể viết lại' },
  text: { en: 'A signature proves <b>who</b> signed, but not <b>when</b>, and a normal log can be edited by whoever runs the database. SecureSign records every event as a <b>receipt signed by the server</b> (ECDSA P-256) and links it to the previous one with <b>SHA-256</b>.',
          vi: 'Chữ ký chứng minh <b>ai</b> đã ký, nhưng không chứng minh <b>khi nào</b>, và nhật ký thông thường thì ai quản lý database cũng sửa được. SecureSign ghi mỗi sự kiện thành một <b>biên nhận do máy chủ ký</b> (ECDSA P-256) và nối với mục trước bằng <b>SHA-256</b>.' },
  steps: [
    { btn: { en: '✍️ Alice signs the contract and sends it to Bob', vi: '✍️ Alice ký hợp đồng và gửi cho Bob' },
      title: { en: 'Three events, three chained receipts', vi: 'Ba sự kiện, ba biên nhận nối chuỗi' },
      text: { en: 'Each entry contains the hash of the previous one (<code>prev_hash</code>) and is signed by the server. Bob downloads receipt #2 (PDF signed) and keeps it.',
              vi: 'Mỗi mục chứa hash của mục trước (<code>prev_hash</code>) và được máy chủ ký. Bob tải biên nhận #2 (đã ký PDF) về và giữ lại.' },
      run: async S => {
        const j = await api('evidence/setup', { message: ALICE_MSG }); S.ev = j;
        S.add('alice', { icon: '📄', title: { en: 'Signed contract PDF', vi: 'Hợp đồng PDF đã ký' }, doc: esc(ALICE_MSG), rows: [{ label: pdfLabel, hex: j.document_sha256 }] });
        const names = { KEY_REGISTERED: { en: 'Key registered', vi: 'Đăng ký khóa' }, PDF_SIGNED: { en: 'PDF signed', vi: 'Ký PDF' }, DOCUMENT_SENT: { en: 'Sent to Bob', vi: 'Gửi cho Bob' } };
        j.entries.forEach(e => S.add('net', { id: 'log' + e.seq, icon: '🔗', title: `#${e.seq} · ${t(names[e.event])}`, rows: [{ label: 'entry_hash', hex: e.hash }],
          after: '', math: `time = ${e.time}` }));
        S.add('bob', { icon: '🧾', title: { en: 'Bob keeps receipt #2', vi: 'Bob giữ biên nhận #2' }, rows: [{ label: 'entry_hash', hex: j.entries[1].hash, cls: 'same' }],
          math: `time = ${j.receipt_time}<br>signed by server key ${j.server_key.slice(0, 16)}…` });
        S.update('log2', c => { c.rows[0].cls = 'same'; });
      } },
    { btn: { en: '🙅 Alice: "I signed it a week later" (fake receipt)', vi: '🙅 Alice: "Tôi ký sau đó một tuần" (biên nhận giả)' },
      title: { en: 'The server-signed receipt settles the dispute', vi: 'Biên nhận do máy chủ ký giải quyết tranh chấp' },
      text: { en: 'The judge checks Bob\'s receipt with SecureSign\'s <b>public</b> key: valid, and it fixes the time. Alice\'s own "receipt" with a later date is rejected, because only the server can sign receipts. Together with her valid PDF signature, Alice <b>cannot repudiate</b> it.',
              vi: 'Trọng tài kiểm tra biên nhận của Bob bằng khóa <b>công khai</b> của SecureSign: hợp lệ, và nó cố định thời điểm ký. "Biên nhận" Alice tự làm với ngày muộn hơn bị từ chối, vì chỉ máy chủ mới ký được biên nhận. Cộng với chữ ký PDF hợp lệ, Alice <b>không thể chối bỏ</b>.' },
      run: async S => {
        const j = await api('evidence/deny');
        S.add('alice', { icon: '🧾', evil: true, title: { en: 'Alice\'s fake receipt', vi: 'Biên nhận giả của Alice' }, doc: 'time = 2026-12-05T10:00:00Z', tag: { tone: 'bad', text: { en: 'own key', vi: 'khóa riêng' } } });
        S.add('bob', { type: 'verdict', tone: j.receipt_valid && !j.fake_valid ? 'good' : 'bad', icon: '⚖️',
          title: { en: `Receipt valid: signed at ${j.time}`, vi: `Biên nhận hợp lệ: ký lúc ${j.time}` },
          sub: { en: 'Fake receipt rejected.', vi: 'Biên nhận giả bị từ chối.' }, math: esc(j.fake_reason) });
      } },
    { btn: { en: '🕵️ Mallory edits entry #2 in the database', vi: '🕵️ Mallory sửa mục #2 trong database' },
      title: { en: 'Editing one entry breaks the chain', vi: 'Sửa một mục là đứt chuỗi' },
      text: { en: 'Mallory moves the signing time of entry #2 to a week later. Its SHA-256 no longer matches <code>entry_hash</code>, and entry #3 still points to the old hash. The integrity check (the same one in the admin page) finds it immediately.',
              vi: 'Mallory dời thời điểm ký của mục #2 sang một tuần sau. SHA-256 của mục không còn khớp <code>entry_hash</code>, và mục #3 vẫn trỏ tới hash cũ. Phép kiểm tra toàn vẹn (giống trang quản trị) phát hiện ngay.' },
      run: async S => {
        const j = await api('evidence/tamper', { recompute: false });
        S.add('eve', { icon: '✏️', evil: true, title: { en: 'Edits #2: time → 2026-12-05', vi: 'Sửa #2: thời gian → 2026-12-05' } });
        S.update('log2', c => { c.tag = { tone: 'bad', text: { en: 'edited', vi: 'bị sửa' } }; });
        S.add('bob', { type: 'verdict', tone: j.check.ok ? 'bad' : 'good', icon: '🛡️', title: { en: `Tampering detected at #${j.check.broken_at}`, vi: `Phát hiện sửa đổi tại #${j.check.broken_at}` }, math: esc(j.check.reason) });
      } },
    { btn: { en: '🕵️ Mallory recomputes every hash', vi: '🕵️ Mallory tính lại toàn bộ hash' },
      title: { en: 'Re-hashing does not help: she cannot sign', vi: 'Tính lại hash cũng vô ích: không ký được' },
      text: { en: 'Mallory rewrites #2 and recomputes the hashes of #2 and #3 so the chain looks consistent. But each entry is also signed with the server\'s private key, which she does not have, and Bob\'s receipt still holds the original hash.',
              vi: 'Mallory viết lại #2 và tính lại hash của #2, #3 để chuỗi trông khớp. Nhưng mỗi mục còn được ký bằng khóa bí mật của máy chủ mà cô không có, và biên nhận của Bob vẫn giữ hash gốc.' },
      run: async S => {
        const j = await api('evidence/tamper', { recompute: true });
        S.add('eve', { icon: '🧮', evil: true, title: { en: 'Recomputed hashes', vi: 'Hash đã tính lại' }, rows: [{ label: '#2 new hash', hex: j.new_hash, cls: 'diff' }] });
        S.add('bob', { type: 'verdict', tone: j.check.ok ? 'bad' : 'good', icon: '🛡️',
          title: { en: `Still detected at #${j.check.broken_at}`, vi: `Vẫn bị phát hiện tại #${j.check.broken_at}` },
          sub: j.receipt_matches_log ? '' : { en: 'Bob\'s receipt no longer matches the log.', vi: 'Biên nhận của Bob không còn khớp với sổ.' }, math: esc(j.check.reason) });
      } },
  ],
  end: { title: { en: 'Conclusion: implementation details decide security', vi: 'Kết luận: chi tiết cài đặt quyết định độ an toàn' },
         text: { en: 'RSA and ECC were never broken mathematically. Reused nonces, missing padding, an unverified key registry and an editable log broke them. SecureSign uses RSA-PSS or ECDSA P-256, keeps private keys encrypted in the browser, requires proof-of-possession and issues signed, hash-chained receipts.',
                 vi: 'RSA và ECC chưa bao giờ bị phá về mặt toán học. Chính việc dùng lại k, thiếu padding, danh bạ khóa không kiểm tra và nhật ký sửa được đã phá chúng. SecureSign dùng RSA-PSS hoặc ECDSA P-256, giữ khóa bí mật được mã hóa trong trình duyệt, bắt buộc proof-of-possession và cấp biên nhận có chữ ký, nối chuỗi băm.' },
         next: 'intro', btn: { en: '⌂ Back to start', vi: '⌂ Về trang đầu' } },
};

/* ===================================================================== state & render */
const ORDER = ['intro', 'correct', 'attack', 'defense', 'rsa', 'keysub', 'evidence'];
let CUR = 'intro', ST = null, BUSY = false;

function newState() {
  const S = { step: 0, cols: { alice: [], net: [], eve: [], bob: [] }, vars: {}, seen: new Set(), uid: 0 };
  S.add = (col, card) => { card._id = card.id || (col + S.cols[col].length); S.cols[col].push(card); };
  S.update = (id, fn) => { for (const c of Object.values(S.cols)) for (const x of c) if (x._id === id) fn(x); };
  return S;
}

function renderTabs() {
  const items = [['intro', { en: '⌂ Start', vi: '⌂ Mở đầu' }], ...ORDER.slice(1).map(k => [k, SCENES[k].tab])];
  $('tabs').innerHTML = items.map(([k, lab]) => `<button class="tab ${k === CUR ? 'active' : ''}" data-action="go" data-arg="${k}">${t(lab)}</button>`).join('');
  document.querySelectorAll('[data-t]').forEach(e => e.innerHTML = t(UI[e.dataset.t]));
  $('lang-en').classList.toggle('on', LANG === 'en'); $('lang-vi').classList.toggle('on', LANG === 'vi');
}

function renderIntro() {
  const P = [['🧾', { en: 'Integrity', vi: 'Toàn vẹn' }, { en: 'Any change to the document is detected.', vi: 'Mọi thay đổi trên tài liệu đều bị phát hiện.' }],
             ['🪪', { en: 'Authentication', vi: 'Xác thực' }, { en: 'Proves who signed it.', vi: 'Chứng minh ai là người ký.' }],
             ['✍️', { en: 'Non-repudiation', vi: 'Chống chối bỏ' }, { en: 'The signer cannot deny it later.', vi: 'Người ký không thể chối bỏ.' }]];
  const sc = ORDER.slice(1).map((k, i) => `<button class="scene-card" data-action="go" data-arg="${k}"><span class="n">${i + 1}</span><b>${t(SCENES[k].title)}</b><span>${t(SCENES[k].kicker)}</span></button>`).join('');
  $('main').innerHTML = `
    <div class="hero"><h1>${t({ en: 'SecureSign Security Lab', vi: 'Phòng thí nghiệm bảo mật SecureSign' })}</h1>
      <p>${t({ en: 'How PDF signatures protect integrity, authentication and non-repudiation, four real attacks on badly implemented signatures, and the defenses SecureSign uses. Click through the story one step at a time.',
               vi: 'Chữ ký PDF bảo vệ toàn vẹn, xác thực và chống chối bỏ như thế nào, bốn cuộc tấn công thật vào chữ ký số cài đặt sai, và cách SecureSign phòng thủ. Bấm qua từng bước của câu chuyện.' })}</p></div>
    <div class="props">${P.map(([i, b, s]) => `<div class="prop"><div class="ic">${i}</div><b>${t(b)}</b><span>${t(s)}</span></div>`).join('')}</div>
    <div class="scenes">${sc}</div>
    <div style="text-align:center;margin-top:24px"><button class="next" style="min-width:260px" data-action="go" data-arg="correct">${t(UI.start)}</button></div>
    <div class="team">Trieu Ngoc Van Anh (524H0005) · Duong Tran Quoc Khanh (523H0040) · Nguyen Vo Thanh Tu (523H0189)<br>
      ${t({ en: 'Instructor', vi: 'Giảng viên' })}: Ph.D. Huynh Ngoc Tu · Ton Duc Thang University</div>`;
}

function renderScene() {
  const sc = SCENES[CUR], S = ST, n = sc.steps.length;
  const last = S.step > 0 ? sc.steps[S.step - 1] : null;
  const finished = S.step >= n;
  const head = last || sc;
  let kicker = t(sc.kicker) + (S.step > 0 ? ` · ${t(UI.step)} ${S.step} ${t(UI.of)} ${n}` : '');
  const btnLabel = finished ? t(sc.end.btn) : t(sc.steps[S.step].btn);
  const actors = ACTORS[sc.actors];
  const cols = actors.map(a => `<div class="col ${a.cls}"><div class="actor"><div class="av">${a.av}</div><div><b>${t(a.name)}</b><small>${t(a.role)}</small></div></div>
      ${S.cols[a.id].map(c => { const isNew = !S.seen.has(c._id); return cardHTML(c, isNew); }).join('')}</div>`).join('');
  Object.values(S.cols).flat().forEach(c => S.seen.add(c._id));
  const endBox = finished ? `<div class="note good" style="margin-top:10px;font-size:15px"><b>${t(sc.end.title)}</b><br>${t(sc.end.text)}</div>` : '';
  $('main').innerHTML = `
    <div class="story">
      <div class="txt"><div class="kicker">${kicker}</div><h2>${t(head.title)}</h2><p>${fill(t(head.text), S.vars)}</p>${endBox}</div>
      <div class="ctrl">
        <button class="next ${finished ? 'done' : ''}" id="nextBtn" data-action="next">${btnLabel}</button>
        <div class="sub-ctrl"><div class="dots">${sc.steps.map((_, i) => `<i class="${i < S.step ? 'on' : ''}"></i>`).join('')}</div>
          <button class="link" data-action="restart">${t(UI.restart)}</button></div>
        <div class="keys">${t(UI.keys)}</div>
      </div>
    </div>
    <div class="stage">${cols}</div>`;
}

function render() { renderTabs(); CUR === 'intro' ? renderIntro() : renderScene(); }

/* ===================================================================== actions */
function go(scene) { if (BUSY) return; CUR = scene; ST = newState(); location.hash = scene; render(); window.scrollTo(0, 0); }
function restart() { if (!BUSY) go(CUR); }
async function next() {
  if (CUR === 'intro') return go('correct');
  const sc = SCENES[CUR];
  if (ST.step >= sc.steps.length) return go(sc.end.next);
  if (BUSY) return;
  BUSY = true;
  const b = $('nextBtn'); b.disabled = true; b.innerHTML = '<span class="spin"></span>' + b.innerHTML;
  try { await sc.steps[ST.step].run(ST); ST.step++; }
  catch (e) { toast(e.message); }
  finally { BUSY = false; render(); }
}
function setLang(l) { LANG = l; localStorage.setItem('lang', l); document.documentElement.lang = l; render(); }
function toggleMath() { document.body.classList.toggle('show-math'); $('mathBtn').classList.toggle('on'); }

document.addEventListener('click', e => {
  const el = e.target.closest('[data-action]');
  if (!el) return;
  const a = el.dataset.action;
  if (a === 'go') go(el.dataset.arg);
  else if (a === 'next') next();
  else if (a === 'restart') restart();
  else if (a === 'math') toggleMath();
  else if (a === 'lang') setLang(el.dataset.arg);
  else if (a === 'reveal') el.classList.toggle('shown');
});

document.addEventListener('keydown', e => {
  if (e.target.matches('input, textarea')) return;
  if (e.key === 'ArrowRight' || e.key === ' ' || e.key === 'Enter') { e.preventDefault(); next(); }
  else if (e.key === 'r' || e.key === 'R') restart();
  else if (e.key === 'm' || e.key === 'M') toggleMath();
});

/* Deep links: #attack opens a scene; #attack/5 also runs its first 5 steps (used for report screenshots). */
(async () => {
  document.documentElement.lang = LANG;
  const me = await fetch('/api/auth/me', { credentials: 'same-origin' });
  if (!me.ok) { renderTabs(); showLogin(); return; }
  const [h, n] = location.hash.slice(1).split('/');
  go(ORDER.includes(h) ? h : 'intro');
  for (let i = 0; i < (parseInt(n) || 0) && CUR !== 'intro' && ST.step < SCENES[CUR].steps.length; i++) await next();
  if (n) { location.hash = h + '/' + n; document.title += ' [ready]'; }
})();
