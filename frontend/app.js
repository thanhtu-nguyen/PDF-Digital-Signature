const $ = (id) => document.getElementById(id);
const state = {
  user: null, csrf: "", authMode: "login", currentPage: "dashboard",
  generated: null, signatureBlob: null, signatureName: "signature.sig",
  myKeys: [], directoryKeys: [], documentsMode: "inbox"
};
const MAX_PDF = 25 * 1024 * 1024;
const PSS_SALT_LENGTH = 32;
const PBKDF2_ITERATIONS = 310000;

function showNotice(message, type = "info") {
  const el = $("notice");
  if (!el) return;
  el.textContent = message;
  el.className = `notice ${type}`;
  window.scrollTo({ top: 0, behavior: "smooth" });
}
function showAuthNotice(message, type = "error") {
  const el = $("auth-notice");
  el.textContent = message;
  el.className = `notice ${type}`;
}
function hideNotice() {
  if ($("notice")) $("notice").className = "notice hidden";
  if ($("auth-notice")) $("auth-notice").className = "notice hidden";
}
function hex(buffer) {
  return [...new Uint8Array(buffer)].map(b => b.toString(16).padStart(2, "0")).join("");
}
function pemEncode(label, bytes) {
  const base64 = btoa(String.fromCharCode(...new Uint8Array(bytes)));
  const lines = base64.match(/.{1,64}/g).join("\n");
  return `-----BEGIN ${label}-----\n${lines}\n-----END ${label}-----\n`;
}
function pemDecode(pem) {
  const body = pem.replace(/-----BEGIN [^-]+-----/g, "").replace(/-----END [^-]+-----/g, "").replace(/\s/g, "");
  const binary = atob(body);
  return Uint8Array.from(binary, c => c.charCodeAt(0));
}
function base64ToBytes(value) {
  const binary = atob(value);
  return Uint8Array.from(binary, c => c.charCodeAt(0));
}
function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
function downloadText(text, filename, type = "text/plain") {
  downloadBlob(new Blob([text], { type }), filename);
}
async function sha256(data) { return hex(await crypto.subtle.digest("SHA-256", data)); }
async function publicFingerprint(publicKey) {
  const spki = await crypto.subtle.exportKey("spki", publicKey);
  return sha256(spki);
}
function validatePdf(file) {
  if (!file) throw new Error("Vui lòng chọn tài liệu PDF.");
  if (!file.name.toLowerCase().endsWith(".pdf")) throw new Error("Tệp tài liệu phải có đuôi .pdf.");
  if (file.size > MAX_PDF) throw new Error("PDF vượt quá giới hạn 25 MB.");
}
function cookieValue(name) {
  const prefix = `${name}=`;
  const part = document.cookie.split(";").map(x => x.trim()).find(x => x.startsWith(prefix));
  return part ? decodeURIComponent(part.slice(prefix.length)) : "";
}
async function api(url, options = {}) {
  const { skipCsrf = false, ...fetchOptions } = options;
  const method = (fetchOptions.method || "GET").toUpperCase();
  const headers = new Headers(fetchOptions.headers || {});
  if (!skipCsrf && !["GET", "HEAD", "OPTIONS"].includes(method)) {
    const csrf = state.csrf || cookieValue("securesign_csrf");
    if (csrf) headers.set("X-CSRF-Token", csrf);
  }
  const response = await fetch(url, { ...fetchOptions, headers, credentials: "same-origin" });
  let data = {};
  try { data = await response.json(); } catch {}
  if (!response.ok) {
    let message = data.detail || data.message || `Lỗi máy chủ (${response.status})`;
    if (Array.isArray(message)) message = message.map(x => x.msg || "Dữ liệu không hợp lệ").join("; ");
    if ((response.status === 401 || (response.status === 403 && String(message).includes("Tài khoản đã bị khóa"))) && state.user && !url.startsWith("/api/auth/")) showAuth();
    throw new Error(message);
  }
  return data;
}
function setAuthMode(mode) {
  state.authMode = mode;
  const formIds = {login:"login-form",register:"register-form",forgot:"forgot-form",resend:"resend-form",reset:"reset-form"};
  Object.entries(formIds).forEach(([key,id]) => $(id).classList.toggle("hidden", key !== mode));
  const titles = {
    login:["Chào mừng trở lại","Đăng nhập để quản lý tài liệu và chữ ký số của bạn."],
    register:["Tạo tài khoản SecureSign","Đăng ký miễn phí để bắt đầu ký và trao đổi PDF an toàn."],
    forgot:["Quên mật khẩu?","Nhập email để nhận liên kết đặt lại mật khẩu."],
    resend:["Xác minh email","Nhập email đã đăng ký để gửi lại liên kết xác minh."],
    reset:["Đặt mật khẩu mới","Chọn mật khẩu mới cho tài khoản SecureSign của bạn."]
  };
  $("auth-title").textContent = titles[mode][0];
  $("auth-subtitle").textContent = titles[mode][1];
  const isLoginOrRegister = mode === "login" || mode === "register";
  $("auth-switch").classList.toggle("hidden", !isLoginOrRegister);
  if (isLoginOrRegister) {
    $("auth-switch-label").textContent = mode === "login" ? "Chưa có tài khoản?" : "Đã có tài khoản?";
    $("auth-switch-button").textContent = mode === "login" ? "Đăng ký ngay" : "Đăng nhập";
  }
  hideNotice();
}

function showAuth() {
  state.user = null; state.csrf = "";
  $("app-shell").classList.add("hidden");
  $("auth-view").classList.remove("hidden");
  setAuthMode("login");
}
function showApp(user) {
  state.user = user;
  $("auth-view").classList.add("hidden");
  $("app-shell").classList.remove("hidden");
  $("user-name").textContent = user.full_name;
  $("user-email").textContent = user.email;
  $("user-avatar").textContent = user.full_name.split(/\s+/).map(x => x[0]).slice(0, 2).join("").toUpperCase();
  $("admin-nav").classList.toggle("hidden", user.role !== "admin");
  $("key-owner").value = user.full_name;
  showPage("dashboard");
  refreshAll();
}
function showPage(page) {
  if (page === "admin" && state.user?.role !== "admin") return;
  hideNotice();
  state.currentPage = page;
  document.querySelectorAll(".page").forEach(p => p.classList.toggle("active", p.id === `page-${page}`));
  document.querySelectorAll(".nav-link").forEach(b => b.classList.toggle("active", b.dataset.page === page));
  const titles = {dashboard:"Tổng quan",sign:"Ký tài liệu",verify:"Xác thực chữ ký",keys:"Quản lý khóa",send:"Gửi tài liệu",inbox:"Hộp thư tài liệu",history:"Lịch sử",admin:"Quản trị người dùng"};
  $("page-title").textContent = titles[page] || "SecureSign";
  if (page === "keys") { refreshKeys(); refreshDirectory(); }
  if (page === "verify") refreshDirectory();
  if (page === "send") refreshKeys();
  if (page === "inbox") loadDocuments(state.documentsMode);
  if (page === "history") refreshHistory();
  if (page === "dashboard") refreshDashboard();
  if (page === "admin") loadAdmin();
}
document.querySelectorAll("[data-page]").forEach(b => b.addEventListener("click", () => showPage(b.dataset.page)));
document.querySelectorAll("[data-go]").forEach(b => b.addEventListener("click", () => showPage(b.dataset.go)));

async function checkHealth() {
  try {
    await api("/api/health");
    $("server-status").textContent = "Máy chủ hoạt động";
    $("server-status").parentElement.classList.add("online");
  } catch {
    $("server-status").textContent = "Mất kết nối máy chủ";
    $("server-status").parentElement.classList.remove("online");
  }
}

$("auth-switch-button").addEventListener("click", () => setAuthMode(state.authMode === "login" ? "register" : "login"));
$("login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = $("login-button");
  try {
    button.disabled = true; button.textContent = "Đang đăng nhập...";
    const data = await api("/api/auth/login", {method:"POST", skipCsrf:true, headers:{"Content-Type":"application/json"}, body:JSON.stringify({email:$("login-email").value.trim(),password:$("login-password").value})});
    state.csrf = data.csrf_token;
    showApp(data.user);
  } catch (err) { showAuthNotice(err.message); }
  finally { button.disabled = false; button.innerHTML = 'Đăng nhập <span>→</span>'; }
});
$("register-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = $("register-button");
  try {
    const password = $("register-password").value;
    if (password !== $("register-confirm").value) throw new Error("Hai mật khẩu không trùng khớp.");
    if (password.length < 12) throw new Error("Mật khẩu phải có ít nhất 12 ký tự.");
    button.disabled = true; button.textContent = "Đang tạo tài khoản...";
    const data = await api("/api/auth/register", {method:"POST", skipCsrf:true, headers:{"Content-Type":"application/json"}, body:JSON.stringify({full_name:$("register-name").value.trim(),email:$("register-email").value.trim(),password})});
    if (data.requires_email_verification) { showAuth(); showAuthNotice(data.message,"success"); return; }
    state.csrf = data.csrf_token;
    showApp(data.user);
    showNotice("Đăng ký thành công. Hãy tạo cặp khóa RSA đầu tiên của bạn.", "success");
  } catch (err) { showAuthNotice(err.message); }
  finally { button.disabled = false; button.innerHTML = 'Tạo tài khoản miễn phí <span>→</span>'; }
});
$("forgot-password-link").addEventListener("click", () => setAuthMode("forgot"));
$("resend-verification-link").addEventListener("click", () => setAuthMode("resend"));
document.querySelectorAll("[data-auth-back]").forEach(button => button.addEventListener("click", () => setAuthMode("login")));
$("forgot-form").addEventListener("submit", async (event) => {
  event.preventDefault(); const button = $("forgot-button");
  try {
    button.disabled = true; button.textContent = "Đang gửi...";
    const data = await api("/api/auth/forgot-password", {method:"POST",skipCsrf:true,headers:{"Content-Type":"application/json"},body:JSON.stringify({email:$("forgot-email").value.trim()})});
    showAuthNotice(data.message,"success");
  } catch (err) { showAuthNotice(err.message); }
  finally { button.disabled = false; button.textContent = "Gửi liên kết đặt lại mật khẩu"; }
});
$("resend-form").addEventListener("submit", async (event) => {
  event.preventDefault(); const button = $("resend-button");
  try {
    button.disabled = true; button.textContent = "Đang gửi...";
    const data = await api("/api/auth/resend-verification", {method:"POST",skipCsrf:true,headers:{"Content-Type":"application/json"},body:JSON.stringify({email:$("resend-email").value.trim()})});
    showAuthNotice(data.message,"success");
  } catch (err) { showAuthNotice(err.message); }
  finally { button.disabled = false; button.textContent = "Gửi lại email xác minh"; }
});
$("reset-form").addEventListener("submit", async (event) => {
  event.preventDefault(); const button = $("reset-button");
  try {
    const password = $("reset-password").value;
    if (password !== $("reset-confirm").value) throw new Error("Hai mật khẩu không trùng khớp.");
    if (password.length < 12) throw new Error("Mật khẩu phải có ít nhất 12 ký tự.");
    button.disabled = true; button.textContent = "Đang cập nhật...";
    const data = await api("/api/auth/reset-password", {method:"POST",skipCsrf:true,headers:{"Content-Type":"application/json"},body:JSON.stringify({token:$("reset-token").value,new_password:password})});
    history.replaceState({},"", "/"); setAuthMode("login"); showAuthNotice(data.message,"success");
  } catch (err) { showAuthNotice(err.message); }
  finally { button.disabled = false; button.textContent = "Đặt lại mật khẩu"; }
});

$("logout-button").addEventListener("click", async () => {
  try { await api("/api/auth/logout", {method:"POST"}); }
  catch (err) { console.warn("Logout:", err.message); }
  showAuth();
});

async function refreshAll() {
  await Promise.allSettled([refreshDashboard(), refreshKeys(), refreshDirectory()]);
}
async function refreshDashboard() {
  try {
    const data = await api("/api/dashboard");
    $("stat-sign").textContent = data.sign_count;
    $("stat-valid").textContent = data.valid_count;
    $("stat-keys").textContent = data.key_count;
    $("stat-inbox").textContent = data.inbox_count;
    $("stat-sent").textContent = data.sent_count;
  } catch (err) { if (state.user) console.warn(err); }
}

// --------------------------- Key generation ---------------------------
$("generate-keys").addEventListener("click", async () => {
  const button = $("generate-keys");
  try {
    const name = $("key-owner").value.trim();
    const password = $("new-key-password").value;
    const confirm = $("confirm-key-password").value;
    if (!name) throw new Error("Vui lòng nhập tên hoặc nhãn khóa.");
    if (password.length < 12) throw new Error("Mật khẩu phải có ít nhất 12 ký tự.");
    if (password !== confirm) throw new Error("Hai mật khẩu không trùng khớp.");
    if (!window.isSecureContext || !crypto.subtle) throw new Error("Web Crypto API cần HTTPS hoặc localhost để hoạt động.");
    button.disabled = true; button.textContent = "Đang tạo cặp khóa...";
    const pair = await crypto.subtle.generateKey({name:"RSA-PSS",modulusLength:2048,publicExponent:new Uint8Array([1,0,1]),hash:"SHA-256"},true,["sign","verify"]);
    const spki = await crypto.subtle.exportKey("spki", pair.publicKey);
    const pkcs8 = await crypto.subtle.exportKey("pkcs8", pair.privateKey);
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const material = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveKey"]);
    const aesKey = await crypto.subtle.deriveKey({name:"PBKDF2",salt,iterations:PBKDF2_ITERATIONS,hash:"SHA-256"},material,{name:"AES-GCM",length:256},false,["encrypt"]);
    const encrypted = await crypto.subtle.encrypt({name:"AES-GCM",iv},aesKey,pkcs8);
    const publicKeyPem = pemEncode("PUBLIC KEY", spki);
    const fingerprint = await sha256(spki);
    const toB64 = bytes => btoa(String.fromCharCode(...new Uint8Array(bytes)));
    const bundle = {version:1,algorithm:"RSA-PSS",hash:"SHA-256",modulusLength:2048,cipher:"AES-256-GCM",kdf:"PBKDF2-SHA256",iterations:PBKDF2_ITERATIONS,salt:toB64(salt),iv:toB64(iv),ciphertext:toB64(encrypted),publicKeyPem,fingerprint,owner:name,createdAt:new Date().toISOString()};
    state.generated = {bundle,publicKeyPem,fingerprint,owner:name,privateKey:pair.privateKey};
    $("generated-key-result").classList.remove("hidden");
    showNotice(`Đã tạo cặp khóa RSA 2048-bit. Fingerprint: ${fingerprint}`, "success");
  } catch (err) { showNotice(err.message || "Không thể tạo cặp khóa.", "error"); }
  finally { button.disabled = false; button.innerHTML = 'Tạo cặp khóa RSA <span>→</span>'; }
});
$("download-private").addEventListener("click", () => { if (state.generated) downloadText(JSON.stringify(state.generated.bundle,null,2),"private-key-encrypted.key.json","application/json"); });
$("download-public").addEventListener("click", () => { if (state.generated) downloadText(state.generated.publicKeyPem,"public-key.pem","application/x-pem-file"); });
async function registerPublicKeyWithProof(name, publicKeyPem, privateKey) {
  const challenge = await api("/api/keys/challenge", {method:"POST"});
  const challengeBytes = new TextEncoder().encode(challenge.challenge);
  const proof = await crypto.subtle.sign({name:"RSA-PSS",saltLength:PSS_SALT_LENGTH},privateKey,challengeBytes);
  const proofBase64 = btoa(String.fromCharCode(...new Uint8Array(proof)));
  return api("/api/keys", {method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({name,public_key_pem:publicKeyPem,challenge_id:challenge.challenge_id,proof_signature:proofBase64})});
}

$("register-generated").addEventListener("click", async () => {
  if (!state.generated) return;
  try {
    const data = await registerPublicKeyWithProof(state.generated.owner,state.generated.publicKeyPem,state.generated.privateKey);
    showNotice(`Đã chứng minh quyền sở hữu Private Key và đăng ký Public Key. Fingerprint: ${data.item.fingerprint}`,"success");
    await refreshKeys(); await refreshDirectory(); await refreshDashboard();
  } catch (err) { showNotice(err.message,"error"); }
});
$("import-register-key").addEventListener("click", async () => {
  const button = $("import-register-key");
  try {
    const file = $("import-key-file").files[0];
    const password = $("import-key-password").value;
    if (!file) throw new Error("Vui lòng chọn file Private Key đã mã hóa.");
    if (!password) throw new Error("Vui lòng nhập mật khẩu Private Key.");
    button.disabled = true; button.textContent = "Đang giải mã khóa trong trình duyệt...";
    const bundle = JSON.parse(await file.text());
    if (bundle.version !== 1 || bundle.algorithm !== "RSA-PSS" || bundle.kdf !== "PBKDF2-SHA256" || bundle.cipher !== "AES-256-GCM") throw new Error("Định dạng file khóa không được hỗ trợ.");
    if (!Number.isInteger(bundle.iterations) || bundle.iterations < 100000 || bundle.iterations > 1000000) throw new Error("Thông số KDF trong file khóa không hợp lệ.");
    const material = await crypto.subtle.importKey("raw",new TextEncoder().encode(password),"PBKDF2",false,["deriveKey"]);
    const aesKey = await crypto.subtle.deriveKey({name:"PBKDF2",salt:base64ToBytes(bundle.salt),iterations:bundle.iterations,hash:"SHA-256"},material,{name:"AES-GCM",length:256},false,["decrypt"]);
    const pkcs8 = await crypto.subtle.decrypt({name:"AES-GCM",iv:base64ToBytes(bundle.iv)},aesKey,base64ToBytes(bundle.ciphertext));
    const privateKey = await crypto.subtle.importKey("pkcs8",pkcs8,{name:"RSA-PSS",hash:"SHA-256"},false,["sign"]);
    const publicKey = await crypto.subtle.importKey("spki",pemDecode(bundle.publicKeyPem),{name:"RSA-PSS",hash:"SHA-256"},true,["verify"]);
    const challenge = await api("/api/keys/challenge",{method:"POST"});
    const challengeBytes = new TextEncoder().encode(challenge.challenge);
    const proof = await crypto.subtle.sign({name:"RSA-PSS",saltLength:PSS_SALT_LENGTH},privateKey,challengeBytes);
    const pairMatches = await crypto.subtle.verify({name:"RSA-PSS",saltLength:PSS_SALT_LENGTH},publicKey,proof,challengeBytes);
    if (!pairMatches) throw new Error("Private Key và Public Key trong file không khớp nhau.");
    const proofBase64 = btoa(String.fromCharCode(...new Uint8Array(proof)));
    const name = bundle.owner || state.user.full_name;
    const data = await api("/api/keys",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({name,public_key_pem:bundle.publicKeyPem,challenge_id:challenge.challenge_id,proof_signature:proofBase64})});
    showNotice(`Đã nhập và đăng ký khóa hiện có. Fingerprint: ${data.item.fingerprint}`,"success");
    $("import-key-file").value = ""; $("import-key-password").value = "";
    await refreshKeys(); await refreshDirectory(); await refreshDashboard();
  } catch (err) { showNotice(err.message || "Không thể đăng ký khóa hiện có.","error"); }
  finally { button.disabled = false; button.textContent = "Giải mã cục bộ và đăng ký khóa hiện có"; }
});

async function refreshKeys() {
  try {
    const data = await api("/api/keys/mine");
    state.myKeys = data.items;
    $("key-count").textContent = `${data.items.filter(k=>k.status==="active").length} khóa hoạt động`;
    const list = $("my-keys-list"); list.innerHTML = "";
    if (!data.items.length) { list.className = "list-empty"; list.textContent = "Bạn chưa đăng ký Public Key nào."; }
    else {
      list.className = "";
      data.items.forEach(item => {
        const row = document.createElement("div"); row.className = "key-item";
        const info = document.createElement("div"); info.className = "key-item-meta";
        const title = document.createElement("strong"); title.textContent = item.name;
        const fp = document.createElement("code"); fp.textContent = item.fingerprint;
        const status = document.createElement("span"); status.className = `status-chip ${item.status}`; status.textContent = item.status === "active" ? "Đang hoạt động" : "Đã thu hồi";
        info.append(title,fp,status);
        row.append(info);
        if (item.status === "active") {
          const revoke = document.createElement("button"); revoke.textContent = "Thu hồi"; revoke.type = "button";
          revoke.addEventListener("click", async () => {
            if (!confirm(`Thu hồi khóa “${item.name}”? Khóa sẽ không dùng để gửi tài liệu mới.`)) return;
            try { await api(`/api/keys/${item.id}`,{method:"DELETE"}); await refreshKeys(); await refreshDirectory(); showNotice("Đã thu hồi khóa.","success"); }
            catch(err){showNotice(err.message,"error");}
          });
          row.append(revoke);
        }
        list.append(row);
      });
    }
    const sendSelect = $("send-key-select");
    sendSelect.innerHTML = '<option value="">-- Chọn khóa của tôi --</option>';
    data.items.filter(k=>k.status==="active").forEach(item=>{const opt=document.createElement("option");opt.value=item.id;opt.textContent=`${item.name} · ${item.fingerprint.slice(0,12)}…`;sendSelect.append(opt);});
  } catch (err) { if (state.user) showNotice(`Không tải được khóa: ${err.message}`,"error"); }
}

async function refreshDirectory() {
  try {
    const q = $("directory-search")?.value?.trim() || "";
    const data = await api(`/api/keys/directory${q?`?q=${encodeURIComponent(q)}`:""}`);
    state.directoryKeys = data.items;
    const select = $("verify-key-select");
    select.innerHTML = '<option value="">-- Chọn Public Key --</option>';
    data.items.forEach(item=>{const opt=document.createElement("option");opt.value=item.id;opt.textContent=`${item.owner_name} · ${item.name}${item.trusted?" · Tin cậy":""}`;select.append(opt);});
    const body = $("directory-body"); body.innerHTML = "";
    if (!data.items.length) { const tr=document.createElement("tr");const td=document.createElement("td");td.colSpan=5;td.className="empty-cell";td.textContent="Chưa có Public Key phù hợp.";tr.append(td);body.append(tr);return; }
    data.items.forEach(item=>{
      const tr=document.createElement("tr");
      const owner=document.createElement("td");owner.textContent=item.owner_name;
      const name=document.createElement("td");name.textContent=item.name;
      const fp=document.createElement("td");const code=document.createElement("code");code.textContent=item.fingerprint.slice(0,20)+"…";fp.append(code);
      const trust=document.createElement("td");const chip=document.createElement("span");chip.className=`status-chip ${item.trusted?"active":"pending"}`;chip.textContent=item.trusted?"Đã tin cậy":"Chưa tin cậy";trust.append(chip);
      const action=document.createElement("td");
      const pemBtn=document.createElement("button");pemBtn.className="btn btn-outline small";pemBtn.textContent="Tải PEM";pemBtn.addEventListener("click",()=>downloadProtected(`/api/keys/${item.id}/pem`,`public-key-${item.fingerprint.slice(0,12)}.pem`).catch(e=>showNotice(e.message,"error")));action.append(pemBtn);
      if (!item.is_mine) {
        const btn=document.createElement("button");btn.className="btn btn-outline small";btn.textContent=item.trusted?"Bỏ tin cậy":"Đánh dấu tin cậy";
        btn.addEventListener("click",async()=>{try{await api(`/api/keys/${item.id}/trust`,{method:item.trusted?"DELETE":"POST"});await refreshDirectory();showNotice(item.trusted?"Đã bỏ đánh dấu tin cậy.":"Đã thêm khóa vào danh sách tin cậy.","success");}catch(err){showNotice(err.message,"error");}});action.append(btn);
      } else { const own=document.createElement("span");own.className="status-chip active";own.textContent="Khóa của bạn";action.append(own); }
      tr.append(owner,name,fp,trust,action);body.append(tr);
    });
  } catch (err) { if (state.user) console.warn("Directory:",err.message); }
}
$("directory-search").addEventListener("change", refreshDirectory);

// --------------------------- Signing ---------------------------
$("sign-pdf").addEventListener("change", () => {
  const file = $("sign-pdf").files[0];
  if (!file) return;
  $("sign-file-info").textContent = `${file.name} · ${(file.size / 1024 / 1024).toFixed(2)} MB`;
  $("sign-file-info").classList.remove("hidden");
});
$("sign-button").addEventListener("click", async () => {
  const button = $("sign-button");
  try {
    const pdfFile = $("sign-pdf").files[0]; validatePdf(pdfFile);
    const keyFile = $("sign-private-key").files[0];
    const password = $("sign-password").value;
    if (!keyFile) throw new Error("Vui lòng chọn tệp Private Key đã mã hóa.");
    if (!password) throw new Error("Vui lòng nhập mật khẩu Private Key.");
    if (!window.isSecureContext || !crypto.subtle) throw new Error("Ký số cần HTTPS hoặc localhost.");
    button.disabled = true; button.textContent = "Đang giải mã và ký...";
    const bundle = JSON.parse(await keyFile.text());
    if (bundle.version !== 1 || bundle.algorithm !== "RSA-PSS" || bundle.kdf !== "PBKDF2-SHA256" || bundle.cipher !== "AES-256-GCM") throw new Error("Định dạng tệp khóa không được hỗ trợ.");
    if (!Number.isInteger(bundle.iterations) || bundle.iterations < 100000 || bundle.iterations > 1000000) throw new Error("Thông số KDF trong tệp khóa không hợp lệ.");
    const material = await crypto.subtle.importKey("raw",new TextEncoder().encode(password),"PBKDF2",false,["deriveKey"]);
    const aesKey = await crypto.subtle.deriveKey({name:"PBKDF2",salt:base64ToBytes(bundle.salt),iterations:bundle.iterations,hash:"SHA-256"},material,{name:"AES-GCM",length:256},false,["decrypt"]);
    const pkcs8 = await crypto.subtle.decrypt({name:"AES-GCM",iv:base64ToBytes(bundle.iv)},aesKey,base64ToBytes(bundle.ciphertext));
    const privateKey = await crypto.subtle.importKey("pkcs8",pkcs8,{name:"RSA-PSS",hash:"SHA-256"},false,["sign"]);
    const publicKey = await crypto.subtle.importKey("spki",pemDecode(bundle.publicKeyPem),{name:"RSA-PSS",hash:"SHA-256"},true,["verify"]);
    const fingerprint = await publicFingerprint(publicKey);
    const keyRecord = state.myKeys.find(k=>k.fingerprint===fingerprint && k.status==="active");
    if (!keyRecord) throw new Error("Public Key tương ứng chưa được đăng ký trong tài khoản của bạn. Hãy vào Quản lý khóa và đăng ký trước khi ký.");
    const pdfBytes = await pdfFile.arrayBuffer();
    const digest = await sha256(pdfBytes);
    const signature = await crypto.subtle.sign({name:"RSA-PSS",saltLength:PSS_SALT_LENGTH},privateKey,pdfBytes);
    const pairMatches = await crypto.subtle.verify({name:"RSA-PSS",saltLength:PSS_SALT_LENGTH},publicKey,signature,pdfBytes);
    if (!pairMatches) throw new Error("Private Key và Public Key trong tệp khóa không khớp nhau.");
    state.signatureBlob = new Blob([signature],{type:"application/octet-stream"});
    state.signatureName = `${pdfFile.name.replace(/\.pdf$/i,"")}.sig`;
    $("signed-name").textContent = pdfFile.name;
    $("signed-hash").textContent = digest;
    $("signed-fingerprint").textContent = fingerprint;
    $("sign-empty").classList.add("hidden"); $("sign-result").classList.remove("hidden");
    $("sign-status").textContent = "Đã ký"; $("sign-status").className = "pill good";
    const form = new FormData();
    form.append("pdf",pdfFile,pdfFile.name);
    form.append("signature",state.signatureBlob,state.signatureName);
    form.append("key_id",keyRecord.id);
    await api("/api/history/sign",{method:"POST",body:form});
    showNotice("Ký số thành công. Chữ ký đã được máy chủ kiểm tra bằng Public Key thuộc tài khoản.","success");
    refreshDashboard(); refreshHistory();
  } catch (err) { showNotice(err.message || "Không thể ký tài liệu.","error"); }
  finally { button.disabled = false; button.innerHTML = 'Tạo chữ ký số <span>→</span>'; }
});
$("download-signature").addEventListener("click",()=>{if(state.signatureBlob)downloadBlob(state.signatureBlob,state.signatureName);});

// --------------------------- Verification ---------------------------
$("verify-button").addEventListener("click",async()=>{
  const button=$("verify-button");
  try{
    const pdf=$("verify-pdf").files[0],sig=$("verify-signature").files[0];validatePdf(pdf);
    if(!sig)throw new Error("Vui lòng chọn tệp chữ ký .sig.");
    const keyId=$("verify-key-select").value,publicKeyFile=$("verify-public-key").files[0];
    if(!keyId&&!publicKeyFile)throw new Error("Chọn Public Key trong danh bạ hoặc tải lên tệp PEM.");
    button.disabled=true;button.textContent="Đang xác thực...";
    const form=new FormData();form.append("pdf",pdf,pdf.name);form.append("signature",sig,sig.name);
    if(keyId)form.append("key_id",keyId);else form.append("public_key",publicKeyFile,publicKeyFile.name);
    const result=await api("/api/verify",{method:"POST",body:form});
    $("verify-empty").classList.add("hidden");$("verify-result").classList.remove("hidden");
    $("verify-banner").className=result.valid?"success-banner":"success-banner invalid";
    $("verify-symbol").textContent=result.valid?"✓":"!";
    $("verify-heading").textContent=result.valid?"Chữ ký hợp lệ":"Chữ ký không hợp lệ";
    $("verify-message").textContent=result.message;
    $("verify-name").textContent=result.file_name;
    $("verify-hash").textContent=result.sha256;
    $("verify-fingerprint").textContent=result.fingerprint;
    $("trust-box").textContent=result.trusted?`Khóa đã được bạn đánh dấu tin cậy. Chủ sở hữu: ${result.key_owner_name||"Không rõ"} .`:result.key_owner_name?`Chữ ký được kiểm tra bằng khóa của ${result.key_owner_name}, nhưng bạn chưa đánh dấu khóa này là tin cậy.`:"Public Key tải lên chưa được liên kết với khóa trong danh bạ. Chưa xác minh được danh tính người sở hữu.";
    $("verify-status").textContent=result.valid?"HỢP LỆ":"KHÔNG HỢP LỆ";$("verify-status").className=result.valid?"pill good":"pill bad";
    showNotice(result.valid?"Xác thực mật mã thành công.":"Xác thực thất bại: chữ ký sai hoặc tài liệu đã thay đổi.",result.valid?"success":"error");
    refreshDashboard();refreshHistory();
  }catch(err){showNotice(err.message||"Không thể xác thực chữ ký.","error");}
  finally{button.disabled=false;button.innerHTML='Xác thực chữ ký <span>→</span>';}
});

// --------------------------- Send and receive documents ---------------------------
$("send-button").addEventListener("click",async()=>{
  const button=$("send-button");
  try{
    const recipient=$("send-recipient").value.trim();
    const keyId=$("send-key-select").value;
    const pdf=$("send-pdf").files[0],sig=$("send-signature").files[0];
    if(!recipient)throw new Error("Vui lòng nhập email người nhận.");
    if(!keyId)throw new Error("Vui lòng chọn Public Key đã đăng ký của bạn.");
    validatePdf(pdf);if(!sig)throw new Error("Vui lòng chọn chữ ký .sig.");
    button.disabled=true;button.textContent="Đang kiểm tra và gửi...";
    const form=new FormData();form.append("recipient_email",recipient);form.append("key_id",keyId);form.append("message",$("send-message").value.trim());form.append("pdf",pdf,pdf.name);form.append("signature",sig,sig.name);
    const data=await api("/api/documents/send",{method:"POST",body:form});
    showNotice(`Đã gửi “${data.item.file_name}” đến ${data.item.recipient.email}. Máy chủ đã xác minh chữ ký trước khi gửi.`,"success");
    $("send-recipient").value="";$("send-pdf").value="";$("send-signature").value="";$("send-message").value="";
    refreshDashboard();loadDocuments("sent");
  }catch(err){showNotice(err.message||"Không thể gửi tài liệu.","error");}
  finally{button.disabled=false;button.innerHTML='Kiểm tra và gửi tài liệu <span>→</span>';}
});
async function downloadProtected(url,filename){
  const response=await fetch(url,{credentials:"same-origin"});
  if(!response.ok){let data={};try{data=await response.json();}catch{}throw new Error(data.detail||"Không thể tải tệp.");}
  downloadBlob(await response.blob(),filename);
}
async function verifyDocument(id){
  try{
    const result=await api(`/api/documents/${id}/verify`,{method:"POST"});
    showNotice(`${result.valid?"Chữ ký hợp lệ":"Chữ ký không hợp lệ"}. ${result.trusted?"Khóa đã được bạn tin cậy.":"Khóa chưa được bạn đánh dấu tin cậy."}`,result.valid?"success":"error");
    await loadDocuments(state.documentsMode);refreshDashboard();refreshHistory();
  }catch(err){showNotice(err.message,"error");}
}
async function loadDocuments(mode="inbox"){
  state.documentsMode=mode;
  document.querySelectorAll("[data-doc-mode]").forEach(b=>b.classList.toggle("active",b.dataset.docMode===mode));
  $("documents-heading").textContent=mode==="inbox"?"Tài liệu nhận":"Tài liệu đã gửi";
  try{
    const data=await api(`/api/documents/${mode}`);
    const body=$("documents-body");body.innerHTML="";
    if(!data.items.length){const tr=document.createElement("tr"),td=document.createElement("td");td.colSpan=5;td.className="empty-cell";td.textContent=mode==="inbox"?"Hộp thư chưa có tài liệu.":"Bạn chưa gửi tài liệu nào.";tr.append(td);body.append(tr);return;}
    data.items.forEach(item=>{
      const tr=document.createElement("tr");
      const date=document.createElement("td");date.textContent=new Date(item.created_at).toLocaleString("vi-VN");
      const file=document.createElement("td");const strong=document.createElement("strong");strong.textContent=item.file_name;const msg=document.createElement("small");msg.className="table-subtext";msg.textContent=item.message||"Không có lời nhắn";file.append(strong,msg);
      const person=document.createElement("td");const p=item.direction==="received"?item.sender:item.recipient;person.textContent=p?`${p.name} · ${p.email}`:"—";
      const status=document.createElement("td");const chip=document.createElement("span");chip.className=`status-chip ${item.verification_status}`;chip.textContent=item.verification_status==="pending"?"Chưa xác thực":item.verification_status==="valid"?"Hợp lệ":"Không hợp lệ";status.append(chip);
      const actions=document.createElement("td");const wrap=document.createElement("div");wrap.className="action-buttons";
      const verifyBtn=document.createElement("button");verifyBtn.className="btn btn-outline small";verifyBtn.textContent="Kiểm tra";verifyBtn.addEventListener("click",()=>verifyDocument(item.id));
      const pdfBtn=document.createElement("button");pdfBtn.className="btn btn-secondary small";pdfBtn.textContent="PDF";pdfBtn.addEventListener("click",()=>downloadProtected(`/api/documents/${item.id}/pdf`,item.file_name).catch(e=>showNotice(e.message,"error")));
      const sigBtn=document.createElement("button");sigBtn.className="btn btn-outline small";sigBtn.textContent=".sig";sigBtn.addEventListener("click",()=>downloadProtected(`/api/documents/${item.id}/signature`,`${item.file_name.replace(/\.pdf$/i,"")}.sig`).catch(e=>showNotice(e.message,"error")));
      wrap.append(verifyBtn,pdfBtn,sigBtn);actions.append(wrap);tr.append(date,file,person,status,actions);body.append(tr);
    });
  }catch(err){showNotice(`Không tải được hộp thư: ${err.message}`,"error");}
}
document.querySelectorAll("[data-doc-mode]").forEach(b=>b.addEventListener("click",()=>loadDocuments(b.dataset.docMode)));
$("refresh-documents").addEventListener("click",()=>loadDocuments(state.documentsMode));

// --------------------------- History ---------------------------
async function refreshHistory(){
  try{
    const data=await api("/api/history");const body=$("history-body");body.innerHTML="";
    if(!data.items.length){const tr=document.createElement("tr"),td=document.createElement("td");td.colSpan=5;td.className="empty-cell";td.textContent="Chưa có dữ liệu.";tr.append(td);body.append(tr);return;}
    data.items.forEach(item=>{
      const tr=document.createElement("tr");
      const values=[new Date(item.created_at).toLocaleString("vi-VN"),item.event_type,item.file_name||item.details||"—",item.result,item.sha256?item.sha256.slice(0,20)+"…":"—"];
      values.forEach((value,index)=>{const td=document.createElement("td");if(index===1){const tag=document.createElement("span");tag.className=`event-tag ${item.event_type.toLowerCase()}`;tag.textContent=value;td.append(tag);}else if(index===3){const tag=document.createElement("span");tag.className=`result-tag ${item.result.toLowerCase()}`;tag.textContent=value;td.append(tag);}else if(index===4){const code=document.createElement("code");code.textContent=value;td.append(code);}else td.textContent=value;tr.append(td);});
      body.append(tr);
    });
  }catch(err){showNotice(`Không tải được lịch sử: ${err.message}`,"error");}
}
$("refresh-history").addEventListener("click",refreshHistory);

// --------------------------- Admin ---------------------------
async function loadAdmin(){
  if(state.user?.role!=="admin")return;
  try{
    const [overview,users]=await Promise.all([api("/api/admin/overview"),api(`/api/admin/users${$("admin-search").value.trim()?`?q=${encodeURIComponent($("admin-search").value.trim())}`:""}`)]);
    $("admin-total-users").textContent=overview.users;$("admin-active-users").textContent=overview.active_users;$("admin-total-keys").textContent=overview.keys;$("admin-total-docs").textContent=overview.documents;
    const body=$("admin-users-body");body.innerHTML="";
    users.items.forEach(u=>{
      const tr=document.createElement("tr");
      const person=document.createElement("td");const strong=document.createElement("strong");strong.textContent=u.full_name;const small=document.createElement("small");small.className="table-subtext";small.textContent=u.email;person.append(strong,small);
      const role=document.createElement("td");const roleChip=document.createElement("span");roleChip.className="status-chip";roleChip.textContent=u.role;role.append(roleChip);
      const status=document.createElement("td");const statusChip=document.createElement("span");statusChip.className=`status-chip ${u.status}`;statusChip.textContent=u.status==="active"?"Hoạt động":"Đã khóa";status.append(statusChip);
      const keys=document.createElement("td");keys.textContent=u.key_count;const docs=document.createElement("td");docs.textContent=u.document_count;
      const actions=document.createElement("td");const wrap=document.createElement("div");wrap.className="action-buttons";
      if(u.id!==state.user.id){
        const statusBtn=document.createElement("button");statusBtn.className="btn btn-outline small";statusBtn.textContent=u.status==="active"?"Khóa":"Mở khóa";statusBtn.addEventListener("click",()=>updateAdminUser(u.id,{status:u.status==="active"?"suspended":"active"}));
        const roleBtn=document.createElement("button");roleBtn.className="btn btn-secondary small";roleBtn.textContent=u.role==="admin"?"Hạ quyền":"Cấp admin";roleBtn.addEventListener("click",()=>updateAdminUser(u.id,{role:u.role==="admin"?"user":"admin"}));
        wrap.append(statusBtn,roleBtn);
      }else{wrap.textContent="Tài khoản hiện tại";}
      actions.append(wrap);tr.append(person,role,status,keys,docs,actions);body.append(tr);
    });
    if(!users.items.length){const tr=document.createElement("tr"),td=document.createElement("td");td.colSpan=6;td.className="empty-cell";td.textContent="Không tìm thấy tài khoản.";tr.append(td);body.append(tr);}
  }catch(err){showNotice(`Không tải được trang quản trị: ${err.message}`,"error");}
}
async function updateAdminUser(id,payload){
  const action=payload.status?`đổi trạng thái thành ${payload.status}`:`đổi vai trò thành ${payload.role}`;
  if(!confirm(`Bạn có chắc muốn ${action}?`))return;
  try{await api(`/api/admin/users/${id}`,{method:"PATCH",headers:{"Content-Type":"application/json"},body:JSON.stringify(payload)});showNotice("Đã cập nhật tài khoản.","success");await loadAdmin();}
  catch(err){showNotice(err.message,"error");}
}
$("admin-search").addEventListener("change",loadAdmin);

async function init(){
  await checkHealth();
  const params = new URLSearchParams(window.location.search);
  if (params.has("reset_token")) {
    showAuth(); setAuthMode("reset"); $("reset-token").value = params.get("reset_token"); return;
  }
  if (params.get("verified") === "1") {
    showAuth(); showAuthNotice("Email đã được xác minh. Bạn có thể đăng nhập.","success"); return;
  }
  if (params.get("verify_error") === "1") {
    showAuth(); showAuthNotice("Liên kết xác minh không hợp lệ hoặc đã hết hạn. Hãy yêu cầu gửi lại email."); return;
  }
  try{
    const data=await api("/api/auth/me");
    const csrf=await api("/api/auth/csrf");state.csrf=csrf.csrf_token;
    showApp(data.user);
  }catch{showAuth();}
}
init();
