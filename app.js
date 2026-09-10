// ============================================================
// 前端主逻辑 v2 - 12人加密群聊 / 每人独立密钥分区 / 12层嵌套
// ============================================================

const State = {
  user: null,
  groupKey: null,
  privateKeys: null,
  decodeOrder: null,
  messages: [],
  sse: null,
  selectedHistory: new Set(),
  currentSetupUser: null,
  webrtc: { pc: null, localStream: null, callType: null, incoming: false, pendingOffer: null, targetUserId: null }
};

const API_BASE = '';

async function api(path, options = {}) {
  const headers = { 'Content-Type': 'application/json', ...(options.headers || {}) };
  if (State.user && State.user.token) headers['Authorization'] = 'Bearer ' + State.user.token;
  const res = await fetch(API_BASE + path, { ...options, headers });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || '请求失败');
  return data;
}

async function apiUpload(path, formData) {
  const headers = {};
  if (State.user && State.user.token) headers['Authorization'] = 'Bearer ' + State.user.token;
  const res = await fetch(API_BASE + path, { method: 'POST', body: formData, headers });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || '上传失败');
  return data;
}

function showView(id) {
  document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
  document.getElementById(id).classList.add('active');
}

function toast(msg, duration = 2500) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), duration);
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

function scrollToBottom() {
  document.getElementById('messages-container').scrollTop = document.getElementById('messages-container').scrollHeight;
}

function copyToClipboard(text, msg) {
  navigator.clipboard.writeText(text).then(() => toast(msg)).catch(() => {
    const ta = document.createElement('textarea');
    ta.value = text; document.body.appendChild(ta); ta.select();
    document.execCommand('copy'); document.body.removeChild(ta);
    toast(msg);
  });
}

let currentCaptchaToken = '';
async function refreshCaptcha() {
  try {
    const data = await api('/api/captcha');
    document.getElementById('captcha-question').textContent = data.question;
    currentCaptchaToken = data.token;
  } catch (e) { document.getElementById('captcha-question').textContent = '刷新失败'; }
}

// ---------- 登录/注册 ----------
async function handleLogin() {
  const username = document.getElementById('login-username').value.trim();
  const password = document.getElementById('login-password').value;
  const captcha = document.getElementById('login-captcha').value.trim();
  const errorEl = document.getElementById('login-error');
  if (!username || !password || !captcha) { errorEl.textContent = '请填写所有字段'; return; }
  try {
    const data = await api('/api/login', {
      method: 'POST',
      body: JSON.stringify({ username, password, captcha_token: currentCaptchaToken, captcha_answer: captcha })
    });
    State.user = { id: data.user_id, username: data.username, role: data.role, display_name: data.display_name, token: data.token };
    if (data.role === 'admin') localStorage.setItem('permanent_token', data.token);
    await enterChatFlow();
  } catch (e) {
    errorEl.textContent = e.message;
    refreshCaptcha();
    document.getElementById('login-captcha').value = '';
  }
}

async function handleRegister() {
  const username = document.getElementById('reg-username').value.trim();
  const displayName = document.getElementById('reg-displayname').value.trim();
  const password = document.getElementById('reg-password').value;
  const role = document.getElementById('reg-role').value;
  if (!username || !password) { toast('请填写账号和密码'); return; }
  try {
    await api('/api/register', { method: 'POST', body: JSON.stringify({ username, password, display_name: displayName, role }) });
    toast('账号创建成功, 请登录');
    document.getElementById('reg-username').value = '';
    document.getElementById('reg-displayname').value = '';
    document.getElementById('reg-password').value = '';
  } catch (e) { toast(e.message); }
}

// ---------- 进入聊天流程 ----------
async function enterChatFlow() {
  const privateKeys = CryptoModule.load('user_private_keys');
  const decodeOrder = CryptoModule.load('user_decode_order');

  if (State.user.role === 'admin') {
    let groupKeyB64 = CryptoModule.load('admin_group_key');
    if (!groupKeyB64) {
      State.groupKey = CryptoModule.generateGroupKey();
      CryptoModule.store('admin_group_key', CryptoModule.b64encode(State.groupKey));
    } else {
      State.groupKey = CryptoModule.b64decode(groupKeyB64);
    }
    State.privateKeys = privateKeys;
    State.decodeOrder = decodeOrder;
    enterChat();
  } else {
    if (!privateKeys || !decodeOrder) { showView('keyexchange-view'); return; }
    State.privateKeys = privateKeys;
    State.decodeOrder = decodeOrder;
    try {
      const wrap = await api('/api/keywrap');
      State.groupKey = await CryptoModule.unwrapGroupKey(wrap, State.privateKeys, State.decodeOrder);
      enterChat();
    } catch (e) {
      toast('群组密钥解密失败: ' + e.message);
      showView('keyexchange-view');
    }
  }
}

// ---------- 客户端密钥配置 ----------
async function handleKeyExchange() {
  const otp = document.getElementById('exchange-otp').value.trim();
  const bundleText = document.getElementById('exchange-bundle').value.trim();
  const errorEl = document.getElementById('exchange-error');
  if (!otp || !bundleText) { errorEl.textContent = '请输入OTP和密钥包'; return; }
  try {
    const bundle = JSON.parse(bundleText);
    const decrypted = await CryptoModule.decryptKeyBundle(bundle, otp);
    State.decodeOrder = decrypted.decode_order;
    State.privateKeys = decrypted.private_keys;
    CryptoModule.store('user_private_keys', decrypted.private_keys);
    CryptoModule.store('user_decode_order', decrypted.decode_order);
    const wrap = await api('/api/keywrap');
    State.groupKey = await CryptoModule.unwrapGroupKey(wrap, State.privateKeys, State.decodeOrder);
    document.getElementById('exchange-error').textContent = '';
    document.getElementById('exchange-success').style.display = 'block';
    setTimeout(() => enterChat(), 1500);
  } catch (e) {
    errorEl.textContent = '解密失败: OTP错误或密钥包无效';
  }
}

// ---------- 管理员: 成员管理 ----------
async function openUsersPanel() {
  document.getElementById('users-panel').classList.add('open');
  document.getElementById('panel-overlay').style.display = 'block';
  await loadUserList();
}

function closeUsersPanel() {
  document.getElementById('users-panel').classList.remove('open');
  document.getElementById('panel-overlay').style.display = 'none';
}

async function loadUserList() {
  try {
    const data = await api('/api/users');
    const list = document.getElementById('user-list');
    list.innerHTML = '';
    for (const u of data.users) {
      if (u.id === State.user.id) continue;
      const item = document.createElement('div');
      item.className = 'user-item';
      const initial = (u.display_name || u.username).charAt(0).toUpperCase();
      const statusText = u.key_wrap_configured ? '✅ 密钥已配置' : '⚠️ 待配置密钥';
      const statusClass = u.key_wrap_configured ? 'configured' : 'unconfigured';
      item.innerHTML = `
        <div class="user-avatar">${initial}</div>
        <div class="user-info">
          <div class="user-name">${escapeHtml(u.display_name || u.username)}</div>
          <div class="user-status ${statusClass}">${statusText}</div>
        </div>
        <div class="user-role-badge">${u.role === 'admin' ? '管理员' : '成员'}</div>`;
      item.addEventListener('click', () => openKeySetup(u));
      list.appendChild(item);
    }
    if (list.children.length === 0) list.innerHTML = '<p class="panel-empty">暂无其他成员</p>';
  } catch (e) {
    document.getElementById('user-list').innerHTML = '<p class="panel-empty">加载失败</p>';
  }
}

// ---------- 管理员: 为成员配置密钥 ----------
function openKeySetup(user) {
  State.currentSetupUser = user;
  document.getElementById('keysetup-title').textContent = `为 ${user.display_name || user.username} 配置密钥`;
  document.getElementById('keysetup-modal').style.display = 'flex';
  document.getElementById('ks-result').style.display = 'none';
  document.getElementById('ks-progress').style.display = 'none';
  document.getElementById('ks-start').style.display = 'block';
  ['ks-step-1','ks-step-2','ks-step-3'].forEach(id => document.getElementById(id).classList.remove('active','done'));
}

function closeKeySetup() {
  document.getElementById('keysetup-modal').style.display = 'none';
  State.currentSetupUser = null;
}

function updateKsProgress(pct, text) {
  document.getElementById('ks-progress-fill').style.width = pct + '%';
  document.getElementById('ks-progress-text').textContent = text;
}

async function startKeySetup() {
  const user = State.currentSetupUser;
  if (!user) return;
  document.getElementById('ks-start').style.display = 'none';
  document.getElementById('ks-progress').style.display = 'block';
  try {
    document.getElementById('ks-step-1').classList.add('active');
    updateKsProgress(5, '正在生成48对RSA-2048密钥...');
    const keyPairs = await CryptoModule.generate48KeyPairs();
    updateKsProgress(30, '密钥生成完成!');

    document.getElementById('ks-step-2').classList.add('active');
    document.getElementById('ks-step-1').classList.add('done');
    updateKsProgress(35, '正在导出公钥...');
    const pubKeys = [];
    for (let i = 0; i < 48; i++) pubKeys.push(await CryptoModule.exportPublicKey(keyPairs[i]));
    updateKsProgress(45, '正在上传公钥...');
    await api('/api/keys', { method: 'POST', body: JSON.stringify({ user_id: user.id, keys: pubKeys }) });

    const decodeOrder = CryptoModule.generateDecodeOrder();
    updateKsProgress(60, '正在用12层嵌套加密封装群组密钥...');
    const wrap = await CryptoModule.wrapGroupKey(State.groupKey, pubKeys, decodeOrder);
    updateKsProgress(75, '正在上传密钥封装...');
    await api('/api/keywrap', { method: 'POST', body: JSON.stringify({ user_id: user.id, ...wrap, key_version: 1 }) });

    document.getElementById('ks-step-3').classList.add('active');
    document.getElementById('ks-step-2').classList.add('done');
    updateKsProgress(85, '正在生成OTP和密钥包...');
    const otp = CryptoModule.generateOTP();
    const keyBundle = await CryptoModule.createKeyBundle(keyPairs, decodeOrder, otp);
    updateKsProgress(100, '配置完成!');
    document.getElementById('ks-step-3').classList.add('done');

    document.getElementById('ks-otp').textContent = otp;
    document.getElementById('ks-bundle').textContent = JSON.stringify(keyBundle);
    document.getElementById('ks-result').style.display = 'block';
    document.getElementById('ks-progress').style.display = 'none';
    toast('密钥配置完成! 请将OTP和密钥包发送给该成员');
  } catch (e) {
    toast('配置失败: ' + e.message);
    document.getElementById('ks-start').style.display = 'block';
    document.getElementById('ks-progress').style.display = 'none';
  }
}

async function rotateGroupKey() {
  if (!confirm('确定要轮换群组密钥? 所有成员需要重新配置密钥。')) return;
  try {
    State.groupKey = CryptoModule.generateGroupKey();
    CryptoModule.store('admin_group_key', CryptoModule.b64encode(State.groupKey));
    toast('群组密钥已轮换, 请为每个成员重新配置密钥');
    closeUsersPanel();
  } catch (e) { toast('轮换失败: ' + e.message); }
}

// ---------- 聊天 ----------
async function enterChat() {
  showView('chat-view');
  if (State.user.role === 'client') {
    State.messages = [];
    document.getElementById('messages-container').innerHTML = `
      <div class="welcome-msg">
        <p>🔒 消息经群组AES密钥加密</p>
        <p class="welcome-sub">退出后历史记录将自动清除</p>
      </div>`;
  }
  document.getElementById('btn-users').style.display = State.user.role === 'admin' ? 'block' : 'none';
  document.getElementById('btn-history').style.display = State.user.role === 'admin' ? 'block' : 'none';
  await loadMessages();
  connectSSE();
}

async function loadMessages() {
  try {
    const since = State.messages.length > 0 ? State.messages[State.messages.length - 1].timestamp : 0;
    const data = await api('/api/messages?since=' + since);
    for (const msg of data.messages) {
      if (!State.messages.find(m => m.id === msg.id)) {
        State.messages.push(msg);
        await renderMessage(msg);
      }
    }
    scrollToBottom();
  } catch (e) { console.error('加载消息失败', e); }
}

async function renderMessage(msg) {
  const container = document.getElementById('messages-container');
  const isSelf = msg.sender_id === State.user.id;
  const div = document.createElement('div');
  div.className = 'message ' + (isSelf ? 'self' : 'other');
  const time = new Date(msg.timestamp).toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit' });
  const senderName = msg.sender_display || msg.sender_name || '成员';
  div.innerHTML = `
    ${!isSelf ? `<div class="message-sender">${escapeHtml(senderName)}</div>` : ''}
    <div class="message-content decrypting">解密中...</div>
    <div class="message-time">${time}</div>`;
  container.appendChild(div);
  try {
    const plaintext = await CryptoModule.decryptMessage(msg, State.groupKey);
    const contentEl = div.querySelector('.message-content');
    contentEl.classList.remove('decrypting');
    contentEl.innerHTML = formatMessageContent(plaintext);
  } catch (e) {
    div.querySelector('.message-content').textContent = '⚠️ 解密失败';
  }
}

function formatMessageContent(obj) {
  if (obj.type === 'text') return escapeHtml(obj.content).replace(/\n/g, '<br>');
  if (obj.type === 'image') return `<img src="/api/file?id=${obj.file_id}" alt="图片" loading="lazy"><br>${obj.caption ? escapeHtml(obj.caption) : ''}`;
  if (obj.type === 'mixed') {
    return obj.content.map(part => {
      if (part.type === 'text') return escapeHtml(part.text).replace(/\n/g, '<br>');
      if (part.type === 'image') return `<img src="/api/file?id=${part.file_id}" alt="图片" loading="lazy">`;
      return '';
    }).join(' ');
  }
  return escapeHtml(JSON.stringify(obj));
}

async function sendMessage() {
  const input = document.getElementById('message-input');
  const text = input.value.trim();
  if (!text) return;
  input.value = '';
  input.style.height = 'auto';
  document.getElementById('encrypt-status').textContent = '加密中...';
  try {
    const encrypted = await CryptoModule.encryptMessage({ type: 'text', content: text }, State.groupKey);
    await api('/api/messages', { method: 'POST', body: JSON.stringify({ ...encrypted, message_type: 'text' }) });
    document.getElementById('encrypt-status').textContent = '';
  } catch (e) {
    document.getElementById('encrypt-status').textContent = '发送失败';
    toast('发送失败: ' + e.message);
  }
}

async function handleImageUpload(files) {
  for (const file of files) {
    document.getElementById('encrypt-status').textContent = '上传中...';
    try {
      const formData = new FormData();
      formData.append('file', file);
      const uploadRes = await apiUpload('/api/upload', formData);
      document.getElementById('encrypt-status').textContent = '加密中...';
      const encrypted = await CryptoModule.encryptMessage(
        { type: 'image', file_id: uploadRes.file_id, caption: file.name }, State.groupKey
      );
      await api('/api/messages', { method: 'POST', body: JSON.stringify({ ...encrypted, message_type: 'image' }) });
      document.getElementById('encrypt-status').textContent = '';
    } catch (e) {
      document.getElementById('encrypt-status').textContent = '上传失败';
      toast('图片发送失败: ' + e.message);
    }
  }
}

// ---------- SSE ----------
function connectSSE() {
  if (State.sse) State.sse.close();
  const es = new EventSource(API_BASE + '/api/stream?token=' + encodeURIComponent(State.user.token));
  State.sse = es;
  es.addEventListener('connected', () => { document.getElementById('chat-status').textContent = '在线'; });
  es.addEventListener('new_message', async (e) => {
    const msg = JSON.parse(e.data);
    if (!State.messages.find(m => m.id === msg.id)) {
      State.messages.push(msg);
      await renderMessage(msg);
      scrollToBottom();
    }
  });
  es.addEventListener('shared_history', async (e) => {
    const data = JSON.parse(e.data);
    toast('收到分享的历史消息');
    for (const msg of data.messages) {
      if (!State.messages.find(m => m.id === msg.id)) {
        State.messages.push(msg);
        await renderMessage(msg);
      }
    }
    scrollToBottom();
  });
  es.addEventListener('webrtc_signal', (e) => handleWebRTCSignal(JSON.parse(e.data)));
  es.addEventListener('ping', () => {});
  es.onerror = () => {
    document.getElementById('chat-status').textContent = '重连中...';
    setTimeout(() => { if (State.user) connectSSE(); }, 3000);
  };
}

// ---------- 历史记录 ----------
async function openHistory() {
  document.getElementById('history-panel').classList.add('open');
  document.getElementById('panel-overlay').style.display = 'block';
  State.selectedHistory.clear();
  try {
    const data = await api('/api/users');
    const select = document.getElementById('share-target');
    select.innerHTML = '<option value="">分享给...</option>';
    for (const u of data.users) {
      if (u.id !== State.user.id) select.innerHTML += `<option value="${u.id}">${escapeHtml(u.display_name || u.username)}</option>`;
    }
  } catch (e) {}
  try {
    const data = await api('/api/history');
    const list = document.getElementById('history-list');
    list.innerHTML = '';
    if (data.messages.length === 0) { list.innerHTML = '<p class="panel-empty">暂无历史消息</p>'; return; }
    for (const msg of data.messages) {
      let preview = '...';
      try {
        const pt = await CryptoModule.decryptMessage(msg, State.groupKey);
        if (pt.type === 'text') preview = pt.content.substring(0, 50);
        else if (pt.type === 'image') preview = '[图片] ' + (pt.caption || '');
      } catch (e) { preview = '[解密失败]'; }
      const time = new Date(msg.timestamp).toLocaleString('zh-CN', { month:'2-digit', day:'2-digit', hour:'2-digit', minute:'2-digit' });
      const item = document.createElement('div');
      item.className = 'history-item';
      item.dataset.id = msg.id;
      item.innerHTML = `
        <input type="checkbox" class="history-check">
        <div class="history-item-content">
          <div class="history-item-sender">${escapeHtml(msg.sender_display || msg.sender_name)} · ${time}</div>
          <div class="history-item-text">${escapeHtml(preview)}</div>
        </div>`;
      item.addEventListener('click', (e) => {
        if (e.target.type !== 'checkbox') { const cb = item.querySelector('.history-check'); cb.checked = !cb.checked; }
        if (item.querySelector('.history-check').checked) {
          item.classList.add('selected'); State.selectedHistory.add(parseInt(item.dataset.id));
        } else {
          item.classList.remove('selected'); State.selectedHistory.delete(parseInt(item.dataset.id));
        }
      });
      list.appendChild(item);
    }
  } catch (e) {
    document.getElementById('history-list').innerHTML = '<p class="panel-empty">加载失败</p>';
  }
}

function closeHistory() {
  document.getElementById('history-panel').classList.remove('open');
  document.getElementById('panel-overlay').style.display = 'none';
}

function selectAllHistory() {
  const items = document.querySelectorAll('.history-item');
  const allChecked = Array.from(items).every(i => i.querySelector('.history-check').checked);
  items.forEach(item => {
    const cb = item.querySelector('.history-check');
    cb.checked = !allChecked;
    if (!allChecked) { item.classList.add('selected'); State.selectedHistory.add(parseInt(item.dataset.id)); }
    else { item.classList.remove('selected'); State.selectedHistory.delete(parseInt(item.dataset.id)); }
  });
}

async function shareSelected() {
  const targetId = document.getElementById('share-target').value;
  if (!targetId) { toast('请选择分享对象'); return; }
  if (State.selectedHistory.size === 0) { toast('请先选择消息'); return; }
  try {
    await api('/api/share', {
      method: 'POST',
      body: JSON.stringify({ message_ids: Array.from(State.selectedHistory), target_user_id: parseInt(targetId) })
    });
    toast(`已分享 ${State.selectedHistory.size} 条消息`);
    State.selectedHistory.clear();
    closeHistory();
  } catch (e) { toast('分享失败: ' + e.message); }
}

// ---------- WebRTC ----------
const RTC_CONFIG = {
  iceServers: [
    { urls: 'stun:stun.l.google.com:19302' },
    { urls: 'stun:stun1.l.google.com:19302' },
    { urls: 'turn:openrelay.metered.ca:80', username: 'openrelayproject', credential: 'openrelayproject' }
  ]
};

async function openCallSelect() {
  document.getElementById('call-select-modal').style.display = 'flex';
  try {
    const data = await api('/api/users');
    const list = document.getElementById('call-user-list');
    list.innerHTML = '';
    for (const u of data.users) {
      if (u.id === State.user.id) continue;
      const item = document.createElement('div');
      item.className = 'user-item';
      const initial = (u.display_name || u.username).charAt(0).toUpperCase();
      item.innerHTML = `
        <div class="user-avatar">${initial}</div>
        <div class="user-info">
          <div class="user-name">${escapeHtml(u.display_name || u.username)}</div>
          <div class="user-status">点击语音通话</div>
        </div>`;
      item.addEventListener('click', () => {
        document.getElementById('call-select-modal').style.display = 'none';
        startCall('audio', u.id, u.display_name || u.username);
      });
      list.appendChild(item);
    }
  } catch (e) {
    document.getElementById('call-user-list').innerHTML = '<p class="panel-empty">加载失败</p>';
  }
}

async function startCall(type, targetUserId, targetName) {
  State.webrtc.callType = type;
  State.webrtc.targetUserId = targetUserId;
  State.webrtc.incoming = false;
  try {
    State.webrtc.localStream = await navigator.mediaDevices.getUserMedia({ audio: true });
    const pc = new RTCPeerConnection(RTC_CONFIG);
    State.webrtc.pc = pc;
    State.webrtc.localStream.getTracks().forEach(t => pc.addTrack(t, State.webrtc.localStream));
    pc.ontrack = (e) => { const rv = document.getElementById('remote-video'); if (rv) rv.srcObject = e.streams[0]; };
    pc.onicecandidate = (e) => { if (e.candidate) sendSignal('ice', { candidate: e.candidate }, targetUserId); };
    pc.onconnectionstatechange = () => {
      if (pc.connectionState === 'connected') document.getElementById('call-status').textContent = '通话中...';
      else if (pc.connectionState === 'disconnected' || pc.connectionState === 'failed') endCall();
    };
    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);
    sendSignal('offer', { sdp: offer, type }, targetUserId);
    document.getElementById('call-peer-name').textContent = targetName;
    document.getElementById('call-overlay').style.display = 'flex';
    document.getElementById('call-status').textContent = '正在呼叫...';
    document.getElementById('call-audio-visual').style.display = 'block';
    document.getElementById('call-video-container').style.display = 'none';
    document.getElementById('btn-accept-call').style.display = 'none';
  } catch (e) {
    toast('无法访问麦克风: ' + e.message);
    cleanupWebRTC();
  }
}

async function handleWebRTCSignal(data) {
  const { type, payload, from, from_name } = data;
  if (type === 'offer') {
    State.webrtc.incoming = true;
    State.webrtc.callType = payload.type;
    State.webrtc.pendingOffer = payload.sdp;
    State.webrtc.targetUserId = from;
    document.getElementById('incoming-title').textContent = (from_name || '成员') + ' 来电...';
    document.getElementById('incoming-type').textContent = '语音通话';
    document.getElementById('incoming-call').style.display = 'flex';
  }
  if (type === 'answer' && State.webrtc.pc) {
    await State.webrtc.pc.setRemoteDescription(new RTCSessionDescription(payload.sdp));
  }
  if (type === 'ice' && State.webrtc.pc) {
    try { await State.webrtc.pc.addIceCandidate(new RTCIceCandidate(payload.candidate)); } catch (e) {}
  }
  if (type === 'hangup') endCall();
}

async function acceptCall() {
  document.getElementById('incoming-call').style.display = 'none';
  try {
    State.webrtc.localStream = await navigator.mediaDevices.getUserMedia({ audio: true });
    const pc = new RTCPeerConnection(RTC_CONFIG);
    State.webrtc.pc = pc;
    State.webrtc.localStream.getTracks().forEach(t => pc.addTrack(t, State.webrtc.localStream));
    pc.ontrack = (e) => { const rv = document.getElementById('remote-video'); if (rv) rv.srcObject = e.streams[0]; };
    pc.onicecandidate = (e) => { if (e.candidate) sendSignal('ice', { candidate: e.candidate }, State.webrtc.targetUserId); };
    pc.onconnectionstatechange = () => {
      if (pc.connectionState === 'connected') document.getElementById('call-status').textContent = '通话中...';
      else if (pc.connectionState === 'disconnected' || pc.connectionState === 'failed') endCall();
    };
    await pc.setRemoteDescription(new RTCSessionDescription(State.webrtc.pendingOffer));
    const answer = await pc.createAnswer();
    await pc.setLocalDescription(answer);
    sendSignal('answer', { sdp: answer }, State.webrtc.targetUserId);
    document.getElementById('call-peer-name').textContent = '对方';
    document.getElementById('call-overlay').style.display = 'flex';
    document.getElementById('call-status').textContent = '连接中...';
    document.getElementById('call-audio-visual').style.display = 'block';
    document.getElementById('call-video-container').style.display = 'none';
    document.getElementById('btn-accept-call').style.display = 'none';
  } catch (e) {
    toast('接听失败: ' + e.message);
    sendSignal('hangup', {}, State.webrtc.targetUserId);
    cleanupWebRTC();
  }
}

function rejectCall() {
  document.getElementById('incoming-call').style.display = 'none';
  sendSignal('hangup', {}, State.webrtc.targetUserId);
  State.webrtc.incoming = false;
}

function endCall() {
  if (State.webrtc.targetUserId) sendSignal('hangup', {}, State.webrtc.targetUserId);
  document.getElementById('call-overlay').style.display = 'none';
  document.getElementById('incoming-call').style.display = 'none';
  cleanupWebRTC();
}

function cleanupWebRTC() {
  if (State.webrtc.localStream) State.webrtc.localStream.getTracks().forEach(t => t.stop());
  if (State.webrtc.pc) State.webrtc.pc.close();
  State.webrtc = { pc: null, localStream: null, callType: null, incoming: false, pendingOffer: null, targetUserId: null };
}

function toggleMute() {
  if (State.webrtc.localStream) {
    const t = State.webrtc.localStream.getAudioTracks()[0];
    if (t) { t.enabled = !t.enabled; document.getElementById('btn-mute').textContent = t.enabled ? '🎤 静音' : '🔇 取消'; }
  }
}

function sendSignal(type, payload, targetUserId) {
  api('/api/signal', { method: 'POST', body: JSON.stringify({ type, payload, target_user_id: targetUserId }) }).catch(() => {});
}

// ---------- 登出 ----------
async function handleLogout() {
  try { await api('/api/logout', { method: 'POST' }); } catch (e) {}
  if (State.sse) State.sse.close();
  if (State.user && State.user.role === 'client') State.messages = [];
  State.user = null; State.sse = null; State.groupKey = null;
  localStorage.removeItem('permanent_token');
  showView('login-view');
  refreshCaptcha();
}

// ---------- 自动登录 ----------
async function tryAutoLogin() {
  const token = localStorage.getItem('permanent_token');
  if (!token) return false;
  try {
    const res = await fetch(API_BASE + '/api/check-token', { headers: { 'Authorization': 'Bearer ' + token } });
    if (!res.ok) return false;
    const data = await res.json();
    State.user = { id: data.user_id, username: data.username, role: data.role, display_name: data.display_name, token };
    await enterChatFlow();
    return true;
  } catch (e) { return false; }
}

// ---------- 初始化 ----------
document.addEventListener('DOMContentLoaded', async () => {
  const destroyAt = CryptoModule.load('otp_destroy_at');
  if (destroyAt && Date.now() >= destroyAt) {
    CryptoModule.remove('pending_otp'); CryptoModule.remove('pending_keybundle'); CryptoModule.remove('otp_destroy_at');
  }

  document.getElementById('btn-login').addEventListener('click', handleLogin);
  document.getElementById('btn-register').addEventListener('click', handleRegister);
  document.getElementById('captcha-question').addEventListener('click', refreshCaptcha);
  document.getElementById('btn-exchange').addEventListener('click', handleKeyExchange);
  document.getElementById('btn-send').addEventListener('click', sendMessage);
  document.getElementById('btn-emoji').addEventListener('click', () => {
    const p = document.getElementById('emoji-panel');
    p.style.display = p.style.display === 'none' ? 'block' : 'none';
  });
  document.getElementById('btn-image').addEventListener('click', () => document.getElementById('image-input').click());
  document.getElementById('image-input').addEventListener('change', (e) => {
    if (e.target.files.length > 0) handleImageUpload(Array.from(e.target.files));
    e.target.value = '';
  });
  document.getElementById('btn-users').addEventListener('click', openUsersPanel);
  document.getElementById('btn-close-users').addEventListener('click', closeUsersPanel);
  document.getElementById('btn-rotate-key').addEventListener('click', rotateGroupKey);
  document.getElementById('ks-start').addEventListener('click', startKeySetup);
  document.getElementById('btn-close-keysetup').addEventListener('click', closeKeySetup);
  document.getElementById('ks-copy-otp').addEventListener('click', () => copyToClipboard(document.getElementById('ks-otp').textContent, 'OTP已复制'));
  document.getElementById('ks-copy-bundle').addEventListener('click', () => copyToClipboard(document.getElementById('ks-bundle').textContent, '密钥包已复制'));
  document.getElementById('btn-call').addEventListener('click', openCallSelect);
  document.getElementById('btn-close-call-select').addEventListener('click', () => { document.getElementById('call-select-modal').style.display = 'none'; });
  document.getElementById('btn-history').addEventListener('click', openHistory);
  document.getElementById('btn-close-history').addEventListener('click', closeHistory);
  document.getElementById('panel-overlay').addEventListener('click', () => { closeHistory(); closeUsersPanel(); });
  document.getElementById('btn-select-all').addEventListener('click', selectAllHistory);
  document.getElementById('btn-share-selected').addEventListener('click', shareSelected);
  document.getElementById('btn-logout').addEventListener('click', handleLogout);
  document.getElementById('btn-hangup').addEventListener('click', endCall);
  document.getElementById('btn-accept-call').addEventListener('click', acceptCall);
  document.getElementById('btn-accept-incoming').addEventListener('click', acceptCall);
  document.getElementById('btn-reject-call').addEventListener('click', rejectCall);
  document.getElementById('btn-mute').addEventListener('click', toggleMute);

  document.querySelectorAll('.emoji-grid span').forEach(span => {
    span.addEventListener('click', () => {
      const input = document.getElementById('message-input');
      input.value += span.textContent;
      input.focus();
    });
  });

  document.getElementById('message-input').addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(); }
  });
  document.getElementById('message-input').addEventListener('input', function() {
    this.style.height = 'auto';
    this.style.height = Math.min(this.scrollHeight, 100) + 'px';
  });

  ['login-username','login-password','login-captcha'].forEach(id => {
    document.getElementById(id).addEventListener('keydown', (e) => { if (e.key === 'Enter') handleLogin(); });
  });

  const autoLogged = await tryAutoLogin();
  if (!autoLogged) { showView('login-view'); refreshCaptcha(); }
});
