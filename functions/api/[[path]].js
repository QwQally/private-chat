// ============================================================
// 私密聊天 v2 - Cloudflare Pages Functions 后端
// 12人群组 / 每人独立密钥分区 / 12层嵌套加密 / 30天令牌续期
// ============================================================

const sseConnections = new Map(); // userId -> { writer, pingInterval }
const CONVERSATION_ID = 1; // 默认群聊ID
const MAX_USERS = 12;

// ---------- 工具 ----------

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }
  });
}

function errorResponse(message, status = 400) {
  return jsonResponse({ error: message }, status);
}

async function hashPassword(password, saltBase64) {
  const enc = new TextEncoder();
  const salt = Uint8Array.from(atob(saltBase64), c => c.charCodeAt(0));
  const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, keyMaterial, 256
  );
  return btoa(String.fromCharCode(...new Uint8Array(bits)));
}

function generateSalt() {
  const arr = new Uint8Array(16);
  crypto.getRandomValues(arr);
  return btoa(String.fromCharCode(...arr));
}

function generateToken() {
  const arr = new Uint8Array(32);
  crypto.getRandomValues(arr);
  return btoa(String.fromCharCode(...arr)).replace(/[^a-zA-Z0-9]/g, '');
}

function now() { return Date.now(); }

async function generateCaptcha(env) {
  const a = Math.floor(Math.random() * 10) + 1;
  const b = Math.floor(Math.random() * 10) + 1;
  const answer = (a + b).toString();
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(env.CAPTCHA_SECRET || 'default-secret'), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(answer + '|' + Math.floor(now() / 60000)));
  return { question: `${a} + ${b} = ?`, token: btoa(String.fromCharCode(...new Uint8Array(sig))) };
}

async function verifyCaptcha(env, token, answer) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(env.CAPTCHA_SECRET || 'default-secret'), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  for (const offset of [0, 1]) {
    const expected = await crypto.subtle.sign('HMAC', key, enc.encode(answer + '|' + (Math.floor(now() / 60000) - offset)));
    if (token === btoa(String.fromCharCode(...new Uint8Array(expected)))) return true;
  }
  return false;
}

// 认证: admin令牌每次验证自动续期30天
async function authenticate(request, env) {
  let token = null;
  const auth = request.headers.get('Authorization');
  if (auth && auth.startsWith('Bearer ')) token = auth.slice(7);
  else {
    const url = new URL(request.url);
    token = url.searchParams.get('token');
  }
  if (!token) return null;

  const result = await env.DB.prepare(
    'SELECT s.*, u.username, u.role, u.display_name FROM sessions s JOIN users u ON s.user_id = u.id WHERE s.token = ?'
  ).bind(token).first();
  if (!result) return null;

  if (result.expires_at < now()) {
    await env.DB.prepare('DELETE FROM sessions WHERE token = ?').bind(token).run();
    return null;
  }

  // admin角色: 每次认证自动续期30天
  if (result.role === 'admin') {
    const newExpiry = now() + 30 * 24 * 3600 * 1000;
    await env.DB.prepare('UPDATE sessions SET expires_at = ? WHERE token = ?').bind(newExpiry, token).run();
    result.expires_at = newExpiry;
  }

  return result;
}

function broadcastToUser(userId, event, data) {
  const conn = sseConnections.get(userId);
  if (conn && conn.writer) {
    conn.writer.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
  }
}

async function broadcastToConversation(env, conversationId, event, data) {
  const members = await env.DB.prepare(
    'SELECT user_id FROM conversation_members WHERE conversation_id = ?'
  ).bind(conversationId).all();
  for (const m of members.results) {
    broadcastToUser(m.user_id, event, data);
  }
}

// ---------- API ----------

async function handleGetCaptcha(env) {
  return jsonResponse(await generateCaptcha(env));
}

async function handleRegister(request, env) {
  if (env.ALLOW_REGISTRATION !== 'true') return errorResponse('注册已关闭', 403);

  const body = await request.json().catch(() => null);
  if (!body || !body.username || !body.password) return errorResponse('用户名和密码不能为空');

  // 检查人数上限
  const count = await env.DB.prepare('SELECT COUNT(*) as c FROM users').first();
  if (count.c >= MAX_USERS) return errorResponse(`已达最大用户数(${MAX_USERS})`, 403);

  const existing = await env.DB.prepare('SELECT id FROM users WHERE username = ?').bind(body.username).first();
  if (existing) return errorResponse('用户名已存在');

  const salt = generateSalt();
  const hash = await hashPassword(body.password, salt);
  const role = body.role === 'admin' ? 'admin' : 'client';
  const displayName = body.display_name || body.username;

  const result = await env.DB.prepare(
    'INSERT INTO users (username, password_hash, password_salt, role, display_name, created_at) VALUES (?, ?, ?, ?, ?, ?)'
  ).bind(body.username, hash, salt, role, displayName, now()).run();

  const userId = result.meta.last_row_id;

  // 加入默认群聊
  await env.DB.prepare(
    'INSERT OR IGNORE INTO conversation_members (conversation_id, user_id, joined_at) VALUES (?, ?, ?)'
  ).bind(CONVERSATION_ID, userId, now()).run();

  return jsonResponse({ success: true, user_id: userId, role });
}

async function handleLogin(request, env) {
  const body = await request.json().catch(() => null);
  if (!body || !body.username || !body.password || !body.captcha_token || !body.captcha_answer) {
    return errorResponse('请填写账号、密码和验证码');
  }

  if (!await verifyCaptcha(env, body.captcha_token, body.captcha_answer)) {
    return errorResponse('验证码错误或已过期', 401);
  }

  const user = await env.DB.prepare('SELECT * FROM users WHERE username = ?').bind(body.username).first();
  if (!user) return errorResponse('账号或密码错误', 401);

  const hash = await hashPassword(body.password, user.password_salt);
  if (hash !== user.password_hash) return errorResponse('账号或密码错误', 401);

  const token = generateToken();
  // admin: 30天; client: 24小时
  const expiresAt = user.role === 'admin'
    ? now() + 30 * 24 * 3600 * 1000
    : now() + 24 * 3600 * 1000;

  // client每次登录删除旧会话(强制重新登录)
  if (user.role === 'client') {
    await env.DB.prepare('DELETE FROM sessions WHERE user_id = ?').bind(user.id).run();
  }

  await env.DB.prepare(
    'INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)'
  ).bind(token, user.id, now(), expiresAt).run();

  return jsonResponse({
    success: true, token, user_id: user.id,
    username: user.username, role: user.role, display_name: user.display_name
  });
}

async function handleLogout(request, env, auth) {
  await env.DB.prepare('DELETE FROM sessions WHERE token = ?').bind(auth.token).run();
  sseConnections.delete(auth.user_id);
  return jsonResponse({ success: true });
}

async function handleCheckToken(request, env) {
  const auth = await authenticate(request, env);
  if (!auth) return errorResponse('未登录', 401);
  return jsonResponse({
    user_id: auth.user_id, username: auth.username,
    role: auth.role, display_name: auth.display_name
  });
}

// 获取用户列表 (admin)
async function handleGetUsers(env, auth) {
  if (auth.role !== 'admin') return errorResponse('仅管理员可查看', 403);
  const result = await env.DB.prepare(
    'SELECT id, username, display_name, role, created_at FROM users ORDER BY id'
  ).all();
  // 检查每个用户是否已配置密钥
  const users = [];
  for (const u of result.results) {
    const keyCount = await env.DB.prepare(
      'SELECT COUNT(*) as c FROM public_keys WHERE user_id = ?'
    ).bind(u.id).first();
    const wrapCount = await env.DB.prepare(
      'SELECT COUNT(*) as c FROM group_key_wraps WHERE user_id = ? AND conversation_id = ?'
    ).bind(u.id, CONVERSATION_ID).first();
    users.push({ ...u, keys_configured: keyCount.c === 48, key_wrap_configured: wrapCount.c > 0 });
  }
  return jsonResponse({ users });
}

// 上传某用户的48个公钥 (admin为用户配置)
async function handleUploadKeys(request, env, auth) {
  if (auth.role !== 'admin') return errorResponse('仅管理员可上传公钥', 403);
  const body = await request.json().catch(() => null);
  if (!body || !body.user_id || !Array.isArray(body.keys) || body.keys.length !== 48) {
    return errorResponse('需要user_id和48个公钥');
  }
  await env.DB.prepare('DELETE FROM public_keys WHERE user_id = ?').bind(body.user_id).run();
  const stmt = env.DB.prepare('INSERT INTO public_keys (user_id, key_index, jwk_json, created_at) VALUES (?, ?, ?, ?)');
  for (let i = 0; i < 48; i++) {
    await stmt.bind(body.user_id, i, JSON.stringify(body.keys[i]), now()).run();
  }
  return jsonResponse({ success: true, count: 48 });
}

// 获取当前用户的公钥
async function handleGetKeys(request, env, auth) {
  const url = new URL(request.url);
  const userId = parseInt(url.searchParams.get('user_id') || auth.user_id);
  // admin可查任意用户, client只能查自己
  if (auth.role !== 'admin' && userId !== auth.user_id) {
    return errorResponse('无权查看', 403);
  }
  const result = await env.DB.prepare(
    'SELECT key_index, jwk_json FROM public_keys WHERE user_id = ? ORDER BY key_index'
  ).bind(userId).all();
  const keys = result.results.map(r => JSON.parse(r.jwk_json));
  return jsonResponse({ keys, user_id: userId });
}

// 上传群组密钥封装 (admin为用户生成)
async function handleUploadKeyWrap(request, env, auth) {
  if (auth.role !== 'admin') return errorResponse('仅管理员可上传密钥封装', 403);
  const body = await request.json().catch(() => null);
  if (!body || !body.user_id || !body.wrapped_key || !body.wrap_iv || !body.e_values) {
    return errorResponse('参数不完整');
  }
  const keyVersion = body.key_version || 1;
  // 删除旧版本
  await env.DB.prepare(
    'DELETE FROM group_key_wraps WHERE user_id = ? AND conversation_id = ?'
  ).bind(body.user_id, CONVERSATION_ID).run();
  await env.DB.prepare(
    'INSERT INTO group_key_wraps (user_id, conversation_id, wrapped_key, wrap_iv, e_values, key_version, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)'
  ).bind(body.user_id, CONVERSATION_ID, body.wrapped_key, body.wrap_iv,
    JSON.stringify(body.e_values), keyVersion, now()).run();
  return jsonResponse({ success: true });
}

// 获取当前用户的群组密钥封装
async function handleGetKeyWrap(env, auth) {
  const result = await env.DB.prepare(
    'SELECT wrapped_key, wrap_iv, e_values, key_version FROM group_key_wraps WHERE user_id = ? AND conversation_id = ? ORDER BY key_version DESC LIMIT 1'
  ).bind(auth.user_id, CONVERSATION_ID).first();
  if (!result) return errorResponse('密钥未配置', 404);
  return jsonResponse({
    wrapped_key: result.wrapped_key,
    wrap_iv: result.wrap_iv,
    e_values: JSON.parse(result.e_values),
    key_version: result.key_version
  });
}

// 发送消息 (群组AES密钥加密, 不含e_values)
async function handleSendMessage(request, env, auth) {
  const body = await request.json().catch(() => null);
  if (!body || !body.ciphertext || !body.aes_iv) return errorResponse('消息格式不完整');

  const msgType = body.message_type || 'text';
  const result = await env.DB.prepare(
    'INSERT INTO messages (conversation_id, sender_id, ciphertext, aes_iv, message_type, timestamp, shared_with) VALUES (?, ?, ?, ?, ?, ?, ?)'
  ).bind(CONVERSATION_ID, auth.user_id, body.ciphertext, body.aes_iv, msgType, now(), null).run();

  const msg = {
    id: result.meta.last_row_id,
    conversation_id: CONVERSATION_ID,
    sender_id: auth.user_id,
    sender_name: auth.display_name || auth.username,
    ciphertext: body.ciphertext,
    aes_iv: body.aes_iv,
    message_type: msgType,
    timestamp: now(),
    shared_with: null
  };

  await broadcastToConversation(env, CONVERSATION_ID, 'new_message', msg);
  return jsonResponse({ success: true, message_id: msg.id, timestamp: msg.timestamp });
}

// 获取消息
async function handleGetMessages(request, env, auth) {
  const url = new URL(request.url);
  const since = parseInt(url.searchParams.get('since') || '0');

  let query, params;
  if (auth.role === 'admin') {
    // admin看全部
    query = `SELECT m.*, u.username as sender_name, u.display_name as sender_display
             FROM messages m JOIN users u ON m.sender_id = u.id
             WHERE m.conversation_id = ? AND m.timestamp > ? ORDER BY m.timestamp ASC`;
    params = [CONVERSATION_ID, since];
  } else {
    // client: 看加入后的 + 被分享的
    const membership = await env.DB.prepare(
      'SELECT joined_at FROM conversation_members WHERE conversation_id = ? AND user_id = ?'
    ).bind(CONVERSATION_ID, auth.user_id).first();
    const joinTime = membership ? membership.joined_at : now();
    query = `SELECT m.*, u.username as sender_name, u.display_name as sender_display
             FROM messages m JOIN users u ON m.sender_id = u.id
             WHERE m.conversation_id = ? AND m.timestamp > ?
             AND (m.timestamp >= ? OR (m.shared_with IS NOT NULL AND json_extract(m.shared_with, '$') LIKE ?))
             ORDER BY m.timestamp ASC`;
    params = [CONVERSATION_ID, since, joinTime, `%${auth.user_id}%`];
  }

  const result = await env.DB.prepare(query).bind(...params).all();
  return jsonResponse({ messages: result.results });
}

// admin获取全部历史
async function handleGetHistory(env, auth) {
  if (auth.role !== 'admin') return errorResponse('仅管理员可查看', 403);
  const result = await env.DB.prepare(
    `SELECT m.*, u.username as sender_name, u.display_name as sender_display
     FROM messages m JOIN users u ON m.sender_id = u.id
     WHERE m.conversation_id = ? ORDER BY m.timestamp ASC`
  ).bind(CONVERSATION_ID).all();
  return jsonResponse({ messages: result.results });
}

// admin分享历史消息给指定用户
async function handleShare(request, env, auth) {
  if (auth.role !== 'admin') return errorResponse('仅管理员可分享', 403);
  const body = await request.json().catch(() => null);
  if (!body || !body.message_ids || !Array.isArray(body.message_ids) || !body.target_user_id) {
    return errorResponse('需要message_ids和target_user_id');
  }
  const placeholders = body.message_ids.map(() => '?').join(',');
  // 更新shared_with字段(追加user_id)
  const messages = await env.DB.prepare(
    `SELECT id, shared_with FROM messages WHERE id IN (${placeholders})`
  ).bind(...body.message_ids).all();

  const updateStmt = env.DB.prepare('UPDATE messages SET shared_with = ? WHERE id = ?');
  for (const m of messages.results) {
    let shared = m.shared_with ? JSON.parse(m.shared_with) : [];
    if (!shared.includes(body.target_user_id)) {
      shared.push(body.target_user_id);
      await updateStmt.bind(JSON.stringify(shared), m.id).run();
    }
  }

  // 推送给目标用户
  const sharedMsgs = await env.DB.prepare(
    `SELECT m.*, u.username as sender_name, u.display_name as sender_display
     FROM messages m JOIN users u ON m.sender_id = u.id WHERE m.id IN (${placeholders})`
  ).bind(...body.message_ids).all();
  broadcastToUser(body.target_user_id, 'shared_history', { messages: sharedMsgs.results });

  return jsonResponse({ success: true, shared_count: body.message_ids.length });
}

// SSE实时流
async function handleSSE(request, env, auth) {
  const { readable, writable } = new TransformStream();
  const writer = writable.getWriter();

  writer.write(`event: connected\ndata: ${JSON.stringify({ user_id: auth.user_id, role: auth.role })}\n\n`);

  const pingInterval = setInterval(() => {
    writer.write(`event: ping\ndata: ${JSON.stringify({ time: now() })}\n\n`).catch(() => {});
  }, 25000);

  sseConnections.set(auth.user_id, { writer, pingInterval });
  request.signal.addEventListener('abort', () => {
    clearInterval(pingInterval);
    sseConnections.delete(auth.user_id);
    writer.close().catch(() => {});
  });

  return new Response(readable, {
    headers: {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
      'X-Accel-Buffering': 'no'
    }
  });
}

// WebRTC信令 (发给指定用户)
async function handleSignal(request, env, auth) {
  const body = await request.json().catch(() => null);
  if (!body || !body.type || !body.payload || !body.target_user_id) {
    return errorResponse('信令格式错误');
  }
  broadcastToUser(body.target_user_id, 'webrtc_signal', {
    from: auth.user_id,
    from_name: auth.display_name || auth.username,
    type: body.type,
    payload: body.payload
  });
  return jsonResponse({ success: true });
}

// 文件上传
async function handleUpload(request, env, auth) {
  const formData = await request.formData();
  const file = formData.get('file');
  if (!file) return errorResponse('没有文件');
  const fileId = generateToken() + '_' + Date.now();
  await env.BUCKET.put(fileId, file.stream(), { httpMetadata: { contentType: file.type } });
  return jsonResponse({ success: true, file_id: fileId, filename: file.name, size: file.size });
}

async function handleGetFile(request, env) {
  const url = new URL(request.url);
  const fileId = url.searchParams.get('id');
  if (!fileId) return errorResponse('缺少文件ID');
  const obj = await env.BUCKET.get(fileId);
  if (!obj) return errorResponse('文件不存在', 404);
  const headers = new Headers();
  obj.writeHttpMetadata(headers);
  headers.set('Cache-Control', 'public, max-age=31536000');
  return new Response(obj.body, { headers });
}

// ---------- 主入口 ----------

export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const path = '/api/' + (context.params.path || []).join('/');
  const method = request.method;

  if (method === 'OPTIONS') {
    return new Response(null, {
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization'
      }
    });
  }

  // 公开路由
  if (path === '/api/captcha' && method === 'GET') return handleGetCaptcha(env);
  if (path === '/api/register' && method === 'POST') return handleRegister(request, env);
  if (path === '/api/login' && method === 'POST') return handleLogin(request, env);
  if (path === '/api/check-token' && method === 'GET') return handleCheckToken(request, env);
  if (path === '/api/file' && method === 'GET') return handleGetFile(request, env);

  // 需认证
  const auth = await authenticate(request, env);
  if (!auth) return errorResponse('未登录或登录已过期', 401);

  if (path === '/api/logout' && method === 'POST') return handleLogout(request, env, auth);
  if (path === '/api/users' && method === 'GET') return handleGetUsers(env, auth);
  if (path === '/api/keys' && method === 'POST') return handleUploadKeys(request, env, auth);
  if (path === '/api/keys' && method === 'GET') return handleGetKeys(request, env, auth);
  if (path === '/api/keywrap' && method === 'POST') return handleUploadKeyWrap(request, env, auth);
  if (path === '/api/keywrap' && method === 'GET') return handleGetKeyWrap(env, auth);
  if (path === '/api/messages' && method === 'GET') return handleGetMessages(request, env, auth);
  if (path === '/api/messages' && method === 'POST') return handleSendMessage(request, env, auth);
  if (path === '/api/history' && method === 'GET') return handleGetHistory(env, auth);
  if (path === '/api/share' && method === 'POST') return handleShare(request, env, auth);
  if (path === '/api/stream' && method === 'GET') return handleSSE(request, env, auth);
  if (path === '/api/signal' && method === 'POST') return handleSignal(request, env, auth);
  if (path === '/api/upload' && method === 'POST') return handleUpload(request, env, auth);

  return errorResponse('接口不存在', 404);
}
