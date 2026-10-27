// Central Copy Via — API (Netlify Functions v2 + Netlify Blobs)
import { getStore } from "@netlify/blobs";
import SEED from "../lib/seed-data.mjs";
import { scryptSync, randomBytes, createHmac, timingSafeEqual, randomUUID } from "node:crypto";

const json = (data, status = 200, headers = {}) =>
  new Response(JSON.stringify(data), { status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...headers } });
const err = (msg, status = 400) => json({ erro: msg }, status);

const store = () => getStore({ name: "central-copy-via", consistency: "strong" });
let _secret = null;
async function loadSecret(st) {
  if (_secret) return _secret;
  if (process.env.SESSION_SECRET && process.env.SESSION_SECRET.length >= 32) return (_secret = process.env.SESSION_SECRET);
  let s = await st.get("secret");
  if (!s) { s = randomBytes(48).toString("base64url"); await st.set("secret", s); }
  return (_secret = s);
}
const SECRET = () => { if (!_secret) throw new Error("segredo não carregado"); return _secret; };
const SESSION_DAYS = 7;

/* ---------- senhas ---------- */
function hashPassword(pw) {
  const salt = randomBytes(16);
  const hash = scryptSync(pw, salt, 64, { N: 16384, r: 8, p: 1 });
  return `scrypt$${salt.toString("base64")}$${hash.toString("base64")}`;
}
function checkPassword(pw, stored) {
  try {
    const [, s, h] = stored.split("$");
    const expected = Buffer.from(h, "base64");
    const got = scryptSync(pw, Buffer.from(s, "base64"), expected.length, { N: 16384, r: 8, p: 1 });
    return timingSafeEqual(got, expected);
  } catch { return false; }
}

/* ---------- sessão (cookie assinado) ---------- */
const b64u = (b) => Buffer.from(b).toString("base64url");
function sign(payload) {
  const body = b64u(JSON.stringify(payload));
  const mac = createHmac("sha256", SECRET()).update(body).digest("base64url");
  return `${body}.${mac}`;
}
function verify(token) {
  if (!token || !token.includes(".")) return null;
  const [body, mac] = token.split(".");
  const exp = createHmac("sha256", SECRET()).update(body).digest("base64url");
  const a = Buffer.from(mac), b = Buffer.from(exp);
  if (a.length !== b.length || !timingSafeEqual(a, b)) return null;
  try { const p = JSON.parse(Buffer.from(body, "base64url").toString()); return p.exp > Date.now() ? p : null; } catch { return null; }
}
function cookieOf(req, name) {
  const c = req.headers.get("cookie") || "";
  const m = c.split(/;\s*/).find((x) => x.startsWith(name + "="));
  return m ? decodeURIComponent(m.slice(name.length + 1)) : null;
}
const setSession = (token, maxAge) =>
  `ccv_sid=${encodeURIComponent(token)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAge}`;

/* ---------- usuários ---------- */
const norm = (e) => String(e || "").trim().toLowerCase();
async function getUsers(st) { return (await st.get("users", { type: "json" })) || {}; }
async function saveUsers(st, users) { await st.setJSON("users", users); }
const publicUser = (u) => ({ email: u.email, nome: u.nome || "", papel: u.papel, criado: u.criado });

async function currentUser(req, st) {
  const p = verify(cookieOf(req, "ccv_sid"));
  if (!p) return null;
  const users = await getUsers(st);
  const u = users[p.e];
  if (!u || (u.sv || 0) !== (p.sv || 0)) return null; // sessão invalidada ao trocar senha/excluir
  return u;
}

/* ---------- spy: junção de dados novos ---------- */
function mergeChannel(oldDoc, items, meta) {
  const key = (r) => (r.n || "") + "|" + (r.d || "");
  const map = new Map();
  for (const r of (oldDoc?.items || [])) map.set(key(r), r);
  const added = [];
  for (const r of items) { if (!map.has(key(r))) added.push(r); map.set(key(r), r); }
  const all = [...map.values()].sort((a, b) => String(b.d).localeCompare(String(a.d)));
  return { doc: { ...(oldDoc || {}), ...(meta || {}), items: all, atualizado: new Date().toLocaleDateString("pt-BR", { timeZone: "America/Sao_Paulo" }) }, added };
}

/* ---------- dados iniciais (empacotados com a função, não ficam públicos) ---------- */
async function seedIfEmpty(st) {
  const { blobs } = await st.list({ prefix: "spy:" });
  if (blobs.length) return;
  for (const [k, v] of Object.entries(SEED.spy || {})) await st.setJSON("spy:" + k, v);
  for (const [k, v] of Object.entries(SEED.conteudo || {})) await st.setJSON("conteudo:" + k, v);
  if (SEED.meta) await st.setJSON("meta:status", SEED.meta);
}

/* ---------- rotas ---------- */
export default async (req) => {
  const url = new URL(req.url);
  const path = url.pathname.replace(/^\/(?:\.netlify\/functions\/api|api)\/?/, "").replace(/\/$/, "");
  const method = req.method;
  let st;
  try { st = store(); await loadSecret(st); } catch (e) { return err("Servidor não configurado: " + e.message, 500); }
  const body = async () => { try { return await req.json(); } catch { return {}; } };

  // CSRF básico: requisições que alteram dados precisam vir do próprio site
  if (method !== "GET") {
    const origin = req.headers.get("origin");
    if (origin && origin !== url.origin) return err("Origem não permitida", 403);
  }

  /* estado: o site já tem administrador? */
  if (path === "estado" && method === "GET") {
    const users = await getUsers(st);
    return json({ configurado: Object.keys(users).length > 0 });
  }
  /* primeiro acesso: cria o administrador (só funciona com o cadastro vazio) */
  if (path === "setup" && method === "POST") {
    const users = await getUsers(st);
    if (Object.keys(users).length) return err("O site já foi configurado.", 409);
    const { email, nome, senha } = await body();
    const e = norm(email);
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(e)) return err("E-mail inválido.");
    if (!senha || senha.length < 6) return err("A senha precisa de pelo menos 6 caracteres.");
    users[e] = { email: e, nome: String(nome || "").slice(0, 80), papel: "admin", hash: hashPassword(senha), criado: new Date().toISOString(), sv: 1 };
    await saveUsers(st, users);
    await seedIfEmpty(st);
    const token = sign({ e, sv: 1, exp: Date.now() + SESSION_DAYS * 864e5 });
    return json({ usuario: publicUser(users[e]) }, 201, { "set-cookie": setSession(token, SESSION_DAYS * 86400) });
  }

  /* login */
  if (path === "login" && method === "POST") {
    const { email, senha } = await body();
    const e = norm(email);
    if (!e || !senha) return err("Informe e-mail e senha.");
    const lockKey = "lock:" + e;
    const lock = (await st.get(lockKey, { type: "json" })) || { n: 0, ate: 0 };
    if (lock.ate > Date.now()) return err("Muitas tentativas. Tente de novo em alguns minutos.", 429);

    const users = await getUsers(st);
    const u = users[e];
    if (!u || !checkPassword(senha, u.hash)) {
      const n = lock.n + 1;
      await st.setJSON(lockKey, { n: n >= 5 ? 0 : n, ate: n >= 5 ? Date.now() + 15 * 60e3 : 0 });
      return err("E-mail ou senha incorretos.", 401);
    }
    await st.delete(lockKey);
    const token = sign({ e, sv: u.sv || 0, exp: Date.now() + SESSION_DAYS * 864e5 });
    return json({ usuario: publicUser(u) }, 200, { "set-cookie": setSession(token, SESSION_DAYS * 86400) });
  }
  if (path === "logout" && method === "POST") return json({ ok: true }, 200, { "set-cookie": setSession("", 0) });

  const me = await currentUser(req, st);
  if (!me) return err("Faça login para continuar.", 401);
  const isAdmin = me.papel === "admin";

  if (path === "me" && method === "GET") return json({ usuario: publicUser(me) });

  /* trocar a própria senha */
  if (path === "senha" && method === "POST") {
    const { atual, nova } = await body();
    if (!checkPassword(atual || "", me.hash)) return err("Senha atual incorreta.", 401);
    if (!nova || nova.length < 8) return err("A nova senha precisa de pelo menos 8 caracteres.");
    const users = await getUsers(st);
    users[me.email] = { ...users[me.email], hash: hashPassword(nova), sv: (users[me.email].sv || 0) + 1 };
    await saveUsers(st, users);
    const token = sign({ e: me.email, sv: users[me.email].sv, exp: Date.now() + SESSION_DAYS * 864e5 });
    return json({ ok: true }, 200, { "set-cookie": setSession(token, SESSION_DAYS * 86400) });
  }

  /* usuários (só admin) */
  if (path === "usuarios") {
    if (!isAdmin) return err("Só administradores gerenciam usuários.", 403);
    const users = await getUsers(st);
    if (method === "GET") return json({ usuarios: Object.values(users).map(publicUser).sort((a, b) => a.email.localeCompare(b.email)) });
    if (method === "POST") {
      const { email, nome, senha, papel } = await body();
      const e = norm(email);
      if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(e)) return err("E-mail inválido.");
      if (users[e]) return err("Esse e-mail já está cadastrado.");
      if (!senha || senha.length < 8) return err("A senha precisa de pelo menos 8 caracteres.");
      const p = ["admin", "membro", "leitor"].includes(papel) ? papel : "membro";
      users[e] = { email: e, nome: String(nome || "").slice(0, 80), papel: p, hash: hashPassword(senha), criado: new Date().toISOString(), sv: 1 };
      await saveUsers(st, users);
      return json({ usuario: publicUser(users[e]) }, 201);
    }
    if (method === "DELETE") {
      const e = norm(url.searchParams.get("email"));
      if (!users[e]) return err("Usuário não encontrado.", 404);
      if (e === me.email) return err("Você não pode excluir o próprio acesso.");
      if (users[e].papel === "admin" && Object.values(users).filter((u) => u.papel === "admin").length <= 1) return err("É preciso manter ao menos um administrador.");
      delete users[e];
      await saveUsers(st, users);
      return json({ ok: true });
    }
  }

  /* dados de leitura */
  if (path === "dados" && method === "GET") {
    const [spyList, contList] = await Promise.all([st.list({ prefix: "spy:" }), st.list({ prefix: "conteudo:" })]);
    const spy = {}, conteudo = {};
    await Promise.all([
      ...spyList.blobs.map(async (b) => { spy[b.key.slice(4)] = await st.get(b.key, { type: "json" }); }),
      ...contList.blobs.map(async (b) => { conteudo[b.key.slice(9)] = await st.get(b.key, { type: "json" }); }),
    ]);
    const meta = (await st.get("meta:status", { type: "json" })) || {};
    return json({ spy, conteudo, meta });
  }

  /* criativos */
  if (path === "criativos") {
    if (method === "GET") {
      const { blobs } = await st.list({ prefix: "criativo:" });
      const itens = (await Promise.all(blobs.map((b) => st.get(b.key, { type: "json" })))).filter(Boolean);
      return json({ criativos: itens });
    }
    if (me.papel === "leitor") return err("Seu acesso é só de leitura.", 403);
    if (method === "POST" || method === "PUT") {
      const c = await body();
      const id = method === "PUT" && c.id ? String(c.id).replace(/[^\w-]/g, "") : randomUUID();
      const prev = method === "PUT" ? await st.get("criativo:" + id, { type: "json" }) : null;
      if (method === "PUT" && !prev) return err("Criativo não encontrado.", 404);
      const campos = ["oferta", "status", "titulo", "formato", "angulo", "ganchos", "roteiro", "resp", "link", "resultado"];
      const item = { ...(prev || { id, criado: new Date().toISOString(), autor: me.email }) };
      for (const k of campos) if (k in c) item[k] = String(c[k] ?? "").slice(0, 20000);
      if (!item.titulo) return err("Dê um título ao criativo.");
      item.atualizado = new Date().toISOString(); item.editor = me.email;
      await st.setJSON("criativo:" + id, item);
      return json({ criativo: item }, method === "POST" ? 201 : 200);
    }
    if (method === "DELETE") {
      const id = String(url.searchParams.get("id") || "").replace(/[^\w-]/g, "");
      await st.delete("criativo:" + id);
      return json({ ok: true });
    }
  }

  /* ingestão do spy e do conteúdo (só admin; usado pela atualização diária) */
  if (path === "ingest" && method === "POST") {
    if (!isAdmin) return err("Só administradores atualizam os dados.", 403);
    const b = await body();
    const resumo = { canais: {}, novas: [] };
    for (const [canal, payload] of Object.entries(b.spy || {})) {
      if (!/^[\w-]{1,40}$/.test(canal)) continue;
      const items = Array.isArray(payload) ? payload : payload.items;
      if (!Array.isArray(items)) continue;
      const meta = Array.isArray(payload) ? {} : { mercado: payload.mercado, nicho: payload.nicho, canal: payload.canal };
      const old = await st.get("spy:" + canal, { type: "json" });
      const { doc, added } = b.substituir ? { doc: { ...meta, items, atualizado: new Date().toLocaleDateString("pt-BR", { timeZone: "America/Sao_Paulo" }) }, added: [] } : mergeChannel(old, items, old ? {} : meta);
      await st.setJSON("spy:" + canal, doc);
      resumo.canais[canal] = { total: doc.items.length, novas: added.length };
      resumo.novas.push(...added.map((r) => ({ n: r.n, v: r.v || 0, canal })));
    }
    for (const [id, doc] of Object.entries(b.conteudo || {})) {
      if (!/^[\w-]{1,60}$/.test(id) || typeof doc !== "object") continue;
      await st.setJSON("conteudo:" + id, doc);
    }
    if (Object.keys(b.spy || {}).length) {
      const top = resumo.novas.sort((a, x) => x.v - a.v).slice(0, 5).map((r) => r.n);
      const agora = new Date().toLocaleString("pt-BR", { timeZone: "America/Sao_Paulo", dateStyle: "short", timeStyle: "short" });
      await st.setJSON("meta:status", { spyAtualizado: agora, novas: resumo.novas.length, nota: resumo.novas.length ? `${resumo.novas.length} ofertas novas: ${top.join(", ")}` : "Nenhuma oferta nova nesta atualização" });
    }
    return json({ ok: true, resumo: { canais: resumo.canais, novas: resumo.novas.length } });
  }

  return err("Rota não encontrada.", 404);
};

export const config = { path: "/api/*" };
