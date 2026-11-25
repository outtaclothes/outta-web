// OUTTA' — Worker: sirve la página (public/) y la API de pagos con Bold.
// Secretos (Cloudflare → Worker → Settings → Variables and Secrets):
//   BOLD_SECRET      llave secreta del Botón de pagos de Bold
//   SUPABASE_SECRET  llave secreta (service role) de Supabase
//   META_TOKEN       token de acceso de la API de conversiones de Meta
const J = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } });
const hex = b => [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, '0')).join('');
const enc = s => new TextEncoder().encode(s);
const sha256 = async s => hex(await crypto.subtle.digest('SHA-256', enc(s)));
async function hmac(key, msg) {
  // HMAC con llave vacía (modo pruebas de Bold) equivale a una llave de 64 bytes en cero.
  const raw = key ? enc(key) : new Uint8Array(64);
  const k = await crypto.subtle.importKey('raw', raw, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return hex(await crypto.subtle.sign('HMAC', k, enc(msg)));
}
const b64 = buf => { let s = ''; const u = new Uint8Array(buf); for (let i = 0; i < u.length; i += 0x8000) s += String.fromCharCode(...u.subarray(i, i + 0x8000)); return btoa(s); };
const safeEq = (a, b) => { if (a.length !== b.length) return false; let r = 0; for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i); return r === 0; };

async function rpc(env, fn, args, secret) {
  const key = secret ? env.SUPABASE_SECRET : env.SUPABASE_ANON;
  const h = { 'content-type': 'application/json', apikey: key };
  if (key && key.startsWith('eyJ')) h.authorization = 'Bearer ' + key;
  const r = await fetch(`${env.SUPABASE_URL}/rest/v1/rpc/${fn}`, { method: 'POST', headers: h, body: JSON.stringify(args) });
  const t = await r.text();
  if (!r.ok) throw new Error(`${fn} ${r.status}: ${t.slice(0, 300)}`);
  return t ? JSON.parse(t) : null;
}

async function firma(req, env) {
  const { pedido_id } = await req.json().catch(() => ({}));
  if (!/^[0-9a-f-]{36}$/i.test(pedido_id || '')) return J({ error: 'Pedido no válido' }, 400);
  if (!env.BOLD_SECRET) return J({ error: 'La pasarela aún no está configurada (falta la llave secreta)' }, 503);
  if (env.BOLD_MODE !== 'produccion' && !(await rpc(env, 'pedido_es_de_equipo', { p_id: pedido_id }, true))) return J({ error: 'La tienda está en modo pruebas: por ahora los pedidos se hacen por WhatsApp' }, 403);
  const p = await rpc(env, 'pedido_para_pago', { p_id: pedido_id });
  if (!p) return J({ error: 'Pedido no encontrado' }, 404);
  if (p.estado !== 'pendiente') return J({ error: 'Este pedido ya no está pendiente de pago' }, 409);
  const amount = String(p.total);
  const origin = new URL(req.url).origin;
  return J({
    orderId: p.numero, amount, currency: 'COP', apiKey: env.BOLD_ID,
    integritySignature: await sha256(`${p.numero}${amount}COP${env.BOLD_SECRET}`),
    redirectionUrl: `${origin}/?tienda=prueba&pago=${pedido_id}`
  });
}

async function webhook(req, env, ctx) {
  const raw = await req.arrayBuffer();
  const sig = req.headers.get('x-bold-signature') || '';
  const key = env.BOLD_MODE === 'produccion' ? (env.BOLD_SECRET || '') : '';
  if (env.BOLD_MODE === 'produccion' && !key) return J({ error: 'sin llave' }, 503);
  const calc = await hmac(key, b64(raw));
  if (!safeEq(calc, sig)) return J({ error: 'firma inválida' }, 401);
  let ev; try { ev = JSON.parse(new TextDecoder().decode(raw)); } catch { return J({ ok: true }); }
  const d = ev.data || {}, ref = d.metadata && d.metadata.reference;
  if (!ref || !/^SALE_(APPROVED|REJECTED)$/.test(ev.type || '')) return J({ ok: true });
  ctx.waitUntil(rpc(env, 'confirmar_pago', {
    p_numero: ref, p_tx: d.payment_id || ev.subject || ev.id, p_aprobado: ev.type === 'SALE_APPROVED',
    p_metodo: d.payment_method || null, p_monto: Math.round(Number(d.amount && d.amount.total) || 0), p_payload: ev
  }, true).catch(e => console.error('confirmar_pago', e.message)));
  return J({ ok: true });
}

// Solo en modo pruebas: Bold no envía webhooks de transacciones de prueba,
// así que el regreso a la tienda confirma el resultado de la prueba.
async function confirmarPrueba(req, env) {
  if (env.BOLD_MODE !== 'pruebas') return J({ error: 'solo en pruebas' }, 403);
  const { pedido_id, status, tx } = await req.json().catch(() => ({}));
  if (!/^[0-9a-f-]{36}$/i.test(pedido_id || '')) return J({ error: 'Pedido no válido' }, 400);
  // En pruebas solo se confirman compras hechas por el equipo de OUTTA.
  if (!(await rpc(env, 'pedido_es_de_equipo', { p_id: pedido_id }, true))) return J({ error: 'Las compras de prueba solo las puede hacer el equipo' }, 403);
  const p = await rpc(env, 'pedido_para_pago', { p_id: pedido_id });
  if (!p) return J({ error: 'no existe' }, 404);
  const r = await rpc(env, 'confirmar_pago', { p_numero: p.numero, p_tx: 'PRUEBA-' + (tx || pedido_id), p_aprobado: status === 'approved', p_metodo: 'prueba', p_monto: p.total, p_payload: { prueba: true, status } }, true);
  return J(r || { ok: true });
}

// ---------- Meta: API de conversiones ----------
// El Pixel ID y el código de prueba se leen de la tabla config (clave 'meta'), que el panel edita.
const META_V = 'v21.0';
const META_OK = new Set(['PageView', 'ViewContent', 'AddToCart', 'InitiateCheckout', 'AddPaymentInfo', 'Purchase', 'Lead', 'CompleteRegistration', 'Contact', 'Search']);
let metaCache = { t: 0, v: null };
async function metaCfg(env) {
  if (metaCache.v && Date.now() - metaCache.t < 60000) return metaCache.v;
  const r = await fetch(`${env.SUPABASE_URL}/rest/v1/config?clave=eq.meta&select=valor`, { headers: { apikey: env.SUPABASE_ANON } });
  const rows = r.ok ? await r.json() : [];
  metaCache = { t: Date.now(), v: (rows[0] && rows[0].valor) || {} };
  return metaCache.v;
}
const normPh = s => { let d = String(s || '').replace(/\D/g, ''); if (d.length === 10 && d[0] === '3') d = '57' + d; return d; };
async function metaEvento(req, env, ctx) {
  const b = await req.json().catch(() => null);
  if (!b || !META_OK.has(b.name) || typeof b.id !== 'string' || b.id.length > 100) return J({ ok: false, motivo: 'evento no válido' }, 400);
  const cfg = await metaCfg(env), pixel = String(cfg.pixel || '').replace(/\D/g, '');
  if (!pixel || !env.META_TOKEN) return J({ ok: false, motivo: 'Meta sin configurar' });
  const d = b.data || {}, cd = {};
  for (const k of ['value', 'currency', 'content_ids', 'content_type', 'content_name', 'num_items', 'order_id', 'status']) if (d[k] !== undefined) cd[k] = d[k];
  if (cd.content_ids && !cd.content_type) cd.content_type = 'product';
  if (b.name === 'Purchase') {
    // La compra solo cuenta si el pago está confirmado en la base de datos; el valor sale de ahí.
    if (!/^[0-9a-f-]{36}$/i.test(b.pid || '')) return J({ ok: false, motivo: 'compra sin pedido' }, 400);
    const p = await rpc(env, 'pedido_para_pago', { p_id: b.pid });
    if (!p || p.estado !== 'pagado' || p.numero !== b.id) return J({ ok: false, motivo: 'pago no confirmado' }, 409);
    cd.value = p.total; cd.currency = 'COP'; cd.order_id = p.numero;
  }
  const ud = { client_ip_address: req.headers.get('cf-connecting-ip') || undefined, client_user_agent: req.headers.get('user-agent') || undefined };
  if (b.fbp) ud.fbp = String(b.fbp).slice(0, 200);
  if (b.fbc) ud.fbc = String(b.fbc).slice(0, 300);
  const em = String(b.em || '').trim().toLowerCase(); if (/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(em)) ud.em = [await sha256(em)];
  const ph = normPh(b.ph); if (ph.length >= 10) ud.ph = [await sha256(ph)];
  if (b.xid) ud.external_id = [await sha256(String(b.xid))];
  let src = ''; try { const u = new URL(b.url); if (u.hostname === new URL(req.url).hostname) src = u.origin + u.pathname; } catch {}
  const payload = { data: [{ event_name: b.name, event_time: Math.floor(Date.now() / 1000), event_id: b.id, action_source: 'website', event_source_url: src || new URL(req.url).origin + '/', user_data: ud, custom_data: cd }] };
  if (cfg.test) payload.test_event_code = String(cfg.test);
  ctx.waitUntil(fetch(`https://graph.facebook.com/${META_V}/${pixel}/events?access_token=${encodeURIComponent(env.META_TOKEN)}`, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(payload)
  }).then(async r => { if (!r.ok) console.error('meta', r.status, (await r.text()).slice(0, 300)); }).catch(e => console.error('meta', e.message)));
  return J({ ok: true });
}

export default {
  async fetch(req, env, ctx) {
    const url = new URL(req.url);
    try {
      if (url.pathname === '/api/pago/firma' && req.method === 'POST') return await firma(req, env);
      if (url.pathname === '/api/bold/webhook' && req.method === 'POST') return await webhook(req, env, ctx);
      if (url.pathname === '/api/pago/confirmar-prueba' && req.method === 'POST') return await confirmarPrueba(req, env);
      if (url.pathname === '/api/meta/evento' && req.method === 'POST') return await metaEvento(req, env, ctx);
      if (url.pathname === '/api/salud') return J({ ok: true, modo: env.BOLD_MODE, bold: !!env.BOLD_SECRET, supabase: !!env.SUPABASE_SECRET, meta: !!env.META_TOKEN });
      if (url.pathname.startsWith('/api/')) return J({ error: 'no existe' }, 404);
    } catch (e) {
      console.error(e);
      return J({ error: 'Error del servidor' }, 500);
    }
    return env.ASSETS.fetch(req);
  }
};
