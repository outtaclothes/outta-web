// OUTTA' — Worker: sirve la página (public/) y la API de pagos con Bold.
// Secretos (Cloudflare → Worker → Settings → Variables and Secrets):
//   BOLD_SECRET      llave secreta del Botón de pagos de Bold
//   SUPABASE_SECRET  llave secreta (service role) de Supabase
//   META_TOKEN       token de acceso de la API de conversiones de Meta
//   RESEND_KEY       llave de Resend (Sending access) para los correos de pedidos
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
  }, true).then(r => r && r.estado === 'pagado' ? notificar(env, ref, 'pagado') : null)
    .catch(e => console.error('confirmar_pago', e.message)));
  return J({ ok: true });
}

// Solo en modo pruebas: Bold no envía webhooks de transacciones de prueba,
// así que el regreso a la tienda confirma el resultado de la prueba.
async function confirmarPrueba(req, env, ctx) {
  if (env.BOLD_MODE !== 'pruebas') return J({ error: 'solo en pruebas' }, 403);
  const { pedido_id, status, tx } = await req.json().catch(() => ({}));
  if (!/^[0-9a-f-]{36}$/i.test(pedido_id || '')) return J({ error: 'Pedido no válido' }, 400);
  // En pruebas solo se confirman compras hechas por el equipo de OUTTA.
  if (!(await rpc(env, 'pedido_es_de_equipo', { p_id: pedido_id }, true))) return J({ error: 'Las compras de prueba solo las puede hacer el equipo' }, 403);
  const p = await rpc(env, 'pedido_para_pago', { p_id: pedido_id });
  if (!p) return J({ error: 'no existe' }, 404);
  const r = await rpc(env, 'confirmar_pago', { p_numero: p.numero, p_tx: 'PRUEBA-' + (tx || pedido_id), p_aprobado: status === 'approved', p_metodo: 'prueba', p_monto: p.total, p_payload: { prueba: true, status } }, true);
  if (r && r.estado === 'pagado') ctx.waitUntil(notificar(env, p.numero, 'pagado').catch(e => console.error('correo', e.message)));
  return J(r || { ok: true });
}

// ---------- Correos de pedidos (Resend) ----------
const DUENO = 'clothesoutta@gmail.com';
const cop = n => '$' + Math.round(Number(n) || 0).toLocaleString('es-CO').replace(/,/g, '.');
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
async function sbRest(env, path, init = {}) {
  const k = env.SUPABASE_SECRET, h = { apikey: k, 'content-type': 'application/json', ...(init.headers || {}) };
  if (k && k.startsWith('eyJ')) h.authorization = 'Bearer ' + k;
  const r = await fetch(`${env.SUPABASE_URL}/rest/v1/${path}`, { ...init, headers: h });
  if (!r.ok) throw new Error(`rest ${path.split('?')[0]} ${r.status}: ${(await r.text()).slice(0, 200)}`);
  const t = await r.text(); return t ? JSON.parse(t) : null;
}
function mailHtml(o, titulo, intro, extra) {
  const filas = (o.pedido_lineas || []).map(l => `<tr><td style="padding:8px 0;border-bottom:1px solid #e3e3e0;font-size:14px;color:#111;">${esc(l.nombre)}<br><span style="font-size:12px;color:#777;">Talla ${esc(l.talla)} · x${l.cantidad}</span></td><td align="right" style="padding:8px 0;border-bottom:1px solid #e3e3e0;font-size:14px;color:#111;">${cop(l.precio * l.cantidad)}</td></tr>`).join('');
  const tot = (k, v, b) => `<tr><td style="padding:4px 0;font-size:${b ? 15 : 13}px;color:${b ? '#111' : '#555'};${b ? 'font-weight:700;' : ''}">${k}</td><td align="right" style="padding:4px 0;font-size:${b ? 15 : 13}px;color:${b ? '#111' : '#555'};${b ? 'font-weight:700;' : ''}">${v}</td></tr>`;
  const e = o.envio || {};
  return `<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(titulo)}</title></head>
<body style="margin:0;padding:0;background:#f2f2f0;"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f2f2f0;"><tr><td align="center" style="padding:32px 12px;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:520px;background:#fff;border:1px solid #111;">
<tr><td style="padding:28px 32px 20px;border-bottom:1px solid #111;"><img src="https://outtaclothes.com/img/wordmark-negro-mail.png" width="140" alt="OUTTA'" style="display:block;border:0;width:140px;height:auto;"></td></tr>
<tr><td style="padding:32px 32px 8px;font-family:Helvetica,Arial,sans-serif;color:#111;">
<p style="margin:0 0 6px;font-size:11px;letter-spacing:1.5px;color:#777;">PEDIDO ${esc(o.numero)}</p>
<h1 style="margin:0 0 16px;font-size:24px;line-height:1.15;font-weight:700;text-transform:uppercase;">${esc(titulo)}</h1>
<p style="margin:0 0 22px;font-size:15px;line-height:1.6;color:#333;">${intro}</p>${extra || ''}
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="font-family:Helvetica,Arial,sans-serif;">${filas}</table>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin-top:10px;font-family:Helvetica,Arial,sans-serif;">${tot('Subtotal', cop(o.subtotal))}${o.descuento ? tot('Descuento' + (o.cupon ? ' (' + esc(o.cupon) + ')' : ''), '−' + cop(o.descuento)) : ''}${tot('Envío', o.costo_envio ? cop(o.costo_envio) : 'Gratis')}${tot('Total', cop(o.total), 1)}</table>
<p style="margin:22px 0 0;font-size:13px;line-height:1.6;color:#555;"><b style="color:#111;">Envío a</b><br>${esc(o.nombre)} ${esc(o.apellido)}<br>${esc(e.direccion)}${e.barrio ? ', ' + esc(e.barrio) : ''}<br>${esc(e.ciudad)}, ${esc(e.departamento)}</p>
<table role="presentation" cellpadding="0" cellspacing="0" style="margin-top:24px;"><tr><td style="background:#111;"><a href="https://outtaclothes.com/#cuenta" style="display:inline-block;padding:13px 24px;font-family:Helvetica,Arial,sans-serif;font-size:12px;font-weight:700;letter-spacing:1.5px;text-transform:uppercase;color:#fff;text-decoration:none;">Ver mi pedido</a></td></tr></table>
</td></tr>
<tr><td style="padding:24px 32px 28px;font-family:Helvetica,Arial,sans-serif;font-size:11px;line-height:1.6;color:#777;border-top:1px solid #e3e3e0;">OUTTA' · Bogotá, Colombia · <a href="https://outtaclothes.com" style="color:#111;">outtaclothes.com</a> · <a href="https://www.instagram.com/outta.__/" style="color:#111;">@outta.__</a><br>¿Dudas con tu pedido? Responde este correo o escríbenos por WhatsApp al 310 578 4965. Tienes derecho de retracto dentro de los 5 días hábiles siguientes a la entrega.</td></tr>
</table></td></tr></table></body></html>`;
}
async function enviarCorreo(env, to, subject, html, replyTo) {
  const r = await fetch('https://api.resend.com/emails', { method: 'POST', headers: { authorization: 'Bearer ' + env.RESEND_KEY, 'content-type': 'application/json' },
    body: JSON.stringify({ from: "OUTTA' <pedidos@outtaclothes.com>", to: [to], subject, html, reply_to: replyTo || DUENO }) });
  if (!r.ok) throw new Error('resend ' + r.status + ': ' + (await r.text()).slice(0, 200));
}
// tipo: 'pagado' | 'enviado' | 'entregado'. Cada correo sale una sola vez por pedido (columna correos).
async function notificar(env, numero, tipo) {
  if (!env.RESEND_KEY || !env.SUPABASE_SECRET) return { ok: false, motivo: 'correo sin configurar' };
  const rows = await sbRest(env, `pedidos?numero=eq.${encodeURIComponent(numero)}&select=*,pedido_lineas(*)`);
  const o = rows && rows[0]; if (!o) return { ok: false, motivo: 'pedido no existe' };
  if ((o.correos || {})[tipo]) return { ok: true, repetido: true };
  if (tipo === 'pagado' && o.estado !== 'pagado') return { ok: false, motivo: 'no está pagado' };
  const nom = esc((o.nombre || '').split(' ')[0]);
  if (tipo === 'pagado') {
    await enviarCorreo(env, o.email, `Pedido ${o.numero} confirmado · OUTTA'`, mailHtml(o, 'Tu pedido está confirmado', `${nom}, recibimos tu pago. Vamos a preparar tus piezas y te escribimos con la guía cuando salgan del taller.`));
    const e = o.envio || {};
    await enviarCorreo(env, DUENO, `Nueva venta ${o.numero} · ${cop(o.total)}`, mailHtml(o, 'Nueva venta en la web', `${esc(o.nombre)} ${esc(o.apellido)} · ${esc(o.email)} · ${esc(o.celular)}<br>${esc(e.indicaciones || '')}`), o.email);
  } else if (tipo === 'enviado') {
    if (!o.guia) return { ok: false, motivo: 'falta el número de guía' };
    await enviarCorreo(env, o.email, `Tu pedido ${o.numero} va en camino · OUTTA'`, mailHtml(o, 'Tu pedido va en camino', `${nom}, tus piezas ya salieron.`,
      `<p style="margin:0 0 22px;padding:14px 16px;background:#f2f2f0;font-size:14px;line-height:1.6;color:#111;">Transportadora: <b>${esc(o.transportadora || '—')}</b><br>Número de guía: <b>${esc(o.guia)}</b></p>`));
  } else if (tipo === 'entregado') {
    await enviarCorreo(env, o.email, `Pedido ${o.numero} entregado · OUTTA'`, mailHtml(o, 'Tu pedido llegó', `${nom}, tu pedido figura como entregado. Si algo no está bien con la talla o la pieza, responde este correo: tienes 5 días hábiles para retracto y cambios según nuestra política.`));
  } else return { ok: false, motivo: 'tipo no válido' };
  await sbRest(env, `pedidos?id=eq.${o.id}`, { method: 'PATCH', headers: { prefer: 'return=minimal' }, body: JSON.stringify({ correos: { ...(o.correos || {}), [tipo]: new Date().toISOString() } }) });
  return { ok: true };
}
// El panel avisa cuando un pedido pasa a enviado o entregado. Solo dueño u operador.
async function notificarPanel(req, env) {
  const tok = (req.headers.get('authorization') || '').replace(/^Bearer\s+/i, '');
  if (!tok) return J({ error: 'sin sesión' }, 401);
  const u = await fetch(`${env.SUPABASE_URL}/auth/v1/user`, { headers: { apikey: env.SUPABASE_ANON, authorization: 'Bearer ' + tok } });
  if (!u.ok) return J({ error: 'sesión no válida' }, 401);
  const user = await u.json();
  const eq = await sbRest(env, `equipo?user_id=eq.${user.id}&rol=in.(dueno,operador)&select=rol`);
  if (!eq || !eq.length) return J({ error: 'sin permiso' }, 403);
  const { numero, tipo } = await req.json().catch(() => ({}));
  if (!/^OUT-\d+$/.test(numero || '') || !['enviado', 'entregado'].includes(tipo)) return J({ error: 'datos no válidos' }, 400);
  return J(await notificar(env, numero, tipo));
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
      if (url.pathname === '/api/pago/confirmar-prueba' && req.method === 'POST') return await confirmarPrueba(req, env, ctx);
      if (url.pathname === '/api/notificar' && req.method === 'POST') return await notificarPanel(req, env);
      if (url.pathname === '/api/meta/evento' && req.method === 'POST') return await metaEvento(req, env, ctx);
      if (url.pathname === '/api/salud') return J({ ok: true, modo: env.BOLD_MODE, bold: !!env.BOLD_SECRET, supabase: !!env.SUPABASE_SECRET, meta: !!env.META_TOKEN, correo: !!env.RESEND_KEY });
      if (url.pathname.startsWith('/api/')) return J({ error: 'no existe' }, 404);
    } catch (e) {
      console.error(e);
      return J({ error: 'Error del servidor' }, 500);
    }
    return env.ASSETS.fetch(req);
  }
};
