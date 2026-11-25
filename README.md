# OUTTA' — outtaclothes.com

- `public/` — la página (estática). Por defecto se ve en **modo vitrina** (pedidos por WhatsApp).
  Con `?tienda=prueba` se activa la **tienda completa** (cuentas, checkout con Bold) en ese navegador; `?tienda=off` la apaga.
- `src/index.js` — Worker de Cloudflare: API de pagos.
  - `POST /api/pago/firma` firma de integridad de Bold (la llave secreta nunca sale del servidor).
  - `POST /api/bold/webhook` recibe la confirmación de Bold (verifica `x-bold-signature`).
  - `POST /api/pago/confirmar-prueba` solo en modo pruebas.
  - `GET /api/salud` estado de la configuración.
- Base de datos: Supabase (proyecto `outta`). Precios, stock, cupones y envío se calculan en la base de datos.

Secretos en Cloudflare (Worker `outta-web` → Settings → Variables and Secrets): `BOLD_SECRET`, `SUPABASE_SECRET`.
Cada push a `main` se despliega solo.
