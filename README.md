# Control Gastos

Aplicación de finanzas personales con acceso por Google, almacenamiento por usuario en SQLite y despliegue en Vercel.

## Desarrollo local

Requiere Node.js 24.x.

```powershell
npm install
Copy-Item .env.example .env
```

Generá un secreto de sesión y pegalo como `SESSION_SECRET` en `.env`:

```powershell
[Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
```

Para habilitar Google OAuth, creá un cliente OAuth de tipo **Aplicación web** en Google Cloud Console. Configurá como origen autorizado `http://localhost:5173` (o el puerto que muestre Vite) y como URI de redireccionamiento `http://localhost:5173/api/auth/google/callback`. Completá `GOOGLE_CLIENT_ID` y `GOOGLE_CLIENT_SECRET` en `.env`. Si el puerto local cambia, agregá el nuevo origen y callback en Google y fijá `GOOGLE_REDIRECT_URI` con esa URL.

Luego ejecutá:

```powershell
npm run dev
```

En local se guarda en `data/control-gastos.db`, ignorado por Git. La API, el frontend y el flujo OAuth comparten el mismo origen local.

## Arquitectura

- `src/`: SPA de React y Vite. El selector de mes y las fechas usan calendarios propios; las operaciones confirmadas muestran toasts.
- `api/[...route].js`: funciones HTTP para inicio y callback OAuth de Google, sesión, cierre de sesión y lectura/escritura autenticada.
- `api/_db.js`: SQLite local con `node:sqlite` y acceso HTTP a Turso/libSQL en producción.
- `users`: una fila por identidad de Google (`sub`). La API deriva el usuario de una cookie de sesión firmada, `HttpOnly`, `SameSite=Lax` y `Secure` en HTTPS; no acepta un `user_id` enviado por el navegador.
- `user_data`: filas por usuario y colección (`expenses`, `cards`, `services`, `finance`, `closings`), con clave foránea a `users`. Todas las consultas están limitadas al usuario de la sesión.

El acceso de Google solo solicita `openid email profile`. No guardamos tokens de Google. La cookie de sesión se firma con `SESSION_SECRET`.

## Vercel y SQLite

Vercel ejecuta Functions en un entorno sin disco persistente compartido; una SQLite local allí podría perder escrituras o divergir entre instancias. Por eso el código usa un archivo SQLite para desarrollo y la API HTTP de Turso/libSQL, que mantiene compatibilidad con SQLite, en producción.

1. Creá una base SQLite en Turso y generá un token de acceso.
2. Importá el repositorio en Vercel; se usa `vercel.json` para compilar Vite y servir el frontend.
3. Agregá estas variables en Vercel (Production y Preview, según corresponda):
   - `GOOGLE_CLIENT_ID`
   - `GOOGLE_CLIENT_SECRET`
   - `GOOGLE_REDIRECT_URI=https://TU-DOMINIO/api/auth/google/callback`
   - `SESSION_SECRET` (distinto y aleatorio, de al menos 32 caracteres)
   - `TURSO_DATABASE_URL=libsql://...`
   - `TURSO_AUTH_TOKEN`
   - `RESEND_API_KEY`
   - `REMINDER_FROM_EMAIL` (remitente de un dominio verificado en Resend)
   - `CRON_SECRET` (secreto aleatorio para autenticar la ruta de cron)
4. En Google Cloud, agregá el dominio publicado como origen autorizado y la URI exacta `/api/auth/google/callback` como redireccionamiento autorizado. Google requiere que la URI coincida exactamente.
5. Volvé a desplegar después de guardar las variables.

### Recordatorios por vencimiento

La ruta `/api/cron/reminders` se ejecuta una vez por día desde Vercel Cron, aproximadamente al mediodía de Argentina. Vercel Cron usa UTC y, en el plan Hobby, la ejecución puede ocurrir en cualquier momento dentro de esa hora. Los recordatorios se envían al correo de Google de cada usuario e incluyen servicios que vencen ese día y siguen como `No Pagado`, además de tarjetas con vencimiento configurado y cuotas por pagar ese mes. Se envía un solo correo diario por usuario y se registra la entrega para evitar duplicados.

Para habilitar los correos:

1. Creá una cuenta en Resend, verificá un dominio de envío y generá una API key. La dirección de `REMINDER_FROM_EMAIL` debe pertenecer al dominio verificado, por ejemplo `Control Gastos <avisos@tudominio.com>`.
2. En Vercel, agregá `RESEND_API_KEY`, `REMINDER_FROM_EMAIL` y `CRON_SECRET` como variables de entorno de **Production**. `CRON_SECRET` debe ser aleatorio y privado; Vercel lo envía como `Authorization: Bearer ...` al ejecutar el cron.
3. Hacé un nuevo deploy de producción. Vercel activa los cron jobs desde el despliegue de producción, no desde Preview.

El endpoint usa la fecha de `America/Argentina/Buenos_Aires`. Los servicios se notifican cuando su fecha guardada coincide con el día actual y no están marcados como pagados; la notificación no cambia el estado del servicio.

No guardes secretos en el frontend, en Git ni en archivos `.env` versionados. `.env.example` contiene solo nombres y valores vacíos.

Los datos que estaban en la versión anterior del navegador no se suben automáticamente. Al entrar por primera vez, la aplicación ofrece importarlos explícitamente a la cuenta de Google iniciada; la copia local se conserva.
