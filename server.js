require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const GitHubStrategy = require('passport-github2').Strategy;
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'secreto_techstore';
const DB = './usuarios.json';

app.use(express.json());
app.use(express.static('public'));
app.use(session({ secret: JWT_SECRET, resave: false, saveUninitialized: false }));
app.use(passport.initialize());

// ---------- "Base de datos" en archivo JSON ----------
const leer = () => { try { const t = fs.readFileSync(DB, 'utf8'); return t.trim() ? JSON.parse(t) : []; } catch { return []; } };
const guardar = (u) => fs.writeFileSync(DB, JSON.stringify(u, null, 2));
const buscar = (email) => leer().find((u) => u.email === email);
const actualizar = (user) => { const us = leer().map((u) => (u.email === user.email ? user : u)); guardar(us); };

// Contraseña: min 8, mayúscula, número, carácter especial
const passValida = (p) => /^(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,}$/.test(p);

// ---------- PARTE 1: REGISTRO ----------
app.post('/api/registro', async (req, res) => {
  const { nombre, email, password, tienda } = req.body;
  if (!nombre || !email || !password || !tienda) return res.status(400).json({ error: 'Todos los campos son obligatorios' });
  if (buscar(email)) return res.status(400).json({ error: 'El email ya está registrado' });
  if (!passValida(password)) return res.status(400).json({ error: 'La contraseña debe tener mínimo 8 caracteres, una mayúscula, un número y un carácter especial' });

  const secreto = speakeasy.generateSecret({ name: `TechStore (${email})` });
  const user = {
    nombre, email, tienda, // Seguridad: nadie elige su propio rol. El primer usuario es Administrador; los demás, Empleado de Ventas
    rol: leer().length === 0 ? 'Administrador del Sistema' : 'Empleado de Ventas',
    password: await bcrypt.hash(password, 10),
    mfaSecret: secreto.base32,
    intentosFallidos: 0, bloqueado: false, proveedor: 'local'
  };
  const usuarios = leer(); usuarios.push(user); guardar(usuarios);
  const qr = await QRCode.toDataURL(secreto.otpauth_url);
  res.json({ mensaje: 'Usuario registrado. Escanea el QR con Google Authenticator', qr });
});

// ---------- PARTE 1: LOGIN (con bloqueo a los 5 intentos) ----------
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const user = buscar(email);
  if (!user) return res.status(401).json({ error: 'Credenciales inválidas' });
  if (user.bloqueado) return res.status(423).json({ error: 'Cuenta bloqueada por 5 intentos fallidos' });

  const ok = await bcrypt.compare(password, user.password || '');
  if (!ok) {
    user.intentosFallidos++;
    if (user.intentosFallidos >= 5) user.bloqueado = true;
    actualizar(user);
    return res.status(401).json({ error: user.bloqueado ? 'Cuenta bloqueada por 5 intentos fallidos' : `Credenciales inválidas. Intento ${user.intentosFallidos} de 5` });
  }
  user.intentosFallidos = 0; user.intentosMfa = 0; actualizar(user);
  // Token temporal: aún NO tiene acceso completo
  const tempToken = jwt.sign({ email, mfa: false }, JWT_SECRET, { expiresIn: '5m' });
  res.json({ mensaje: 'Credenciales correctas. Ingresa el código MFA', tempToken });
});

// ---------- PARTE 2: MFA TOTP (máximo 3 intentos) ----------
app.post('/api/mfa', (req, res) => {
  const { tempToken, codigo } = req.body;
  let data;
  try { data = jwt.verify(tempToken, JWT_SECRET); } catch { return res.status(401).json({ error: 'Token temporal inválido o expirado' }); }
  const user = buscar(data.email);
  if ((user.intentosMfa || 0) >= 3) return res.status(403).json({ error: 'Máximo de 3 intentos MFA alcanzado. Inicia sesión de nuevo' });

  const valido = speakeasy.totp.verify({ secret: user.mfaSecret, encoding: 'base32', token: codigo, window: 1 });
  if (!valido) {
    user.intentosMfa = (user.intentosMfa || 0) + 1; actualizar(user);
    return res.status(401).json({ error: `Código incorrecto. Intento ${user.intentosMfa} de 3` });
  }
  user.intentosMfa = 0; actualizar(user);
  const token = jwt.sign({ email: user.email, nombre: user.nombre, rol: user.rol, tienda: user.tienda, mfa: true }, JWT_SECRET, { expiresIn: '1h' });
  res.json({ mensaje: 'Acceso concedido', token });
});

// ---------- AUTORIZACIÓN POR PERFIL (RBAC) ----------
const ROLES = { ADMIN: 'Administrador del Sistema', GERENTE: 'Gerente de Tienda', EMPLEADO: 'Empleado de Ventas', AUDITOR: 'Auditor' };
// Compatibilidad con usuarios registrados antes con nombres cortos
const normalizarRol = (r) => ({ 'Administrador': ROLES.ADMIN, 'Gerente': ROLES.GERENTE, 'Empleado': ROLES.EMPLEADO }[r] || r);

// Verifica el JWT completo (con MFA) y carga el rol ACTUAL desde la base de datos
function verificarToken(req, res, next) {
  const token = (req.headers.authorization || '').split(' ')[1];
  try {
    const data = jwt.verify(token, JWT_SECRET);
    if (!data.mfa) return res.status(403).json({ error: 'Falta completar MFA' });
    const u = buscar(data.email);
    if (!u) return res.status(401).json({ error: 'Usuario no existe' });
    if (u.bloqueado) return res.status(423).json({ error: 'Cuenta bloqueada' });
    req.user = { email: u.email, nombre: u.nombre, rol: normalizarRol(u.rol), tienda: u.tienda, exp: data.exp, mfa: true };
    next();
  } catch { res.status(401).json({ error: 'Token inválido' }); }
}
// Solo deja pasar a los roles indicados
const permitir = (...roles) => (req, res, next) =>
  roles.includes(req.user.rol) ? next() : res.status(403).json({ error: `Acceso denegado: el perfil ${req.user.rol} no tiene permiso` });

app.get('/api/perfil', verificarToken, (req, res) => res.json({ usuario: req.user }));

// ---------- Productos ----------
const DBP = './productos.json';
const PRODUCTOS_INICIALES = [
  { id: 1, nombre: 'Laptop Lenovo IdeaPad', tienda: 'TechStore Lima', precio: 2500, stock: 10 },
  { id: 2, nombre: 'Mouse Logitech M170', tienda: 'TechStore Lima', precio: 45, stock: 50 },
  { id: 3, nombre: 'Monitor Samsung 24"', tienda: 'TechStore Arequipa', precio: 650, stock: 8 },
  { id: 4, nombre: 'Teclado Redragon Kumara', tienda: 'TechStore Arequipa', precio: 180, stock: 20 }
];
const leerP = () => { try { const t = fs.readFileSync(DBP, 'utf8'); return t.trim() ? JSON.parse(t) : PRODUCTOS_INICIALES; } catch { return PRODUCTOS_INICIALES; } };
const guardarP = (p) => fs.writeFileSync(DBP, JSON.stringify(p, null, 2));

// Consultar productos: todos los perfiles
app.get('/api/productos', verificarToken, (req, res) => res.json(leerP()));

// Crear producto: Administrador (cualquier tienda) y Gerente (solo su tienda)
app.post('/api/productos', verificarToken, permitir(ROLES.ADMIN, ROLES.GERENTE), (req, res) => {
  const { nombre, precio, stock } = req.body;
  const tienda = req.user.rol === ROLES.GERENTE ? req.user.tienda : (req.body.tienda || req.user.tienda);
  if (!nombre || precio == null || stock == null) return res.status(400).json({ error: 'Nombre, precio y stock son obligatorios' });
  const ps = leerP();
  const nuevo = { id: Math.max(0, ...ps.map((p) => p.id)) + 1, nombre, tienda, precio: Number(precio), stock: Number(stock) };
  ps.push(nuevo); guardarP(ps);
  res.json({ mensaje: 'Producto creado', producto: nuevo });
});

// Actualizar producto
app.put('/api/productos/:id', verificarToken, permitir(ROLES.ADMIN, ROLES.GERENTE, ROLES.EMPLEADO), (req, res) => {
  const ps = leerP(); const p = ps.find((x) => x.id == req.params.id);
  if (!p) return res.status(404).json({ error: 'Producto no encontrado' });
  const { rol, tienda } = req.user;
  if (rol === ROLES.EMPLEADO) {
    // Empleado: solo actualiza stock, NO puede modificar precios
    if (req.body.precio != null && Number(req.body.precio) !== p.precio) return res.status(403).json({ error: 'Acceso denegado: el Empleado de Ventas no puede modificar precios' });
    if (req.body.stock == null) return res.status(400).json({ error: 'Indica el stock' });
    p.stock = Number(req.body.stock);
  } else {
    if (rol === ROLES.GERENTE && p.tienda !== tienda) return res.status(403).json({ error: 'Acceso denegado: el Gerente solo gestiona productos de su tienda' });
    if (req.body.precio != null) p.precio = Number(req.body.precio);
    if (req.body.stock != null) p.stock = Number(req.body.stock);
  }
  guardarP(ps);
  res.json({ mensaje: 'Producto actualizado', producto: p });
});

// Eliminar producto: Administrador (todos) y Gerente (solo su tienda)
app.delete('/api/productos/:id', verificarToken, permitir(ROLES.ADMIN, ROLES.GERENTE), (req, res) => {
  const ps = leerP(); const p = ps.find((x) => x.id == req.params.id);
  if (!p) return res.status(404).json({ error: 'Producto no encontrado' });
  if (req.user.rol === ROLES.GERENTE && p.tienda !== req.user.tienda) return res.status(403).json({ error: 'Acceso denegado: el Gerente no puede eliminar productos de otras tiendas' });
  guardarP(ps.filter((x) => x.id !== p.id));
  res.json({ mensaje: 'Producto eliminado' });
});

// Reportes: Administrador y Auditor (todas las tiendas), Gerente (solo su tienda)
app.get('/api/reportes', verificarToken, permitir(ROLES.ADMIN, ROLES.GERENTE, ROLES.AUDITOR), (req, res) => {
  let ps = leerP();
  if (req.user.rol === ROLES.GERENTE) ps = ps.filter((p) => p.tienda === req.user.tienda);
  const porTienda = {};
  ps.forEach((p) => {
    porTienda[p.tienda] = porTienda[p.tienda] || { productos: 0, unidades: 0, valorInventario: 0 };
    porTienda[p.tienda].productos++; porTienda[p.tienda].unidades += p.stock; porTienda[p.tienda].valorInventario += p.precio * p.stock;
  });
  res.json({ generadoPor: req.user.nombre, rol: req.user.rol, fecha: new Date().toLocaleString(), porTienda });
});

// ---------- Gestión de usuarios: solo Administrador ----------
app.get('/api/usuarios', verificarToken, permitir(ROLES.ADMIN), (req, res) =>
  res.json(leer().map((u) => ({ nombre: u.nombre, email: u.email, rol: normalizarRol(u.rol), tienda: u.tienda, bloqueado: u.bloqueado, proveedor: u.proveedor }))));

app.put('/api/usuarios/:email', verificarToken, permitir(ROLES.ADMIN), (req, res) => {
  const u = buscar(req.params.email);
  if (!u) return res.status(404).json({ error: 'Usuario no encontrado' });
  if (req.body.rol) { if (!Object.values(ROLES).includes(req.body.rol)) return res.status(400).json({ error: 'Rol inválido' }); u.rol = req.body.rol; }
  if (req.body.tienda) u.tienda = req.body.tienda;
  if (req.body.desbloquear) { u.bloqueado = false; u.intentosFallidos = 0; }
  actualizar(u);
  res.json({ mensaje: 'Usuario actualizado' });
});

// ---------- Login con redes sociales ----------
function socialLogin(proveedor) {
  return (accessToken, refreshToken, profile, done) => {
    const email = (profile.emails && profile.emails[0] && profile.emails[0].value) || `${profile.username || profile.id}@${proveedor}.com`;
    let user = buscar(email);
    if (!user) {
      user = { nombre: profile.displayName || profile.username, email, tienda: 'TechStore Lima', rol: 'Empleado de Ventas', proveedor, intentosFallidos: 0, bloqueado: false };
      const us = leer(); us.push(user); guardar(us);
    }
    done(null, user);
  };
}
if (process.env.GOOGLE_CLIENT_ID) {
  passport.use(new GoogleStrategy({ clientID: process.env.GOOGLE_CLIENT_ID, clientSecret: process.env.GOOGLE_CLIENT_SECRET, callbackURL: '/auth/google/callback' }, socialLogin('google')));
}
if (process.env.GITHUB_CLIENT_ID) {
  passport.use(new GitHubStrategy({ clientID: process.env.GITHUB_CLIENT_ID, clientSecret: process.env.GITHUB_CLIENT_SECRET, callbackURL: '/auth/github/callback', scope: ['user:email'] }, socialLogin('github')));
}
const finSocial = (req, res) => {
  const u = req.user;
  const token = jwt.sign({ email: u.email, nombre: u.nombre, rol: u.rol, tienda: u.tienda, mfa: true, proveedor: u.proveedor }, JWT_SECRET, { expiresIn: '1h' });
  res.redirect('/?token=' + token);
};
const configurado = (p) => (req, res, next) => passport._strategy(p) ? next() : res.send(`Falta configurar ${p} en el archivo .env`);
app.get('/auth/google', configurado('google'), passport.authenticate('google', { scope: ['profile', 'email'], session: false }));
app.get('/auth/google/callback', passport.authenticate('google', { session: false, failureRedirect: '/' }), finSocial);
app.get('/auth/github', configurado('github'), passport.authenticate('github', { session: false }));
app.get('/auth/github/callback', passport.authenticate('github', { session: false, failureRedirect: '/' }), finSocial);

app.listen(PORT, () => console.log(`TechStore corriendo en http://localhost:${PORT}`));