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
const leer = () => (fs.existsSync(DB) ? JSON.parse(fs.readFileSync(DB)) : []);
const guardar = (u) => fs.writeFileSync(DB, JSON.stringify(u, null, 2));
const buscar = (email) => leer().find((u) => u.email === email);
const actualizar = (user) => { const us = leer().map((u) => (u.email === user.email ? user : u)); guardar(us); };

// Contraseña: min 8, mayúscula, número, carácter especial
const passValida = (p) => /^(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,}$/.test(p);

// ---------- PARTE 1: REGISTRO ----------
app.post('/api/registro', async (req, res) => {
  const { nombre, email, password, tienda, rol } = req.body;
  if (!nombre || !email || !password || !tienda) return res.status(400).json({ error: 'Todos los campos son obligatorios' });
  if (buscar(email)) return res.status(400).json({ error: 'El email ya está registrado' });
  if (!passValida(password)) return res.status(400).json({ error: 'La contraseña debe tener mínimo 8 caracteres, una mayúscula, un número y un carácter especial' });

  const secreto = speakeasy.generateSecret({ name: `TechStore (${email})` });
  const user = {
    nombre, email, tienda, rol: rol || 'Empleado',
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

// ---------- Ruta protegida (requiere JWT completo) ----------
function verificarToken(req, res, next) {
  const token = (req.headers.authorization || '').split(' ')[1];
  try {
    const data = jwt.verify(token, JWT_SECRET);
    if (!data.mfa) return res.status(403).json({ error: 'Falta completar MFA' });
    req.user = data; next();
  } catch { res.status(401).json({ error: 'Token inválido' }); }
}
app.get('/api/perfil', verificarToken, (req, res) => res.json({ usuario: req.user }));

// ---------- Login con redes sociales ----------
function socialLogin(proveedor) {
  return (accessToken, refreshToken, profile, done) => {
    const email = (profile.emails && profile.emails[0] && profile.emails[0].value) || `${profile.username || profile.id}@${proveedor}.com`;
    let user = buscar(email);
    if (!user) {
      user = { nombre: profile.displayName || profile.username, email, tienda: 'Sin asignar', rol: 'Empleado', proveedor, intentosFallidos: 0, bloqueado: false };
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