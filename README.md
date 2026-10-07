# TechStore - Sistema de Gestión de Inventario (Laboratorio 08)

Aplicación web con controles de seguridad: registro, login con JWT, bloqueo por intentos fallidos, MFA con TOTP y login con Google y GitHub.

## Funcionalidades
- Registro con email único, nombre, tienda y rol
- Contraseña segura: mínimo 8 caracteres, mayúscula, número y carácter especial (encriptada con bcrypt)
- Login con validación de credenciales y token JWT
- Bloqueo de la cuenta después de 5 intentos fallidos
- MFA con TOTP (Google Authenticator), código de 6 dígitos cada 30 segundos, máximo 3 intentos
- Login con Google y GitHub mediante OAuth 2.0

## Instalación
npm install

## Configuración
Crear un archivo .env en la raíz con:

JWT_SECRET=secreto_techstore
GITHUB_CLIENT_ID=
GITHUB_CLIENT_SECRET=
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=

Callbacks:
- GitHub: http://localhost:3000/auth/github/callback
- Google: http://localhost:3000/auth/google/callback

## Ejecución
node server.js

Abrir http://localhost:3000