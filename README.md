# 🎥 Plataforma de Videoconferencias - Mini Proyecto #3

**Curso:** 750018C PROYECTO INTEGRADOR I 2025-2

## 📋 Descripción del Proyecto

Plataforma web de videoconferencia que permite la creación de reuniones, chat en tiempo real, transmisión de voz y vídeo entre 2 y 10 participantes. El sistema incluye autenticación multicanal (OAuth + manual), interfaz responsiva y accesible, y comunicación en tiempo real mediante WebSockets y WebRTC.

---

## 🛠️ Stack Tecnológico

### Frontend
- **Framework:** React 18+ con TypeScript
- **Build Tool:** Vite.js
- **Estilos:** SASS/SCSS
- **HTTP Client:** Fetch API
- **Deploy:** Vercel
- **Estándares:** Heurísticas de Nielsen (progresivas hasta 10), WCAG 2.1 (progresivo hasta AA-AAA)

### Backend
- **Runtime:** Node.js 18+ con Express
- **Lenguaje:** TypeScript
- **Tiempo Real:** Socket.io (chat, señalización)
- **WebRTC:** Peer.js con servidores STUN propios
- **Deploy:** Render (1-4 microservicios)

### Base de Datos
- **Autenticación:** Firebase Authentication
- **Base de Datos:** Firestore
- **Colecciones:** `users`, `meetings`, `chat`, `summaries`

### DevOps & Gestión
- **Gestión de Proyecto:** TAIGA (metodología SCRUM)
- **Control de Versiones:** GitHub (ramas individuales + PR por sprint)
- **CI/CD:** Deploy automático en Vercel + Render

---

## 🏗️ Arquitectura del Sistema

```
┌─────────────────────────────────────────────────────────────┐
│                      FRONTEND (React + TS)                   │
│  ┌──────────┬──────────┬──────────┬──────────┬──────────┐   │
│  │   Auth   │   Home   │ Meeting  │  Chat    │  Video   │   │
│  └──────────┴──────────┴──────────┴──────────┴──────────┘   │
│              ↓ Fetch API        ↓ Socket.io  ↓ WebRTC       │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│                  BACKEND (Node + Express + TS)               │
│  ┌──────────────┬────────────────┬──────────────────────┐   │
│  │ Auth Service │  Chat Service  │  WebRTC/STUN Service │   │
│  └──────────────┴────────────────┴──────────────────────┘   │
│              ↓                    ↓                          │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│              FIREBASE (Auth + Firestore)                     │
│  ┌──────────┬──────────┬──────────┬──────────────────────┐  │
│  │  users   │ meetings │   chat   │      summaries       │  │
│  └──────────┴──────────┴──────────┴──────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

---

## 📅 Plan de Desarrollo por Sprints

### **Sprint 1: Gestión de Usuarios + GUI Base** (35% FE / 30% BE / 10% BD / 5% Gestión / 20% QA)

#### 🎯 Objetivos
- Sistema completo de autenticación (registro, login, logout, recuperación de contraseña)
- OAuth con Google y Facebook
- Gestión de perfil (editar usuario)
- Creación de reuniones (sin funcionalidad de conexión aún)
- GUI base: menú, inicio, mapa del sitio, sobre nosotros, footer

#### 📝 Historias de Usuario

**H1: Sign-up básico**
- Formulario de registro con validación en tiempo real
- Campos: Nombres, Apellidos, Edad (≥13), Email, Contraseña (≥8 chars con mayúscula, número, especial)
- Hash bcrypt (10+ salt rounds)
- Respuesta: HTTP 201 + ID usuario
- Manejo de errores: 409 (email duplicado), 5xx genérico

**H2: Inicio de sesión**
- Login manual con email/contraseña
- OAuth con Google y Facebook
- Generación de JWT
- Rate limiting: 5 intentos/10min por IP (429 Too Many Requests)
- Logout: limpia token y redirige a /inicio

**H3: Recuperar contraseña**
- Flujo: /forgot-password → email con token de 1 hora (un solo uso)
- Formulario de restablecimiento en /reset?token=XYZ
- Validación: mismos requisitos que signup
- Respuesta genérica (202) para emails no registrados (seguridad)

**H4: Edición de perfil**
- Ruta: /profile/edit con datos precargados
- Campos editables: Nombres, Apellidos, Edad, Email
- Endpoint: PUT /users/me → HTTP 200
- Manejo: 409 si email duplicado

**H5: Creación de reunión**
- Botón "Nueva reunión" en /dashboard
- Generación de ID único (UUID v4 o Firestore autoID)
- Endpoint: POST /meetings → HTTP 201
- Funcionalidad: copiar ID o enlace /meeting/:id

#### ✅ Criterios de Aceptación Sprint 1
- Frontend desplegado en Vercel con 2 heurísticas de Nielsen + 1 nivel WCAG
- Backend de autenticación y usuarios en Render
- Firestore con colección `users`
- Diseño responsivo validado en 320px, 768px, 1024px
- Documentación JSDoc completa
- Video e informe de pruebas de usuario

---

### **Sprint 2: Chat en Tiempo Real** (20% FE / 40% BE / 15% BD / 5% Gestión / 20% QA)

#### 🎯 Objetivos
- Unirse a reunión mediante ID o enlace directo
- Chat en tiempo real con Socket.io
- Sincronización de participantes conectados
- Persistencia de mensajes en Firestore

#### 📝 Historias de Usuario

**H6: Unirse a reunión**
- Input de ID en /dashboard o acceso directo /meeting/:id
- Validación: ID debe existir en Firestore con `status="active"`
- Actualización: agregar usuario a `participants[]` con `{userId, joinedAt, active: true}`
- Sincronización Socket.io sin recarga
- Errores: "Reunión no encontrada" o "Reunión finalizada"

**H7: Chat en tiempo real** (Por definir en detalle)
- Envío/recepción de mensajes vía Socket.io
- Persistencia en colección `chat` de Firestore
- Indicador de "escribiendo..."
- Timestamps y usuario emisor

#### ✅ Criterios de Aceptación Sprint 2
- Frontend actualizado: 4 heurísticas + 2 WCAG
- Backend: auth + chat con Socket.io
- Firestore: `users` + `meetings` + `chat`
- Pruebas con 2-10 usuarios simultáneos
- Videos e informes acumulativos S1-S2

---

### **Sprint 3: Transmisión de Voz** (Distribución por definir)

#### 🎯 Objetivos
- Audio bidireccional (full-duplex) con WebRTC/Peer.js
- Controles: activar/desactivar micrófono
- Servidor STUN propio para NAT traversal
- Resumen de chat con IA

#### 📝 Funcionalidades
- Conexión de audio peer-to-peer
- Indicadores visuales de participantes hablando
- Calidad adaptativa según ancho de banda
- Guardar resumen IA en colección `summaries`

#### ✅ Criterios de Aceptación Sprint 3
- Frontend: 7 heurísticas + 3 WCAG (perceptible, operable, comprensible)
- Backend: auth + chat + voz (Socket.io + Peer.js + STUN)
- Firestore: `users` + `meetings` + `summaries`
- Audio funcional entre 2-10 participantes

---

### **Sprint 4: Transmisión de Video** (Distribución por definir)

#### 🎯 Objetivos
- Video bidireccional con WebRTC/Peer.js
- Controles: activar/desactivar cámara
- 2 servidores STUN (uno para audio, otro para video)
- Resúmenes IA mejorados

#### 📝 Funcionalidades
- Múltiples streams de video simultáneos (grid layout)
- Compartir pantalla (opcional/extensión)
- Grabación de sesión (opcional)
- Optimización de ancho de banda

#### ✅ Criterios de Aceptación Sprint 4
- Frontend: 10 heurísticas + 4 WCAG (añade robusto)
- Backend completo: auth + chat + voz + video
- 2 servidores STUN operativos
- Sistema completo funcional end-to-end
- Videos e informes S1-S4

---

## 📂 Estructura del Proyecto

```
meet_back/                          # Repositorio backend
├── .env.example                    # Variables de entorno template
├── package.json
├── tsconfig.json
├── src/
│   ├── config/                    # Configuración Firebase, Socket.io
│   ├── controllers/               # Controladores por dominio
│   │   ├── auth.controller.ts
│   │   ├── users.controller.ts
│   │   ├── meetings.controller.ts
│   │   └── chat.controller.ts
│   ├── middleware/                # JWT, rate limiting, validación
│   ├── models/                    # Tipos y esquemas Firestore
│   ├── routes/                    # Rutas Express
│   ├── services/                  # Lógica de negocio
│   │   ├── auth.service.ts
│   │   ├── socket.service.ts
│   │   └── webrtc.service.ts
│   ├── utils/                     # Helpers, logger
│   └── index.ts                   # Entry point
├── tests/                         # Tests unitarios e integración
└── docs/                          # Documentación técnica

meet_front/                         # Repositorio frontend (separado)
├── .env.example
├── package.json
├── tsconfig.json
├── vite.config.ts
├── src/
│   ├── components/                # Componentes reutilizables
│   ├── pages/                     # Páginas/vistas principales
│   │   ├── Auth/                 # Login, Signup, ForgotPassword
│   │   ├── Dashboard/
│   │   ├── Meeting/              # Sala de reunión
│   │   └── Profile/
│   ├── hooks/                     # Custom hooks
│   ├── services/                  # API calls
│   ├── context/                   # Context providers (Auth, Socket)
│   ├── styles/                    # SCSS global y variables
│   ├── utils/                     # Helpers, constantes
│   └── App.tsx
└── public/
```

---

## 👥 Roles del Equipo (5 integrantes)

| Rol | Responsabilidades |
|-----|-------------------|
| **Frontend Developer** | React + TypeScript + SASS. Implementación de UX/UI, responsividad, accesibilidad (WCAG), integración con Figma. |
| **Backend Developer** | Node.js + Express + TypeScript. API REST, Socket.io, WebRTC/Peer.js, servidores STUN, autenticación JWT, integración Firebase. |
| **Database Engineer** | Firebase Authentication + Firestore. Diseño de esquemas, colecciones, operaciones CRUD, optimización de queries. |
| **Project Manager & VCS** | Gestión SCRUM con TAIGA. Planificación de sprints, seguimiento de tareas, administración de GitHub (branches, PR, code reviews). |
| **QA & UX Tester** | Pruebas de usuario, evaluación de accesibilidad, detección de bugs, retroalimentación UX, elaboración de informes y videos. |

---

## 🔧 Configuración Inicial

### Backend (meet_back)
```bash
# Instalar dependencias
npm install

# Variables de entorno (.env)
PORT=3000
NODE_ENV=development
JWT_SECRET=your_jwt_secret
FIREBASE_PROJECT_ID=your_project_id
FIREBASE_PRIVATE_KEY=your_private_key
FIREBASE_CLIENT_EMAIL=your_client_email

# Ejecutar en desarrollo
npm run dev

# Build para producción
npm run build
npm start
```

### Frontend (meet_front)
```bash
# Instalar dependencias
npm install

# Variables de entorno (.env)
VITE_API_URL=http://localhost:3000
VITE_SOCKET_URL=http://localhost:3000
VITE_FIREBASE_API_KEY=your_api_key
VITE_FIREBASE_AUTH_DOMAIN=your_auth_domain

# Ejecutar en desarrollo
npm run dev

# Build para producción
npm run build
npm run preview
```

---

## 🔄 Metodología de Trabajo

### Flujo de Desarrollo (GitHub)
1. **Rama individual por desarrollador:** `feature/nombre-funcionalidad`
2. **Commits pequeños y descriptivos:** "feat: add user registration form validation"
3. **Pull Request al finalizar sprint:** con tag `sprint-X-release`
4. **Code Review:** mínimo 2 aprobaciones antes de merge
5. **Merge a rama principal:** solo al completar sprint

### Gestión con TAIGA
- **Product Backlog:** todas las HU priorizadas
- **Sprint Planning:** inicio de cada sprint (1-2 semanas)
- **Daily Standups:** sincronización diaria (opcional)
- **Sprint Review:** demo de funcionalidades completadas
- **Sprint Retrospective:** lecciones aprendidas y mejoras

### Definición de "Hecho" (DoD)
- ✅ Todos los criterios de aceptación cumplidos
- ✅ Código documentado con JSDoc
- ✅ README actualizado con nuevas funcionalidades
- ✅ Responsividad validada (320px, 768px, 1024px)
- ✅ Despliegue exitoso en Vercel (FE) y Render (BE)
- ✅ Pruebas de usuario realizadas y documentadas
- ✅ Sin errores en consola (modo producción)

---

## 📡 API Documentation

### Base URL
- **Development:** `http://localhost:3000/api`
- **Production:** `https://meet-api.onrender.com/api`

### Authentication
Most endpoints require a JWT token in the Authorization header:
```
Authorization: Bearer <your_jwt_token>
```

### Response Format
All responses follow this format:
```json
{
  "success": true/false,
  "data": { ... } or null,
  "message": "Optional message"
}
```

### Error Format
```json
{
  "success": false,
  "error": {
    "message": "Error description",
    "code": "ERROR_CODE"
  }
}
```

---

### Authentication Endpoints

#### Sign Up (H1)
**POST** `/api/auth/signup`

Register a new user account.

**Request Body:**
```json
{
  "firstName": "John",
  "lastName": "Doe",
  "age": 25,
  "email": "john@example.com",
  "password": "SecurePass123!",
  "confirmPassword": "SecurePass123!"
}
```

**Validation Rules:**
- First Name & Last Name: 2-50 characters, letters only
- Age: ≥ 13
- Email: Valid RFC 5322 format
- Password: ≥8 characters with 1 uppercase, 1 lowercase, 1 number, 1 special char

**Response:** `201 Created`
```json
{
  "success": true,
  "data": {
    "id": "uuid-here"
  },
  "message": "Account created successfully"
}
```

**Errors:**
- `400` - Validation errors
- `409` - Email already registered
- `429` - Too many signup attempts (5 per hour)

---

#### Login (H2)
**POST** `/api/auth/login`

Authenticate with email and password.

**Request Body:**
```json
{
  "email": "john@example.com",
  "password": "SecurePass123!"
}
```

**Response:** `200 OK`
```json
{
  "success": true,
  "data": {
    "token": "jwt.token.here",
    "user": {
      "id": "uuid",
      "firstName": "John",
      "lastName": "Doe",
      "email": "john@example.com",
      "age": 25,
      "provider": "email",
      "createdAt": "2025-01-01T00:00:00.000Z",
      "updatedAt": "2025-01-01T00:00:00.000Z"
    }
  },
  "message": "Login successful"
}
```

**Errors:**
- `401` - Invalid credentials
- `423` - Account locked (after 5 failed attempts)
- `429` - Too many login attempts (5 per 10 min)

---

#### OAuth Login (H2)
**POST** `/api/auth/oauth`

Login or register via Google/Facebook OAuth.

**Request Body:**
```json
{
  "provider": "google",
  "providerId": "google-user-id",
  "email": "john@example.com",
  "firstName": "John",
  "lastName": "Doe"
}
```

**Response:** `200 OK` (same as login)

---

#### Logout (H2)
**POST** `/api/auth/logout`

🔒 **Protected Route**

Logout current user (client-side handled, server logs event).

**Response:** `200 OK`
```json
{
  "success": true,
  "data": null,
  "message": "Logout successful"
}
```

---

#### Forgot Password (H3)
**POST** `/api/auth/forgot-password`

Request password reset link.

**Request Body:**
```json
{
  "email": "john@example.com"
}
```

**Response:** `202 Accepted`
```json
{
  "success": true,
  "data": null,
  "message": "If an account exists with this email, a password reset link has been sent"
}
```

**Notes:**
- Always returns 202 to prevent email enumeration
- Reset token valid for 1 hour
- Token is single-use only
- Rate limited: 3 attempts per 15 min

---

#### Reset Password (H3)
**POST** `/api/auth/reset-password`

Reset password using token from email.

**Request Body:**
```json
{
  "token": "reset-token-from-email",
  "password": "NewSecurePass123!",
  "confirmPassword": "NewSecurePass123!"
}
```

**Response:** `200 OK`
```json
{
  "success": true,
  "data": null,
  "message": "Password reset successful"
}
```

**Errors:**
- `400` - Invalid/expired/used token
- `400` - Password validation error

---

### User Endpoints

#### Get Current Profile
**GET** `/api/users/me`

🔒 **Protected Route**

Get current authenticated user profile.

**Response:** `200 OK`
```json
{
  "success": true,
  "data": {
    "id": "uuid",
    "firstName": "John",
    "lastName": "Doe",
    "email": "john@example.com",
    "age": 25,
    "provider": "email",
    "createdAt": "2025-01-01T00:00:00.000Z",
    "updatedAt": "2025-01-01T00:00:00.000Z"
  }
}
```

---

#### Update Profile (H4)
**PUT** `/api/users/me`

🔒 **Protected Route**

Update user profile information.

**Request Body:** (all fields optional)
```json
{
  "firstName": "John",
  "lastName": "Smith",
  "age": 26,
  "email": "john.smith@example.com"
}
```

**Response:** `200 OK`
```json
{
  "success": true,
  "data": {
    "id": "uuid",
    "firstName": "John",
    "lastName": "Smith",
    "age": 26,
    "email": "john.smith@example.com",
    "provider": "email",
    "createdAt": "2025-01-01T00:00:00.000Z",
    "updatedAt": "2025-01-02T00:00:00.000Z"
  },
  "message": "Profile updated successfully"
}
```

**Errors:**
- `400` - Validation error
- `409` - Email already in use

---

### Meeting Endpoints

#### Create Meeting (H5)
**POST** `/api/meetings`

🔒 **Protected Route**

Create a new video conference meeting.

**Request Body:** (all fields optional)
```json
{
  "maxParticipants": 10
}
```

**Response:** `201 Created`
```json
{
  "success": true,
  "data": {
    "id": "meeting-uuid",
    "createdBy": "user-uuid",
    "createdAt": "2025-01-01T00:00:00.000Z",
    "status": "active",
    "participants": [],
    "maxParticipants": 10,
    "participantCount": 0,
    "canJoin": true
  },
  "message": "Meeting created successfully"
}
```

**Notes:**
- Meeting ID can be shared via link: `/meeting/:id`
- Max participants: 2-10 (default: 10)

---

#### Get Meeting by ID
**GET** `/api/meetings/:id`

🔒 **Protected Route**

Get meeting information by ID.

**Response:** `200 OK`
```json
{
  "success": true,
  "data": {
    "id": "meeting-uuid",
    "createdBy": "user-uuid",
    "createdAt": "2025-01-01T00:00:00.000Z",
    "status": "active",
    "participants": [
      {
        "userId": "user-uuid",
        "joinedAt": "2025-01-01T00:05:00.000Z",
        "active": true
      }
    ],
    "maxParticipants": 10,
    "participantCount": 1,
    "canJoin": true
  }
}
```

**Errors:**
- `404` - Meeting not found

---

#### Get My Meetings
**GET** `/api/meetings`

🔒 **Protected Route**

Get all meetings created by current user.

**Response:** `200 OK`
```json
{
  "success": true,
  "data": [
    {
      "id": "meeting-uuid-1",
      "createdBy": "user-uuid",
      "createdAt": "2025-01-01T00:00:00.000Z",
      "status": "active",
      "participants": [],
      "maxParticipants": 10,
      "participantCount": 0,
      "canJoin": true
    }
  ]
}
```

---

#### Join Meeting (Sprint 2)
**POST** `/api/meetings/:id/join`

🔒 **Protected Route**

Join an existing meeting.

**Response:** `200 OK`
```json
{
  "success": true,
  "data": {
    "id": "meeting-uuid",
    "createdBy": "creator-uuid",
    "createdAt": "2025-01-01T00:00:00.000Z",
    "status": "active",
    "participants": [
      {
        "userId": "your-user-uuid",
        "joinedAt": "2025-01-01T00:10:00.000Z",
        "active": true
      }
    ],
    "maxParticipants": 10,
    "participantCount": 1,
    "canJoin": true
  },
  "message": "Joined meeting successfully"
}
```

**Errors:**
- `400` - Meeting ended
- `400` - Meeting is full
- `404` - Meeting not found

---

#### Leave Meeting (Sprint 2)
**POST** `/api/meetings/:id/leave`

🔒 **Protected Route**

Leave a meeting.

**Response:** `200 OK`
```json
{
  "success": true,
  "data": null,
  "message": "Left meeting successfully"
}
```

---

#### End Meeting
**POST** `/api/meetings/:id/end`

🔒 **Protected Route** (Creator only)

End a meeting (only creator can end).

**Response:** `200 OK`
```json
{
  "success": true,
  "data": null,
  "message": "Meeting ended successfully"
}
```

**Errors:**
- `400` - Only meeting creator can end the meeting
- `404` - Meeting not found

---

### Health Check

#### Server Status
**GET** `/health`

Check if server is running.

**Response:** `200 OK`
```json
{
  "success": true,
  "message": "Server is running",
  "timestamp": "2025-01-01T00:00:00.000Z"
}
```

---

## 📦 Entregas por Sprint

### Documentos Requeridos
1. **Pull Request** con tag `sprint-X-release`
2. **URLs de producción:**
   - Frontend: `https://meet-app.vercel.app`
   - Backend: `https://meet-api.onrender.com`
3. **Video de pruebas:** máx. 10 min mostrando funcionalidades del sprint
4. **Informe PDF:** incluye:
   - Metodología aplicada
   - Problemas encontrados y soluciones
   - Capturas de pantalla
   - Métricas de accesibilidad (Lighthouse)
   - Lecciones aprendidas
5. **Sustentación:** presentación pública ante el curso

### Criterios de Evaluación
- **Funcionalidad:** 40%
- **Código limpio y documentación:** 20%
- **UX/UI y accesibilidad:** 20%
- **Trabajo en equipo (TAIGA):** 10%
- **Pruebas y calidad:** 10%

---

## 🚀 Despliegue

### Frontend (Vercel)
```bash
# Conectar repo de GitHub con Vercel
# Configurar variables de entorno en Vercel Dashboard
# Deploy automático en cada push a main
```

### Backend (Render)
```bash
# Crear Web Service en Render
# Conectar repo de GitHub
# Configurar variables de entorno
# Build Command: npm run build
# Start Command: npm start
```

### Base de Datos (Firebase)
- Crear proyecto en Firebase Console
- Activar Authentication (Email/Password + Google + Facebook)
- Crear Firestore database en modo producción
- Configurar reglas de seguridad
- Obtener credenciales para backend (.env)

---

## 🔒 Seguridad

### Prácticas Implementadas
- ✅ Contraseñas hasheadas con bcrypt (10+ salt rounds)
- ✅ JWT con expiración configurable
- ✅ Rate limiting (5 intentos fallidos / 10 min)
- ✅ Validación de inputs (sanitización contra XSS)
- ✅ CORS configurado correctamente
- ✅ Variables de entorno para secrets
- ✅ HTTPS en producción (Vercel + Render)
- ✅ Firestore rules para autorización

---

## 📚 Recursos y Referencias

### Documentación Técnica
- [React + TypeScript](https://react-typescript-cheatsheet.netlify.app/)
- [Socket.io Documentation](https://socket.io/docs/v4/)
- [Peer.js Guide](https://peerjs.com/docs/)
- [Firebase Web Setup](https://firebase.google.com/docs/web/setup)
- [WCAG 2.1 Guidelines](https://www.w3.org/WAI/WCAG21/quickref/)
- [Nielsen's 10 Usability Heuristics](https://www.nngroup.com/articles/ten-usability-heuristics/)

### Herramientas de Desarrollo
- **Testing:** Jest, React Testing Library
- **Linting:** ESLint + Prettier
- **Accesibilidad:** axe DevTools, Lighthouse
- **API Testing:** Postman/Insomnia
- **Monitoreo:** Render logs, Vercel Analytics

---

## 📞 Contacto y Soporte

- **Repositorio Backend:** [GitHub - meet_back](https://github.com/dhchicaiza/meet_back)
- **Repositorio Frontend:** [GitHub - meet_front](#) (por crear)
- **Gestión de Proyecto:** [TAIGA Board](#) (por configurar)
- **Documentos Compartidos:** Google Drive del equipo

---

## 📄 Licencia

Este proyecto es parte del curso **750018C PROYECTO INTEGRADOR I 2025-2** y está desarrollado con fines académicos.

---

## 🎯 Estado Actual del Proyecto

**Sprint Actual:** Sprint 1 - Gestión de Usuarios + GUI Base
**Progreso:** 0% (Proyecto en fase de planificación)
**Próximo Hito:** Configuración inicial del proyecto y creación de estructura base

---

**Última actualización:** 11 de noviembre de 2025
