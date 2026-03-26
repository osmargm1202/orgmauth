# OrgAuth

Servicio centralizado de autenticación para los proyectos de OR-GM utilizando Google OAuth.

## Descripción

OrgAuth es una API FastAPI que centraliza la autenticación de todas las aplicaciones del equipo OR-GM. Utiliza Google OAuth como proveedor de identidad, emitiendo tokens JWT propios (15 min) y refresh tokens (7 días).

### Características

- Autenticación via Google OAuth
- Tokens JWT con expiración de 15 minutos
- Refresh tokens con expiración de 7 días
- Almacenamiento de sesiones en base de datos (revocación de tokens)
- Lista de aplicaciones negadas por usuario
- Logging de accesos
- Dominio de email restringido a `or-gm.com`

### Aplicaciones Soportadas

- orgmorg
- orgmcalc
- orgmcalc-cli
- orgmbt
- orgmbt-cli
- orgmbt-app
- orgmrnc

## Variables de Entorno (.env)

Definir las siguientes variables antes de desplegar:

```env
DATABASE_URL=postgresql://user:password@host:5432/orgmauth
GOOGLE_CLIENT_ID=tu_google_client_id
GOOGLE_CLIENT_SECRET=tu_google_client_secret
ORGM_SECRET_KEY=tu_secret_key_para_jwt_min_32_caracteres
ACCESS_TOKEN_ACTIVE_KID=orgauth-rs256-2026-03
ACCESS_TOKEN_PRIVATE_KEY_PEM="-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"
ACCESS_TOKEN_PUBLIC_KEY_PEM="-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"
ALLOWED_DOMAIN=or-gm.com
BASE_URL=https://auth.or-gm.com
ACCESS_TOKEN_EXPIRE_MINUTES=15
REFRESH_TOKEN_EXPIRE_DAYS=7
```

## Despliegue

### Opción 1: Docker Compose

Descargar el archivo `docker-compose.yml` directamente:

```bash
wget https://raw.githubusercontent.com/osmargm1202/orgmauth/main/docker-compose.yml
```

Configurar las variables de entorno en `.env` y luego:

```bash
docker-compose up -d
```

### Opción 2: Build local y desplegar

```bash
# Construir imagen
docker build -t orgmcr.or-gm.com/osmargm1202/orgmauth:latest .

# Subir imagen
docker push orgmcr.or-gm.com/osmargm1202/orgmauth:latest
```

## Endpoints

### Públicos

| Método | Path | Descripción |
|--------|------|-------------|
| GET | `/auth?app_name=X&redirect_uri=Y` | Inicia OAuth Google |
| GET | `/callback?code=X&state=Y` | Callback de Google |
| GET | `/apps` | Lista de aplicaciones |
| GET | `/users` | Lista de usuarios |
| GET | `/users/{email}/allowed-apps` | Apps permitidas para un usuario |

### Protegidos (requieren JWT)

| Método | Path | Descripción |
|--------|------|-------------|
| POST | `/token/refresh` | Refresca access token |
| GET | `/token/me` | Datos del usuario actual |
| GET | `/token/denied-apps` | Lista de apps negadas |
| POST | `/token/denied-apps` | Agrega app negada |
| DELETE | `/token/denied-apps/{app_name}` | Quita app negada |

## Flujo de Autenticación CLI

```
1. CLI llama GET /auth?app_name=orgmcalc-cli&redirect_uri=http://localhost:3000/callback
2. API redirige a Google
3. Usuario autentifica en Google
4. Google redirige a /callback?code=XXX
5. API intercambia código por tokens de Google
6. API verifica email es @or-gm.com
7. API crea sesión en base de datos
8. API redirige a redirect_uri con token JWT y refresh token
9. CLI almacena tokens y los usa para llamadas subsecuentes
```

## Desarrollo Local

```bash
# Instalar dependencias
uv sync

# Crear tablas y seed
uv run python seed.py

# Correr servidor
uv run uvicorn app.main:app --host 0.0.0.0 --port 8500
```

## Pruebas

```bash
# Instalar dependencias de desarrollo
uv sync --extra dev

# Ejecutar pruebas
uv run pytest

# Ejecutar pruebas con coverage
uv run pytest --cov=app --cov-report=term-missing
```

## Licencia

Privado - OR-GM
