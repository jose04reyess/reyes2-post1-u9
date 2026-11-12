# Post-contenido — Unidad 9: Seguridad en Aplicaciones Web (Sesión y JWT)

**Autor:** Reyes  
**Institución:** Universidad / Facultad de Ingeniería y Tecnologías  
**Asignatura:** Programación Web — Unidad 9  
**Stack Tecnológico:** Java 17 LTS, Spring Boot 3.2.5, Spring Security 6, Spring Data JPA, MySQL 8 / H2 in-memory, Thymeleaf, JJWT 0.12.5, Bootstrap 5.

---

## 1. Resumen Ejecutivo y Arquitectura Global

Este repositorio implementa una solución integral de ciberseguridad y arquitectura web resiliente siguiendo las directrices del **OWASP Top 10** y las capacidades avanzadas de **Spring Security 6**. El sistema resuelve el desafío arquitectónico de coexistencia entre dos paradigmas de autenticación y control de acceso diametralmente opuestos dentro del mismo proyecto monolítico Spring Boot:

1. **Parte 1 — Aplicación Web MVC con Thymeleaf (Stateful / Con Estado):**
   - Autenticación basada en sesión de servidor y cookies de sesión (`JSESSIONID`).
   - Cifrado unidireccional y robusto de contraseñas con **BCrypt** (factor de costo 12).
   - Control de Acceso Basado en Roles (**RBAC**) mediante `ROLE_USER` y `ROLE_ADMIN`.
   - Protección activa contra **Cross-Site Request Forgery (CSRF)** activada por defecto mediante tokens sincronizados.
   - Mitigación rigurosa de **Cross-Site Scripting (XSS)** en la capa de presentación mediante el escape automático de entidades HTML con `th:text` (contrastado pedagógicamente contra `th:utext`).
   - Prevención exhaustiva de **Inyecciones SQL (SQLi)** en la capa de persistencia mediante consultas parametrizadas seguras con `@Query` y placeholders JPQL (`:texto`).

2. **Parte 2 — Extensión con API REST Stateless (Sin Estado / JWT):**
   - Arquitectura desacoplada sin persistencia de sesión HTTP en el servidor (`SessionCreationPolicy.STATELESS`).
   - Autenticación mediante tokens criptográficos **JSON Web Tokens (JWT)** firmados con algoritmo simétrico **HMAC-SHA256** utilizando **JJWT 0.12.5**.
   - Filtro interceptor personalizado `JwtAuthFilter` (`OncePerRequestFilter`) que procesa cabeceras `Authorization: Bearer <token>`, valida firma y tiempo de vida, y puebla el `SecurityContextHolder`.
   - Manejador de excepciones `AuthenticationEntryPoint` que garantiza códigos HTTP de error nativos (`401 Unauthorized` / `403 Forbidden`) en formato JSON puro, eliminando cualquier redirección indeseada a vistas HTML.

---

## 2. Decisiones de Diseño y Fundamentos de Ciberseguridad

### 2.1 Precedencia Determinista de Filtros: `@Order(1)` vs `@Order(2)`
Spring Security 6 permite registrar múltiples `SecurityFilterChain`. Para evitar colisiones y comportamientos erráticos, se estableció un orden de precedencia estricto:
- **`apiFilterChain` (`@Order(1)`) con `securityMatcher("/api/**")`:** Se evalúa en primer lugar. Cualquier petición cuyo URI comience con `/api/` es capturada de forma inmediata por este filtro. Si un cliente solicita un recurso protegido de la API sin token o con credenciales erróneas, el punto de entrada emite un código HTTP `401 Unauthorized` inmediato.
- **`webFilterChain` (`@Order(2)`) con `securityMatcher("/**")`:** Actúa como filtro general por defecto para el resto de rutas web (vistas HTML, assets estáticos, formularios). Si no se hubiera aplicado `@Order(1)` a la API, la cadena web interceptaría las llamadas REST y respondería con un código de redirección HTTP `302 Found` hacia `/login`, rompiendo los estándares de interoperabilidad de clientes REST (móviles, SPAs).

### 2.2 Coexistencia de Dos Mecanismos de Autenticación
- **Sesión de Servidor + Cookies + CSRF:** Óptima para navegadores web que consumen plantillas Thymeleaf, permitiendo una experiencia de usuario fluida con redirecciones tras login/logout y almacenamiento del contexto de seguridad en la memoria del servidor.
- **JWT Autocontenido Stateless en Cabecera `Authorization: Bearer`:** Óptimo para APIs consumidas por aplicaciones SPA (Angular, React, Vue), dispositivos móviles Android/iOS o microservicios, donde no existe almacenamiento de sesión en el backend y cada solicitud es autocontenida y verificable de manera distribuida.

### 2.3 Por qué CSRF se desactiva SOLO en `apiFilterChain`
El ataque de **Cross-Site Request Forgery (CSRF)** se fundamenta en la transmisión automática que realiza el navegador de las credenciales implícitas (cookies `JSESSIONID`) al realizar peticiones entre dominios cruzados. 
- En `/api/**`, la API es **stateless** y no utiliza cookies de sesión. La autenticación viaja de manera explícita en el encabezado `Authorization: Bearer <jwt>`, el cual un atacante de otro origen no puede forzar al navegador a inyectar arbitrariamente mediante peticiones cross-site automáticas. Por ende, en la API el vector CSRF no existe y mantenerlo activado requeriría tokens redundantes que complican a clientes nativos.
- En `/**`, las vistas web dependen de la cookie `JSESSIONID`, por lo que **CSRF permanece 100% activo** con tokens sincronizadores ocultos gestionados por Thymeleaf.

### 2.4 Por qué `JwtAuthFilter` no lanza excepciones directamente
`JwtAuthFilter` extiende `OncePerRequestFilter`. Su única responsabilidad es inspeccionar si existe un encabezado `Authorization: Bearer <token>`, comprobar su firma y validez mediante `JwtUtil`, y en caso positivo, registrar el `UsernamePasswordAuthenticationToken` en el `SecurityContextHolder`. Si el token falta, está mal formado o ha expirado, el filtro **no interrumpe el flujo con excepciones**, sino que simplemente cede el control a la cadena (`filterChain.doFilter(request, response)`). Esto permite que la política centralizada de autorización de Spring Security (`authorizeHttpRequests`) sea la que decida si el endpoint requiere autenticación (emitiendo `401 Unauthorized` vía el `AuthenticationEntryPoint`) o si es un endpoint público (como `/api/auth/login`), manteniendo el principio de responsabilidad única.

### 2.5 Seguridad de Secretos Criptográficos en Producción
La clave de firma simétrica HMAC (`jwt.secret`) y el tiempo de expiración (`jwt.expiration-ms`) se encuentran externalizados en `src/main/resources/application.properties` e inyectados mediante `@Value`. 
- **En entorno de desarrollo:** Se utiliza una clave de 256 bits segura (`clave-secreta-super-segura-minimo-32-caracteres-udes-2026`).
- **En entorno de producción:** Esta propiedad se sobreescribe sin tocar el código fuente mediante variables de entorno del sistema operativo (`export JWT_SECRET=...`) o bóvedas de secretos (Vault, AWS Secrets Manager, Kubernetes Secrets), impidiendo la exposición de credenciales en el control de versiones (CWE-798).

---

## 3. Matriz de Mitigación OWASP Top 10

| ID OWASP | Vulnerabilidad | Vector de Ataque | Mitigación Implementada en el Código |
|---|---|---|---|
| **A01:2021** | Pérdida de Control de Acceso (Broken Access Control) | Usuarios convencionales intentando acceder a rutas `/admin/**` o `/api/admin/**`. | `@PreAuthorize("hasRole('ADMIN')")` en capas de servicio y reglas `.hasRole("ADMIN")` estrictas en `SecurityConfig`. |
| **A02:2021** | Fallas Criptográficas (Cryptographic Failures) | Almacenamiento de claves en texto plano o hashing vulnerable (MD5/SHA1). | `BCryptPasswordEncoder(12)` con salt aleatorio por usuario y firma JWT HMAC-SHA256 con llave segura. |
| **A03:2021** | Inyección SQL (SQL Injection) | Manipulación de campos de búsqueda mediante `' OR '1'='1' --`. | Consultas JPA parametrizadas `@Query("SELECT t FROM Tarea t WHERE t.titulo LIKE %:texto%")` con placeholders binarios seguros. |
| **A03:2021** | Cross-Site Scripting (XSS Almacenado / Reflejado) | Inyección de payloads `<script>alert('XSS')</script>` en nombres de usuario o tareas. | Uso estricto de la directiva `th:text` en Thymeleaf que escapa entidades HTML a `&lt;` y `&gt;`. |
| **A05:2021** | Configuración de Seguridad Incorrecta | Respuestas con redirección en endpoints API o secretos hardcodeados. | `AuthenticationEntryPoint` que retorna `401 No autorizado` puro y secretos desacoplados en `application.properties`. |
| **A07:2021** | Fallas de Identificación y Autenticación | Ataques de fijación de sesión y reutilización de tokens. | `invalidateHttpSession(true)`, `deleteCookies("JSESSIONID")`, y expiración de tokens JWT limitada a 1 hora. |

---

## 4. Estructura del Proyecto

```text
reyes2-post1-u9/
├── .gitignore
├── README.md
├── capturas/                                    <- Directorio para evidencias gráficas
└── seguridad-web/
    ├── pom.xml                                  <- Maven POM (Spring Boot 3.2.5, JJWT 0.12.5)
    └── src/
        ├── main/
        │   ├── java/com/universidad/seguridad/
        │   │   ├── SeguridadApplication.java    <- Clase principal Spring Boot
        │   │   ├── config/
        │   │   │   ├── DataInitializer.java     <- Inicialización de admin y tarea inicial
        │   │   │   └── SecurityConfig.java      <- Doble cadena de seguridad (@Order 1 y 2)
        │   │   ├── controller/
        │   │   │   ├── ApiAdminController.java  <- Endpoints protegidos /api/admin/**
        │   │   │   ├── ApiAuthController.java   <- Endpoint de login REST /api/auth/login
        │   │   │   ├── ApiTareaController.java  <- Endpoints protegidos /api/tareas
        │   │   │   ├── AuthController.java      <- Vistas web (Login, Registro, Dashboard, Admin)
        │   │   └── dto/
        │   │       ├── LoginRequest.java        <- DTO petición login JSON
        │   │       └── LoginResponse.java       <- DTO respuesta con Token JWT
        │   │   ├── model/
        │   │   │   ├── Tarea.java               <- Entidad Tarea (@Table tareas)
        │   │   │   └── Usuario.java             <- Entidad Usuario (@Table usuarios)
        │   │   ├── repository/
        │   │   │   ├── TareaRepository.java     <- Consultas seguras @Query parametrizadas
        │   │   │   └── UsuarioRepository.java   <- Consultas seguras findByEmail, existsByEmail
        │   │   ├── security/
        │   │   │   ├── JwtAuthFilter.java       <- Filtro OncePerRequestFilter para cabecera Bearer
        │   │   │   └── JwtUtil.java             <- Generación y validación HMAC-SHA256
        │   │   └── service/
        │   │       ├── TareaService.java        <- Lógica de negocio y @PreAuthorize
        │   │       ├── UsuarioDetailsService.java <- Adaptador Spring Security UserDetailsService
        │   │       └── UsuarioService.java      <- Registro con hash BCrypt y @Transactional
        │   └── resources/
        │       ├── application.properties       <- Configuración DataSource MySQL y JWT
        │       └── templates/
        │           ├── admin/
        │           │   └── panel.html           <- Panel administrativo exclusivo ROLE_ADMIN
        │           ├── auth/
        │           │   ├── login.html           <- Formulario de login con alertas
        │           │   └── registro.html        <- Formulario de registro con validaciones
        │           └── dashboard.html           <- Dashboard seguro con mitigación XSS (th:text)
        └── test/
            ├── java/com/universidad/seguridad/
            │   ├── JwtUtilTest.java             <- Pruebas unitarias de emisión y verificación JWT
            │   ├── SecurityDualChainIntegrationTest.java <- Pruebas de integración MockMvc (10 tests)
            │   └── SeguridadApplicationTests.java <- Verificación de carga de contexto
            └── resources/
                └── application.properties       <- Configuración para ejecución in-memory (H2)
```

---

## 5. Instrucciones de Configuración y Despliegue

### 5.1 Requisitos Previos
- **Java Development Kit (JDK):** Versión 17 LTS o superior.
- **Apache Maven:** Versión 3.9+ (o ejecutable local).
- **Base de Datos:** MySQL Server 8.0+ en `localhost:3306` con base de datos `seguridad_db` (o motor de pruebas H2 automático).

### 5.2 Compilación y Ejecución de Pruebas
Para compilar el proyecto y ejecutar la suite completa de 14 pruebas automatizadas (unitarias e integración):

```bash
cd seguridad-web
mvn clean test
```

*Resultado esperado:*
```text
[INFO] Tests run: 14, Failures: 0, Errors: 0, Skipped: 0
[INFO] BUILD SUCCESS
```

### 5.3 Arranque de la Aplicación
Para iniciar el servidor web embebido Tomcat en el puerto `8080`:

```bash
mvn spring-boot:run
```

Al iniciar por primera vez, el componente `DataInitializer` creará automáticamente el usuario administrador inicial:
- **Usuario:** `admin@universidad.edu`
- **Contraseña:** `admin123`
- **Rol:** `ROLE_ADMIN`
- **Estado:** Activo (`true`)
- **Tarea Inicial:** "Auditoría de Seguridad Inicial OWASP"

---

## 6. Guía de Verificación y Pruebas con cURL

### 6.1 Pruebas de la Parte 2 — API REST Stateless con JWT

#### A. Intento de acceso sin autenticación (401 Unauthorized nativo)
```bash
curl -i -X GET http://localhost:8080/api/tareas
```
**Respuesta esperada:**
```http
HTTP/1.1 401 Unauthorized
Content-Type: text/plain;charset=UTF-8

No autorizado
```
*(Confirma que no existe redirección HTTP 302 a login.html).*

---

#### B. Autenticación exitosa y obtención de JWT (`/api/auth/login`)
```bash
curl -i -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"admin@universidad.edu\", \"contrasenia\":\"admin123\"}"
```
**Respuesta esperada:**
```json
HTTP/1.1 200 OK
Content-Type: application/json

{
  "token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbkB1bml2ZXJzaWRhZC5lZHUiLCJyb2wiOiJST0xFX0FETUlOIiwiZXhwIjoxNzk0NTk4ODAwfQ...",
  "email": "admin@universidad.edu",
  "rol": "ROLE_ADMIN"
}
```

---

#### C. Acceso a recursos protegidos con Bearer Token
```bash
# Guardar el token en una variable de entorno (reemplazar <TOKEN_AQUI>)
TOKEN="<TOKEN_AQUI>"

curl -i -X GET http://localhost:8080/api/tareas \
  -H "Authorization: Bearer $TOKEN"
```
**Respuesta esperada:**
```json
HTTP/1.1 200 OK
Content-Type: application/json

[
  {
    "id": 1,
    "titulo": "Auditoría de Seguridad Inicial OWASP",
    "descripcion": "Revisar controles de autenticación, CSRF, mitigación de XSS y parametrización SQL.",
    "completada": false
  }
]
```

---

#### D. Creación de una nueva tarea vía REST con JWT
```bash
curl -i -X POST http://localhost:8080/api/tareas \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"titulo\":\"Implementar Rate Limiting\", \"descripcion\":\"Mitigar ataques de fuerza bruta en login\", \"completada\":false}"
```
**Respuesta esperada:**
```json
HTTP/1.1 200 OK
Content-Type: application/json

{
  "id": 2,
  "titulo": "Implementar Rate Limiting",
  "descripcion": "Mitigar ataques de fuerza bruta en login",
  "completada": false
}
```

---

#### E. Validación de Control de Acceso Basado en Roles (RBAC en API)
Si se utiliza un token perteneciente a un usuario con rol `ROLE_USER` para consultar la ruta restringida `/api/admin/usuarios`:
```bash
curl -i -X GET http://localhost:8080/api/admin/usuarios \
  -H "Authorization: Bearer $TOKEN_USER"
```
**Respuesta esperada:**
```http
HTTP/1.1 403 Forbidden
```
Si se utiliza el token del administrador (`ROLE_ADMIN`):
```http
HTTP/1.1 200 OK
[{"id":1,"nombre":"Administrador","email":"admin@universidad.edu","rol":"ROLE_ADMIN","activo":true}]
```

---

### 6.2 Pruebas de la Parte 1 — Interfaz Web Thymeleaf

1. **Acceso al Dashboard sin sesión:**
   Navegar a `http://localhost:8080/dashboard`. El navegador es redirigido inmediatamente a `http://localhost:8080/login`.
2. **Inicio de sesión:**
   Introducir `admin@universidad.edu` y `admin123`. Redirige con éxito a `http://localhost:8080/dashboard`.
3. **Comprobación de Experimento XSS:**
   - Registrar una cuenta en `/registro` con nombre: `<script>alert('VULNERABLE XSS')</script>`.
   - Iniciar sesión con esa cuenta.
   - En el Dashboard, comprobar que el texto se renderiza de forma literal como texto plano inocuo (`&lt;script&gt;...&lt;/script&gt;`) gracias a `th:text="${nombreUsuario}"`.
   - Revisar el código fuente HTML (`Ctrl + U`) para observar la demostración comentada con `th:utext`.
4. **Comprobación de Prevención SQL Injection:**
   - En el buscador de tareas del Dashboard, buscar: `' OR '1'='1' --`.
   - La consulta no genera excepciones ni expone tareas ajenas; retorna cero resultados porque el motor JDBC utiliza `PreparedStatement` parametrizado.
5. **Cierre de sesión seguro:**
   - Hacer clic en "Cerrar Sesión". La cookie `JSESSIONID` es invalidada y se redirige a `/login?logout`.

---

## 7. Catálogo de Evidencias en `capturas/`

Para respaldar la entrega formal, el directorio `capturas/` contiene las evidencias gráficas de las pruebas realizadas:

- `capturas/01-login-form.png`: Vista del formulario de autenticación web con alertas y enlaces.
- `capturas/02-registro-usuario.png`: Formulario de registro con validación de campos y hash BCrypt.
- `capturas/03-dashboard-xss-seguro.png`: Panel principal evidenciando la mitigación activa de XSS con `th:text`.
- `capturas/04-buscador-sqli-seguro.png`: Búsqueda parametrizada segura con payload `' OR '1'='1`.
- `capturas/05-panel-admin-rbac.png`: Vista protegida `/admin` visible exclusivamente con `ROLE_ADMIN`.
- `capturas/06-jwt-login-postman-curl.png`: Ejecución de `/api/auth/login` con retorno del token Bearer.
- `capturas/07-jwt-api-tareas-autorizado.png`: Petición autorizada a `/api/tareas` con cabecera `Authorization`.
- `capturas/08-jwt-api-401-unauthorized.png`: Respuesta 401 pura sin redirección al acceder sin token.
- `capturas/09-test-suite-success.png`: Consola de Maven mostrando `14/14 tests` ejecutados exitosamente (`BUILD SUCCESS`).
