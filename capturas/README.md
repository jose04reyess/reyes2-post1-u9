# Directorio de Capturas y Evidencias de Evaluación (R2-Lab)

En este directorio se deben ubicar las capturas de pantalla que respaldan la ejecución exitosa de los requerimientos de la Unidad 9 para el estudiante Reyes:

1. `01-login-form.png`: Formulario de login web en `http://localhost:8080/login` con mensajes de error, logout o registro.
2. `02-registro-usuario.png`: Formulario de registro en `http://localhost:8080/registro` con validaciones de campos `@NotBlank` y `@Email`.
3. `03-dashboard-xss-seguro.png`: Dashboard en `http://localhost:8080/dashboard` mostrando el escape seguro del nombre de usuario (`th:text`) ante un payload inyectado `<script>...`.
4. `04-buscador-sqli-seguro.png`: Prueba en el buscador de tareas demostrando la inocuidad del payload `' OR '1'='1' --` gracias a la consulta parametrizada `@Query`.
5. `05-panel-admin-rbac.png`: Acceso a `http://localhost:8080/admin` mostrando la lista de usuarios y roles, exclusivo para `ROLE_ADMIN`.
6. `06-jwt-login-postman-curl.png`: Petición POST a `/api/auth/login` retornando el token JWT firmado con HMAC-SHA256.
7. `07-jwt-api-tareas-autorizado.png`: Petición GET a `/api/tareas` con cabecera `Authorization: Bearer <token>` retornando 200 OK con la lista de tareas.
8. `08-jwt-api-401-unauthorized.png`: Petición GET a `/api/tareas` sin token retornando código HTTP `401 Unauthorized` puro (sin redirección HTML).
9. `09-test-suite-success.png`: Salida de consola ejecutando `mvn clean test` con resultado `BUILD SUCCESS` (14/14 tests pasando).

