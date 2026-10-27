# Portal ESFAP (prototipo) – Spring Boot

Importar en Spring Tool Suite: File > Import > Maven > Existing Maven Projects > carpeta `portal-esfap`.
Ejecutar: clic derecho en `PortalApplication` > Run As > Spring Boot App. Abrir http://localhost:8080
Pruebas: Run As > JUnit Test. Requiere JDK 17+.

El front editable está en `src/main/resources/static/index.html` (datos de prueba en memoria).
Siguiente etapa: API REST, JPA/PostgreSQL y Spring Security (BCrypt, roles, CSRF) bajo `pe.edu.esfap.portal`.

## Versión con backend
Usuarios y contraseñas iniciales en `docs/DOCUMENTACION.md`. Los datos se guardan en `./data` (H2).
