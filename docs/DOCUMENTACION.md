# Portal ESFAP – Documentación técnica

## Arquitectura
Navegador (HTML/JS) -> Spring Boot (API REST + estáticos) -> base de datos. Modelo híbrido: portal y BD del portal en la nube; BD institucional en la VLAN 20 de la sede (accesible solo en red local). Respaldo: copia cifrada de `./data/esfap.mv.db` a la sede.

## Modelo de datos
- `usuarios`(username PK, password_hash BCrypt, role, name, active, fails)
- `store`(id PK, json CLOB): matrículas, pagos, notas, trámites, tickets, biblioteca
- `log_entry`(id PK, at, actor, action): auditoría

## Seguridad
- Contraseñas: BCrypt; mínimo 8 caracteres con letras y números; cambio desde "Cambiar contraseña".
- Bloqueo tras 3 intentos fallidos (lo libera Soporte TI/Administración). Sesión con cookie HttpOnly, SameSite=Strict, expira a los 5 min.
- Control de accesos por rol validado en el servidor (usuarios y auditoría); menús por rol en el cliente.
- Anti-CSRF por cabecera `X-Requested-With`; XSS: salida escapada; SQLi: JPA parametrizado.
- Cifrado en tránsito: TLS 1.2+ (proxy inverso o `server.ssl`). En reposo: cifrar disco/respaldos (Ley N.° 29733).
- Incidentes: notificar en 48 h (RS-04).

## Instalación
JDK 17+. STS: importar proyecto Maven y ejecutar `PortalApplication`. Consola: `mvn spring-boot:run`. Abrir http://localhost:8080

## Usuarios iniciales (cámbielos)
E2024001 / Estud2026 (estudiante) · 45678912 / Docen2026 (docente) · secretaria / Admin2026 (administrativo) · soporte / Soporte2026 (TI)

## Manual por rol
- Estudiante: matrícula, pagos (simulados), notas, trámites con código, biblioteca, mesa de servicio.
- Docente: asistencia, notas, mesa de servicio.
- Administrativo: aprobar matrículas, conciliar pagos, emitir certificados, reportes, usuarios, auditoría.
- Soporte TI: usuarios y roles, logs, respaldos.
- Visitante: portada, carreras, biblioteca, contacto, verificación de documentos por código.
