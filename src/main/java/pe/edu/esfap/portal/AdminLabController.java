package pe.edu.esfap.portal;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * LABORATORIO 2 — Modificación de Objetos (Elevación de Privilegios). SOLO PARA FINES DIDÁCTICOS.
 *
 * Este controlador reproduce intencionalmente, dentro de esta app Java, la vulnerabilidad del
 * laboratorio de PortSwigger "Modifying serialized objects" (originalmente en PHP):
 * https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-modifyingserializedobjects
 *
 * VULNERABILIDAD INTENCIONAL (NO replicar en producción):
 * Al iniciar sesión, el servidor entrega además la cookie "auth_obj": un objeto serializado con
 * formato tipo PHP, codificado en Base64, con el username y un flag booleano "admin":
 *
 *     O:4:"User":2:{s:8:"username";s:6:"wiener";s:5:"admin";b:0;}
 *
 * Los endpoints de este controlador confían ciegamente en ese flag "admin" SIN volver a verificar
 * el rol real del usuario contra la base de datos (UserRepo) y SIN ninguna firma/MAC que proteja la
 * integridad del objeto. Cualquiera que intercepte la cookie (p. ej. con Burp Suite) puede:
 *   1) Tomar el valor de la cookie "auth_obj" y pasarlo por Decoder (URL Decode -> Base64 Decode).
 *   2) Cambiar "b:0" por "b:1".
 *   3) Volver a codificar (Base64 -> URL Encode) y pegar la cookie modificada en Repeater.
 *   4) Usar GET /api/admin/panel y DELETE /api/admin/users/{id} para actuar como administrador,
 *      por ejemplo eliminando al usuario "45678912" (Prof. Carlos Ccente, el "carlos" del lab).
 *
 * REMEDIACIÓN (para la sección correspondiente del informe):
 * El estado de autorización nunca debe derivarse de un dato que el cliente puede leer o modificar.
 * Debe calcularse siempre del lado del servidor a partir de la sesión HTTP (que ya existe en
 * ApiController.me()) consultando el rol real en la base de datos, como hace Policy.canManageUsers().
 * Si de verdad se necesita mandar datos de sesión al cliente, deben ir firmados (HMAC) o cifrados,
 * nunca en texto plano confiable sin verificación de integridad.
 */
@RestController
@RequestMapping("/api/admin")
public class AdminLabController {

    private static final Pattern AUTH_OBJ =
        Pattern.compile("s:8:\"username\";s:\\d+:\"([^\"]*)\";s:5:\"admin\";b:(0|1);");

    private final UserRepo users;
    private final LogRepo logs;

    public AdminLabController(UserRepo u, LogRepo l) { users = u; logs = l; }

    /** Construye el objeto serializado tipo PHP: O:4:"User":2:{s:8:"username";s:N:"...";s:5:"admin";b:0;} */
    static String serialize(String username, boolean admin) {
        int len = username.getBytes(StandardCharsets.UTF_8).length;
        return "O:4:\"User\":2:{s:8:\"username\";s:" + len + ":\"" + username + "\";s:5:\"admin\";b:"
            + (admin ? 1 : 0) + ";}";
    }

    /** Emite la cookie vulnerable al iniciar sesión (invocado desde ApiController.login). */
    static void issue(HttpServletResponse r, String username, boolean admin) {
        String raw = serialize(username, admin);
        String b64 = Base64.getEncoder().encodeToString(raw.getBytes(StandardCharsets.UTF_8));
        Cookie c = new Cookie("auth_obj", b64);
        c.setPath("/");
        // Intencionalmente SIN HttpOnly: en el lab se edita manualmente en Burp, igual que la cookie
        // de sesión original de PortSwigger. No usar este patrón en código real.
        r.addCookie(c);
    }

    /** Lee la cookie y confía en su flag "admin" SIN validarlo contra la base de datos (vulnerable a propósito). */
    private boolean cookieSaysAdmin(HttpServletRequest q) {
        if (q.getCookies() == null) return false;
        for (Cookie c : q.getCookies()) {
            if ("auth_obj".equals(c.getName())) {
                try {
                    String raw = new String(Base64.getDecoder().decode(c.getValue()), StandardCharsets.UTF_8);
                    Matcher m = AUTH_OBJ.matcher(raw);
                    if (m.find()) return "1".equals(m.group(2));
                } catch (Exception ignored) { /* cookie corrupta -> se trata como no-admin */ }
            }
        }
        return false;
    }

    /** "Panel admin": solo exige la cookie manipulable, no la sesión/rol real del usuario. */
    @GetMapping("/panel")
    ResponseEntity<?> panel(HttpServletRequest q) {
        if (!cookieSaysAdmin(q)) return ResponseEntity.status(403).build();
        return ResponseEntity.ok(users.findAll().stream()
            .map(x -> Map.of("username", x.username, "name", x.name, "role", x.role, "active", x.active))
            .toList());
    }

    /** Elimina un usuario confiando solo en la cookie manipulable (vulnerable a propósito, Lab 2). */
    @DeleteMapping("/users/{id}")
    ResponseEntity<?> deleteUser(@PathVariable String id, HttpServletRequest q) {
        if (!cookieSaysAdmin(q)) return ResponseEntity.status(403).build();
        var t = users.findById(id).orElse(null);
        if (t == null) return ResponseEntity.notFound().build();
        users.deleteById(id);
        var e = new LogEntry();
        e.actor = "auth_obj(" + id + ")";
        e.action = "Usuario eliminado vía /api/admin (Lab 2 - elevación de privilegios por modificación de objeto)";
        logs.save(e);
        return ResponseEntity.ok().build();
    }
}
