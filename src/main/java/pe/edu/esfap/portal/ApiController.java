package pe.edu.esfap.portal;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.Map;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

/** API REST: autenticación, sesión, datos institucionales, usuarios, auditoría y verificación de documentos. */
@RestController @RequestMapping("/api")
public class ApiController {
    record Login(String id, String pw) {}
    record Pass(String old, String neu) {}
    record NewUser(String username, String name, String role, String pw) {}
    private final UserRepo users; private final StoreRepo store; private final LogRepo logs;
    private final BCryptPasswordEncoder enc = new BCryptPasswordEncoder();
    private final ObjectMapper om = new ObjectMapper();
    public ApiController(UserRepo u, StoreRepo s, LogRepo l) { users = u; store = s; logs = l; }

    void audit(String who, String what) { var e = new LogEntry(); e.actor = who; e.action = what; logs.save(e); }
    AppUser me(HttpServletRequest q) {
        var s = q.getSession(false);
        if (s == null || s.getAttribute("u") == null) return null;
        return users.findById((String) s.getAttribute("u")).filter(x -> x.active).orElse(null);
    }
    Map<String, Object> view(AppUser u) { return Map.of("id", u.username, "role", u.role, "name", u.name); }

    @PostMapping("/login")
    ResponseEntity<?> login(@RequestBody Login b, HttpServletRequest q, HttpServletResponse r) {
        var id = b.id() == null ? "" : b.id().trim();
        var u = id.length() > 60 ? null : users.findById(id).orElse(null);
        if (u == null) { audit(id.length() > 60 ? "?" : id, "Login fallido: usuario inexistente"); return ResponseEntity.status(401).build(); }
        if (Policy.locked(u.fails) || !u.active) { audit(id, "Login rechazado: cuenta bloqueada o inactiva"); return ResponseEntity.status(423).build(); }
        if (!enc.matches(b.pw() == null ? "" : b.pw(), u.passwordHash)) { u.fails++; users.save(u); audit(id, "Login fallido (" + u.fails + ")"); return ResponseEntity.status(401).build(); }
        u.fails = 0; users.save(u);
        q.getSession(true); q.changeSessionId(); q.getSession().setAttribute("u", id);
        // LAB 2 (intencional): emite el objeto serializado tipo PHP en la cookie "auth_obj",
        // ver AdminLabController para el detalle de la vulnerabilidad y su remediación.
        AdminLabController.issue(r, id, Policy.canManageUsers(u.role));
        audit(id, "Inicio de sesión");
        return ResponseEntity.ok(view(u));
    }

    @PostMapping("/logout")
    ResponseEntity<?> logout(HttpServletRequest q) {
        var u = me(q); if (u != null) audit(u.username, "Cierre de sesión");
        var s = q.getSession(false); if (s != null) s.invalidate();
        return ResponseEntity.ok().build();
    }

    @GetMapping("/me")
    ResponseEntity<?> whoami(HttpServletRequest q) { var u = me(q); return u == null ? ResponseEntity.status(401).build() : ResponseEntity.ok(view(u)); }

    @GetMapping(value = "/state", produces = "application/json")
    ResponseEntity<String> getState(HttpServletRequest q) {
        if (me(q) == null) return ResponseEntity.status(401).build();
        return ResponseEntity.ok(store.findById(1L).map(x -> x.json).orElse(""));
    }

    @PutMapping("/state")
    ResponseEntity<?> putState(@RequestBody String json, HttpServletRequest q) {
        if (me(q) == null) return ResponseEntity.status(401).build();
        try { om.readTree(json); } catch (Exception e) { return ResponseEntity.badRequest().build(); }
        var s = new Store(); s.json = json; store.save(s);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/password")
    ResponseEntity<?> password(@RequestBody Pass b, HttpServletRequest q) {
        var u = me(q); if (u == null) return ResponseEntity.status(401).build();
        if (b.old() == null || !enc.matches(b.old(), u.passwordHash) || !Policy.strongPassword(b.neu())) return ResponseEntity.badRequest().build();
        u.passwordHash = enc.encode(b.neu()); users.save(u); audit(u.username, "Cambio de contraseña");
        return ResponseEntity.ok().build();
    }

    @GetMapping("/logs")
    ResponseEntity<?> logs(HttpServletRequest q) {
        var u = me(q); if (u == null || !Policy.canViewLogs(u.role)) return ResponseEntity.status(403).build();
        return ResponseEntity.ok(logs.findTop100ByOrderByIdDesc());
    }

    @GetMapping("/users")
    ResponseEntity<?> listUsers(HttpServletRequest q) {
        var u = me(q); if (u == null || !Policy.canManageUsers(u.role)) return ResponseEntity.status(403).build();
        return ResponseEntity.ok(users.findAll().stream().map(x -> Map.of("username", x.username, "name", x.name, "role", x.role, "active", x.active, "fails", x.fails)).toList());
    }

    @PostMapping("/users")
    ResponseEntity<?> addUser(@RequestBody NewUser b, HttpServletRequest q) {
        var u = me(q); if (u == null || !Policy.canManageUsers(u.role)) return ResponseEntity.status(403).build();
        if (!Policy.validUsername(b.username()) || !Policy.validRole(b.role()) || b.name() == null || b.name().isBlank() || b.name().length() > 100
            || !Policy.strongPassword(b.pw()) || users.existsById(b.username())) return ResponseEntity.badRequest().build();
        var n = new AppUser(); n.username = b.username(); n.name = b.name().trim(); n.role = b.role(); n.passwordHash = enc.encode(b.pw());
        users.save(n); audit(u.username, "Usuario creado: " + n.username);
        return ResponseEntity.ok().build();
    }

    @PutMapping("/users/{id}/toggle")
    ResponseEntity<?> toggle(@PathVariable String id, HttpServletRequest q) {
        var u = me(q); if (u == null || !Policy.canManageUsers(u.role)) return ResponseEntity.status(403).build();
        var t = users.findById(id).orElse(null);
        if (t == null || t.username.equals(u.username)) return ResponseEntity.badRequest().build();
        t.active = !t.active; t.fails = 0; users.save(t); audit(u.username, (t.active ? "Usuario activado: " : "Usuario desactivado: ") + t.username);
        return ResponseEntity.ok().build();
    }

    /** Verificación pública de autenticidad por código del documento. */
    @GetMapping("/verify/{code}")
    Map<String, Object> verify(@PathVariable String code) {
        try {
            for (var t : om.readTree(store.findById(1L).map(x -> x.json).orElse("{}")).path("tram"))
                if (code.equals(t.path("code").asText())) return Map.of("valid", true, "tipo", t.path("t").asText(), "estado", t.path("st").asText());
        } catch (Exception e) { /* se responde como no válido */ }
        return Map.of("valid", false);
    }
}
