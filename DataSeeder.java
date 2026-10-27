package pe.edu.esfap.portal;

import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

/** Crea los 4 usuarios iniciales la primera vez. Cambie estas contraseñas al ingresar. */
@Component
public class DataSeeder implements CommandLineRunner {
    private final UserRepo users;
    DataSeeder(UserRepo u) { users = u; }

    public void run(String... args) {
        if (users.count() > 0) return;
        var enc = new BCryptPasswordEncoder();
        String[][] d = {{"E2024001", "Lucía Quispe Huamán", "est", "Estud2026"}, {"45678912", "Prof. Carlos Ccente", "doc", "Docen2026"},
            {"secretaria", "Rosa Palomino (Administración)", "adm", "Admin2026"}, {"soporte", "Soporte TI", "ti", "Soporte2026"}};
        for (var r : d) {
            var u = new AppUser(); u.username = r[0]; u.name = r[1]; u.role = r[2]; u.passwordHash = enc.encode(r[3]); users.save(u);
        }
    }
}
