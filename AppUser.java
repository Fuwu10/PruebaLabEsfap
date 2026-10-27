package pe.edu.esfap.portal;

import jakarta.persistence.*;

/** Usuario del portal. La contraseña se guarda solo como hash BCrypt. */
@Entity @Table(name = "usuarios")
public class AppUser {
    @Id public String username;
    public String passwordHash, role, name;
    public boolean active = true;
    public int fails;
}
