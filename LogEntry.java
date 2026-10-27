package pe.edu.esfap.portal;

import jakarta.persistence.*;
import java.time.Instant;

/** Registro de auditoría de seguridad. */
@Entity
public class LogEntry {
    @Id @GeneratedValue public Long id;
    public Instant at = Instant.now();
    public String actor, action;
}
