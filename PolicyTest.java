package pe.edu.esfap.portal;

import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;

class PolicyTest {
    @Test void bloqueoTrasTresIntentos() { assertFalse(Policy.locked(2)); assertTrue(Policy.locked(3)); }
    @Test void contrasenaFuerte() { assertTrue(Policy.strongPassword("Estud2026")); assertFalse(Policy.strongPassword("corta1")); assertFalse(Policy.strongPassword("sololetras")); assertFalse(Policy.strongPassword(null)); }
    @Test void roles() { assertTrue(Policy.canViewLogs("ti")); assertFalse(Policy.canViewLogs("est")); assertTrue(Policy.validRole("doc")); assertFalse(Policy.validRole("root")); assertFalse(Policy.canManageUsers("doc")); }
    @Test void nombresDeUsuario() { assertTrue(Policy.validUsername("E2024001")); assertFalse(Policy.validUsername("a'b")); assertFalse(Policy.validUsername("ab")); }
}
