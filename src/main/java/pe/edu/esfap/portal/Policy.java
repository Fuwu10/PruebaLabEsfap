package pe.edu.esfap.portal;

import java.util.Set;

/** Reglas de seguridad puras (fáciles de probar): bloqueo, contraseñas, roles y nombres de usuario. */
public final class Policy {
    public static final int MAX_FAILS = 3;
    private Policy() {}
    public static boolean locked(int fails) { return fails >= MAX_FAILS; }
    public static boolean strongPassword(String p) { return p != null && p.length() >= 8 && p.length() <= 72 && p.matches(".*[A-Za-z].*") && p.matches(".*\\d.*"); }
    public static boolean validRole(String r) { return r != null && Set.of("est", "doc", "adm", "ti").contains(r); }
    public static boolean validUsername(String u) { return u != null && u.matches("[A-Za-z0-9._-]{3,30}"); }
    public static boolean canViewLogs(String r) { return "ti".equals(r) || "adm".equals(r); }
    public static boolean canManageUsers(String r) { return "ti".equals(r) || "adm".equals(r); }
}
