package pe.edu.esfap.portal;

import jakarta.servlet.*;
import jakarta.servlet.http.*;
import java.io.IOException;
import java.util.List;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/** Exige cabecera X-Requested-With en peticiones que modifican datos (anti-CSRF) y añade cabeceras de seguridad. */
@Component
public class CsrfGuard extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest q, HttpServletResponse r, FilterChain c) throws ServletException, IOException {
        boolean mutates = !List.of("GET", "HEAD", "OPTIONS").contains(q.getMethod());
        if (q.getRequestURI().startsWith("/api/") && mutates && !"ESFAP".equals(q.getHeader("X-Requested-With"))) { r.sendError(403, "CSRF"); return; }
        r.setHeader("X-Content-Type-Options", "nosniff");
        r.setHeader("X-Frame-Options", "DENY");
        r.setHeader("Referrer-Policy", "same-origin");
        c.doFilter(q, r);
    }
}
