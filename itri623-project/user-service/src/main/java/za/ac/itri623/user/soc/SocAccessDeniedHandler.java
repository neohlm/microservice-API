package za.ac.itri623.user.soc;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * Fires whenever Spring Security blocks a request with 403 Forbidden
 * (e.g. a non-admin user attempting DELETE /api/users/{id}). This is the
 * real, tested RBAC-denial path from Phase 1 — now also emitting an
 * UNAUTHORISED_ACCESS event for the SOC layer.
 */
@Component
public class SocAccessDeniedHandler implements AccessDeniedHandler {

    private final SocEventClient socEventClient;

    public SocAccessDeniedHandler(SocEventClient socEventClient) {
        this.socEventClient = socEventClient;
    }

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException ex)
            throws IOException {
        String username = (request.getUserPrincipal() != null) ? request.getUserPrincipal().getName() : "unknown";

        socEventClient.emit(
                "user-service", "UNAUTHORISED_ACCESS", "HIGH", username,
                request.getRemoteAddr(), request.getRequestURI(), request.getMethod(), 403,
                "User attempted to access a protected endpoint without sufficient authority",
                request.getRequestURI()
        );

        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        response.setContentType("application/json");
        response.getWriter().write("{\"error\":\"Forbidden\"}");
    }
}
