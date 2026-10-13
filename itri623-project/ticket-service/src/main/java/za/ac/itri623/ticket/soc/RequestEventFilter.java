package za.ac.itri623.ticket.soc;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/** Emits one REQUEST_RECEIVED event per /api/ request (used by the Abnormal Request Rate rule). */
@Component
public class RequestEventFilter extends OncePerRequestFilter {

    private final SocEventClient soc;

    public RequestEventFilter(SocEventClient soc) {
        this.soc = soc;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !request.getRequestURI().startsWith("/api/");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
            throws ServletException, IOException {
        try {
            chain.doFilter(req, res);
        } finally {
            String xff = req.getHeader("X-Forwarded-For");
            String ip = (xff != null && !xff.isBlank()) ? xff.split(",")[0].trim() : req.getRemoteAddr();
            soc.emit("ticket-service", "REQUEST_RECEIVED", "LOW", null, ip,
                    req.getRequestURI(), req.getMethod(), res.getStatus(),
                    "Request handled by ticket-service", "ticket-service");
        }
    }
}
