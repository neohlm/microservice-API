package za.ac.itri623.user.controller;

import jakarta.servlet.http.HttpServletRequest;
import za.ac.itri623.user.dto.LoginRequest;
import za.ac.itri623.user.dto.LoginResponse;
import za.ac.itri623.user.repository.UserRepository;
import za.ac.itri623.user.security.JwtUtil;
import za.ac.itri623.user.soc.SocEventClient;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final SocEventClient socEventClient;

    public AuthController(UserRepository userRepository, PasswordEncoder passwordEncoder,
                            JwtUtil jwtUtil, SocEventClient socEventClient) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtil = jwtUtil;
        this.socEventClient = socEventClient;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request, HttpServletRequest httpRequest) {
        return userRepository.findByUsername(request.getUsername())
                .filter(u -> passwordEncoder.matches(request.getPassword(), u.getPassword()))
                .<ResponseEntity<?>>map(u -> {
                    socEventClient.emit("user-service", "AUTH_SUCCESS", "LOW", u.getUsername(),
                            httpRequest.getRemoteAddr(), "/api/auth/login", "POST", 200,
                            "Successful login", "login-endpoint");
                    return ResponseEntity.ok(new LoginResponse(
                            jwtUtil.generateToken(u.getUsername(), u.getRole()), u.getUsername(), u.getRole()));
                })
                .orElseGet(() -> {
                    socEventClient.emit("user-service", "AUTH_FAILURE", "MEDIUM", request.getUsername(),
                            httpRequest.getRemoteAddr(), "/api/auth/login", "POST", 401,
                            "Failed login attempt", "login-endpoint");
                    return ResponseEntity.status(401).body("Invalid username or password");
                });
    }
}
