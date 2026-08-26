package za.ac.itri623.user.controller;

import za.ac.itri623.user.dto.LoginRequest;
import za.ac.itri623.user.dto.LoginResponse;
import za.ac.itri623.user.model.User;
import za.ac.itri623.user.repository.UserRepository;
import za.ac.itri623.user.security.JwtUtil;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;

    public AuthController(UserRepository userRepository, PasswordEncoder passwordEncoder, JwtUtil jwtUtil) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtil = jwtUtil;
    }

    // NOTE: In Phase 2, wrap this endpoint to also emit SOC events on
    // successful/failed login (AUTH_SUCCESS / AUTH_FAILURE) to the SOC Event Service.
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request) {
        return userRepository.findByUsername(request.getUsername())
            .filter(u -> passwordEncoder.matches(request.getPassword(), u.getPassword()))
            .<ResponseEntity<?>>map(u -> ResponseEntity.ok(
                    new LoginResponse(jwtUtil.generateToken(u.getUsername(), u.getRole()), u.getUsername(), u.getRole())))
            .orElseGet(() -> ResponseEntity.status(401).body("Invalid username or password"));
    }   
}
