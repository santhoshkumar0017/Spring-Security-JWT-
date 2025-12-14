package spring.security.securityJwt.controller;


import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import spring.security.securityJwt.dto.RegisterRequest;
import spring.security.securityJwt.entity.Role;
import spring.security.securityJwt.entity.User;
import spring.security.securityJwt.repository.RoleRepository;
import spring.security.securityJwt.repository.UserRepository;
import spring.security.securityJwt.security.JwtUtil;

import java.util.HashSet;
import java.util.Set;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;


    public AuthController(AuthenticationManager authenticationManager, JwtUtil jwtUtil, UserRepository userRepository, RoleRepository roleRepository, PasswordEncoder passwordEncoder) {
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
    }

    // Register user API
    @PostMapping("/register")
    public ResponseEntity<String> register (@RequestBody RegisterRequest registerRequest){

        if(userRepository.findByUserName(registerRequest.getUserName()).isPresent()){
            return ResponseEntity.badRequest().body("Username is already taken");
        }

        User newUser=new User();
        newUser.setUserName(registerRequest.getUserName());

        String encodePassword=passwordEncoder.encode(registerRequest.getPassword());
        newUser.setPassword(encodePassword);

        System.out.println("EncoderPassword: " + encodePassword);
        Set<Role> roles = new HashSet<>();

        for(String roleName : registerRequest.getRoles()){
            Role role = roleRepository.findByName(roleName).orElseThrow(() -> new RuntimeException("Role not found: "+roleName));
            roles.add(role);
        }

        Set<Role> roles1 = new HashSet<>();
        for(String roleName : registerRequest.getRoles()){
         Role role =roleRepository.findByName(roleName).orElseThrow(() -> new RuntimeException("Roles not found: "+roleName));
         roles.add(role);
        }
        newUser.setRoles(roles);
        userRepository.save(newUser);
        return ResponseEntity.ok("User Registered Successfully");
    }

    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody User loginRequest){

        try{
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken
                    (loginRequest.getUserName(),loginRequest.getPassword()));
        }
        catch (Exception e){
            System.out.println("Exception: "+e);
        }
        String token = jwtUtil.generateToken(loginRequest.getUserName());
        return ResponseEntity.ok(token);

    }
}
