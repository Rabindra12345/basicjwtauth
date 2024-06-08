package com.baldur.jwtauth.controller;

import java.security.Principal;
import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import com.baldur.jwtauth.exception.TokenNotFoundException;
import com.baldur.jwtauth.jwt.JwtUtils;
import com.baldur.jwtauth.model.ERole;
import com.baldur.jwtauth.model.RefreshToken;
import com.baldur.jwtauth.model.Role;
import com.baldur.jwtauth.model.User;
import com.baldur.jwtauth.payload.request.LoginRequest;
import com.baldur.jwtauth.payload.request.SignUpRequest;
import com.baldur.jwtauth.payload.response.JwtResponse;
import com.baldur.jwtauth.payload.response.MessageResponse;
import com.baldur.jwtauth.payload.response.RefreshTokenRequestRecord;
import com.baldur.jwtauth.repository.RoleRepository;
import com.baldur.jwtauth.repository.UserRepository;
import com.baldur.jwtauth.service.RefreshTokenService;
import com.baldur.jwtauth.service.UserDetailsImpl;
import com.baldur.jwtauth.service.UserDetailsServiceImpl;
import jakarta.validation.Valid;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;


@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final Logger logger = LogManager.getLogger(AuthController.class);
    @Autowired
    AuthenticationManager authenticationManager;

//    @Autowired
//    RefreshTokenService refreshTokenService;

    @Autowired
    UserRepository userRepository;

    @Autowired
    private UserDetailsServiceImpl userDetailsService;

    @Autowired
    RoleRepository roleRepository;

    @Autowired
    PasswordEncoder encoder;

    @Autowired
    JwtUtils jwtUtils;
    @Autowired
    private RefreshTokenService refreshTokenService;

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
        System.out.println("PRINTING_______________________________________________________________________ :"+authentication.toString());
        SecurityContextHolder.getContext().setAuthentication(authentication);

        String jwt = jwtUtils.generateJwtToken(authentication);
        System.out.println("PRINTING JWT _____________________________________________________________ :"+jwt);
        System.out.println("PRINTING CURRENT DATE TIEM +"+ LocalDateTime.now());
//        String refreshToken = ;
        if(authentication.isAuthenticated()){
            RefreshToken refreshToken = refreshTokenService.createRefreshToken(loginRequest.getUsername());
            System.out.println("PRINTING REFRESH TOKEN _____________________________________________________________ :"+refreshToken.getToken());
            return ResponseEntity.ok(JwtResponse.builder()
                    .accessToken(jwt)
                    .token(refreshToken.getToken())
                    .build());

        } else {
            throw new UsernameNotFoundException("invalid user request..!!");
        }
//        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
//        List<String> roles = userDetails.getAuthorities().stream()
//                .map(item -> item.getAuthority())
//                .collect(Collectors.toList());

//        return ResponseEntity.ok(new JwtResponse(jwt,
////                userDetails.getId(),
////                userDetails.getUsername(),
////                userDetails.getEmail(),
//                refreshToken));
    }

    @PostMapping(value = "/refresh",produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> getAccessTokenUsingRefreshToken(@RequestBody RefreshTokenRequestRecord refreshTokenRequestRecord){
        String refreshToken = refreshTokenRequestRecord.token();
        if(refreshToken == null){
            return ResponseEntity.badRequest().body(new MessageResponse("Invalid refresh token"));
        }
        RefreshToken refreshTokenInstance = refreshTokenService.findByToken(refreshToken).get();
        if(refreshTokenService.verifyExpiration(refreshTokenInstance)){
//            Authentication authentication = authenticationManager.authenticate(
//                    new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
//            System.out.println("PRINTING_______________________________________________________________________ :"+authentication.toString());
//            SecurityContextHolder.getContext().setAuthentication(authentication);

            String newAccessToken = jwtUtils.generateJwtTokenWithUserInfo(refreshTokenInstance.getUserInfo());

            return ResponseEntity.ok(JwtResponse.builder()
                    .accessToken(newAccessToken)
                    .token(refreshTokenRequestRecord.token())
                    .build());
        }
        return ResponseEntity.ok("token verification failed.");


    }

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignUpRequest signUpRequest) {
        if (userRepository.existsByUsername(signUpRequest.getUsername())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Username is already taken!"));
        }

        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Email is already in use!"));
        }

        // Create new user's account
        User user = new User(signUpRequest.getUsername(),
                signUpRequest.getEmail(),
                encoder.encode(signUpRequest.getPassword()));

        Set<String> strRoles = signUpRequest.getRole();
        Set<Role> roles = new HashSet<>();

        if (strRoles == null) {
            Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            roles.add(userRole);
        } else {
            strRoles.forEach(role -> {
                switch (role) {
                    case "admin":
                        Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(adminRole);

                        break;
                    case "mod":
                        Role modRole = roleRepository.findByName(ERole.ROLE_MODERATOR)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(modRole);

                        break;
                    default:
                        Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(userRole);
                }
            });
        }

        user.setRoles(roles);
        userRepository.save(user);

        return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
    }


    @GetMapping("/current-user")
    public ResponseEntity<UserDetails> getCurrentLoggedInUserDetails(Principal principal){

        logger.info("PRINTING CURRENTLY LOGGED IN USER__time changed.");
        UserDetails user =  userDetailsService.loadUserByUsername(principal.getName());

        return ResponseEntity.ok(user);
    }
}
