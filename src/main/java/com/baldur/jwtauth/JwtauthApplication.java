package com.baldur.jwtauth;

import com.baldur.jwtauth.model.ERole;
import com.baldur.jwtauth.model.Role;
import com.baldur.jwtauth.model.User;
import com.baldur.jwtauth.payload.request.SignUpRequest;
import com.baldur.jwtauth.repository.RoleRepository;
import com.baldur.jwtauth.repository.UserRepository;
import jakarta.annotation.PostConstruct;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

@SpringBootApplication
public class JwtauthApplication {

	private static final Logger logger = LogManager.getLogger(JwtauthApplication.class);

	@Autowired
	private RoleRepository roleRepository;

	public static void main(String[] args) {
		SpringApplication.run(JwtauthApplication.class, args);

	}

//	@PostConstruct
//	public

	@Bean
	public CommandLineRunner init(UserRepository userRepository,BCryptPasswordEncoder passwordEncoder) {
		return args -> {
			if (userRepository.findByUsername("ADMIN").isEmpty()) {
				SignUpRequest signUpRequest = new SignUpRequest();
				User user = new User("ADMIN@123#",
						"admin@jwtauth.com",
						passwordEncoder.encode("admin@321!^*#"));

				Optional<Role> roleFromDb = roleRepository.findByName(ERole.ROLE_ADMIN);
//				Role role = new Role(ERole.ROLE_ADMIN);


				Set<Role> adminRole = new HashSet<Role>();
				adminRole.add(new Role(ERole.ROLE_ADMIN));
				if (roleFromDb.isEmpty()) {
					Role role = new Role(ERole.ROLE_ADMIN);
					user.setRoles(adminRole);

//                    roleRepository.save(role);
				}
				userRepository.save(user);
			} else {
				logger.info("Admin user already exists. No action needed.");
			}

		};


	}
}
