package com.baldur.jwtauth.repository;

import com.baldur.jwtauth.model.ERole;
import com.baldur.jwtauth.model.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByName(ERole name);
}