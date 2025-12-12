package spring.security.securityJwt.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import spring.security.securityJwt.entity.Role;

import java.util.Optional;

public interface RoleRepository extends JpaRepository <Role,Long>{

    Optional<Role> findByName(String name);
}
