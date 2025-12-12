package spring.security.securityJwt.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import spring.security.securityJwt.entity.User;

import java.util.Optional;

public interface UserRepository extends JpaRepository <User,Long>{

    Optional<User> findByUsername(String userName);
}
