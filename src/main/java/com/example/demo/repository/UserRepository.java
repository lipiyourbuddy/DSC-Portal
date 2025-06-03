package com.example.demo.repository;
import java.util.List;
import java.util.Optional;

import org.springframework.data.repository.CrudRepository;
import com.example.demo.model.User;

public interface UserRepository extends CrudRepository<User, Long> {

	User findByEmail(String email);
	Optional<User> findById(Long id);
	User findByFullName(String fullName);
	List<User> findByAuthMode(String string);
	List<User> findByAuthModeIsNull();


}