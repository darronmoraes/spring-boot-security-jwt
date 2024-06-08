package com.example.jwt.repository;

import com.example.jwt.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import javax.swing.text.html.Option;
import java.util.Optional;

@Repository
public interface UserInfoRepository extends JpaRepository<User, Integer> {

    Optional<User> findByName(String username);
}
