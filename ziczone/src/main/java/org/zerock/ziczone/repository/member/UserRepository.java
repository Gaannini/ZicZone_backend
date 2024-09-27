package org.zerock.ziczone.repository.member;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;
import org.zerock.ziczone.domain.member.User;
import org.zerock.ziczone.domain.member.UserType;

import java.util.Optional;

//User는 RestRepository에서 제외
@RepositoryRestResource(exported = false)
public interface UserRepository extends JpaRepository<User, Long> {
    User findByUserId(Long userId);
    Optional<User> findByEmail(String email);

    Optional<User> findByRefreshToken(String refreshToken);

}
