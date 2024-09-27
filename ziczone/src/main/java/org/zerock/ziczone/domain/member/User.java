package org.zerock.ziczone.domain.member;

import lombok.*;
import net.minidev.json.annotate.JsonIgnore;
import org.hibernate.annotations.CreationTimestamp;

import javax.persistence.*;
import java.time.LocalDateTime;

@Entity
@Getter
@Builder(toBuilder = true)
@AllArgsConstructor
@NoArgsConstructor
@ToString(exclude = "personalUser")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "user_id")
    private Long userId;                    // id

    @Column(length = 100, nullable = false)
    private String email;                   // 이메일

    @Column(length = 100, nullable = false)
    private String password;                // 비밀번호

    @Column(length = 100, nullable = false)
    private String userName;                // 유저이름

    @Column(nullable = false)
    @Enumerated(EnumType.STRING)
    private UserType userType;              // 유저 타입(기업/개인)

    @CreationTimestamp
    @Column(nullable = false, updatable = false)
    private LocalDateTime userCreate;       // 유저 가입 날짜

    @Column(length = 255, nullable = false)
    private String userIntro;               // 간단한 자기 소개

    @JsonIgnore
    @OneToOne(mappedBy = "user", fetch = FetchType.LAZY)
    private PersonalUser personalUser;      // 개인 회원 테이블

    @Column
    private String refreshToken; // refreshToken
}
