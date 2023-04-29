package com.cnu.coffee.member;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.GenericGenerator;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.persistence.*;
import java.time.LocalDateTime;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

@Builder
@Getter
@Entity
@Table(name = "members")
@AllArgsConstructor
@NoArgsConstructor
public class Member {
    @Id
    @GeneratedValue(generator = "uuid2")
    @GenericGenerator(name = "uuid2", strategy = "uuid2")
    @Column(name = "id", nullable = false, unique = true, columnDefinition = "BINARY(16)")
    private UUID id;

    @Column(name = "nick_name", nullable = false, length = 10)
    private String nickName;

    @Column(name = "email", nullable = false, unique = true, length = 50)
    private String email;

    @Column(name = "member_secret", nullable = false)
    private String memberSecret;

    @Enumerated(EnumType.ORDINAL)
    @Column(name = "role")
    private Role role;

    @Column(name = "registered_date", nullable = false, columnDefinition = "TIMESTAMP")
    private LocalDateTime registeredDate;

    private LocalDateTime modifiedDate;

    public List<GrantedAuthority> getAuthorities(){
        return Collections.singletonList(
                new SimpleGrantedAuthority(role.toString())
        );
    }

    public void checkPassword(PasswordEncoder passwordEncoder, String credentials) {
        if (!passwordEncoder.matches(credentials, memberSecret))
            throw new IllegalArgumentException("Bad credential");
    }
}
