package com.cnu.coffee.member;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.GenericGenerator;

import javax.persistence.*;
import java.time.LocalDateTime;
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

    @Column(name = "ebcrypted_pswd", nullable = false)
    private String credential;

    @Enumerated(EnumType.ORDINAL)
    @Column(name = "role")
    private Role role;

    @Column(name = "registered_date", nullable = false, columnDefinition = "TIMESTAMP")
    private LocalDateTime registeredDate;

    private LocalDateTime modifiedDate;
}
