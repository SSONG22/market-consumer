package com.pmc.market.entity;

import lombok.*;

import javax.persistence.*;
import javax.validation.constraints.NotNull;
import java.time.LocalDateTime;

@Builder
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Table(name = "users", uniqueConstraints = {@UniqueConstraint(columnNames = "email")})
@Entity
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotNull
    private String email;

    @NotNull
    private AuthProvider provider;

    @NotNull
//    @JsonIgnore TODO : search
    private String password;

    @NotNull
    private String address;

    @NotNull
    private String name;

    @Enumerated(EnumType.STRING)
    @NotNull
    private Role role;

    @NotNull
    @Enumerated(EnumType.STRING)
    private Status status;

    @Column
    private String picture;

    @Column
    private LocalDateTime regDate;

    @Column
    private LocalDateTime updateDate;

    @Column
    private String authKey;

    @Builder
    public User(String name, String email, Role role, Status status, String picture, AuthProvider authProvider) {
        this.name = name;
        this.email = email;
        this.role = role;
        this.status = status;
        this.picture = picture;
        this.provider = authProvider;
    }

    public User update(String name, String picture) {
        this.name = name;
        this.picture = picture;
        return this;
    }

    public String getRoleKey() {
        return this.role.getKey();
    }
}
