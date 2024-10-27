package com.securityjwt.jwtfinal.models;

import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;


import java.util.Collection;
import java.util.Date;
import java.util.Set;
import java.util.stream.Collectors;

@Entity
@Table(name = "users",
uniqueConstraints = {
        @UniqueConstraint(columnNames = "username"),
        @UniqueConstraint(columnNames = "email")
})
@Getter
@Setter
@RequiredArgsConstructor
public class User {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;
  @NotBlank
  private String username;
  @NotBlank
  @Email
  private String email;

  @NotBlank
    private String password;
  @ElementCollection(fetch = FetchType.EAGER)
  @CollectionTable(name="user_roles", joinColumns = @JoinColumn(name="user_id"))
  private Set<String> roles;

  @CreationTimestamp
  @Column(updatable = false, name = "created_at")
  private Date createdAt;

  @UpdateTimestamp
    @Column(name = "updated_at")
    private Date updatedAt;

  public User(String username, String email, String password) {
    this.username = username;
    this.email = email;
    this.password = password;
  }
  public User(String username, String email, String password, Set<String> roles) {
    this.username = username;
    this.email = email;
    this.password = password;
    this.roles = roles;
  }


}
