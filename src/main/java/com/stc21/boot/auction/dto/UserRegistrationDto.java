package com.stc21.boot.auction.dto;

import com.stc21.boot.auction.dto.validators.annotations.EqualPasswords;
import com.stc21.boot.auction.dto.validators.annotations.ValidEmail;
import com.stc21.boot.auction.dto.validators.annotations.ValidPhoneNumber;
import com.stc21.boot.auction.entity.City;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;
import javax.validation.constraints.Size;

@Data
@NoArgsConstructor
@EqualPasswords
public class UserRegistrationDto {
    @NotNull
    @Size(min=3, max=25)
    @Pattern(regexp = "^[A-Za-z0-9]*$", message = "Логин содержит недопустимые символы.")
    private String username;

    @NotNull
    @Size(min=3, max=25)
    @Pattern(regexp = "^[A-Za-z0-9]*$", message = "Пароль содержит недопустимые символы.")
    private String password;
    private String repeatPassword;

    @ValidEmail
    private String email;
    @ValidPhoneNumber
    private String phoneNumber;

    @Size(min=0, max=255)
    private String firstName;
    @Size(min=0, max=255)
    private String lastName;

//    private Role role;
    private Long wallet;
    private City city;
    private Boolean deleted = false;
}