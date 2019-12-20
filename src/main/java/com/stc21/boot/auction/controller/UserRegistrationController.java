package com.stc21.boot.auction.controller;

import com.stc21.boot.auction.dto.UserRegistrationDto;
import com.stc21.boot.auction.entity.City;
import com.stc21.boot.auction.service.CityService;
import com.stc21.boot.auction.service.UserService;
import lombok.SneakyThrows;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import java.util.List;

@Controller
@RequestMapping("/register")
public class UserRegistrationController {

    private final UserService userService;
    private final CityService cityService;

    public UserRegistrationController(UserService userService, CityService cityService) {
        this.userService = userService;
        this.cityService = cityService;
    }

    @ModelAttribute("user")
    public UserRegistrationDto userRegistrationDto() {
        return new UserRegistrationDto();
    }

    @GetMapping
    public String showRegistrationForm(Model model) {
        List<City> cities = cityService.findAll();
        model.addAttribute("cities", cities);
        return "register";
    }

    @PostMapping
    @SneakyThrows
    public String registerUserAccount(
            HttpServletRequest request,
            Model model,
            @ModelAttribute("user") @Valid UserRegistrationDto userRegistrationDto,
            BindingResult result) {

        userService
                .fieldsWithErrors(userRegistrationDto)
                .forEach(
                        fieldName->result.rejectValue(
                                fieldName,
                                null,
                                "Username with this " + fieldName + " already exist. Pick another one."));

        if (result.hasErrors()) {
            List<City> cities = cityService.findAll();
            model.addAttribute("cities", cities);
            return "register";
        }

        userService.save(userRegistrationDto);
        request.login(userRegistrationDto.getUsername(), userRegistrationDto.getPassword());
        return "redirect:/register?success=true";
    }
}