package com.stc21.boot.auction.controller;

import com.stc21.boot.auction.dto.LotDto;
import com.stc21.boot.auction.dto.UserDto;
import com.stc21.boot.auction.repository.PurchaseRepository;
import com.stc21.boot.auction.service.LotService;
import com.stc21.boot.auction.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Pageable;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

@Controller
@RequestMapping(path = "/account")
public class AccountController {

    LotService lotService;
    UserService userService;

    @Autowired
    private PurchaseRepository purchaseRepository;

    public AccountController(LotService lotService, UserService userService) {
        this.lotService = lotService;
        this.userService = userService;
    }

    @ModelAttribute(name = "unboughtLots")
    public List<LotDto> userUnboughtLots(@AuthenticationPrincipal Authentication token)  {
        return lotService.getUnboughtLotsOf(token.getName(), Pageable.unpaged()).toList();
    }

    @ModelAttribute(name = "soldLots")
    public List<LotDto> userSoldLots(@AuthenticationPrincipal Authentication token)  {
        return lotService.getBoughtLotsOf(token.getName(), Pageable.unpaged()).toList();
    }

    @ModelAttribute(name = "user")
    public UserDto currentUser(@AuthenticationPrincipal Authentication token)  {
        return userService.findByUsername(token.getName());
    }

    @ModelAttribute(name = "purchasedLots")
    public List<LotDto> allByBuyer(@AuthenticationPrincipal Authentication token)  {
        return lotService.getBoughtLotsBy(token.getName(), Pageable.unpaged()).toList();
    }

    @GetMapping()
    public String showAccountPage(
            Model model,
            @AuthenticationPrincipal Authentication token) {
//        List<Lot> userLots = lotService.getAllLotsByUsername(token);
//        List<Lot> allLots = lotService.getAllLots();
//        List<UserDto> allUsers = userService.getAllUsers();
//        List<Purchase> allByBuyer = purchaseRepository.findAllByBuyer(userService.convertToEntity(currentUser));
//        model.addAttribute("lots", userLots);
//        model.addAttribute("user", currentUser);
//        model.addAttribute("purchases", allByBuyer);
        return "account";
    }

    @PostMapping
    public String processAccountPage(@RequestParam(name = "money") Long money,
                                     @AuthenticationPrincipal Authentication token) {
        UserDto user = userService.findByUsername(token.getName());
        userService.updateWalletTo(user.getId(), user.getWallet() + money);
        return "redirect:/account";
    }
}