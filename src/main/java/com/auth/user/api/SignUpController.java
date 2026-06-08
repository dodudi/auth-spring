package com.auth.user.api;

import com.auth.common.exception.AuthException;
import com.auth.user.application.UserService;
import com.auth.user.dto.SignUpRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/signup")
@RequiredArgsConstructor
public class SignUpController {

    private final UserService userService;

    @GetMapping
    public String signUpPage(Model model) {
        model.addAttribute("form", new SignUpRequest(null, null, null));
        return "signup";
    }

    @PostMapping
    public String signUp(@Valid @ModelAttribute("form") SignUpRequest form, BindingResult bindingResult, Model model) {
        if (bindingResult.hasErrors()) {
            return "signup";
        }

        try {
            userService.signUp(form);
        } catch (AuthException e) {
            model.addAttribute("errorMessage", e.getErrorCode().getMessage());
            return "signup";
        }

        return "redirect:/login?signup=success";
    }
}
