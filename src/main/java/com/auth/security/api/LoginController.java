package com.auth.security.api;

import jakarta.servlet.http.HttpSession;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class LoginController {

    @GetMapping("/login")
    public String loginPage(HttpSession session, Model model) {
        String errorCode = (String) session.getAttribute("LOGIN_ERROR_CODE");
        if (errorCode != null) {
            model.addAttribute("loginErrorCode", errorCode);
            session.removeAttribute("LOGIN_ERROR_CODE");
        }
        return "login";
    }
}
