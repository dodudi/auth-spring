package com.auth.security.api;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
@RequestMapping("/oauth/error")
public class OAuthErrorController {

    @GetMapping
    public String error(
            @RequestParam String error,
            @RequestParam(required = false, name = "error_description") String errorDescription,
            Model model
    ) {
        model.addAttribute("error", error);
        model.addAttribute("errorDescription", errorDescription);
        return "oauth-error";
    }
}
