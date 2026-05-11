package com.auth.admin.api;

import com.auth.admin.application.AdminClientManagement;
import com.auth.admin.dto.ClientCreateRequest;
import com.auth.admin.dto.ClientUpdateRequest;
import com.auth.admin.dto.SecretRevealResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.HashSet;

@Controller
@RequiredArgsConstructor
@RequestMapping("/admin/clients")
public class AdminClientController {

    private final AdminClientManagement adminClientManagement;

    @GetMapping
    public String list(Model model) {
        model.addAttribute("clients", adminClientManagement.findAll());
        return "admin/clients/list";
    }

    @GetMapping("/new")
    public String newForm(Model model) {
        model.addAttribute("form", new ClientCreateRequest());
        return "admin/clients/new";
    }

    @PostMapping("/new")
    public String create(
            @Valid @ModelAttribute("form") ClientCreateRequest form,
            BindingResult bindingResult,
            RedirectAttributes redirectAttributes
    ) {
        if (bindingResult.hasErrors()) {
            return "admin/clients/new";
        }
        SecretRevealResponse reveal = adminClientManagement.create(form);
        redirectAttributes.addFlashAttribute("reveal", reveal);
        return "redirect:/admin/clients/" + reveal.id() + "/secret-reveal";
    }

    @GetMapping("/{id}/secret-reveal")
    public String secretReveal(@PathVariable String id, Model model) {
        if (!model.containsAttribute("reveal")) {
            return "redirect:/admin/clients";
        }
        return "admin/clients/secret-reveal";
    }

    @GetMapping("/{id}/edit")
    public String editForm(@PathVariable String id, Model model) {
        var detail = adminClientManagement.getDetail(id);
        model.addAttribute("detail", detail);

        ClientUpdateRequest form = new ClientUpdateRequest();
        form.setClientName(detail.clientName());
        form.setGrantTypes(new HashSet<>(detail.grantTypes()));
        form.setScopes(new HashSet<>(detail.scopes()));
        form.setRedirectUrisRaw(detail.redirectUrisRaw());
        form.setPostLogoutRedirectUrisRaw(detail.postLogoutRedirectUrisRaw());
        form.setRequirePkce(detail.requirePkce());
        form.setAccessTokenTtlMinutes(detail.accessTokenTtlMinutes());
        form.setRefreshTokenTtlDays(detail.refreshTokenTtlDays());
        form.setLoginPageUri(detail.loginPageUri());
        model.addAttribute("form", form);

        return "admin/clients/edit";
    }

    @PostMapping("/{id}/edit")
    public String update(
            @PathVariable String id,
            @Valid @ModelAttribute("form") ClientUpdateRequest form,
            BindingResult bindingResult,
            Model model
    ) {
        if (bindingResult.hasErrors()) {
            model.addAttribute("detail", adminClientManagement.getDetail(id));
            return "admin/clients/edit";
        }
        adminClientManagement.update(id, form);
        return "redirect:/admin/clients";
    }

    @PostMapping("/{id}/regenerate-secret")
    public String regenerateSecret(
            @PathVariable String id,
            RedirectAttributes redirectAttributes
    ) {
        SecretRevealResponse reveal = adminClientManagement.regenerateSecret(id);
        redirectAttributes.addFlashAttribute("reveal", reveal);
        return "redirect:/admin/clients/" + id + "/secret-reveal";
    }

    @PostMapping("/{id}/delete")
    public String delete(@PathVariable String id) {
        adminClientManagement.delete(id);
        return "redirect:/admin/clients";
    }
}
