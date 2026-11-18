package com.alertforge.alertforge.web;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class DashboardController {

    private final int pollSeconds;

    public DashboardController(@Value("${alertforge.dashboard.poll-seconds:3}") int pollSeconds) {
        this.pollSeconds = pollSeconds;
    }

    @GetMapping("/")
    public String dashboard(Model model) {
        model.addAttribute("pollSeconds", pollSeconds);
        return "dashboard";   // resolves to templates/dashboard.html
    }
}