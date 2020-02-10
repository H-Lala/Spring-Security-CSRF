package com.example.demo.controller;

import org.apache.maven.artifact.repository.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Controller
@RequestMapping("/")
public class TemplateController {
    @GetMapping("login")
    public  String getLoginView(){
        return "login";
    }
    @GetMapping("courses")
    public  String getCourses(){
        return "courses";
    }
    @RequestMapping(value="/courses", method = RequestMethod.POST)
    public String logoutPage (HttpServletRequest request, HttpServletResponse response) {
        Authentication auth = (Authentication) SecurityContextHolder.getContext().getAuthentication();
        if (auth != null){
            new SecurityContextLogoutHandler().logout(request, response, (org.springframework.security.core.Authentication) auth);
        }
        return "redirect";//You can redirect wherever you want, but generally it's a good practice to show login screen again.
    }
}
