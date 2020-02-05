package com.example.demo.security;

import org.springframework.security.web.server.csrf.CsrfToken;
import org.springframework.stereotype.Repository;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class CsrfCookieGeneratorFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain) throws ServletException, IOException {
        CsrfToken csrfToken = (CsrfToken) httpServletRequest.getAttribute("_csrf");
        String actualToken = httpServletRequest.getHeader("X-CSRF-TOKEN");
        if(actualToken==null || !actualToken.equals(csrfToken.getToken())){
            String pCookieName = "CSRF-TOKEN";
            Cookie cookie = new Cookie(pCookieName,csrfToken.getToken());
            cookie.setMaxAge(-1);
            cookie.setHttpOnly(false);
            cookie.setPath("/");
            httpServletResponse.addCookie(cookie);
        }
        filterChain.doFilter(httpServletRequest, httpServletResponse);
    }
}
