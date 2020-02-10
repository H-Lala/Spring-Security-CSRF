package com.example.demo.security;

import org.springframework.security.web.server.csrf.CsrfException;
import org.springframework.security.web.server.csrf.CsrfToken;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class CsrfHeaderFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain) throws ServletException, IOException {
        CsrfToken token =(CsrfToken) httpServletRequest.getAttribute(CsrfToken.class.getName());
        if(token!=null){
            httpServletResponse.setHeader("X-CSRF-HEADER",token.getHeaderName());
            httpServletResponse.setHeader("X-CSRF-PARAM",token.getParameterName());
            httpServletResponse.setHeader("X-CSRF-TOKEN", token.getToken());
        }
        else {
            new CsrfException("CSRF EXCEPTION");
        }
        filterChain.doFilter(httpServletRequest,httpServletResponse);
    }
}
