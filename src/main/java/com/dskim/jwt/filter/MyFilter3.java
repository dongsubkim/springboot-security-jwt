package com.dskim.jwt.filter;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class MyFilter3 implements Filter {
	 
	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {

		HttpServletRequest req = (HttpServletRequest) request;
		HttpServletResponse res = (HttpServletResponse) response;
		req.setCharacterEncoding("UTF-8");
		chain.doFilter(req, res);
		return;
		// token : dskim
//		if (req.getMethod().equals("POST")) {
//			System.out.println("Post requested.");
//			String headerAuth = req.getHeader("Authorization");
//			System.out.println(headerAuth);
//			System.out.println("Filter 3");
//
//			if (headerAuth.equals("dskim")) {
//				chain.doFilter(req, res);
//			} else {
//				PrintWriter out = res.getWriter();
//				out.println("NO VERIFICATION");
//			}
//		}
	}
}
