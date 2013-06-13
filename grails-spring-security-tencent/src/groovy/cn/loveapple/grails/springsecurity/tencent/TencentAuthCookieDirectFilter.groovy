package cn.loveapple.grails.springsecurity.tencent

import javax.servlet.http.Cookie
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

import org.springframework.security.core.Authentication
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter

class TencentAuthCookieDirectFilter extends AbstractAuthenticationProcessingFilter {

	TencentAuthUtils tencentAuthUtils

	TencentAuthCookieDirectFilter(String defaultFilterProcessesUrl) {
		super(defaultFilterProcessesUrl)
	}

	@Override
	Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {
		Cookie cookie = tencentAuthUtils.getAuthCookie(request)
		if (!cookie || cookie.value == null) {
			throw new InvalidCookieException("No cookie")
		}
		TencentAuthToken token = tencentAuthUtils.build(cookie.value)
		return authenticationManager.authenticate(token)
	}
}
