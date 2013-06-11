package cn.loveapple.grails.springsecurity.tencent

import javax.servlet.FilterChain
import javax.servlet.ServletRequest
import javax.servlet.ServletResponse
import javax.servlet.http.Cookie
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

import org.springframework.context.ApplicationEventPublisher
import org.springframework.context.ApplicationEventPublisherAware
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.core.Authentication
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.web.filter.GenericFilterBean

class TencentAuthCookieTransparentFilter extends GenericFilterBean implements ApplicationEventPublisherAware {

	ApplicationEventPublisher applicationEventPublisher
	TencentAuthUtils tencentAuthUtils
	AuthenticationManager authenticationManager
	String logoutUrl = '/j_spring_security_logout'
	String forceLoginParameter
	String filterProcessUrl

	void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, javax.servlet.FilterChain chain) {
		HttpServletRequest request = servletRequest
		HttpServletResponse response = servletResponse
		String url = request.requestURI.substring(request.contextPath.length())
		logger.debug("Processing url: $url")
		if (url != logoutUrl
			&& (SecurityContextHolder.context.authentication == null
				|| (forceLoginParameter
					&& servletRequest.getParameter(forceLoginParameter) == 'true'))) {
			logger.debug("Applying tencent auth filter")
			assert tencentAuthUtils != null
			Cookie cookie = tencentAuthUtils.getAuthCookie(request)
			if (cookie != null) {
				try {
					TencentAuthToken token = tencentAuthUtils.build(cookie.value)
					if (token != null) {
						Authentication authentication
						try {
							authentication = authenticationManager.authenticate(token)
						} catch (Throwable t) {
							logger.warn("Error during authentication. Skipping. Message: "+t.message)
						}
						if (authentication && authentication.authenticated) {
							// Store to SecurityContextHolder
							SecurityContextHolder.context.authentication = authentication

							if (logger.isDebugEnabled()) {
								logger.debug("SecurityContextHolder populated with TencentAuthToken: '"
									+ SecurityContextHolder.context.authentication + "'")
							}
							try {
								chain.doFilter(request, response)
							} finally {
								SecurityContextHolder.context.authentication = null
							}
							return
						}
					}
				} catch (BadCredentialsException e) {
					logger.info("Invalid cookie, skip. Message was: $e.message")
				}
			} else {
				logger.debug("No auth cookie")
			}
		} else {
			logger.debug("SecurityContextHolder not populated with TencentAuthToken token, as it already contained: $SecurityContextHolder.context.authentication")
		}

		//when not authenticated, dont have auth cookie or bad credentials
		chain.doFilter(request, response)
	}
}
