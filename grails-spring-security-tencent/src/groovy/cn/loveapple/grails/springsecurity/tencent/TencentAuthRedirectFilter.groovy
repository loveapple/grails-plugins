package cn.loveapple.grails.springsecurity.tencent

import grails.plugins.springsecurity.SpringSecurityService

import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

import org.apache.commons.lang.builder.ToStringBuilder
import org.codehaus.groovy.grails.commons.GrailsApplication
import org.codehaus.groovy.grails.web.mapping.LinkGenerator
import org.springframework.security.core.Authentication
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter

class TencentAuthRedirectFilter extends AbstractAuthenticationProcessingFilter {
	
	TencentAuthUtils tencentAuthUtils

	String redirectFromUrl
	
	SpringSecurityService springSecurityService
	
	GrailsApplication grailsApplication

	LinkGenerator linkGenerator

	TencentAuthRedirectFilter(String defaultFilterProcessesUrl) {
		super(defaultFilterProcessesUrl)
	}

	@Override
	Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {
		String code = request.getParameter('code')
		if (code) {
			
			TencentAuthToken token = new TencentAuthToken(
					code: code,
					redirectUri: getAbsoluteRedirectUrl(),
					principal: request.session['SPRING_SECURITY_CONTEXT']?.getAuthentication()?.getPrincipal() 
			)
			
			logger.debug("Got 'code' from Tencent. Process authentication using this code. token: $token  session: ${ToStringBuilder.reflectionToString(request.session)}")
			
			return authenticationManager.authenticate(token)
		}
		throw new InvalidRequestException("Request is empty")
	}

	@Override
	protected boolean requiresAuthentication(HttpServletRequest request, HttpServletResponse response) {
		String uri = request.getRequestURI()
		int pathParamIndex = uri.indexOf(';')

		if (pathParamIndex > 0) {
			// strip everything after the first semi-colon
			uri = uri.substring(0, pathParamIndex)
		}

		uri = uri.substring(request.contextPath.length())

		if (uri.equals(redirectFromUrl)) {
			response.sendRedirect(tencentAuthUtils.prepareRedirectUrl(getAbsoluteRedirectUrl(), tencentAuthUtils.requiredPermissions))
			return false
		}

		return uri.equals(filterProcessesUrl)
	}

	String getAbsoluteRedirectUrl() {
		String path = getFilterProcessesUrl()
		linkGenerator.link(uri: path, absolute: true)
	}
}
