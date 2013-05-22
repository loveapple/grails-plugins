package cn.loveapple.grails.springsecurity.tencent

import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

import org.apache.commons.lang.StringUtils
import org.apache.log4j.Logger
import org.springframework.security.core.Authentication
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter

class TencentAuthJsonFilter extends AbstractAuthenticationProcessingFilter {
	private static def log = Logger.getLogger(this)
	
		TencentAuthUtils tencentAuthUtils
	
		List<String> methods = ['POST']
	
		def TencentAuthJsonFilter(String url) {
			super(url)
		}
	
		public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {
			String method = request.method?.toUpperCase() ?: 'UNKNOWN'
			if (!methods.contains(method)) {
				log.error("Request method: $method, allowed only $methods")
				throw new InvalidRequestException("$method is not accepted")
			}
	
			TencentAuthToken token = null
	
			if (StringUtils.isNotEmpty(request.getParameter('access_token'))) {
				String accessTokenValue = request.getParameter('access_token')
				TencentAccessToken accessToken = tencentAuthUtils.refreshAccessToken(accessTokenValue)
				if (accessToken != null) {
					token = new TencentAuthToken(
							accessToken: accessToken,
							authenticated: true
					)
					Authentication authentication = getAuthenticationManager().authenticate(token);
					return authentication
				} else {
					throw new InvalidRequestException("Invalid access_token value (or expired)")
				}
			}
	
			if (StringUtils.isNotEmpty(request.getParameter('signed_request'))) {
				token = tencentAuthUtils.build(request.getParameter('signed_request'))
			} else if (StringUtils.isNotEmpty(request.getParameter('signedRequest'))) { //TODO remove. for backward compatibility only
				token = tencentAuthUtils.build(request.getParameter('signedRequest'))
			}
			if (token != null) {
				Authentication authentication = getAuthenticationManager().authenticate(token);
				return authentication
			}
	
			throw new InvalidRequestException("Client didn't provide any details for authorization")
		}

}
