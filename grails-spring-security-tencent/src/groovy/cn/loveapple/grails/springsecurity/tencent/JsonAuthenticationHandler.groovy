package cn.loveapple.grails.springsecurity.tencent

import grails.converters.JSON

import javax.servlet.ServletException
import javax.servlet.ServletOutputStream
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.InitializingBean
import org.springframework.context.ApplicationContext
import org.springframework.context.ApplicationContextAware
import org.springframework.security.core.Authentication
import org.springframework.security.core.AuthenticationException
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.web.authentication.AuthenticationFailureHandler
import org.springframework.security.web.authentication.AuthenticationSuccessHandler

class JsonAuthenticationHandler implements AuthenticationSuccessHandler, AuthenticationFailureHandler, InitializingBean, ApplicationContextAware {

	private static Logger log = LoggerFactory.getLogger(this)

	ApplicationContext applicationContext

	boolean useJsonp = false
	boolean defaultJsonpCallback = 'jsonpCallback'
	def tencentAuthService

	void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception)
	throws IOException, javax.servlet.ServletException {
		response.status = HttpServletResponse.SC_UNAUTHORIZED
		Map data = [
			authenticated: false,
			message: exception?.message
		]
		if (tencentAuthService && tencentAuthService.respondsTo('onJsonFailure')) {
			def data2 = tencentAuthService.onJsonFailure(data, exception)
			if (data2 != null) {
				data = data2
			}
		}
		JSON json = new JSON(data)
		if (useJsonp) {
			renderAsJSONP(json, request, response)
		} else {
			json.render(response)
		}
	}

	void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
	throws IOException, ServletException {
		TencentAuthToken token = authentication
		Map data = [
			authenticated: true,
			uid: token.uid,
			roles: token.authorities?.collect { it.authority }
		]
		if (token.principal != null && UserDetails.isAssignableFrom(token.principal.class)) {
			data.username = token.principal.username
			data.enabled = token.principal.enabled
		}
		if (tencentAuthService && tencentAuthService.respondsTo('onJsonSuccess')) {
			def data2 = tencentAuthService.onJsonSuccess(data, authentication)
			if (data2 != null) {
				data = data2
			}
		}
		JSON json = new JSON(data)
		if (useJsonp) {
			renderAsJSONP(json, request, response)
		} else {
			json.render(response)
		}
	}

	void renderAsJSONP(JSON json, HttpServletRequest request, HttpServletResponse response) {
		String callback = this.defaultJsonpCallback
		if (request.getParameterMap().containsKey('callback')) {
			callback = request.getParameter('callback')
		} else if (request.getParameterMap().containsKey('jsonp')) {
			callback = request.getParameter('jsonp')
		}
		response.setContentType('application/javascript')
		String jsonString = json.toString()
		response.setContentLength(callback.bytes.length + 'c'.bytes.length*2 + jsonString.bytes.length)
		ServletOutputStream out = response.outputStream
		out.print(callback)
		out.print('(')
		out.print(jsonString)
		out.print(')')
	}

	void afterPropertiesSet() {
		if (!tencentAuthService) {
			if (applicationContext.containsBean('tencentAuthService')) {
				log.debug("Use provided tencentAuthService")
				tencentAuthService = applicationContext.getBean('tencentAuthService')
			}
		}
	}
}
