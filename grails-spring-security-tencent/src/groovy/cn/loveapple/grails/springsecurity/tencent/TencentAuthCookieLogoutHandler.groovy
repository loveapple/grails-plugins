package cn.loveapple.grails.springsecurity.tencent

import java.util.regex.Matcher

import javax.servlet.http.Cookie
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

import org.codehaus.groovy.grails.plugins.springsecurity.SpringSecurityUtils
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.security.core.Authentication
import org.springframework.security.web.authentication.logout.LogoutHandler

class TencentAuthCookieLogoutHandler implements LogoutHandler {

	private static final Logger logger = LoggerFactory.getLogger(this)

	TencentAuthUtils tencentAuthUtils

	boolean cleanupToken = true
	TencentAuthDao tencentAuthDao

	void logout(HttpServletRequest httpServletRequest,
			HttpServletResponse httpServletResponse,
			Authentication authentication) {

		String baseDomain

		List<Cookie> cookies = httpServletRequest.cookies.findAll { Cookie it ->
			//TencentAuthUtils.log.debug("Cookier $it.name, expected $cookieName")
			return it.name ==~ /fb\w*_$tencentAuthUtils.applicationId/
		}

		baseDomain = cookies.find {
			return it.name == "fbm_\$tencentAuthUtils.applicationId" && it.value ==~ /base_domain=.+/
		}?.value?.split('=')?.last()

		if (!baseDomain) {
			//Tencent uses invalid cookie format, so sometimes we need to parse it manually
			String rawCookie = httpServletRequest.getHeader('Cookie')
			logger.info("raw cookie: $rawCookie")
			if (rawCookie) {
				Matcher m = rawCookie =~ /fbm_$tencentAuthUtils.applicationId=base_domain=(.+?);/
				if (m.find()) {
					baseDomain = m.group(1)
				}
			}
		}

		if (!baseDomain) {
			def conf = SpringSecurityUtils.securityConfig.tencent
			if (conf.host && conf.host.length() > 0) {
				baseDomain = conf.host
			}
			logger.debug("Can't find base domain for Tencent cookie. Use '$baseDomain'")
		}

		cookies.each { cookie ->
			cookie.maxAge = 0
			cookie.path = '/'
			if (baseDomain) {
				cookie.domain = baseDomain
			}
			httpServletResponse.addCookie(cookie)
		}

		if (cleanupToken && (authentication instanceof TencentAuthToken)) {
			cleanupToken(authentication)
		}
	}

	void cleanupToken(TencentAuthToken authentication) {
		if (!tencentAuthDao) {
			logger.error("No TencentAuthDao")
			return
		}
		try {
			def user = tencentAuthDao.findUser(authentication.uid)
			authentication.accessToken = null
			tencentAuthDao.updateToken(user, authentication)
		} catch (Throwable t) {
			logger.error("Can't remove existing token", t)
		}
	}
}
