package cn.loveapple.grails.springsecurity.tencent

import org.springframework.security.core.AuthenticationException

class InvalidCookieException extends AuthenticationException {
	InvalidCookieException(String msg) {
		super(msg)
	}

	InvalidCookieException(String msg, Object extraInformation) {
		super(msg, extraInformation)
	}
}
