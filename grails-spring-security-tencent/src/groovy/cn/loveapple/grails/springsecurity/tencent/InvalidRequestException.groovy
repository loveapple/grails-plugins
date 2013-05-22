package cn.loveapple.grails.springsecurity.tencent

import org.springframework.security.core.AuthenticationException

class InvalidRequestException extends AuthenticationException {
	InvalidRequestException(String msg, Throwable t) {
		super(msg, t)
	}

	InvalidRequestException(String msg) {
		super(msg)
	}
}
