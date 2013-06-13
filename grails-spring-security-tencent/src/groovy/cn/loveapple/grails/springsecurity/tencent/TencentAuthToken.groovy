package cn.loveapple.grails.springsecurity.tencent

import org.springframework.security.authentication.AbstractAuthenticationToken
import org.springframework.security.core.GrantedAuthority

class TencentAuthToken extends AbstractAuthenticationToken {
	String uid
	TencentAccessToken accessToken
	String code
	String redirectUri

	Object principal

	Collection<GrantedAuthority> authorities

	def TencentAuthToken() {
		super([] as Collection<GrantedAuthority>)
	}

	Object getCredentials() {
		return uid
	}
	
	Object getPrincipal(){
		return principal
	}

	String toString() {
		return "[code: $code Principal: $principal, uid: $uid, roles: ${authorities.collect { it.authority}}  redirectUri: $redirectUri accessToken: $accessToken]"
	}
}
