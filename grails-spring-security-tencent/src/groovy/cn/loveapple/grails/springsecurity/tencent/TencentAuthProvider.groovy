package cn.loveapple.grails.springsecurity.tencent

import org.apache.commons.lang.StringUtils
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.InitializingBean
import org.springframework.context.ApplicationContext
import org.springframework.context.ApplicationContextAware
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.authentication.CredentialsExpiredException
import org.springframework.security.core.Authentication
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UsernameNotFoundException

class TencentAuthProvider implements AuthenticationProvider, InitializingBean, ApplicationContextAware {

	private static Logger log = LoggerFactory.getLogger(this)

	TencentAuthDao tencentAuthDao
	TencentAuthUtils tencentAuthUtils
	def tencentAuthService
	ApplicationContext applicationContext

	boolean createNew = true

	Authentication authenticate(Authentication authentication) {
		TencentAuthToken token = authentication

		log.debug "authenticate token : $token"
		
		if (token.uid) {
			
			Date now = new Date()
			
			if (StringUtils.isEmpty(token.code) && token.accessToken == null) {
				log.error("Token should contain 'code' OR 'accessToken' to get uid")
				token.authenticated = false
				return token
			}
			if (token.code
				&& (!token.accessToken?.expireAt|| now.after(token.accessToken.expireAt))) {
				
				log.debug "get access token in method authenticate. accessToken: ${token.accessToken}"
				token.accessToken = tencentAuthUtils.getAccessToken(token.code, token.redirectUri)
				if (!token.accessToken.accessToken) {
					log.error("Can't fetch access_token for code '$token.code'")
					token.authenticated = false
					return token
				}
			}
			if(!token.accessToken?.expireAt|| now.after(token.accessToken.expireAt)){
				
				log.debug "load user uid in method authenticate. accessToken: ${token.accessToken}"
				
				token.uid = tencentAuthUtils.loadUserUid(token.accessToken.accessToken)
				if (!token.uid) {
					log.error("Can't fetch uid")
					token.authenticated = false
					return token
				}
			}
		}

		def user = tencentAuthDao.findUser(token.uid)
		boolean justCreated = false

		if (user == null) {
			//log.debug "New person $token.uid"
			if (createNew) {
				log.info "Create new tencent user with uid $token.uid"
				if (token.accessToken == null) {
				log.debug "get access token in method authenticate when user is null. accessToken: ${token.accessToken}"
					token.accessToken = tencentAuthUtils.getAccessToken(token.code, token.redirectUri)
				}
				if (token.accessToken == null) {
					log.error("Can't create user w/o access_token")
					throw new CredentialsExpiredException("Can't receive access_token from Tencent")
				}
				user = tencentAuthDao.create(token)
				justCreated = true
			} else {
				log.error "User $token.uid doesn't exist, and creation of a new user is disabled."
				log.debug "To enabled auto creation of users set `grails.plugins.springsecurity.tencent.autoCreate.enabled` to true"
				throw new UsernameNotFoundException("Tencent user with uid $token.uid doesn't exist")
			}
		}
		if (user != null) {
			if (justCreated) {
				log.debug("User is just created")
			}
			if (!justCreated 
					&& token.accessToken != null) {
				if (user.properties.containsKey('accessToken')) {
					if(user.accessToken != token.accessToken.accessToken){
						log.debug("Set new access token for user $user")
						tencentAuthDao.updateToken(user, token)
					}
				}
					
			}
			if (!tencentAuthDao.hasValidToken(user)) {
				log.debug("User $user has invalid access token")
				String currentAccessToken = tencentAuthDao.getAccessToken(user)
				TencentAccessToken freshToken = null
				if (currentAccessToken) {
					try {
						log.debug("Refresh access token for $user")
						freshToken = tencentAuthUtils.refreshAccessToken(currentAccessToken)
						if (!freshToken) {
							log.warn("Can't refresh access token for user $user")
						}
					} catch (IOException e) {
						log.warn("Can't refresh access token for user $user")
					}
				}

				if (!freshToken) {
					log.debug("Load a new access token, from code")
					freshToken = tencentAuthUtils.getAccessToken(token.code, token.redirectUri)
				}

				if (freshToken) {
					if (freshToken.accessToken != currentAccessToken) {
						log.debug("Update access token for user $user")
						token.accessToken = freshToken
						tencentAuthDao.updateToken(user, token)
					} else {
						log.debug("User $user already have same access token")
					}
				} else {
					log.error("Can't update accessToken from Tencent, current token is expired. Disable current authentication")
					token.authenticated = false
					return token
				}
			}

			Object appUser = tencentAuthDao.getAppUser(user)
			Object principal = tencentAuthDao.getPrincipal(appUser)

			token.details = null
			token.principal = principal
			if (UserDetails.isAssignableFrom(principal.class)) {
				token.authorities = ((UserDetails)principal).getAuthorities()
			} else {
				token.authorities = tencentAuthDao.getRoles(appUser)
			}

		} else {
			token.authenticated = false
		}
		return token
	}

	boolean supports(Class<? extends Object> authentication) {
		return TencentAuthToken.isAssignableFrom(authentication);
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
