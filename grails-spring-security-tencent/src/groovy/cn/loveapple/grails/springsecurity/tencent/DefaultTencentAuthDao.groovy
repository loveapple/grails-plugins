package cn.loveapple.grails.springsecurity.tencent

import java.util.concurrent.TimeUnit

import org.codehaus.groovy.grails.commons.GrailsApplication
import org.codehaus.groovy.grails.plugins.springsecurity.GormUserDetailsService
import org.codehaus.groovy.grails.plugins.springsecurity.SpringSecurityUtils
import org.codehaus.groovy.grails.plugins.support.aware.GrailsApplicationAware
import org.hibernate.StaleObjectStateException
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.InitializingBean
import org.springframework.context.ApplicationContext
import org.springframework.context.ApplicationContextAware
import org.springframework.dao.OptimisticLockingFailureException
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.GrantedAuthorityImpl
import org.springframework.security.core.userdetails.UserDetails

class DefaultTencentAuthDao implements TencentAuthDao<Object, Object>, InitializingBean, ApplicationContextAware, GrailsApplicationAware {

	private static Logger log = LoggerFactory.getLogger(this)

	GrailsApplication grailsApplication
	ApplicationContext applicationContext
	def coreUserDetailsService

	String domainClassName

	String appUserConnectionPropertyName

	String userDomainClassName
	String rolesPropertyName
	List<String> defaultRoleNames = ['ROLE_USER', 'ROLE_TENCENT']

	def tencentAuthService
	DomainsRelation domainsRelation

	private Class<?> TencentUserDomainClazz
	private Class<?> AppUserDomainClazz

	Object getTencentUser(Object user) {
		if (tencentAuthService && tencentAuthService.respondsTo('getTencentUser', user.class)) {
			return tencentAuthService.getTencentUser(user)
		}
		if (domainsRelation == DomainsRelation.JoinedUser) {
			def loaded
			TencentUserDomainClazz.withTransaction { status ->
				user = TencentUserDomainClazz.findWhere((appUserConnectionPropertyName): user)
			}
			return loaded
		}
		if (domainsRelation == DomainsRelation.SameObject) {
			return user
		}
		log.error("Invalid domainsRelation value: $domainsRelation")
		return user
	}

	Object getAppUser(Object tencentUser) {
		if (tencentAuthService && tencentAuthService.respondsTo('getAppUser', tencentUser.class)) {
			return tencentAuthService.getAppUser(tencentUser)
		}
		if (tencentUser == null) {
			log.warn("Passed tencentUser is null")
			return tencentUser
		}
		if (domainsRelation == DomainsRelation.SameObject) {
			return tencentUser
		}
		if (domainsRelation == DomainsRelation.JoinedUser) {
			Object result
			TencentUserDomainClazz.withTransaction { status ->
				tencentUser.merge()
				result = tencentUser.getAt(appUserConnectionPropertyName)
			}
			return result
		}
		log.error("Invalid domainsRelation value: $domainsRelation")
		return tencentUser
	}

	Object findUser(String uid) {
		if (tencentAuthService && tencentAuthService.respondsTo('findUser', String.class)) {
			return tencentAuthService.findUser(uid)
		}
		def user
		TencentUserDomainClazz.withTransaction { status ->
			user = TencentUserDomainClazz.findWhere(uid: uid)
			if (user
			&& !(tencentAuthService && tencentAuthService.respondsTo('getTencentUser', user.class))
			&& domainsRelation == DomainsRelation.JoinedUser) {
				getTencentUser(user) // load the User object to memory prevent LazyInitializationException
			}
		}
		return user
	}

	Object create(TencentAuthToken token) {
		if (tencentAuthService && tencentAuthService.respondsTo('create', TencentAuthToken)) {
			return tencentAuthService.create(token)
		}

		def securityConf = SpringSecurityUtils.securityConfig

		def user = grailsApplication.getDomainClass(domainClassName).newInstance()
		user.uid = token.uid
		if (user.properties.containsKey('accessToken')) {
			user.accessToken = token.accessToken?.accessToken
		}
		if (user.properties.containsKey('accessTokenExpires')) {
			user.accessTokenExpires = token.accessToken?.expireAt
		}

		def appUser
		if (domainsRelation == DomainsRelation.JoinedUser) {
			if (tencentAuthService && tencentAuthService.respondsTo('createAppUser', TencentUserDomainClazz, TencentAuthToken)) {
				appUser = tencentAuthService.createAppUser(user, token)
			} else {
				appUser = AppUserDomainClazz.newInstance()
				if (tencentAuthService && tencentAuthService.respondsTo('prepopulateAppUser', AppUserDomainClazz, TencentAuthToken)) {
					tencentAuthService.prepopulateAppUser(appUser, token)
				} else {
					appUser[securityConf.userLookup.usernamePropertyName] = "tencent_$token.uid"
					appUser[securityConf.userLookup.passwordPropertyName] = token.accessToken?.accessToken
					appUser[securityConf.userLookup.enabledPropertyName] = true
					appUser[securityConf.userLookup.accountExpiredPropertyName] = false
					appUser[securityConf.userLookup.accountLockedPropertyName] = false
					appUser[securityConf.userLookup.passwordExpiredPropertyName] = false
				}
				AppUserDomainClazz.withTransaction {
					appUser.save(flush: true, failOnError: true)
				}
			}
			user[appUserConnectionPropertyName] = appUser
		}

		if (tencentAuthService && tencentAuthService.respondsTo('onCreate', TencentUserDomainClazz, token)) {
			tencentAuthService.onCreate(user, token)
		}

		TencentUserDomainClazz.withTransaction {
			user.save(flush: true, failOnError: true)
		}

		if (tencentAuthService && tencentAuthService.respondsTo('afterCreate', TencentUserDomainClazz, token)) {
			tencentAuthService.afterCreate(user, token)
		}

		if (tencentAuthService && tencentAuthService.respondsTo('createRoles', TencentUserDomainClazz)) {
			tencentAuthService.createRoles(user)
		} else {
			Class<?> PersonRole = grailsApplication.getDomainClass(securityConf.userLookup.authorityJoinClassName).clazz
			Class<?> Authority = grailsApplication.getDomainClass(securityConf.authority.className).clazz
			PersonRole.withTransaction { status ->
				defaultRoleNames.each { String roleName ->
					String findByField = securityConf.authority.nameField[0].toUpperCase() + securityConf.authority.nameField.substring(1)
					def auth = Authority."findBy${findByField}"(roleName)
					if (auth) {
						PersonRole.create(appUser, auth)
					} else {
						log.error("Can't find authority for name '$roleName'")
					}
				}
			}
		}

		return user
	}

	Object getPrincipal(Object user) {
		if (tencentAuthService && tencentAuthService.respondsTo('getPrincipal', user.class)) {
			return tencentAuthService.getPrincipal(user)
		}
		if (coreUserDetailsService) {
			return coreUserDetailsService.createUserDetails(user, getRoles(user))
		}
		return user
	}

	Collection<GrantedAuthority> getRoles(Object user) {
		if (tencentAuthService && tencentAuthService.respondsTo('getRoles', user.class)) {
			return tencentAuthService.getRoles(user)
		}

		if (UserDetails.isAssignableFrom(user.class)) {
			return ((UserDetails)user).getAuthorities()
		}

		def conf = SpringSecurityUtils.securityConfig
		Class<?> PersonRole = grailsApplication.getDomainClass(conf.userLookup.authorityJoinClassName)?.clazz
		if (!PersonRole) {
			log.error("Can't load roles for user $user. Reason: can't find ${conf.userLookup.authorityJoinClassName} class")
			return []
		}
		Collection roles = []
		PersonRole.withTransaction { status ->
			roles = user?.getAt(rolesPropertyName)
		}
		if (!roles) {
			roles = []
		}
		if (roles.empty) {
			return roles
		}
		return roles.collect {
			if (it instanceof String) {
				return new GrantedAuthorityImpl(it.toString())
			}
			new GrantedAuthorityImpl(it[conf.authority.nameField])
		}
	}

	Boolean hasValidToken(Object tencentUser) {
		if (tencentAuthService && tencentAuthService.respondsTo('hasValidToken', tencentUser.class)) {
			return tencentAuthService.hasValidToken(tencentUser)
		}
		if (tencentUser.properties.containsKey('accessToken')) {
			if (tencentUser.accessToken == null) {
				return false
			}
		}
		if (tencentUser.properties.containsKey('accessTokenExpires')) {
			if (tencentUser.accessTokenExpires == null) {
				return false
			}
			Date goodExpiration = new Date(System.currentTimeMillis() + TimeUnit.MINUTES.toMillis(15))
			Date currentExpires = tencentUser.accessTokenExpires
			if (currentExpires.before(goodExpiration)) {
				return false
			}
		} else {
			log.warn("Domain ${tencentUser.class} don't have 'acccessTokenExpires' field, can't check accessToken expiration. And it's very likely that your database contains expired tokens")
		}
		return true
	}

	void updateToken(Object tencentUser, TencentAuthToken token) {
		if (tencentAuthService && tencentAuthService.respondsTo('updateToken', tencentUser.class, token.class)) {
			tencentAuthService.updateToken(tencentUser, token)
			return
		}
		log.debug("Update access token to $token.accessToken for $tencentUser")
		try{
			TencentUserDomainClazz.withTransaction {
				try {
					if (!tencentUser.isAttached()) {
						tencentUser.attach()
					}
					if (tencentUser.properties.containsKey('accessToken')) {
						tencentUser.accessToken = token.accessToken?.accessToken
					}
					if (tencentUser.properties.containsKey('accessTokenExpires')) {
						tencentUser.accessTokenExpires = token.accessToken?.expireAt
					}
					tencentUser.save()
				} catch (OptimisticLockingFailureException e) {
					log.warn("Seems that token was updated in another thread (${e.message}). Skip")
				} catch (Throwable e) {
					log.error("Can't update token", e)
				}
			}
		}catch(StaleObjectStateException e){
			log.warn("Target of tencent user has be updated by other transaction. ${tencentUser}")
		}
	}

	String getAccessToken(Object tencentUser) {
		if (tencentAuthService && tencentAuthService.respondsTo('getAccessToken', tencentUser.class)) {
			return tencentAuthService.getAccessToken(tencentUser)
		}
		if (tencentUser.properties.containsKey('accessToken')) {
			if (tencentUser.properties.containsKey('accessTokenExpires')) {
				Date currentExpires = tencentUser.accessTokenExpires
				if (currentExpires == null) {
					log.debug("Current access token don't have expiration timeout, and should be updated")
					return null
				}
				if (currentExpires.before(new Date())) {
					log.debug("Current access token is expired, and cannot be used anymore")
					return null
				}
			}
			return tencentUser.accessToken
		}
		return null
	}

	void afterPropertiesSet() {
		if (!tencentAuthService) {
			if (applicationContext.containsBean('tencentAuthService')) {
				log.debug("Use provided tencentAuthService")
				tencentAuthService = applicationContext.getBean('tencentAuthService')
			}
		}

		//validate configuration

		List serviceMethods = []
		if (tencentAuthService) {
			tencentAuthService.metaClass.methods.each { serviceMethods<< it.name }
		}

		def conf = SpringSecurityUtils.securityConfig
		if (!serviceMethods.contains('getRoles')) {
			Class<?> UserDomainClass = grailsApplication.getDomainClass(userDomainClassName)?.clazz
			if (UserDomainClass == null || !UserDetails.isAssignableFrom(UserDomainClass)) {
				if (!conf.userLookup.authorityJoinClassName) {
					log.error("Don't have authority join class configuration. Please configure 'grails.plugins.springsecurity.userLookup.authorityJoinClassName' value")
				} else if (!grailsApplication.getDomainClass(conf.userLookup.authorityJoinClassName)) {
					log.error("Can't find authority join class (${conf.userLookup.authorityJoinClassName}). Please configure 'grails.plugins.springsecurity.userLookup.authorityJoinClassName' value, or create your own 'List<GrantedAuthority> tencentAuthService.getRoles(user)'")
				}
			}
		}
		if (!serviceMethods.contains('findUser')) {
			if (!domainClassName) {
				log.error("Don't have tencent user class configuration. Please configure 'grails.plugins.springsecurity.tencent.domain.classname' value")
			} else {
				Class<?> User = grailsApplication.getDomainClass(domainClassName)?.clazz
				if (!User) {
					log.error("Can't find tencent user class ($domainClassName). Please configure 'grails.plugins.springsecurity.tencent.domain.classname' value, or create your own 'Object tencentAuthService.findUser(String)'")
				}
			}
		}

		if (coreUserDetailsService != null) {
			if (!(coreUserDetailsService instanceof GormUserDetailsService && coreUserDetailsService.respondsTo('createUserDetails'))) {
				log.warn("UserDetailsService from spring-security-core don't have method 'createUserDetails()'")
				coreUserDetailsService = null
			}
		} else {
			log.warn("No UserDetailsService bean from spring-security-core")
		}

		TencentUserDomainClazz = grailsApplication.getDomainClass(domainClassName)?.clazz
		if (!TencentUserDomainClazz) {
			log.error("Can't find domain: $domainClassName")
		}
		AppUserDomainClazz = grailsApplication.getDomainClass(userDomainClassName)?.clazz
		if (!AppUserDomainClazz) {
			log.error("Can't find domain: $userDomainClassName")
		}
		if (TencentUserDomainClazz && AppUserDomainClazz) {
			if (TencentUserDomainClazz == AppUserDomainClazz) {
				domainsRelation = DomainsRelation.SameObject
			}
		}
		if (domainsRelation == null) {
			domainsRelation = DomainsRelation.JoinedUser
		}
	}
}
