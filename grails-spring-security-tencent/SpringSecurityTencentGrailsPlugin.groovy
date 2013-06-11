import grails.util.Environment

import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.codehaus.groovy.grails.plugins.springsecurity.SpringSecurityUtils

import cn.loveapple.grails.springsecurity.tencent.DefaultTencentAuthDao
import cn.loveapple.grails.springsecurity.tencent.DomainsRelation
import cn.loveapple.grails.springsecurity.tencent.JsonAuthenticationHandler
import cn.loveapple.grails.springsecurity.tencent.TencentAuthCookieDirectFilter
import cn.loveapple.grails.springsecurity.tencent.TencentAuthCookieLogoutHandler
import cn.loveapple.grails.springsecurity.tencent.TencentAuthCookieTransparentFilter
import cn.loveapple.grails.springsecurity.tencent.TencentAuthJsonFilter
import cn.loveapple.grails.springsecurity.tencent.TencentAuthProvider
import cn.loveapple.grails.springsecurity.tencent.TencentAuthRedirectFilter
import cn.loveapple.grails.springsecurity.tencent.TencentAuthUtils

class SpringSecurityTencentGrailsPlugin {

	def version = "0.0.28"
	def grailsVersion = "2.0 > *"
	def title = "Tencent Authentication for Spring Security"
	def author = "Chunli Hao"
	String authorEmail = 'hao0323+grails-plugin-tencent@gmail.com'
	def description = 'Tencent Authentication for Spring Security Core plugin. This plugin is based on "Tencent Authentication for Spring Security"'
	def documentation = "http://grails.org/plugin/spring-security-tencent"

	def observe = ["springSecurityCore"]

	def license = 'APACHE'
	def organization = [ name: "loveapple", url: "http://www.loveapple.cn/" ]
	def issueManagement = [ system: "GITHUB", url: "https://github.com/loveapple/grails-plugins/issues" ]
	def scm = [ url: "https://github.com/loveapple/grails-plugins" ]

	private String _tencentDaoName

	private static Logger log = LoggerFactory.getLogger(this)

	def doWithSpring = {
		if (Environment.current == Environment.TEST) {
			println "Test mode. Skipping initial plugin initialization"
			return
		}

		def conf = SpringSecurityUtils.securityConfig
		if (!conf) {
			println 'ERROR: There is no Spring Security configuration'
			println 'ERROR: Stop configuring Spring Security Tencent'
			return
		}

		println 'Configuring Spring Security Tencent ...'
		SpringSecurityUtils.loadSecondaryConfig 'DefaultTencentSecurityConfig'
		// have to get again after overlaying DefaultTencentecurityConfig
		conf = SpringSecurityUtils.securityConfig

		_tencentDaoName = conf?.tencent?.bean?.dao ?: null
		if (_tencentDaoName == null) {
			_tencentDaoName = 'tencentAuthDao'
			String _domainsRelation = getConfigValue(conf, 'tencent.domain.relation')
			String _appUserConnectionPropertyName = getConfigValue(conf, 'tencent.domain.appUserConnectionPropertyName', 'tencent.domain.connectionPropertyName')
			List<String> _roles = getAsStringList(conf.tencent.autoCreate.roles, 'grails.plugins.springsecurity.tencent.autoCreate.roles')
			tencentAuthDao(DefaultTencentAuthDao) {
				domainClassName = conf.tencent.domain.classname
				appUserConnectionPropertyName = _appUserConnectionPropertyName
				userDomainClassName = conf.userLookup.userDomainClassName
				rolesPropertyName = conf.userLookup.authoritiesPropertyName
				coreUserDetailsService = ref('userDetailsService')
				if (_domainsRelation) {
					domainsRelation = DomainsRelation.getFrom(_domainsRelation)
				}
				defaultRoleNames = _roles
			}
		} else {
			log.info("Using provided Tencent Auth DAO bean: $_tencentDaoName")
		}

		List<String> _filterTypes = parseFilterTypes(conf)
		List<String> _requiredPermissions = getAsStringList(conf.tencent.permissions, 'Required Permissions', 'tencent.permissions')

		tencentAuthUtils(TencentAuthUtils) {
			apiKey = conf.tencent.apiKey
			secret = conf.tencent.secret
			applicationId = conf.tencent.appId
			filterTypes = _filterTypes
			requiredPermissions = _requiredPermissions
		}

		SpringSecurityUtils.registerProvider 'tencentAuthProvider'
		boolean _createNew = getConfigValue(conf, 'tencent.autoCreate.enabled') ? conf.tencent.autoCreate.enabled as Boolean : false
		tencentAuthProvider(TencentAuthProvider) {
			tencentAuthDao = ref(_tencentDaoName)
			tencentAuthUtils = ref('tencentAuthUtils')
			createNew = _createNew
		}

		addFilters(conf, delegate, _filterTypes)
		println '... finished configuring Spring Security Tencent'
	}

	private List<String> parseFilterTypes(conf) {
		def typesRaw = conf.tencent.filter.types
		List<String> types = null
		if (!typesRaw) {
			log.warn("Value for 'grails.plugins.springsecurity.tencent.filter.types' is empty")
			typesRaw = conf.tencent.filter.type
		}

		String defaultType = 'transparent'
		List validTypes = [
			'transparent',
			'cookieDirect',
			'redirect',
			'json'
		]

		if (!typesRaw) {
			log.error("Invalid Tencent Authentication filters configuration: '$typesRaw'. Should be used on of: $validTypes. Current value will be ignored, and type '$defaultType' will be used instead.")
			types = [defaultType]
		} else if (typesRaw instanceof Collection) {
			types = typesRaw.collect { it.toString() }.findAll { it in validTypes }
		} else if (typesRaw instanceof String) {
			types = typesRaw.split(',').collect { it.trim() }.findAll { it in validTypes }
		} else {
			log.error("Invalid Tencent Authentication filters configuration, invalid value type: '${typesRaw.getClass()}'. Filter typer should be defined as a Collection or String (comma separated, if you need few filters). Type '$defaultType' will be used instead.")
			types = [defaultType]
		}

		if (!types || types.empty) {
			log.error("Tencent Authentication filter is not configured. Should be used one of: $validTypes. So '$defaultType' will be used by default.")
			log.error("To configure Tencent Authentication filters you should add to Config.groovy:")
			log.error("grails.plugins.springsecurity.tencent.filter.types='transparent'")
			log.error("or")
			log.error("grails.plugins.springsecurity.tencent.filter.types='redirect,transparent,cookieDirect'")

			types = [defaultType]
		}
		return types
	}

	private void addFilters(conf, delegate, types) {
		int basePosition = conf.tencent.filter.position

		addFilter.delegate = delegate
		types.eachWithIndex { name, idx ->
			addFilter(conf, name, basePosition + 1 + idx)
		}
	}

	private addFilter = { conf, String name, int position ->
		if (name == 'transparent') {
			String _successHandler = getConfigValue(conf, 'tencent.filter.transparent.successHandler')
			String _failureHandler = getConfigValue(conf, 'tencent.filter.transparent.failureHandler')
			SpringSecurityUtils.registerFilter 'tencentAuthCookieTransparentFilter', position
			tencentAuthCookieTransparentFilter(TencentAuthCookieTransparentFilter) {
				authenticationManager = ref('authenticationManager')
				tencentAuthUtils = ref('tencentAuthUtils')
				logoutUrl = conf.logout.filterProcessesUrl
				forceLoginParameter = conf.tencent.filter.forceLoginParameter
				if (_successHandler) {
					authenticationSuccessHandler = ref(_successHandler)
				}
				if (_failureHandler) {
					authenticationFailureHandler = ref(_failureHandler)
				}
			}
			tencentAuthCookieLogout(TencentAuthCookieLogoutHandler) {
				tencentAuthUtils = ref('tencentAuthUtils')
				tencentAuthDao = ref(_tencentDaoName)
			}
			SpringSecurityUtils.registerLogoutHandler('tencentAuthCookieLogout')
		} else if (name == 'cookieDirect') {
			String _successHandler = getConfigValue(conf, 'tencent.filter.cookieDirect.successHandler')
			String _failureHandler = getConfigValue(conf, 'tencent.filter.cookieDirect.failureHandler')
			String url =  getConfigValue(conf, 'tencent.filter.cookieDirect.processUrl', 'tencent.filter.processUrl')
			SpringSecurityUtils.registerFilter 'tencentAuthCookieDirectFilter', position
			tencentAuthCookieDirectFilter(TencentAuthCookieDirectFilter, url) {
				authenticationManager = ref('authenticationManager')
				tencentAuthUtils = ref('tencentAuthUtils')
				if (_successHandler) {
					authenticationSuccessHandler = ref(_successHandler)
				}
				if (_failureHandler) {
					authenticationFailureHandler = ref(_failureHandler)
				}
			}
		} else if (name == 'redirect') {
			SpringSecurityUtils.registerFilter 'tencentAuthRedirectFilter', position
			String successHandler = getConfigValue(conf, 'tencent.filter.redirect.successHandler')
			String failureHandler = getConfigValue(conf, 'tencent.filter.redirect.failureHandler')
			String _url =  getConfigValue(conf, 'tencent.filter.redirect.processUrl', 'tencent.filter.processUrl')
			String _redirectFromUrl =  getConfigValue(conf, 'tencent.filter.redirect.redirectFromUrl', 'tencent.filter.redirectFromUrl')
			tencentAuthRedirectFilter(TencentAuthRedirectFilter, _url) {
				authenticationManager = ref('authenticationManager')
				tencentAuthUtils = ref('tencentAuthUtils')
				redirectFromUrl = _redirectFromUrl
				linkGenerator = ref('grailsLinkGenerator')
				if (successHandler) {
					authenticationSuccessHandler = ref(successHandler)
				}
				if (failureHandler) {
					authenticationFailureHandler = ref(failureHandler)
				}
			}
		} else if (name == 'json') {
			SpringSecurityUtils.registerFilter 'tencentAuthJsonFilter', position
			String _url = conf.tencent.filter.json.processUrl
			boolean _jsonp = '_jsonp'.equalsIgnoreCase(conf.tencent.filter.json.type)
			tencentJsonAuthenticationHandler(JsonAuthenticationHandler) { useJsonp = _jsonp }
			List<String> _methods = getAsStringList(conf.tencent.filter.json.methods, '**.tencent.filter.json.type')
			_methods = _methods ? _methods*.toUpperCase() : ['POST']
			if (_jsonp) {
				_methods = ['GET']
			}
			tencentAuthJsonFilter(TencentAuthJsonFilter, _url) {
				methods = _methods
				authenticationManager = ref('authenticationManager')
				tencentAuthUtils = ref('tencentAuthUtils')
				authenticationSuccessHandler = ref('tencentJsonAuthenticationHandler')
				authenticationFailureHandler = ref('tencentJsonAuthenticationHandler')
			}
		} else {
			log.error("Invalid filter type: $name")
		}
	}

	def onConfigChange = { event ->
		SpringSecurityUtils.resetSecurityConfig()
	}
	
	private Object getConfigValue(conf, String ... values) {
		conf = conf.flatten()
		String key = values.find {
			if (!conf.containsKey(it)) {
				return false
			}
			def val = conf.get(it)
			if (val == null || val.toString() == '{}') {
				return false
			}
			return true
		}
		if (key) {
			return conf.get(key)
		}
		return null
	}

	private List<String> getAsStringList(conf, String paramHumanName, String paramName = '???') {
		def raw = conf

		if (raw == null) {
			log.error("Invalid $paramHumanName filters configuration: '$raw'")
		} else if (raw instanceof Collection) {
			return raw.collect { it.toString() }
		} else if (raw instanceof String) {
			return raw.split(',').collect { it.trim() }
		} else {
			log.error("Invalid $paramHumanName filters configuration, invalid value type: '${raw.getClass()}'. Value should be defined as a Collection or String (comma separated)")
		}
		return null
	}
}
