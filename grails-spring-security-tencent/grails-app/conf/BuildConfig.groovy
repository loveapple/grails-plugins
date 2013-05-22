grails.project.class.dir = "target/classes"
grails.project.test.class.dir = "target/test-classes"
grails.project.test.reports.dir = "target/test-reports"

String springSecurityVer = "3.0.7.RELEASE"

grails.release.scm.enabled=false
grails.project.repos.default = "grailsCentral"

grails.project.dependency.resolution = {
	inherits("global") {
	}
	log "warn" // log level of Ivy resolver, either 'error', 'warn', 'info', 'debug' or 'verbose'
	legacyResolve false // whether to do a secondary resolve on plugin installation, not advised and here for backwards compatibility
	repositories {
		grailsPlugins()
		grailsHome()
		grailsCentral()
		mavenCentral()

		ebr() // SpringSource  http://www.springsource.com/repository
	}
	dependencies {
		runtime('org.springframework.security:spring-security-core:'+springSecurityVer) {
			excludes 'com.springsource.javax.servlet',
					'com.springsource.org.aopalliance',
					'com.springsource.org.apache.commons.logging',
					'com.springsource.org.apache.xmlcommons',
					'org.springframework.aop',
					'org.springframework.beans',
					'org.springframework.context',
					'org.springframework.core',
					'org.springframework.web'

		}
		runtime('org.springframework.security:spring-security-web:'+springSecurityVer) {
			excludes 'com.springsource.javax.servlet',
					'com.springsource.org.aopalliance',
					'com.springsource.org.apache.commons.logging',
					'com.springsource.org.apache.xmlcommons',
					'org.springframework.aop',
					'org.springframework.beans',
					'org.springframework.context',
					'org.springframework.core',
					'org.springframework.web'
		}
	}

	plugins {
		provided ':webxml:1.4.1'
		compile ':spring-security-core:1.2.7.2'
		test ":spock:0.7"
		build(':release:2.2.0', ':rest-client-builder:1.0.3') { export = false }
	}
}
