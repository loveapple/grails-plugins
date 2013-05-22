package cn.loveapple.grails.springsecurity.tencent

import org.springframework.security.core.GrantedAuthority

interface TencentAuthDao<F, A> {
	/**
	 * Tries to load app user for Tencent user
	 * @param uid UID of Tencent user
	 * @return existing user, or null if there is no user for specified uid
	 */
	F findUser(String uid)

	/**
	 * Called when logged in tencent user doesn't exists in current database
	 * @param token information about current authnetication
	 * @return just created user
	 */
	F create(TencentAuthToken token)

	/**
	 * Returns `principal` that will be stored into Security Context. It's good if it
	 * implements {@link org.springframework.security.core.userdetails.UserDetails UserDetails} or
	 * {@link java.security.Principal Principal}.
	 *
	 * Btw, it's ok to return same object here.
	 *
	 * @param user current app user (main spring security core domain instance)
	 * @return user to put into Security Context
	 */
	Object getPrincipal(A user)

	/**
	 * Return main (spring security user domain) for given tencent user. If it's same domain, just return
	 * passed argument.
	 *
	 * @param user instance of tencent domain
	 * @return instance of spring security domain
	 */
	A getAppUser(F user)

	/**
	 * Roles for current user
	 *
	 * @param user current user
	 * @return roles for user
	 */
	Collection<GrantedAuthority> getRoles(F user)

	/**
	 *
	 * @param user target user
	 * @return false when user have invalid token, or don't have token
	 */
	Boolean hasValidToken(F user)

	/**
	 * Setup new Tencent Access Token for specified user
	 *
	 * @param user target user
	 * @param token valid access token
	 */
	void updateToken(F user, TencentAuthToken token)

	/**
	 *
	 * @param user target user
	 * @return current access_token, or null if not exists
	 */
	String getAccessToken(F user)
}
