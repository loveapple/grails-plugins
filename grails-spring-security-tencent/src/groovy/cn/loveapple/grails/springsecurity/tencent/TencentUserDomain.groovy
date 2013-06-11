package cn.loveapple.grails.springsecurity.tencent

interface TencentUserDomain {
	String getAccessToken()
	void setAccessToken(String accessToken)

	long getUid()
	void setUid(long uid)
}
