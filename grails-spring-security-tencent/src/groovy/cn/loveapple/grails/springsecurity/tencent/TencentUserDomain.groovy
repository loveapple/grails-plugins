package cn.loveapple.grails.springsecurity.tencent

public interface TencentUserDomain {
	String getAccessToken();
	void setAccessToken(String accessToken);

	long getUid();
	void setUid(long uid)
}
