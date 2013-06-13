package cn.loveapple.grails.springsecurity.tencent

class TencentAccessToken implements Serializable {
	String accessToken
	Date expireAt
  
	String toString() {
		"Access token: $accessToken, expires at $expireAt"
	}
}
