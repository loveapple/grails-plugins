package cn.loveapple.grails.springsecurity.tencent

import java.io.Serializable

class TencentAccessToken implements Serializable {
	String accessToken
	Date expireAt
  
	String toString() {
		StringBuilder buf = new StringBuilder()
		buf.append('Access token: ').append(accessToken)
		buf.append(', expires at ').append(expireAt)
		return buf.toString()
	}
}
