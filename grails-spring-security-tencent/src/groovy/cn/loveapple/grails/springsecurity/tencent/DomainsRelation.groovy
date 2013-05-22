package cn.loveapple.grails.springsecurity.tencent

public enum DomainsRelation {
	SameObject,
	JoinedUser

	static DomainsRelation getFrom(Object x) {
		if (x == null) {
			return JoinedUser
		}
		if (x instanceof DomainsRelation) {
			return x
		}
		x = x.toString()
		DomainsRelation found = DomainsRelation.values().find {
			it.name().equalsIgnoreCase(x)
		}
		return found ?: JoinedUser
	}
}
