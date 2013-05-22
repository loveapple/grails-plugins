security {

	tencent {

		appId = "Invalid"
		secret = 'Invalid'
		apiKey = 'Invalid'

		domain {
			classname = 'TencentUser'
			appUserConnectionPropertyName = "user"
		}

		useAjax = true
		autoCheck = true

		jsconf = "fbSecurity"

		//see http://wiki.open.qq.com/wiki/website/%E4%BD%BF%E7%94%A8Authorization_Code%E8%8E%B7%E5%8F%96Access_Token
		permissions = ["get_user_info"]

		taglib {
			language = "zh_CN"
			button {
				text = "Login with Tencent"
				defaultImg = "/images/connect.png"
			}
			initfb = true
		}

		autoCreate {
			enabled = true
			roles = ['ROLE_USER', 'ROLE_TENCENT']
		}

		filter {
			json {
				processUrl = "/j_spring_security_tencent_json"
				type = 'json' // or 'jsonp'
				methods = ['POST']
			}
			redirect { redirectFromUrl = "/j_spring_security_tencent_redirect" }
			processUrl = "/j_spring_security_tencent_check"
			type = 'redirect' //transparent, cookieDirect, redirect or json
			position = 700 //see SecurityFilterPosition
			forceLoginParameter = 'j_spring_tencent_force'
		}

		beans {
			//successHandler =
			//failureHandler =
			//redirectSuccessHandler =
			//redirectFailureHandler =
		}

	}
}
