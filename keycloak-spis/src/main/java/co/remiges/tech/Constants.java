package co.remiges.tech;

/**
 * Keycloak SPI Constants
 * @author bhavyag
 */
public class Constants {

	private Constants() {
	}
	
	/**
	 * Role to be referred to Client Level attributes for IP Validation
	 */
	public static final String ROLE_IP_VALIDATION="IPWhiteListRole";
	
	/**
	 * Attribute name for IP Whitelist. This attribute name will be searched for in Keycloak Configuration at User or Client level
	 */
	public static final String ATTRIB_IP_WHITELIST="ValidIpWhitelist";
	
	/**
	 * Attribute name for Valid ISO Geo Location. This attribute name will be searched for in Keycloak Configuration at User or Client level
	 */
	public static final String ATTRIB_IP_GEO_LOC="ValidISOGeoLocation";
	
	/**
	 * Attribute name for Mobile number for SMS OTP.  This attribute name will be searched for in Keycloak Configuration at User level
	 */
	public static final String ATTRIB_MOB_NUM="mobileNumber";
	/**
	 * Cookie name if 2FA is answered
	 */
	public static final String COOKIE_2FA_ANSWERED="COOKIE_2FA_ANSWERED";
	/**
	 * Cookie name if 2FA is answered
	 */
	public static final String ATTRIB_2FA_COOKIE="setCookieFor2FA";
	/**
	 * validate captcha rest api
	 */
	public static final String VALIDATE_CAPTCHA_API = "validateCaptchaAPI";
	/**
	 * invalid captcha msg
	 */
	public static final String INCORRECT_CAPTCHA_MSG = "incorrectCaptchaMsg";
	/**
	 * validate captcha api header key
	 */
	public static final String HEADER_KEY = "headerKey";
	/**
	 * validate user rest api
	 */
	public static final String VALIDATE_USER_API = "validateUserAPI";
	/**
	 * invalid user msg
	 */
	public static final String INCORRECT_USER_MSG = "incorrectUserMsg";
}
