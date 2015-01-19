package org.wisdom.auth2;

import org.apache.felix.ipojo.annotations.*;
import org.apache.oltu.oauth2.client.OAuthClient;
import org.apache.oltu.oauth2.client.URLConnectionClient;
import org.apache.oltu.oauth2.client.request.OAuthBearerClientRequest;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthResourceResponse;
import org.apache.oltu.oauth2.common.OAuth;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.utils.JSONUtils;
import org.joda.time.Duration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wisdom.api.cache.Cache;
import org.wisdom.api.configuration.ApplicationConfiguration;
import org.wisdom.api.http.Context;
import org.wisdom.api.http.Result;
import org.wisdom.api.security.Authenticator;

import java.util.Map;

@Component
@Provides
@Instantiate
public class OAuth2WisdomAuthenticator implements Authenticator {

	@Requires
	ApplicationConfiguration configuration;

	@Requires
	private Cache cache;

	public static final Logger LOGGER = LoggerFactory.getLogger(OAuth2WisdomAuthenticator.class);

	private String userInfoURL;
	private String loginPage;
	private String loginCallback;
	private String clientId;

	@Override
	public String getName() {
		return "OAuth2";
	}

	@Validate
	public void init() {
		this.userInfoURL = configuration.get("oauth2.userinfo");
		this.loginPage = configuration.get("oauth2.login");
		this.loginCallback = configuration.get("oauth2.callback");
		this.clientId = configuration.get("oauth2.clientId");
	}

	@Override
	public String getUserName(Context context) {

		String accessToken = retrieveToken(context);

		if(accessToken==null)
			return null;

		String email = (String) cache.get(accessToken);
        if(email != null)
			return email;
		try {
			email = getEmail(accessToken);
			if(email==null){
				LOGGER.warn("No email ?");
				return null;
			}
			Long expireIn = Long.parseLong(context.parameter(OAuth.OAUTH_EXPIRES_IN));
			cache.set(accessToken, email, Duration.standardSeconds(expireIn));
			return email;
		} catch (OAuthSystemException | OAuthProblemException e) {
			LOGGER.warn(e.getMessage(), e);
		}

		return null;
	}

	private String getEmail(String accessToken) throws OAuthSystemException, org.apache.oltu.oauth2.common.exception.OAuthProblemException {
		OAuthClient oAuthClient = new OAuthClient(new URLConnectionClient());
		try {
			OAuthBearerClientRequest authBearerClientRequest = new OAuthBearerClientRequest(userInfoURL);
			OAuthClientRequest loginRequest = authBearerClientRequest.setAccessToken(accessToken).buildHeaderMessage();

			OAuthResourceResponse resource = oAuthClient.resource(loginRequest, OAuth.HttpMethod.GET, OAuthResourceResponse.class);

			Map<String, Object> parseJSON = JSONUtils.parseJSON(resource.getBody());
			return parseJSON.get("email").toString();
		}finally {
			oAuthClient.shutdown();
		}

	}

	private String retrieveToken(Context context) {
		String token = context.header(OAuth.OAUTH_ACCESS_TOKEN);
		if(token==null){
			token = context.parameter(OAuth.OAUTH_ACCESS_TOKEN);
		}
		return token;
	}

	@Override
	public Result onUnauthorized(Context context) {

		try {
			OAuthClientRequest request = OAuthClientRequest
                    .authorizationLocation(loginPage)
					.setParameter(OAuth.OAUTH_EXPIRES_IN, "3600")
                    .setClientId(clientId)
                    .setRedirectURI(loginCallback).setResponseType("code")
                    .setScope("openid")
                    .buildQueryMessage();
			return new Result().redirect(request.getLocationUri());
		} catch (OAuthSystemException e) {
			new Result().status(500);
		}

		return new Result().redirect("/");
	}
}
