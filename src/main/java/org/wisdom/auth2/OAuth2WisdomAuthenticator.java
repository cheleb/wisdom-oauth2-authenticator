package org.wisdom.auth2;

import org.apache.felix.ipojo.annotations.Component;
import org.apache.felix.ipojo.annotations.Instantiate;
import org.apache.felix.ipojo.annotations.Provides;
import org.apache.felix.ipojo.annotations.Requires;
import org.apache.oltu.oauth2.client.request.OAuthBearerClientRequest;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.validator.TokenValidator;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wisdom.api.cache.Cache;
import org.wisdom.api.configuration.ApplicationConfiguration;
import org.wisdom.api.http.Context;
import org.wisdom.api.http.Result;
import org.wisdom.api.security.Authenticator;

@Component
@Provides
@Instantiate
public class OAuth2WisdomAuthenticator implements Authenticator {


	@Requires
	ApplicationConfiguration configuration;

	@Requires
	private Cache cache;

	public static final Logger LOGGER = LoggerFactory.getLogger(OAuth2WisdomAuthenticator.class);

	@Override
	public String getName() {
		return "OAuth2";
	}

	@Override
	public String getUserName(Context context) {

		String token = retrieveToken(context);

		if(token==null)
			return null;

		//TokenValidator tokenValidator = new TokenValidator();
		//tokenValidator.

		try {
			OAuthClientRequest bearerClientRequest =
                    new OAuthBearerClientRequest("https://graph.facebook.com/me")
                            .setAccessToken(token).buildQueryMessage();
		} catch (OAuthSystemException e) {
			LOGGER.warn("Boom", e);
			return null;
		}


		return context.cookieValue("email");
	}

	private String retrieveToken(Context context) {
		String token = context.header("token");
		if(token!=null){
			token = context.parameter("token");
		}
		return token;
	}

	@Override
	public Result onUnauthorized(Context context) {
		return new Result().redirect("/");
	}
}
