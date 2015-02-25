package org.wisdom.oauth2;

import org.apache.felix.ipojo.annotations.*;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.common.OAuth;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.joda.time.Duration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wisdom.api.cache.Cache;
import org.wisdom.api.configuration.ApplicationConfiguration;
import org.wisdom.api.http.Context;
import org.wisdom.api.http.HttpMethod;
import org.wisdom.api.http.Result;
import org.wisdom.api.security.Authenticator;
import org.wisdom.oauth2.controller.UserDetails;
import org.wisdom.oauth2.controller.UserDetailsProvider;

@Component
@Provides
@Instantiate
public class OAuth2WisdomAuthenticator implements Authenticator {

    public static final String NAME = "OAuth2";

    @Requires
    ApplicationConfiguration configuration;

    @Requires
    private Cache cache;

    @Requires
    private UserDetailsProvider userDetailsProvider;

    public static final Logger LOGGER = LoggerFactory.getLogger(OAuth2WisdomAuthenticator.class);

    private String loginPage;
    private String loginCallback;
    private String clientId;
    private String authenticated;

    @Override
    public String getName() {
        return NAME;
    }

    @Validate
    public void init() {
        this.loginPage = configuration.get("oauth2.login");
        this.loginCallback = configuration.get("oauth2.callback");
        this.clientId = configuration.get("oauth2.clientId");
        this.authenticated = configuration.get("oauth2.authenticated");
    }

    @Override
    public String getUserName(Context context) {

        String accessToken = retrieveToken(context);

        if (accessToken == null)
            return null;

        String email = (String) cache.get(accessToken);
        if (email != null) {
            LOGGER.info(email + " login");
            context.request().setUsername(email);
            return email;
        }
        UserDetails userDetails = userDetailsProvider.getUserDetails(accessToken);
        if (userDetails == null){
            return null;
        }
        cache.set(accessToken,userDetails.getEmail(), Duration.standardHours(12));

        return userDetails.getEmail();
    }



    private String retrieveToken(Context context) {

        String token = context.session().get(OAuth.OAUTH_ACCESS_TOKEN);
        if (token == null)
            token = context.header(OAuth.OAUTH_ACCESS_TOKEN);
        if (token == null)
            token = context.parameter(OAuth.OAUTH_ACCESS_TOKEN);

        return token;
    }

    @Override
    public Result onUnauthorized(Context context) {

        String state;
        if (context.route().getHttpMethod() == HttpMethod.GET) {
            state = context.request().path();
        } else {
            state = authenticated;
        }

        try {
            OAuthClientRequest request = OAuthClientRequest
                    .authorizationLocation(loginPage)
                    .setParameter(OAuth.OAUTH_EXPIRES_IN, "3600")
                    .setClientId(clientId)
                    .setRedirectURI(loginCallback).setResponseType("code")
                    .setScope("openid")
                    .setState(state)
                    .buildQueryMessage();
            return new Result().redirect(request.getLocationUri());
        } catch (OAuthSystemException e) {
            new Result().status(500);
        }

        return new Result().redirect("/");
    }
}
