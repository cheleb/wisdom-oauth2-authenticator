package org.wisdom.oauth2;

import org.apache.felix.ipojo.annotations.Component;
import org.apache.felix.ipojo.annotations.Requires;
import org.apache.oltu.oauth2.common.OAuth;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wisdom.api.DefaultController;
import org.wisdom.api.cache.Cache;

/**
 * Created by cheleb on 26/01/15.
 */
@Component
public abstract class OAuth2Controller extends DefaultController {

    public static final String NAME = "OAuth2";

    private static final Logger LOGGER = LoggerFactory.getLogger(OAuth2Controller.class);

    private final Cache cache;

    public OAuth2Controller(Cache cache) {
        this.cache = cache;
    }


    private String retrieveToken() {
        String token = session(OAuth.OAUTH_ACCESS_TOKEN);
        if (token == null)
            token = request().getHeader(OAuth.OAUTH_ACCESS_TOKEN);
        if (token == null)
            token = request().parameter(OAuth.OAUTH_ACCESS_TOKEN);

        return token;
    }



    public String getUserName() {

        String accessToken = retrieveToken();

        if (accessToken == null)
            return null;

        String email = (String) cache.get(accessToken);
        if (email != null) {
            LOGGER.info(email + " login");
            return email;
        }


        return null;
    }


}
