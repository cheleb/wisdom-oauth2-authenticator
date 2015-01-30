package org.wisdom.oauth2.controller;

/**
 * Created by cheleb on 30/01/15.
 */
public interface UserDetailsProvider {

    UserDetails getUserDetails(String accessToken);

}
