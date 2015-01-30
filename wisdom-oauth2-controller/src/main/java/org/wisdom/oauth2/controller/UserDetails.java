package org.wisdom.oauth2.controller;

/**
 * Created by cheleb on 30/01/15.
 */
public class UserDetails {

    private final String email;

    public UserDetails(String email) {
        this.email = email;
    }

    public String getEmail() {
        return email;
    }

}
