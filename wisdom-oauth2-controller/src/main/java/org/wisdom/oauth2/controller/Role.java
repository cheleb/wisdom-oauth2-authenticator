package org.wisdom.oauth2.controller;

import org.wisdom.api.annotations.Interception;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Created by cheleb on 27/01/15.
 */
@Interception
@Target({ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
public @interface Role {
    String value();
}
