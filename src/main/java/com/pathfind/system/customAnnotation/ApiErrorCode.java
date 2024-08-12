package com.pathfind.system.customAnnotation;

import com.pathfind.system.exception.BasicErrorCode;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target({ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
public @interface ApiErrorCode {
    Class<? extends BasicErrorCode> value();
}
