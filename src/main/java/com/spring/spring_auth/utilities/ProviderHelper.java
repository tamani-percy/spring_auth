package com.spring.spring_auth.utilities;

import com.spring.spring_auth.models.EProvider;

public class ProviderHelper {

    public static EProvider getProvider(String oauthProvider) {
        if (oauthProvider.equalsIgnoreCase("google-oauth2")) {
            return EProvider.GOOGLE;
        } else if (oauthProvider.equalsIgnoreCase("facebook")) {
            return EProvider.FACEBOOK;
        } else if (oauthProvider.equalsIgnoreCase("github")) {
            return EProvider.GITHUB;
        } else return null;
    }
}
