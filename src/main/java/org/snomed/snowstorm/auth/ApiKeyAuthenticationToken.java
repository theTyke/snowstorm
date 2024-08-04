package org.snomed.snowstorm.auth;

import org.snomed.snowstorm.auth.entity.ApiKey;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.UUID;

public class ApiKeyAuthenticationToken extends AbstractAuthenticationToken {

    private final UUID principal;

    /**
     * Creates a token with the supplied array of authorities.
     *
     * @param principal the application name
     * @param authorities the collection of <tt>GrantedAuthority</tt>s for the principal
     *                    represented by this authentication object.
     * @param details the ApiKey object
     */
    public ApiKeyAuthenticationToken(final UUID principal, final Collection<? extends GrantedAuthority> authorities, final ApiKey details) {
        super(authorities);
        this.principal = principal;
        this.setDetails(details);
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    /**
     * @return the application name
     */
    @Override
    public UUID getPrincipal() {
        return principal;
    }

    public void setDetails(final ApiKey details) {
        super.setDetails(details);
    }

    @Override
    public ApiKey getDetails() {
        return (ApiKey) super.getDetails();
    }

}