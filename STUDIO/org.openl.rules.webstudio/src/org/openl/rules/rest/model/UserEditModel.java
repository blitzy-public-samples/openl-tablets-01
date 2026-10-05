package org.openl.rules.rest.model;

import java.util.Set;
import jakarta.validation.constraints.NotBlank;

import io.swagger.v3.oas.annotations.Parameter;
import lombok.Getter;

import org.openl.rules.rest.validation.LocalPasswordConstraint;

public class UserEditModel extends UserInfoModel {

    @Getter
    // V7: local password policy replaces the 25-character maximum.
    @LocalPasswordConstraint
    @Parameter(description = "Password", example = "qwerty")
    private String password;

    @Getter
    @Parameter(description = "Assigned Groups")
    private Set<String> groups;

    @Override
    @NotBlank
    public String getEmail() {
        return super.getEmail();
    }

    @Override
    public UserEditModel setEmail(String email) {
        return (UserEditModel) super.setEmail(email);
    }

    @Override
    @NotBlank
    public String getDisplayName() {
        return super.getDisplayName();
    }

    @Override
    public UserEditModel setDisplayName(String displayName) {
        return (UserEditModel) super.setDisplayName(displayName);
    }

    @Override
    public UserEditModel setFirstName(String firstName) {
        return (UserEditModel) super.setFirstName(firstName);
    }

    @Override
    public UserEditModel setLastName(String lastName) {
        return (UserEditModel) super.setLastName(lastName);
    }

    public UserEditModel setPassword(String password) {
        this.password = password;
        return this;
    }

    public UserEditModel setGroups(Set<String> groups) {
        this.groups = groups;
        return this;
    }
}
