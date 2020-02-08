package io.mixeway.plugins.codescan.fortify.model;

import com.fasterxml.jackson.annotation.JsonProperty;

public class FortifyCreateProjectResponse {
    @JsonProperty("data")
    FortifyProjectVersions FortifyProjectVersions;

    public FortifyProjectVersions getFortifyProjectVersions() {
        return FortifyProjectVersions;
    }

    public void setFortifyProjectVersions(FortifyProjectVersions fortifyProjectVersions) {
        FortifyProjectVersions = fortifyProjectVersions;
    }
}
