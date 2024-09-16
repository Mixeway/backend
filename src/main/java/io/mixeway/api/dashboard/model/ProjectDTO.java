package io.mixeway.api.dashboard.model;

import lombok.Data;

@Data
public class ProjectDTO {
    private Long id;
    private String ciid;
    private String name;
    private String description;
    private int risk;
    private int enableVulnManage;

    // Constructor
    public ProjectDTO(Long id, String ciid, String name, String description, int risk, int enableVulnManage) {
        this.id = id;
        this.ciid = ciid;
        this.name = name;
        this.description = description;
        this.risk = risk;
        this.enableVulnManage = enableVulnManage;
    }
}