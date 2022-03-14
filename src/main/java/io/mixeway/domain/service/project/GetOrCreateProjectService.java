package io.mixeway.domain.service.project;

import io.mixeway.db.entity.Project;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.security.Principal;

@Service
public class GetOrCreateProjectService {

    private final FindProjectService findProjectService;
    private final CreateProjectService createProjectService;

    @Autowired
    public GetOrCreateProjectService(FindProjectService findProjectService, CreateProjectService createProjectService) {
        this.findProjectService = findProjectService;
        this.createProjectService = createProjectService;
    }

    public Project getProjectId(String ciid, String projectName, Principal principal) {
        return findProjectService
                .findProjectByCiid(ciid)
                .orElse(createProjectService.createAndReturnProject(projectName, ciid, principal));
    }
}
