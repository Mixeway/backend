package io.mixeway.domain.service.scanmanager.code;

import io.mixeway.db.entity.CodeProject;
import io.mixeway.db.entity.Project;
import io.mixeway.db.repository.CodeProjectRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * @author gsiewruk
 */
@Service
@RequiredArgsConstructor
public class FindCodeProjectService {
    private final CodeProjectRepository codeProjectRepository;


    public Optional<CodeProject> findCodeProject(Project project, String codeProjectName){
        return codeProjectRepository.findByProjectAndName(project,codeProjectName);
    }
    public List<CodeProject> findRunningCodeProjects(){
        return codeProjectRepository.findByRunning(true);
    }
    public List<CodeProject> findRunningCodeProjectsLimit5(){
        return codeProjectRepository.findTop5ByRunning(true);
    }
    public Optional<CodeProject> findById(long id){
        return codeProjectRepository.findById(id);
    }
    public Optional<CodeProject> findByRepoUrl(String repoUrl){
        return codeProjectRepository.findByRepoUrl(repoUrl);
    }

    @Transactional
    public List<CodeProject> findByProject(Project project) {
        return codeProjectRepository.findByProject(project);
    }

    public List<CodeProject> findByInQueue(boolean b) {
        return codeProjectRepository.findByInQueue(b);
    }

    public List<CodeProject> findByRequestId(String requestId) {
        return codeProjectRepository.findByRequestId(requestId);
    }

    public List<CodeProject> findByRunning(boolean b) {
        return codeProjectRepository.findByRunning(b);
    }

    public List<CodeProject> getCodeProjectsWithOSIntegrationEnabled() {
        return codeProjectRepository.getCodeProjectsWithOSIntegrationEnabled();
    }
    public List<CodeProject> findProjectWithoutOSIntegration(){
        return codeProjectRepository.getCodeProjectsForSynchro();
    }

    public List<CodeProject> getCodeProjectsInListOfProjects(List<Project> enabledVulnManageProjects) {
        return codeProjectRepository.findByProjectIn(enabledVulnManageProjects);
    }

    public List<CodeProject> findAll() {
        return codeProjectRepository.findAll();
    }

    public List<CodeProject> getProjectChilds(CodeProject codeProject) {
        return codeProjectRepository.findByParent(codeProject);
    }
}
