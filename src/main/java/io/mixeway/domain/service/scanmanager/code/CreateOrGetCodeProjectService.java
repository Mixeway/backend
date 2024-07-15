package io.mixeway.domain.service.scanmanager.code;

import io.mixeway.api.project.model.CodeProjectPutModel;
import io.mixeway.config.Constants;
import io.mixeway.db.entity.CodeProject;
import io.mixeway.db.entity.CodeProjectBranch;
import io.mixeway.db.entity.Project;
import io.mixeway.db.repository.CodeProjectBranchRepository;
import io.mixeway.db.repository.CodeProjectRepository;
import io.mixeway.domain.service.assethistory.CreateAssetHistoryService;
import io.mixeway.domain.service.project.GetOrCreateProjectService;
import io.mixeway.scanmanager.model.CodeScanRequestModel;
import io.mixeway.utils.CodeGroupPutModel;
import io.mixeway.utils.VaultHelper;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.apache.commons.lang3.StringUtils;
import org.checkerframework.checker.nullness.Opt;
import org.springframework.security.core.parameters.P;
import org.springframework.stereotype.Service;

import java.net.MalformedURLException;
import java.net.URL;
import java.security.Principal;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * @author gsiewruk
 */
@Service
@Log4j2
@RequiredArgsConstructor
public class CreateOrGetCodeProjectService {
    private final CodeProjectRepository codeProjectRepository;
    private final VaultHelper vaultHelper;
    private final GetOrCreateProjectService getOrCreateProjectService;
    private final GetOrCreateCodeProjectBranchService getOrCreateCodeProjectBranchService;
    private final CreateAssetHistoryService createAssetHistoryService;


    public CodeProject getOrCreateCodeProject(Project project, String projectName, String codeDefaultBranch) {
        Optional<CodeProject> codeProject = codeProjectRepository.findByProjectAndName(project, projectName);
        codeProject.ifPresent(value -> getOrCreateCodeProjectBranchService.getOrCreateCodeProjectBranch(value, codeDefaultBranch));
        return codeProject.orElseGet(() -> createCodeProject(project, projectName, codeDefaultBranch));
    }

    public CodeProject createCodeProject(Project project, String projectName, String codeDefaultBranch) {
        CodeProject codeProject = new CodeProject(project, projectName, (codeDefaultBranch == null || codeDefaultBranch.isEmpty()) ? "master" : codeDefaultBranch, null,null,null,null);
        codeProject = codeProjectRepository.saveAndFlush(codeProject);
        getOrCreateCodeProjectBranchService.getOrCreateCodeProjectBranch(codeProject, codeProject.getBranch());
        return codeProject;
    }

    public CodeProject createCodeProject(CodeScanRequestModel codeScanRequest, Project project) {
        String branch = codeScanRequest.getBranch();
        CodeProject codeProject = new CodeProject(project, codeScanRequest.getCodeProjectName(), (branch == null || branch.isEmpty()) ? "master" : branch, null,codeScanRequest.getRepoUrl(), codeScanRequest.getRepoUsername(), codeScanRequest.getRepoPassword());

        codeProject.setTechnique(codeScanRequest.getTech());

        codeProject = codeProjectRepository.saveAndFlush(codeProject);
        getOrCreateCodeProjectBranchService.getOrCreateCodeProjectBranch(codeProject, codeProject.getBranch());
        return codeProject;
    }

    public CodeProject createCodeProject(String repoUrl, String repoName, String branch, Principal principal, Project project) {
        CodeProject codeProject = new CodeProject(project, repoName, (branch == null || branch.isEmpty()) ? "master" : branch, null,repoUrl,null,null);

        codeProject = codeProjectRepository.saveAndFlush(codeProject);
        createAssetHistoryService.create(codeProject,0,0,0,0,0,0,0,0,0,0);
        getOrCreateCodeProjectBranchService.getOrCreateCodeProjectBranch(codeProject, codeProject.getBranch());
        return codeProject;
    }
    public CodeProject createChildCodeProject(String repoUrl, String repoName, String branch, Principal principal, Project project, CodeProject parent, String path) {
        CodeProject codeProject = new CodeProject(project, repoName, (branch == null || branch.isEmpty()) ? "master" : branch, null,repoUrl,null,null);
        codeProject.setPath(path);
        codeProject.setParent(parent);

        codeProject = codeProjectRepository.saveAndFlush(codeProject);
        getOrCreateCodeProjectBranchService.getOrCreateCodeProjectBranch(codeProject, codeProject.getBranch());
        return codeProject;
    }

    public CodeProject createOrGetCodeProject(String repoUrl, String branch, String codeProjectName, Principal principal) throws MalformedURLException {
        repoUrl = repoUrl.replaceAll("(https://)(.*:.*@)(.*)","$1$3").replace(".git","");
        URL repo = new URL(repoUrl.split("\\.git")[0]);
        String[] repoUrlParts = repo.getPath().split("/");
        String name = repoUrlParts[repoUrlParts.length-1];

        List<CodeProject> codeProjectList = codeProjectRepository.findByRepoUrlOrRepoUrlAndName(repoUrl, repoUrl+".git", codeProjectName);

        Optional<CodeProject> codeProject = codeProjectList.stream().filter(cp -> cp.getParent() == null).findFirst();
        if (codeProject.isPresent()){
            getOrCreateCodeProjectBranchService.getOrCreateCodeProjectBranch(codeProject.get(), branch);
            return codeProject.get();
        } else {
            Project project = getOrCreateProjectService.getProjectByName(name, principal);
            CodeProject codeProject1 = new CodeProject(project,
                    name,
                    (branch == null || branch.isEmpty()) ? "master" : branch,
                    null,
                    repoUrl,
                    null,
                    null);

            codeProject1 = codeProjectRepository.saveAndFlush(codeProject1);
            getOrCreateCodeProjectBranchService.getOrCreateCodeProjectBranch(codeProject1, codeProject1.getBranch());

            return codeProject1;
        }
    }
    public CodeProject createOrGetCodeProject(String repoUrl, String branch, Principal principal, Project project) throws MalformedURLException {
        Optional<CodeProject> codeProject = codeProjectRepository.findByProjectAndRepoUrl(project, repoUrl);
        if (codeProject.isPresent()){
            getOrCreateCodeProjectBranchService.getOrCreateCodeProjectBranch(codeProject.get(), branch);
            return codeProject.get();
        } else {
            URL repo = new URL(repoUrl.split("\\.git")[0]);
            String projectName, codeProjectName = null;
            String[] repoUrlParts = repo.getPath().split("/");
            String name = repoUrlParts[repoUrlParts.length-1];
            CodeProject codeProject1 = new CodeProject(project,
                    name,
                    (branch == null || branch.isEmpty()) ? "master" : branch,
                    null,
                    repoUrl,
                    null,
                    null);
            codeProject1 = codeProjectRepository.saveAndFlush(codeProject1);
            getOrCreateCodeProjectBranchService.getOrCreateCodeProjectBranch(codeProject1, codeProject1.getBranch());
            return codeProject1;
        }
    }

    public void createCodeProject(Project project, CodeGroupPutModel codeGroupPutModel) {
        Optional<CodeProject> codeProjectOptional = codeProjectRepository.findByProjectAndName(project, codeGroupPutModel.getCodeGroupName());
        if (!codeProjectOptional.isPresent()){
            CodeProject codeProject = new CodeProject();
            codeProject.setName(codeGroupPutModel.getCodeGroupName());
            codeProject.setRepoUrl(setRepoUrl(codeGroupPutModel));
            codeProject.setRepoUsername(codeGroupPutModel.getGitusername());
            codeProject.setTechnique(codeGroupPutModel.getTech());
            codeProject.setVersionIdAll(codeGroupPutModel.getVersionIdAll());
            codeProject.setVersionIdsingle(codeGroupPutModel.getVersionIdSingle());
            codeProject.setProject(project);
            codeProject.setAppClient(codeGroupPutModel.getAppClient());
            String branch = codeGroupPutModel.getBranch();
            //codeProject.setBranch((branch == null || branch.isEmpty()) ? "master" : branch);

            String uuidToken = UUID.randomUUID().toString();
            if (StringUtils.isNotBlank(codeGroupPutModel.getGitpassword()) && vaultHelper.savePassword(codeGroupPutModel.getGitpassword(), uuidToken)) {
                codeProject.setRepoPassword(uuidToken);
            } else {
                codeProject.setRepoPassword(codeGroupPutModel.getGitpassword());
            }
            codeProject= codeProjectRepository.saveAndFlush(codeProject);
            getOrCreateCodeProjectBranchService.getOrCreateCodeProjectBranch(codeProject, codeProject.getBranch());

        }
    }

    /**
     * Removing auth info from model
     * @param codeGroupPutModel
     * @return
     */
    private String setRepoUrl(CodeGroupPutModel codeGroupPutModel) {
        try {
            Pattern pattern = Pattern.compile("https?:\\/\\/(.*:.*@).*");
            Matcher matcher = pattern.matcher(codeGroupPutModel.getGiturl());
            if (matcher.find())
                return codeGroupPutModel.getGiturl().replace(matcher.group(1), "");
            else
                return codeGroupPutModel.getGiturl();
        } catch (NullPointerException e){
            log.error("[CodeService] Trying to save codeproject with name {} with blank repo url", codeGroupPutModel.getCodeGroupName());
        }
        return null;
    }

    public void createCodeProject(Project project, CodeProjectPutModel codeProjectPutModel) {
        Optional<CodeProject> codeProjectOptional = codeProjectRepository.findByProjectAndName(project, codeProjectPutModel.getCodeProjectName());
        if (!codeProjectOptional.isPresent()){
            CodeProject codeProject = new CodeProject(
                    codeProjectPutModel.getCodeProjectName(),
                    codeProjectPutModel.getBranch()!=null && !codeProjectPutModel.getBranch().equals("") ? codeProjectPutModel.getBranch() : Constants.CODE_DEFAULT_BRANCH,
                    null);
            codeProject.setProject(project);
            codeProject.setSkipAllScan(false);
            codeProject.setdTrackUuid(codeProjectPutModel.getDTrackUuid());
            codeProject.setAdditionalPath(codeProjectPutModel.getAdditionalPath());
            codeProject.setRepoUrl(codeProjectPutModel.getProjectGiturl());
            codeProject.setTechnique(codeProjectPutModel.getProjectTech());
            codeProject = codeProjectRepository.saveAndFlush(codeProject);
            getOrCreateCodeProjectBranchService.getOrCreateCodeProjectBranch(codeProject, codeProject.getBranch());

        } else {
            getOrCreateCodeProjectBranchService.getOrCreateCodeProjectBranch(codeProjectOptional.get(), codeProjectOptional.get().getBranch());
        }


    }
}
