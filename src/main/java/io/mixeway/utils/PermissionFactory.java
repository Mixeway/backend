package io.mixeway.utils;

import io.mixeway.api.dashboard.model.ProjectDTO;
import io.mixeway.config.Constants;
import io.mixeway.db.entity.Project;
import io.mixeway.db.entity.User;
import io.mixeway.db.repository.ProjectRepository;
import io.mixeway.db.repository.SettingsRepository;
import io.mixeway.db.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.RequestMapping;

import java.security.Principal;
import java.util.*;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class PermissionFactory {
    private final UserRepository userRepository;
    private final ProjectRepository projectRepository;
    private final SettingsRepository settingsRepository;


    /**
     * Verification if given Principal has authority to access project details
     *
     * @param principal to check
     * @param project to check access
     * @return boolean
     */
    public boolean canUserAccessProject(Principal principal, Project project){
        User user = getUserFromPrincipal(principal);
        if (apiKeyAccessProject(principal,project)){
            return true;
        }
        else if (user != null && (
                user.getPermisions().equals(Constants.ROLE_ADMIN) ||
                user.getPermisions().equals(Constants.ROLE_API) ||
                user.getPermisions().equals(Constants.ROLE_AUDITOR))){
            return true;
        } else if ( user != null && (user.getPermisions().equals(Constants.ROLE_USER) || user.getPermisions().equals(Constants.ROLE_PROJECT_OWNER) || user.getPermisions().equals(Constants.ROLE_EDITOR_RUNNER))){
            return user.getProjects().stream().map(Project::getId).collect(Collectors.toList()).contains(project.getId());
        } else if (principal.getName().equals(Constants.STRATEGY_SCHEDULER)) {
            return true;
        }else
            return false;
    }

    /**
     * Get User entity based on principal name, take care of both username and apikey
     * 1. If Principal.username = user.username return user
     * 2. If Principal.username = user.apikey return user
     * 3. if Principal.username = settings.apikey retrurn Admin
     * 4. if Principal.username = Constants.SCHEDULER return ROLE_API
     * 5. if Principal.username is valid UUID grant ROLE_API - should not happen
     *
     * @param principal to check
     * @return user entity
     */
    public User getUserFromPrincipal(Principal principal) {
        try {
            Optional<User> admin = userRepository.findById(1L);
            Optional<User> userOptional = userRepository.findByUsername(principal.getName());
            Optional<User> userApiKey = userRepository.findByApiKey(principal.getName());
            if (userOptional.isPresent())
                return userOptional.get();
            else if (userApiKey.isPresent()){
                return userApiKey.get();
            } else if (settingsRepository.findAll().stream().findFirst().orElse(null).getMasterApiKey() !=null && settingsRepository.findAll().stream().findFirst().orElse(null).getMasterApiKey().equals(principal.getName())) {
                return userRepository.findByUsername("admin").orElse(null);
            } else if (principal.getName().equals(Constants.ORIGIN_SCHEDULER)) {
                User u = new User();
                u.setUsername(Constants.API_URL);
                u.setPermisions("ROLE_API");
                return u;
            } else if(principal.getName().equals("admin")){
                return admin.orElse(null);
            } else {
                UUID test = UUID.fromString(principal.getName());
                User u = new User();
                u.setUsername(principal.getName());
                u.setPermisions("ROLE_API");
                return u;
            }
        } catch (IllegalArgumentException exception) {
            return null;
        }
    }

    /**
     * Verify if given api key can access project
     * 1. check if apikey's is user's
     * 2. check if apikey's is project's
     * 3. check if apikey is master api key
     *
     * @param principal
     * @param project
     * @return
     */
    private boolean apiKeyAccessProject(Principal principal, Project project){
        try {
            UUID test = UUID.fromString(principal.getName());
            Optional<User> user = userRepository.findByApiKey(principal.getName());
            if (user.isPresent() && (user.get().getPermisions().equals(Constants.ROLE_ADMIN) || user.get().getPermisions().equals(Constants.ROLE_AUDITOR))){
                return true;
            } else if (user.isPresent() && (user.get().getPermisions().equals(Constants.ROLE_USER) || user.get().getPermisions().equals(Constants.ROLE_EDITOR_RUNNER) || user.get().getPermisions().equals(Constants.ROLE_API))){
                return user.get().getProjects().contains(project);
            }
            Optional<Project> optionalProject = projectRepository.findByIdAndApiKey(project.getId(), principal.getName());
            if (optionalProject.isPresent()){
                return true;
            }
            if (settingsRepository.findAll().stream().findFirst().orElse(null).getMasterApiKey().equals(principal.getName())){
                return true;
            }
        } catch (Exception e){
            return false;
        }
        return false;
    }

    /**
     * return list of project given principal is authorized to see
     *
     * @param principal
     * @return
     */
    public List<Project> getProjectForPrincipal(Principal principal){
        Optional<User> userOptional = userRepository.findByUsernameOrApiKey(principal.getName(),principal.getName());
        if (userOptional.isPresent() && (userOptional.get().getPermisions().equals(Constants.ROLE_API) || userOptional.get().getPermisions().equals(Constants.ROLE_USER) || userOptional.get().getPermisions().equals(Constants.ROLE_PROJECT_OWNER) ||
                userOptional.get().getPermisions().equals(Constants.ROLE_EDITOR_RUNNER))){
            return new ArrayList<>(userOptional.get().getProjects());
        } else if (userOptional.isPresent() && (userOptional.get().getPermisions().equals(Constants.ROLE_ADMIN) ||
                userOptional.get().getPermisions().equals(Constants.ROLE_AUDITOR))) {
            return projectRepository.findAll();
        } else {
            return new ArrayList<>();
        }
    }

    public List<ProjectDTO> getProjectForPrincipalWithDTO(Principal principal){
        Optional<User> userOptional = userRepository.findByUsernameOrApiKey(principal.getName(), principal.getName());
        if (userOptional.isPresent()) {
            String permission = userOptional.get().getPermisions();
            if (Arrays.asList(Constants.ROLE_API, Constants.ROLE_USER, Constants.ROLE_PROJECT_OWNER, Constants.ROLE_EDITOR_RUNNER).contains(permission)) {
                // Return projects for the user
                return projectRepository.findProjectDTOsByUsername(principal.getName());
            } else if (Arrays.asList(Constants.ROLE_ADMIN, Constants.ROLE_AUDITOR).contains(permission)) {
                // Return all projects
                return projectRepository.findAllProjectDTOs();
            }
        }
        return Collections.emptyList();
    }

    /**
     * Update user permissions
     *
     * @param projectToCreate
     * @param principal
     */
    @Transactional
    public void grantPermissionToProjectForUser(Project projectToCreate, Principal principal) {
        User user = getUserFromPrincipal(principal);
        if (user.getProjects() != null) {
            user.getProjects().add(projectToCreate);
        } else {
            List<Project> projects = new ArrayList<>();
            projects.add(projectToCreate);
            user.setProjects(new HashSet<>(projects));
        }
    }
}
