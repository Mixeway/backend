package io.mixeway.api.project.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mixeway.api.project.model.*;
import io.mixeway.api.project.service.OperateOnAssetsService;

import io.mixeway.api.protocol.cioperations.PrepareCIOperation;
import io.mixeway.db.entity.*;
import io.mixeway.domain.service.intf.FindInterfaceService;
import io.mixeway.domain.service.project.FindProjectService;
import io.mixeway.domain.service.scanmanager.code.FindCodeProjectService;
import io.mixeway.domain.service.scanmanager.webapp.FindWebAppService;
import io.mixeway.domain.service.vulnmanager.VulnTemplate;
import io.mixeway.utils.PermissionFactory;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.security.Principal;
import java.util.List;
import java.util.Optional;

@RequestMapping("/v3/api/asset")
@RestController()
@RequiredArgsConstructor
public class OperateOnAssets {
    private final OperateOnAssetsService operateOnAssetsService;
    private ObjectMapper objectMapper = new ObjectMapper();
    private final PermissionFactory permissionFactory;
    private final FindProjectService findProjectService;
    private final FindCodeProjectService findCodeProjectService;
    private final FindWebAppService findWebAppService;
    private final FindInterfaceService findInterfaceService;

    @PreAuthorize("hasAuthority('ROLE_PROJECT_OWNER')")
    @PostMapping("/create/project/{id}")
    public ResponseEntity<?> processAsset(@RequestBody String json, @PathVariable("id") Long id, Principal principal) throws IOException {
        Optional<Project> project = findProjectService.findProjectById(id);
        if(project.isPresent() && permissionFactory.canUserAccessProject(principal, project.get())) {
            JsonNode rootNode = objectMapper.readTree(json);
            String assetType = rootNode.path("assetType").asText();
            switch (assetType) {
                case "sourceCodeApp":
                    return ResponseEntity.ok(operateOnAssetsService.createCodeProject(rootNode, project.get(), principal));
                case "webApplication":
                    return ResponseEntity.ok(operateOnAssetsService.createWebApp(rootNode,project.get()));
                case "networkAsset":
                    return ResponseEntity.ok(operateOnAssetsService.createInterface(rootNode, project.get(), principal));
                default:
                    return ResponseEntity.badRequest().body("Invalid assetType: " + assetType);
            }
        } else
            return ResponseEntity.badRequest().body("Not Authorized");
    }

    @PreAuthorize("hasAuthority('ROLE_USER')")
    @GetMapping("/project/{id}")
    public ResponseEntity<?> getAssets(@PathVariable("id") Long id, Principal principal) throws IOException {
        Optional<Project> project = findProjectService.findProjectById(id);
        if(project.isPresent() && permissionFactory.canUserAccessProject(principal, project.get())) {
            return ResponseEntity.ok(operateOnAssetsService.getAssetsForProject(project.get()));

        } else
            return ResponseEntity.badRequest().body("Not Authorized");
    }
    @PreAuthorize("hasAuthority('ROLE_PROJECT_OWNER')")
    @PostMapping("/{id}/edit")
    public ResponseEntity<?> editAsset(@RequestBody EditProjectAssetModel editProjectAssetModel, @PathVariable("id") Long id, Principal principal) throws IOException {
        switch (editProjectAssetModel.getType()) {
            case "codeProject":
                Optional<CodeProject> codeProject = findCodeProjectService.findById(id);
                return operateOnAssetsService.editCodeProject(editProjectAssetModel, codeProject, principal);
            case "webApp":
                Optional<WebApp> webApp = findWebAppService.findById(id);
                return operateOnAssetsService.editWebApp(editProjectAssetModel, webApp, principal);
            case "interface":
                Optional<Interface> anInterface = findInterfaceService.findById(id);
                return operateOnAssetsService.editInterface(editProjectAssetModel, anInterface, principal);
            default:
                return ResponseEntity.badRequest().body("Not Allowed Type");
        }

    }

    @PreAuthorize("hasAuthority('ROLE_USER')")
    @GetMapping("/{id}/{type}/scans")
    public ResponseEntity<?> getScans(@PathVariable("id") Long id, @PathVariable("type") String type, Principal principal) throws IOException {
        return operateOnAssetsService.getScans(id, type, principal);
    }

    @PreAuthorize("hasAuthority('ROLE_USER')")
    @GetMapping("/{id}/{type}/trend")
    public ResponseEntity<ProjectVulnTrendChart> getAssetHistory(@PathVariable("id") Long id, @PathVariable("type") String type, Principal principal) throws IOException {
        return operateOnAssetsService.getAssetHistory(id, type, principal);
    }
    @PreAuthorize("hasAuthority('ROLE_USER')")
    @GetMapping("/{id}/{type}/cioperations")
    public ResponseEntity<List<CiOperations>> getCiOperation(@PathVariable("id") Long id, @PathVariable("type") String type, Principal principal) throws IOException {
        return operateOnAssetsService.getCiOperation(id, type, principal);
    }
    @PreAuthorize("hasAuthority('ROLE_USER')")
    @GetMapping("/{id}/{type}/newvulnerabilities")
    public ResponseEntity<List<NewVulnerabilityModel>> getNewVulnerabilities(@PathVariable("id") Long id, @PathVariable("type") String type, Principal principal) throws IOException {
        return operateOnAssetsService.getNewVulnerabilities(id, type, principal);
    }
    @PreAuthorize("hasAuthority('ROLE_USER')")
    @GetMapping("/{id}/{type}")
    public ResponseEntity<AssetDashboardModel> getAssetDashboard(@PathVariable("id") Long id, @PathVariable("type") String type, Principal principal) throws IOException {
        return operateOnAssetsService.getAssetDashboard(id, type, principal);
    }
    @PreAuthorize("hasAuthority('ROLE_USER')")
    @GetMapping("/{id}/{type}/vulnerabilities")
    public ResponseEntity<List<ProjectVulnerability>> getAssetVulnerabilities(@PathVariable("id") Long id, @PathVariable("type") String type, Principal principal) throws IOException {
        return operateOnAssetsService.getAssetVulnerabilities(id, type, principal);
    }

    @PreAuthorize("hasAuthority('ROLE_USER')")
    @GetMapping("/{id}/{type}/cicd/config")
    public ResponseEntity<MixewayYamlConfigDto> generateCondig(@PathVariable("id") Long id,  @PathVariable("type") String type,Principal principal) throws IOException {
        return operateOnAssetsService.generateCondig(id, type, principal);
    }

}
