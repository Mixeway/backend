package io.mixeway.api.project.service;

import com.fasterxml.jackson.databind.JsonNode;
import io.mixeway.api.project.controller.OperateOnAssets;
import io.mixeway.api.project.model.*;
import io.mixeway.config.Constants;
import io.mixeway.db.entity.*;
import io.mixeway.domain.service.asset.GetAssetDashboardService;
import io.mixeway.domain.service.assethistory.FindAssetHistoryService;
import io.mixeway.domain.service.cioperations.FindCiOperationsService;
import io.mixeway.domain.service.intf.FindInterfaceService;
import io.mixeway.domain.service.intf.UpdateInterfaceService;
import io.mixeway.domain.service.routingdomain.FindRoutingDomainService;
import io.mixeway.domain.service.scan.CreateScanService;
import io.mixeway.domain.service.scan.FindScanService;
import io.mixeway.domain.service.scanmanager.code.CreateOrGetCodeProjectService;
import io.mixeway.domain.service.scanmanager.code.FindCodeProjectService;
import io.mixeway.domain.service.scanmanager.code.UpdateCodeProjectService;
import io.mixeway.domain.service.scanmanager.webapp.FindWebAppService;
import io.mixeway.domain.service.scanmanager.webapp.GetOrCreateWebAppService;
import io.mixeway.domain.service.scanmanager.webapp.UpdateWebAppService;
import io.mixeway.domain.service.vulnhistory.OperateOnVulnHistoryService;
import io.mixeway.domain.service.vulnmanager.VulnTemplate;
import io.mixeway.utils.PermissionFactory;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.security.Principal;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Service
@RequiredArgsConstructor
@Log4j2
public class OperateOnAssetsService {

    private final CreateOrGetCodeProjectService createOrGetCodeProjectService;
    private final GetOrCreateWebAppService getOrCreateWebAppService;
    private final FindRoutingDomainService findRoutingDomainService;
    private final UpdateCodeProjectService updateCodeProjectService;
    private final AssetService assetService;
    private final FindCodeProjectService findCodeProjectService;
    private final FindWebAppService findWebAppService;
    private final FindInterfaceService findInterfaceService;
    private final PermissionFactory permissionFactory;
    private final UpdateWebAppService updateWebAppService;
    private final UpdateInterfaceService updateInterfaceService;
    private final VulnTemplate vulnTemplate;
    private final FindScanService findScanService;
    private final CreateScanService createScanService;
    private final OperateOnVulnHistoryService operateOnVulnHistoryService;
    private final FindCiOperationsService findCiOperationsService;
    private final GetAssetDashboardService getAssetDashboardService;
    private final FindAssetHistoryService findAssetHistoryService;

    public CodeProject createCodeProject(JsonNode rootNode, Project project, Principal principal) {
        String repositoryType = rootNode.path("repositoryType").asText();
        if (repositoryType.equals("single")) {
            return createSingleCodeProject(rootNode, project, principal);
        } else if (repositoryType.equals("multiple")) {
            return createMultipleCodeProject(rootNode, project, principal);
        }
        return null; // Handle invalid repositoryType
    }

    private CodeProject createSingleCodeProject(JsonNode rootNode, Project project, Principal principal) {
        log.info("[OperateOnAsset] {} Created CodeProject with name {} url {}",
                principal.getName(),
                rootNode.path("name").asText(),
                rootNode.path("repositoryUrl").asText());
        return createOrGetCodeProjectService.createCodeProject(
                rootNode.path("repositoryUrl").asText(),
                rootNode.path("name").asText(),
                rootNode.path("defaultBranch").asText(),
                principal,
                project);
    }

    private CodeProject createMultipleCodeProject(JsonNode rootNode, Project project, Principal principal) {
        CodeProject parent = createOrGetCodeProjectService.createCodeProject(
                rootNode.path("repositoryUrl").asText(),
                rootNode.path("name").asText(),
                rootNode.path("defaultBranch").asText(),
                principal,
                project);
        parent = updateCodeProjectService.setAsParent(parent);
        log.info("[OperateOnAsset] {} Created CodeProject with name {} url {}",
                principal.getName(),
                rootNode.path("name").asText(),
                rootNode.path("repositoryUrl").asText());

        JsonNode apps = rootNode.path("apps");
        for (int i = 0; i < apps.size(); i++) {
            JsonNode app = apps.get(i);
            log.info("[OperateOnAsset] {} Created Embeded CodeProject with name {} url {} and directory within repo {}",
                    principal.getName(),
                    app.path("appName").asText(),
                    rootNode.path("repositoryUrl").asText(),
                    app.path("appDirectory").asText());

            createOrGetCodeProjectService.createChildCodeProject(
                    rootNode.path("repositoryUrl").asText(),
                    app.path("appName").asText(),
                    rootNode.path("defaultBranch").asText(),
                    principal,
                    project,
                    parent,
                    app.path("appDirectory").asText());
        }
        return null;
    }

    public WebApp createWebApp(JsonNode rootNode, Project project) {
        Optional<RoutingDomain> routingDomainOptional = findRoutingDomainService.findById(Long.parseLong(rootNode.path("routingDomain").asText()));
        if (routingDomainOptional.isPresent()) {
            return getOrCreateWebAppService.createWebApp(
                    project,
                    rootNode.path("appUrl").asText(),
                    rootNode.path("appName").asText(),
                    routingDomainOptional.get(),
                    rootNode.path("headerName").asText(),
                    rootNode.path("apiKeyName").asText(),
                    rootNode.path("basicAuth").asText());
        } else {
            return null;
        }
    }

    public Interface createInterface(JsonNode rootNode, Project project, Principal principal) {
        Optional<RoutingDomain> routingDomainOptional = findRoutingDomainService.findById(Long.parseLong(rootNode.path("routingDomain").asText()));
        if (routingDomainOptional.isPresent()) {
            AssetPutModel assetPutModel = new AssetPutModel();
            assetPutModel.setAssetName(rootNode.path("name").asText());
            assetPutModel.setIpAddresses(rootNode.path("ip").asText());
            assetPutModel.setRoutingDomainForAsset(Long.parseLong(rootNode.path("routingDomain").asText()));
            assetService.saveAsset(project.getId(), assetPutModel, principal);
            return null;
        } else {
            return null;
        }
    }

    public List<ProjectAssetModel> getAssetsForProject(Project project) {
        List<ProjectAssetModel> projectAssetModels = new ArrayList<>();

        // Combine all find service calls into parallel streams to leverage concurrency
        Stream.concat(Stream.concat(
                        findCodeProjectService.findByProject(project).parallelStream().map(cp -> {
                            AssetHistory assetHistory = findAssetHistoryService.getAssetHistory(cp).stream()
                                    .max(Comparator.comparing(AssetHistory::getInserted)).orElse(new AssetHistory());

                            return new ProjectAssetModel().convertCodeProject(cp, assetHistory.getCrit() + assetHistory.getHigh(),
                                    assetHistory.getMedium(), assetHistory.getLow());
                        }),
                        findWebAppService.findByProject(project).parallelStream().map(wa -> {
                            AssetHistory assetHistory = findAssetHistoryService.getAssetHistory(wa).stream()
                                    .max(Comparator.comparing(AssetHistory::getInserted)).orElse(new AssetHistory());

                            return new ProjectAssetModel().convertWebApp(wa,
                                    assetHistory.getCrit() + assetHistory.getHigh(),
                                    assetHistory.getMedium(), assetHistory.getLow(),
                                    (assetHistory.getCrit() + assetHistory.getHigh() + assetHistory.getMedium() + assetHistory.getLow()) > 0);
                        })),
                findInterfaceService.findByAssetIn(new ArrayList<>(project.getAssets())).parallelStream().map(intf -> {
                    AssetHistory assetHistory = findAssetHistoryService.getAssetHistory(intf).stream()
                            .max(Comparator.comparing(AssetHistory::getInserted)).orElse(new AssetHistory());

                    return new ProjectAssetModel().convertInterface(intf, assetHistory.getCrit() + assetHistory.getHigh(),
                            assetHistory.getMedium(), assetHistory.getLow(),
                            (assetHistory.getCrit() + assetHistory.getHigh() + assetHistory.getMedium() + assetHistory.getLow()) > 0);
                })
        ).forEach(projectAssetModels::add);

        return projectAssetModels;
    }


    public ResponseEntity<?> editCodeProject(EditProjectAssetModel editProjectAssetModel, Optional<CodeProject> codeProject, Principal principal) {
        if (codeProject.isPresent()) {
            if (permissionFactory.canUserAccessProject(principal, codeProject.get().getProject())) {
                updateCodeProjectService.updateCodeProject(editProjectAssetModel, codeProject.get());
                log.info("[OperateOnAsset] Editing CodeProject setting name {}, repoUrl {} and branch {}",
                        editProjectAssetModel.getName(),
                        editProjectAssetModel.getTarget(),
                        editProjectAssetModel.getBranch());
                return new ResponseEntity<>(HttpStatus.OK);
            }
        }
        return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
    }

    public ResponseEntity<?> editWebApp(EditProjectAssetModel editProjectAssetModel, Optional<WebApp> webApp, Principal principal) {
        if (webApp.isPresent()) {
            if (permissionFactory.canUserAccessProject(principal, webApp.get().getProject())) {
                updateWebAppService.edit(editProjectAssetModel, webApp.get());
                log.info("[OperateOnAsset] Editing WebApp setting name {} and Url {}",
                        editProjectAssetModel.getName(),
                        editProjectAssetModel.getTarget());
                return new ResponseEntity<>(HttpStatus.OK);
            }
        }
        return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
    }

    public ResponseEntity<?> editInterface(EditProjectAssetModel editProjectAssetModel, Optional<Interface> anInterface, Principal principal) {
        if (anInterface.isPresent()) {
            if (permissionFactory.canUserAccessProject(principal, anInterface.get().getAsset().getProject())) {
                updateInterfaceService.edit(editProjectAssetModel, anInterface.get());
                log.info("[OperateOnAsset] Editing Interface setting name {} and IP {}",
                        editProjectAssetModel.getName(),
                        editProjectAssetModel.getTarget());
                return new ResponseEntity<>(HttpStatus.OK);
            }
        }
        return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
    }

    public ResponseEntity<?> getScans(Long id, String type, Principal principal) {

        List<Scan> scans = new ArrayList<>();
        switch (type) {
            case "codeProject":
                Optional<CodeProject> codeProject = findCodeProjectService.findById(id);
                if (codeProject.isPresent() && permissionFactory.canUserAccessProject(principal, codeProject.get().getProject())) {
                    scans = findScanService.getScansForAsset(codeProject.get());
                } else {
                    return new ResponseEntity<>(HttpStatus.NOT_FOUND);
                }
                break;
            case "webApp":
                Optional<WebApp> webApp = findWebAppService.findById(id);
                if (webApp.isPresent() && permissionFactory.canUserAccessProject(principal, webApp.get().getProject())) {
                    scans = findScanService.getScansForAsset(webApp.get());
                } else {
                    return new ResponseEntity<>(HttpStatus.NOT_FOUND);
                }
                break;
            case "interface":
                Optional<Interface> anInterface = findInterfaceService.findById(id);
                if (anInterface.isPresent() && permissionFactory.canUserAccessProject(principal, anInterface.get().getAsset().getProject())) {
                    scans = findScanService.getScansForAsset(anInterface.get());
                } else {
                    return new ResponseEntity<>(HttpStatus.NOT_FOUND);
                }
                break;
            default:
                return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
        }
        return new ResponseEntity<>(scans, HttpStatus.OK);
    }

    public ResponseEntity<ProjectVulnTrendChart> getAssetHistory(Long id, String type, Principal principal) {
        ProjectVulnTrendChart projectVulnTrendChart = new ProjectVulnTrendChart();
        switch (type) {
            case "codeProject":
                Optional<CodeProject> codeProject = findCodeProjectService.findById(id);
                if (codeProject.isPresent() && permissionFactory.canUserAccessProject(principal, codeProject.get().getProject())) {
                    projectVulnTrendChart = operateOnVulnHistoryService.getVulnTrendChartForCodeProject(codeProject.get(), 14);
                } else {
                    return new ResponseEntity<>(HttpStatus.NOT_FOUND);
                }
                break;
            case "webApp":
                Optional<WebApp> webApp = findWebAppService.findById(id);
                if (webApp.isPresent() && permissionFactory.canUserAccessProject(principal, webApp.get().getProject())) {
                    projectVulnTrendChart = operateOnVulnHistoryService.getVulnTrendChartForWebApp(webApp.get(), 14);
                } else {
                    return new ResponseEntity<>(HttpStatus.NOT_FOUND);
                }
                break;
            case "interface":
                Optional<Interface> anInterface = findInterfaceService.findById(id);
                if (anInterface.isPresent() && permissionFactory.canUserAccessProject(principal, anInterface.get().getAsset().getProject())) {
                    projectVulnTrendChart = operateOnVulnHistoryService.getVulnTrendChartForInterface(anInterface.get(), 14);
                } else {
                    return new ResponseEntity<>(HttpStatus.NOT_FOUND);
                }
                break;
            default:
                return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
        }
        return new ResponseEntity<>(projectVulnTrendChart, HttpStatus.OK);
    }

    public ResponseEntity<List<CiOperations>> getCiOperation(Long id, String type, Principal principal) {
        List<CiOperations> ciOperations = new ArrayList<>();
        switch (type) {
            case "codeProject":
                Optional<CodeProject> codeProject = findCodeProjectService.findById(id);
                if (codeProject.isPresent() && permissionFactory.canUserAccessProject(principal, codeProject.get().getProject())) {
                    ciOperations = findCiOperationsService.findTop20CodeProject(codeProject.get());
                } else {
                    return new ResponseEntity<>(HttpStatus.NOT_FOUND);
                }
                break;
            case "webApp":
                Optional<WebApp> webApp = findWebAppService.findById(id);
                if (webApp.isPresent() && permissionFactory.canUserAccessProject(principal, webApp.get().getProject())) {
                    ciOperations = findCiOperationsService.findTop20WebApp(webApp.get());
                } else {
                    return new ResponseEntity<>(HttpStatus.NOT_FOUND);
                }
                break;
            case "interface":
                Optional<Interface> anInterface = findInterfaceService.findById(id);
                if (anInterface.isPresent() && permissionFactory.canUserAccessProject(principal, anInterface.get().getAsset().getProject())) {
                    ciOperations = findCiOperationsService.findTop20Interface(anInterface.get());
                } else {
                    return new ResponseEntity<>(HttpStatus.NOT_FOUND);
                }
                break;
            default:
                return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
        }
        return new ResponseEntity<>(ciOperations, HttpStatus.OK);
    }

    public ResponseEntity<List<NewVulnerabilityModel>> getNewVulnerabilities(Long id, String type, Principal principal) {
        List<NewVulnerabilityModel> newVulnerabilityModels = new ArrayList<>();
        List<ProjectVulnerability> projectVulnerabilities = new ArrayList<>();
        switch (type) {
            case "codeProject":
                Optional<CodeProject> codeProject = findCodeProjectService.findById(id);
                if (codeProject.isPresent() && permissionFactory.canUserAccessProject(principal, codeProject.get().getProject())) {
                    projectVulnerabilities.addAll(vulnTemplate.projectVulnerabilityRepository.findByCodeProject(codeProject.get()));
                } else {
                    return new ResponseEntity<>(HttpStatus.NOT_FOUND);
                }
                break;
            case "webApp":
                Optional<WebApp> webApp = findWebAppService.findById(id);
                if (webApp.isPresent() && permissionFactory.canUserAccessProject(principal, webApp.get().getProject())) {
                    projectVulnerabilities.addAll(vulnTemplate.projectVulnerabilityRepository.findByWebApp(webApp.get()));
                } else {
                    return new ResponseEntity<>(HttpStatus.NOT_FOUND);
                }
                break;
            case "interface":
                Optional<Interface> anInterface = findInterfaceService.findById(id);
                if (anInterface.isPresent() && permissionFactory.canUserAccessProject(principal, anInterface.get().getAsset().getProject())) {
                    projectVulnerabilities.addAll(vulnTemplate.projectVulnerabilityRepository.findByAnInterface(anInterface.get()));
                } else {
                    return new ResponseEntity<>(HttpStatus.NOT_FOUND);
                }
                break;
            default:
                return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
        }
        projectVulnerabilities = projectVulnerabilities.stream()
                .sorted(Comparator.comparing(ProjectVulnerability::getInserted).reversed()) // Sort by inserted date in descending order
                .limit(10) // Take only the first 10 elements
                .collect(Collectors.toList());


        return new ResponseEntity<>(projectVulnerabilities.stream()
                .map(projectVulnerability -> {
                    NewVulnerabilityModel newVulnerabilityModel = new NewVulnerabilityModel();
                    newVulnerabilityModel.setSeverity(projectVulnerability.getSeverity());
                    newVulnerabilityModel.setName(projectVulnerability.getVulnerability().getName());
                    newVulnerabilityModel.setScanType(projectVulnerability.getVulnerabilitySource().getName());
                    newVulnerabilityModel.setBranch(projectVulnerability.getCodeProjectBranch() != null ?
                            projectVulnerability.getCodeProjectBranch().getName() : null);
                    return newVulnerabilityModel;
                })
                .collect(Collectors.toList()), HttpStatus.OK);
    }

    public ResponseEntity<AssetDashboardModel> getAssetDashboard(Long id, String type, Principal principal) {
        AssetDashboardModel assetDashboardModel = new AssetDashboardModel();
        switch (type) {
            case "codeProject":
                Optional<CodeProject> codeProject = findCodeProjectService.findById(id);
                if (codeProject.isPresent() && permissionFactory.canUserAccessProject(principal, codeProject.get().getProject())) {
                    assetDashboardModel= getAssetDashboardService.buildDashboardModelForCodeProject(codeProject.get());
                } else {
                    return new ResponseEntity<>(HttpStatus.NOT_FOUND);
                }
                break;
            case "webApp":
                Optional<WebApp> webApp = findWebAppService.findById(id);
                if (webApp.isPresent() && permissionFactory.canUserAccessProject(principal, webApp.get().getProject())) {
                    List<ProjectVulnerability> projectVulnerabilities = vulnTemplate.projectVulnerabilityRepository.findByWebApp(webApp.get());
                    assetDashboardModel= getAssetDashboardService.buildDashboardModel(projectVulnerabilities,
                            webApp.get().getName(),
                            webApp.get().getUrl(),
                            LocalDateTime.parse(webApp.get().getInserted(), DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")));
                } else {
                    return new ResponseEntity<>(HttpStatus.NOT_FOUND);
                }
                break;
            case "interface":
                Optional<Interface> anInterface = findInterfaceService.findById(id);
                if (anInterface.isPresent() && permissionFactory.canUserAccessProject(principal, anInterface.get().getAsset().getProject())) {
                    List<ProjectVulnerability> projectVulnerabilities = vulnTemplate.projectVulnerabilityRepository.findByAnInterface(anInterface.get());
                    assetDashboardModel= getAssetDashboardService.buildDashboardModel(projectVulnerabilities,
                            anInterface.get().getAsset().getName(),
                            anInterface.get().getPrivateip(),
                            anInterface.get().getInserted());
                } else {
                    return new ResponseEntity<>(HttpStatus.NOT_FOUND);
                }
                break;
            default:
                return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
        }
        return new ResponseEntity<>(assetDashboardModel, HttpStatus.OK);
    }

    public ResponseEntity<List<ProjectVulnerability>> getAssetVulnerabilities(Long id, String type, Principal principal) {
        List<ProjectVulnerability> projectVulnerabilities = new ArrayList<>();
        switch (type) {
            case "codeProject":
                Optional<CodeProject> codeProject = findCodeProjectService.findById(id);
                if (codeProject.isPresent() && permissionFactory.canUserAccessProject(principal, codeProject.get().getProject())) {
                    projectVulnerabilities = vulnTemplate.projectVulnerabilityRepository.findByCodeProject(codeProject.get());
                } else {
                    return new ResponseEntity<>(HttpStatus.NOT_FOUND);
                }
                break;
            case "webApp":
                Optional<WebApp> webApp = findWebAppService.findById(id);
                if (webApp.isPresent() && permissionFactory.canUserAccessProject(principal, webApp.get().getProject())) {
                    projectVulnerabilities = vulnTemplate.projectVulnerabilityRepository.findByWebApp(webApp.get());

                } else {
                    return new ResponseEntity<>(HttpStatus.NOT_FOUND);
                }
                break;
            case "interface":
                Optional<Interface> anInterface = findInterfaceService.findById(id);
                if (anInterface.isPresent() && permissionFactory.canUserAccessProject(principal, anInterface.get().getAsset().getProject())) {
                    projectVulnerabilities = vulnTemplate.projectVulnerabilityRepository.findByAnInterface(anInterface.get());

                } else {
                    return new ResponseEntity<>(HttpStatus.NOT_FOUND);
                }
                break;
            default:
                return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
        }
        return new ResponseEntity<>(projectVulnerabilities
                .stream()
                .filter(
                        pv -> !pv.getStatus().getName().equals(vulnTemplate.STATUS_REMOVED.getName())).collect(Collectors.toList()),
                HttpStatus.OK);
    }

    public ResponseEntity<MixewayYamlConfigDto> generateCondig(Long id, String type,Principal principal) {
        MixewayYamlConfigDto mixewayYamlConfigDto = new MixewayYamlConfigDto();
        switch (type) {
            case "codeProject":
                Optional<CodeProject> codeProject = findCodeProjectService.findById(id);
                if (codeProject.isPresent() && permissionFactory.canUserAccessProject(principal, codeProject.get().getProject())) {
                    mixewayYamlConfigDto = mixewayYamlConfigDto.buildCodeResponse(codeProject.get(), findCodeProjectService.getProjectChilds(codeProject.get()));
                } else {
                    return new ResponseEntity<>(HttpStatus.NOT_FOUND);
                }
                break;
            case "webApp":
                Optional<WebApp> webApp = findWebAppService.findById(id);
                if (webApp.isPresent() && permissionFactory.canUserAccessProject(principal, webApp.get().getProject())) {
                    MixewayYamlConfigDto.WA wa  = new MixewayYamlConfigDto.WA();
                    wa.setId(webApp.get().getId());
                    wa.setBackendUrl(webApp.get().getUrl());
                    mixewayYamlConfigDto.setWebapp(wa);

                } else {
                    return new ResponseEntity<>(HttpStatus.NOT_FOUND);
                }
                break;
            default:
                return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
        }
        return new ResponseEntity<>(mixewayYamlConfigDto, HttpStatus.OK);
    }


}