package io.mixeway.api.project.service;

import io.mixeway.api.project.model.*;
import io.mixeway.config.Constants;
import io.mixeway.db.entity.*;
import io.mixeway.domain.service.intf.FindInterfaceService;
import io.mixeway.domain.service.project.FindProjectService;
import io.mixeway.domain.service.project.UpdateProjectService;
import io.mixeway.domain.service.proxy.GetOrCreateProxyService;
import io.mixeway.domain.service.routingdomain.FindRoutingDomainService;
import io.mixeway.domain.service.scanmanager.code.FindCodeProjectService;
import io.mixeway.domain.service.scanner.FindScannerService;
import io.mixeway.domain.service.softwarepackage.FindSoftwarePacketService;
import io.mixeway.domain.service.user.EditUserService;
import io.mixeway.domain.service.user.FindUserService;
import io.mixeway.domain.service.user.GetOrCreateUserService;
import io.mixeway.domain.service.vulnhistory.OperateOnVulnHistoryService;
import io.mixeway.domain.service.vulnmanager.VulnTemplate;
import io.mixeway.utils.PermissionFactory;
import io.mixeway.utils.ProjectRiskAnalyzer;
import io.mixeway.utils.Status;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import javax.mail.internet.AddressException;
import javax.mail.internet.InternetAddress;
import java.security.Principal;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Service
@Transactional
@RequiredArgsConstructor
public class ProjectRestService {
    private static final Logger log = LoggerFactory.getLogger(ProjectRestService.class);

    private final ProjectRiskAnalyzer projectRiskAnalyzer;
    private final PermissionFactory permissionFactory;
    private final VulnTemplate vulnTemplate;
    private final FindProjectService findProjectService;
    private final FindInterfaceService findInterfaceService;
    private final FindSoftwarePacketService findSoftwarePacketService;
    private final FindScannerService findScannerService;
    private final GetOrCreateProxyService getOrCreateProxyService;
    private final OperateOnVulnHistoryService operateOnVulnHistoryService;
    private final UpdateProjectService updateProjectService;
    private final FindRoutingDomainService findRoutingDomainService;
    private final FindUserService findUserService;
    private final GetOrCreateUserService getOrCreateUserService;



    private ArrayList<String> severityList = new ArrayList<String>() {{
        add(Constants.API_SEVERITY_CRITICAL);
        add(Constants.API_SEVERITY_HIGH);
        add(Constants.API_SEVERITY_MEDIUM);
        add(Constants.API_SEVERITY_LOW);
    }};


    public ResponseEntity<RiskCards> showProjectRisk(Long id, Principal principal) {
        Optional<Project> project = findProjectService.findProjectById(id);
        if ( project.isPresent() && permissionFactory.canUserAccessProject(principal, project.get())){
            int webAppRisk = projectRiskAnalyzer.getProjectWebAppRisk(project.get());
            int assetRisk = projectRiskAnalyzer.getProjectInfraRisk(project.get());
            int codeRisk = projectRiskAnalyzer.getProjectCodeRisk(project.get());
            int auditRisk = projectRiskAnalyzer.getProjectAuditRisk(project.get());
            int openSourceRisk = projectRiskAnalyzer.getProjectOpenSourceRisk(project.get());
            int codeProjects = project.get().getCodes().size();
            RiskCards riskCards = new RiskCards();
            riskCards.setEnableVulnAuditor(project.get().isVulnAuditorEnable());
            riskCards.setWebAppNumber(project.get().getWebapps().size());
            riskCards.setWebAppRisk(Math.min(webAppRisk, 100));
            riskCards.setAudit(project.get().getNodes().size());
            riskCards.setAuditRisk(Math.min(auditRisk, 100));
            riskCards.setAssetNumber(findInterfaceService.findByAssetIn(new ArrayList<>(project.get().getAssets())).size());
            riskCards.setAssetRisk(Math.min(assetRisk, 100));
            riskCards.setCodeRepoNumber(codeProjects == 0 ? project.get().getCodes().size() : codeProjects);
            riskCards.setCodeRisk(Math.min(codeRisk, 100));
            riskCards.setOpenSourceLibs(findSoftwarePacketService.getSoftwarePacketForProject(project.get().getId()).size());
            riskCards.setOpenSourceRisk(Math.min(openSourceRisk, 100));
            riskCards.setProjectName(project.get().getName());
            riskCards.setProjectDescription(project.get().getDescription());
            return new ResponseEntity<>(riskCards,HttpStatus.OK);
        } else {
            return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
        }
    }



    public ResponseEntity<List<RoutingDomain>> showRoutingDomains() {
        return new ResponseEntity<>(findScannerService.getDistinctByRoutingDomain(), HttpStatus.OK);
    }

    public ResponseEntity<List<Proxies>> showProxies() {
        return new ResponseEntity<>(getOrCreateProxyService.findAll(), HttpStatus.OK);
    }



    public ResponseEntity<ProjectVulnTrendChart> showVulnTrendChart(Long id, int limit, Principal principal) {
        Optional<Project> project = findProjectService.findProjectById(id) ;
        if (project.isPresent() && permissionFactory.canUserAccessProject(principal, project.get())) {
            return new ResponseEntity<>(operateOnVulnHistoryService.getVulnTrendChart(project.get(), limit),HttpStatus.OK);
        } else {
            return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
        }
    }

    public ResponseEntity<HashMap<String,Long>> showSeverityChart(Long id, Principal principal) {
        Optional<Project> project = findProjectService.findProjectById(id);
        HashMap<String,Long> pieData = new HashMap<>();
        if (project.isPresent() && permissionFactory.canUserAccessProject(principal, project.get())){
            for (String severity : severityList){
                pieData.put(severity,vulnTemplate.projectVulnerabilityRepository.countVulnsbyProject(project.get(), severity));
            }
            return new ResponseEntity<>(pieData,HttpStatus.OK);
        } else {
            return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
        }
    }

    public ResponseEntity<Status> updateContactList(Long id, ContactList contactList, Principal principal) {
        Optional<Project> project = findProjectService.findProjectById(id);
        if (project.isPresent() &&
                permissionFactory.canUserAccessProject(principal,project.get()) &&
                verifyContactList(contactList) ){
            updateProjectService.updateContactList(project.get(), contactList);
            return new ResponseEntity<>(HttpStatus.OK);
        } else {
            return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
        }
    }

    private boolean verifyContactList(ContactList contactList) {
        boolean result = true;
        try {
            for (String email : contactList.getContactList().split(",")) {
                InternetAddress emailAddr = new InternetAddress(email);
                emailAddr.validate();
            }
        } catch (AddressException ex) {
            result = false;
        }
        return result;
    }

    public ResponseEntity<List<ScannerType>> scannersAvaliable() {
        return new ResponseEntity<>(findScannerService.getDistinctScannerTypes(), HttpStatus.OK);
    }

    public ResponseEntity<List<ProjectVulnerability>> showVulnerabilitiesForProject(Long id, Principal principal) {
        Optional<Project> project = findProjectService.findProjectById(id);
        if (project.isPresent() && permissionFactory.canUserAccessProject(principal, project.get())){
            List<ProjectVulnerability> vulns = vulnTemplate.projectVulnerabilityRepository
                    .findByProjectAndStatusIdNotAndGradeNot(project.get(), vulnTemplate.STATUS_REMOVED.getId(), 0);
            return new ResponseEntity<>(vulns, HttpStatus.OK);

        } else {
            return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
        }
    }

    public ResponseEntity<ProjectVulnerability> showVulnerability(Long id, Long vulnId, Principal principal) {
        Optional<Project> project = findProjectService.findProjectById(id);
        if (project.isPresent() && permissionFactory.canUserAccessProject(principal, project.get())){
            Optional<ProjectVulnerability> projectVulnerability = vulnTemplate.projectVulnerabilityRepository.findById(vulnId);
            if (projectVulnerability.isPresent() && projectVulnerability.get().getProject().getId().equals(project.get().getId()))
                return new ResponseEntity<>(projectVulnerability.get(),HttpStatus.OK);
        } else {
            return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
        }
        return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
    }

    public ResponseEntity<Project> showProject(Long id, Principal principal) {
        Optional<Project> project = findProjectService.findProjectById(id);
        if (project.isPresent() && permissionFactory.canUserAccessProject(principal, project.get())){
           return new ResponseEntity<>(project.get(), HttpStatus.OK);
        } else {
            return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
        }
    }
    @Transactional(propagation = Propagation.REQUIRED)
    public ResponseEntity<Status> updateVulnAuditorSettings(Long id, VulnAuditorSettings settings, Principal principal) {
        Optional<Project> project = findProjectService.findProjectById(id);
        if (project.isPresent() && permissionFactory.canUserAccessProject(principal, project.get())){
            updateProjectService.setVulnAuditor(project.get(), settings);
            return new ResponseEntity<>(HttpStatus.OK);
        } else {
            return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
        }
    }

    public ResponseEntity<Status> setGradeForVulnerability(Long id, Long vulnId,int grade, Principal principal) {
        Optional<Project> project = findProjectService.findProjectById(id);
        if (project.isPresent() && permissionFactory.canUserAccessProject(principal, project.get())){
            Optional<ProjectVulnerability> projectVulnerability = vulnTemplate.projectVulnerabilityRepository.findById(vulnId);
            if (projectVulnerability.isPresent() && projectVulnerability.get().getProject().getId().equals(project.get().getId()) && (grade==1 || grade==0)) {
                List<ProjectVulnerability> projectVulnerabilities = vulnTemplate.projectVulnerabilityRepository
                        .findByVulnerabilityAndLocationAndDescription(
                                projectVulnerability.get().getVulnerability(),
                                projectVulnerability.get().getLocation(),
                                projectVulnerability.get().getDescription()
                        );
                projectVulnerabilities.forEach(pv -> pv.setGrade(grade));

                //projectVulnerability.get().setGrade(grade);
                log.info("{} - changed Grade for Vulnerability {} to {}, affected vulnerabilities in {} branches", principal.getName(), projectVulnerability.get().getId(), grade, 0);
                return new ResponseEntity<>( HttpStatus.OK);
            }
        } else {
            return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
        }
        return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
    }

    public ResponseEntity<List<RoutingDomain>> showAllRoutingDomains() {
        return new ResponseEntity<>(findRoutingDomainService.findAll(), HttpStatus.OK);
    }

    public ResponseEntity<ProjectStats> showProjectStats(Long id, Principal principal) {
        Optional<Project> project = findProjectService.findProjectById(id);
        if (project.isPresent() && permissionFactory.canUserAccessProject(principal, project.get())){
            List<ProjectVulnerability> projectVulnerabilities = vulnTemplate.projectVulnerabilityRepository.findByProject(project.get()).collect(Collectors.toList());
            ProjectStats projectStats = ProjectStats.builder()
                    .libs(vulnTemplate.projectVulnerabilityRepository
                            .findByProjectAndVulnerabilitySource(project.get(), vulnTemplate.SOURCE_OPENSOURCE)
                            .map(ProjectVulnerability::getSoftwarePacket)
                            .distinct()
                            .count())
                    .repos(project.get().getCodes().size())
                    .webApps(project.get().getWebapps().size())
                    .assets(project.get().getAssets().size())
                    .vulnCrit(projectVulnerabilities.stream().filter(pv -> (pv.getSeverity().equals(Constants.VULN_CRITICALITY_CRITICAL) || pv.getSeverity().equals(Constants.VULN_CRITICALITY_HIGH)) && !Objects.equals(pv.getStatus().getId(), vulnTemplate.STATUS_REMOVED.getId()) && pv.getGrade()!=0).count())
                    .vulnMedium(projectVulnerabilities.stream().filter(pv -> pv.getSeverity().equals(Constants.VULN_CRITICALITY_MEDIUM) && !Objects.equals(pv.getStatus().getId(), vulnTemplate.STATUS_REMOVED.getId()) && pv.getGrade()!=0).count())
                    .vulnLow(projectVulnerabilities.stream().filter(pv -> pv.getSeverity().equals(Constants.VULN_CRITICALITY_LOW) && !Objects.equals(pv.getStatus().getId(), vulnTemplate.STATUS_REMOVED.getId()) && pv.getGrade()!=0).count())
                    .build();
            return new ResponseEntity<>(projectStats, HttpStatus.OK);

        } else {
            return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
        }
    }

    public ResponseEntity<Project> getProjectByCiid(String ciid, Principal principal) {
        Optional<Project> project = findProjectService.findProjectByCiid(ciid);
        return project.map(value -> new ResponseEntity<>(value, HttpStatus.OK)).orElseGet(() -> new ResponseEntity<>(HttpStatus.NOT_FOUND));
    }

    public ResponseEntity<DetailStats> detailStats(Long id, Principal principal) {
        Optional<Project> project = findProjectService.findProjectById(id);
        if (project.isPresent() && permissionFactory.canUserAccessProject(principal, project.get())){
            List<ProjectVulnerability> projectVulnerabilities = vulnTemplate.projectVulnerabilityRepository.findByProject(project.get()).collect(Collectors.toList());
            int detectedVulnerabilities = projectVulnerabilities.size();
            long detectedCriticalVulnerabilities = projectVulnerabilities.stream().filter(pv -> pv.getSeverity().equals(Constants.API_SEVERITY_CRITICAL)).count();
            long resolvedCriticalVulnerabilities = projectVulnerabilities.stream().filter(pv -> pv.getSeverity().equals(Constants.API_SEVERITY_CRITICAL) && Objects.equals(pv.getStatus().getId(), vulnTemplate.STATUS_REMOVED.getId()) && pv.getGrade()!=0).count();
            List<ProjectVulnerability> solvedVulnerabilities = projectVulnerabilities.stream().filter(pv -> pv.getStatus().getId().equals(vulnTemplate.STATUS_REMOVED.getId())).collect(Collectors.toList());
            int percentResolvedCritical = (int) Math.ceil(((double) resolvedCriticalVulnerabilities / detectedCriticalVulnerabilities) * 100);
            int avgTimeToFix= (int) Math.ceil(calculateAverageDifferenceInDays(solvedVulnerabilities));
            DetailStats detailStats = DetailStats.builder()
                    .resolvedCriticals(percentResolvedCritical)
                    .detectedVulnerabilities(detectedVulnerabilities)
                    .resolvedVulnerabilities(solvedVulnerabilities.size())
                    .avgTimeToFix(avgTimeToFix)
                    .build();
            return new ResponseEntity<>(detailStats, HttpStatus.OK);
        }
        return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
    }

    private static double calculateAverageDifferenceInDays(List<ProjectVulnerability> list) {
        if (list == null || list.isEmpty()) {
            // Handle this case as per your requirements, could throw an exception or return 0
            return 0;
        }

        long sumOfDifferences = 0;
        for (ProjectVulnerability pv : list) {
            sumOfDifferences += pv.calculateDifferenceInDays();
        }

        // Calculate the average
        return sumOfDifferences / (double) list.size();
    }

    public ResponseEntity<List<VulnHistory>> detailedHistory(Long id, Principal principal) {
        Optional<Project> project = findProjectService.findProjectById(id);
        if (project.isPresent() && permissionFactory.canUserAccessProject(principal, project.get())){
            List<VulnHistory> vulnHistories = operateOnVulnHistoryService.getLatestVulnHistoryForProject(project.get());
            return new ResponseEntity<>(vulnHistories, HttpStatus.OK);
        }
        return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
    }
    public ResponseEntity<Status> setProjectUser(Long id, ProjectUser user, Principal principal) {
        Optional<Project> project = findProjectService.findProjectById(id);
        User user_read = findUserService.findByUsername(user.getUser()).orElse(null);

        if (user_read == null){
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }

        if (project.isPresent() && permissionFactory.canUserAccessProject(principal, project.get())) {
            Set<Project> userProjectsSet = user_read.getProjects();
            List<Long> project_list =new ArrayList<>();
            if (userProjectsSet != null)
                for (Project proj : userProjectsSet) {
                    project_list.add(proj.getId());
                }
            project_list.add((project.get().getId()));
            getOrCreateUserService.loadProjectPermissionsForUser(project_list,user_read);
            log.info("{} - grant access to {} to {}", principal.getName(), project.get().getName(),user_read.getUsername());
        }
        return new ResponseEntity<>(HttpStatus.OK);
    }
}
