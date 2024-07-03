package io.mixeway.api.cicd.service;

import io.mixeway.api.cicd.model.GitleaksReport;
import io.mixeway.api.cicd.model.KicsReport;
import io.mixeway.api.cicd.model.LoadSCA;
import io.mixeway.api.cicd.model.ProjectMetadata;
import io.mixeway.api.cioperations.model.ZapReportModel;
import io.mixeway.api.protocol.OpenSourceConfig;
import io.mixeway.api.protocol.cioperations.GetInfoRequest;
import io.mixeway.api.protocol.cioperations.InfoScanPerformed;
import io.mixeway.api.protocol.cioperations.PrepareCIOperation;
import io.mixeway.api.protocol.securitygateway.SecurityGatewayResponse;
import io.mixeway.api.protocol.vulnerability.Vuln;
import io.mixeway.config.Constants;
import io.mixeway.db.entity.*;
import io.mixeway.domain.service.cioperations.CreateCiOperationsService;
import io.mixeway.domain.service.cioperations.FindCiOperationsService;
import io.mixeway.domain.service.cioperations.UpdateCiOperationsService;
import io.mixeway.domain.service.scanmanager.code.CreateOrGetCodeProjectService;
import io.mixeway.domain.service.scanmanager.code.FindCodeProjectService;
import io.mixeway.domain.service.scanmanager.code.GetOrCreateCodeProjectBranchService;
import io.mixeway.domain.service.scanmanager.code.UpdateCodeProjectService;
import io.mixeway.domain.service.vulnmanager.VulnTemplate;
import io.mixeway.scanmanager.service.code.CodeScanService;
import io.mixeway.scanmanager.service.opensource.OpenSourceScanService;
import io.mixeway.scanmanager.service.webapp.WebAppScanService;
import io.mixeway.utils.*;
import io.mixeway.utils.ScannerType;
import io.mixeway.utils.Status;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.apache.commons.lang3.StringUtils;
import org.checkerframework.checker.nullness.Opt;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.net.UnknownHostException;
import java.security.*;
import java.security.cert.CertificateException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Log4j2
public class CICDService {
    private final CreateOrGetCodeProjectService createOrGetCodeProjectService;
    private final OpenSourceScanService openSourceScanService;
    private final FindCodeProjectService findCodeProjectService;
    private final FindCiOperationsService findCiOperationsService;
    private final CreateCiOperationsService createCiOperationsService;
    private final UpdateCodeProjectService updateCodeProjectService;
    private final GetOrCreateCodeProjectBranchService getOrCreateCodeProjectBranchService;
    private final PermissionFactory permissionFactory;
    private final CodeScanService codeScanService;
    private final WebAppScanService webAppScanService;
    private final VulnTemplate vulnTemplate;
    private final SecurityQualityGateway securityQualityGateway;
    private final UpdateCiOperationsService updateCiOperationsService;


    public ResponseEntity<PrepareCIOperation> getCPInfo(GetInfoRequest getInfoRequest, Principal principal) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
        CodeProject codeProject = createOrGetCodeProjectService.createOrGetCodeProject(getInfoRequest.getRepoUrl(), getInfoRequest.getBranch(), getInfoRequest.getRepoName(), principal);
        if (StringUtils.isBlank(codeProject.getdTrackUuid())) {
            openSourceScanService.createProjectOnOpenSourceScanner(codeProject);
        }
        OpenSourceConfig openSourceConfig = openSourceScanService
                .getOpenSourceScannerConfiguration(
                        codeProject.getProject().getId(),
                        codeProject.getName(),
                        codeProject.getName(),
                        principal)
                .getBody();
        // FOR NOW owasp dtrack hardcoded
        return new ResponseEntity<>(new PrepareCIOperation(openSourceConfig, codeProject, "OWASP Dependency Track"), HttpStatus.OK);

    }

    public ResponseEntity<Status> loadSca(LoadSCA loadSCA, Principal principal) throws UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, KeyManagementException {
        Optional<CodeProject> codeProject = findCodeProjectService.findById(loadSCA.getCodeProjectId());
        if (codeProject.isPresent() ){
            Optional<CiOperations> ciOperations = findCiOperationsService.findByCodeProjectAndCommitId(codeProject.get(), loadSCA.getCommitId());
            if (!ciOperations.isPresent()){
                createCiOperationsService.create(codeProject.get(), loadSCA);
            }
            CodeProjectBranch codeProjectBranch = getOrCreateCodeProjectBranchService.getOrCreateCodeProjectBranch(codeProject.get(), loadSCA.getBranch());
            updateCodeProjectService.changeCommitId(loadSCA.getCommitId(), codeProject.get());
            openSourceScanService.loadVulnerabilitiesForBranch(codeProject.get(), loadSCA.getBranch());
            return new ResponseEntity<>(HttpStatus.OK);
        } else {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
    }

    @Transactional
    public ResponseEntity<Status> loadVulnerabilitiesFromCICDToProject(List<VulnerabilityModel> vulns, Long projectId,
                                                                       String branch,
                                                                       String commitId, Principal principal) {
        Optional<CodeProject> codeProject = findCodeProjectService.findById(projectId);
        if (codeProject.isPresent() && permissionFactory.canUserAccessProject(principal, codeProject.get().getProject())) {
            log.info("[CICD] Loading vulns from CICD pipeline for {}, detected vulns {}", codeProject.get().getName(), vulns.size());

            CodeProjectBranch codeProjectBranch = getOrCreateCodeProjectBranchService.getOrCreateCodeProjectBranch(codeProject.get(), branch);
            updateCodeProjectService.changeCommitId(commitId, codeProject.get());


            // to support legacy application where client call SAST while it should be IAC
            List<VulnerabilityModel> sastVulns = vulns.stream().filter(v -> v.getScannerType().equals(ScannerType.IAC)).collect(Collectors.toList());
            if (sastVulns.size() > 0 ){
                log.info("[CICD] Loading vulns from CICD pipeline for {}, IAC type: {}", codeProject.get().getName(), sastVulns.size());
                codeScanService.loadVulnsFromCICDToCodeProjectForBranch(codeProject.get(), sastVulns, ScannerType.IAC, codeProjectBranch);
            } else {
                log.info("[CICD] Loading vulns from CICD pipeline for {}, IAC type: {}", codeProject.get().getName(), 0);
                codeScanService.loadVulnsFromCICDToCodeProjectForBranch(codeProject.get(), new ArrayList<>(), ScannerType.IAC, codeProjectBranch);
            }
            List<VulnerabilityModel> gitLeaksVulns = vulns.stream().filter(v -> v.getScannerType().equals(ScannerType.GITLEAKS)).collect(Collectors.toList());
            if (gitLeaksVulns.size() > 0 ){
                log.info("[CICD] Loading vulns from CICD pipeline for {}, Gitleaks type: {}", codeProject.get().getName(), gitLeaksVulns.size());
                codeScanService.loadVulnsFromCICDToCodeProjectForBranch(codeProject.get(), gitLeaksVulns, ScannerType.GITLEAKS, codeProjectBranch);
            } else {
                log.info("[CICD] Loading vulns from CICD pipeline for {}, Gitleaks type: {}", codeProject.get().getName(), 0);
                codeScanService.loadVulnsFromCICDToCodeProjectForBranch(codeProject.get(), new ArrayList<>(), ScannerType.GITLEAKS, codeProjectBranch);
            }
            //FOR NOW THIS FUNCTIONALITY IS NOT MIGRATED TO V3
//            List<VulnerabilityModel> openSourceVulns = vulns.stream().filter(v -> v.getScannerType().equals(ScannerType.OPENSOURCE)).collect(Collectors.toList());
//            if (openSourceVulns.size() > 0) {
//                openSourceScanService.loadVulnsFromCICDToCodeProject(codeProject.get(), openSourceVulns);
//            } else {
//                openSourceScanService.loadVulnsFromCICDToCodeProject(codeProject.get(), new ArrayList<>());
//            }

            return new ResponseEntity<>(new Status("Vulnerabilities uploaded"), HttpStatus.OK);

        } else {
            return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
        }

    }

    public ResponseEntity<Status> performSastScanForCodeProject(LoadSCA loadSCA, Principal principal) {
        Optional<CodeProject> codeProject = findCodeProjectService.findById(loadSCA.getCodeProjectId());
        if (codeProject.isPresent() && permissionFactory.canUserAccessProject(principal, codeProject.get().getProject())) {
            CodeProjectBranch codeProjectBranch = getOrCreateCodeProjectBranchService.getOrCreateCodeProjectBranch(codeProject.get(), loadSCA.getBranch());
            updateCodeProjectService.updateActiveBranch(codeProject.get(), codeProjectBranch);
            codeScanService.putCodeProjectToQueue(codeProject.get().getId(),principal);

            log.info("[CICD] {} put SAST Project in queue - {}", principal.getName(), codeProject.get().getName());
            return new ResponseEntity<>(HttpStatus.OK);
        } else {
            log.error("[CICD] {} tries to run SAST scan for id {} but project doesnt exist or user has no permission to do so.", principal.getName(), loadSCA.getCodeProjectId());
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
    }

    /**
     * ZAP reports
     */

    @Transactional
    public ResponseEntity<Status> loadVulnZap(ZapReportModel loadVulnModel, String ciid, Principal principal) throws ParseException {
        log.info("ZAP DAST JSON report received for ciid {}", ciid);
        return webAppScanService.prepareAndLoadZapVulns(loadVulnModel,ciid,principal);
    }

    public ResponseEntity<SecurityGatewayResponse> validate(LoadSCA loadSCA, Principal principal) throws UnknownHostException {
        Optional<CodeProject> codeProject = findCodeProjectService.findById(loadSCA.getCodeProjectId());
        if (codeProject.isPresent() && permissionFactory.canUserAccessProject(principal, codeProject.get().getProject())) {
            CodeProjectBranch codeProjectBranch = getOrCreateCodeProjectBranchService.getOrCreateCodeProjectBranch(codeProject.get(), loadSCA.getBranch());


            List<ProjectVulnerability> vulns = vulnTemplate.projectVulnerabilityRepository.findByCodeProjectAndCodeProjectBranch(codeProject.get(), codeProjectBranch).stream().filter(projectVulnerability -> !projectVulnerability.getStatus().equals(vulnTemplate.STATUS_REMOVED)).collect(Collectors.toList());
            List<Vuln> vulnList = new ArrayList<>();
            vulns.removeIf(projectVulnerability -> projectVulnerability.getGrade() == 0);
            for (ProjectVulnerability pv : vulns){
                if (pv.getVulnerabilitySource().getId().equals(vulnTemplate.SOURCE_OPENSOURCE.getId())){
                    vulnList.add(new Vuln(pv,null,null,pv.getCodeProject(),Constants.VULN_TYPE_OPENSOURCE));
                } else if (pv.getVulnerabilitySource().getId().equals(vulnTemplate.SOURCE_SOURCECODE.getId())){
                    vulnList.add(new Vuln(pv,null,null,pv.getCodeProject(),Constants.VULN_TYPE_SOURCECODE));
                } else if (pv.getVulnerabilitySource().getId().equals(vulnTemplate.SOURCE_GITLEAKS.getId())){
                    vulnList.add(new Vuln(pv,null,null,pv.getCodeProject(),Constants.VULN_TYPE_SOURCECODE));
                } else if (pv.getVulnerabilitySource().getId().equals(vulnTemplate.SOURCE_IAC.getId())){
                    vulnList.add(new Vuln(pv,null,null,pv.getCodeProject(),Constants.VULN_TYPE_SOURCECODE));
                }
            }
            vulnList.removeIf(vuln -> vuln.getId() == null);
            SecurityGatewayEntry securityGatewayEntry = securityQualityGateway.buildGatewayResponse(vulns);
            updateCiOperationWithSecurityGatewayResponse(codeProject.get(), securityGatewayEntry);
            return new ResponseEntity<SecurityGatewayResponse>(
                    new SecurityGatewayResponse(securityGatewayEntry.isPassed(),
                            securityGatewayEntry.isPassed() ? Constants.SECURITY_GATEWAY_PASSED : Constants.SECURITY_GATEWAY_FAILED,
                            vulnList),
                    HttpStatus.OK);


         }else {
            log.error("[CICD] {} tries to run Validate project of id {} but project doesnt exist or user has no permission to do so.", principal.getName(), loadSCA.getCodeProjectId());
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
    }

    /**
     * Updating CIOperations entry (for codeproject, branch and commitid) with scan performed, result and vulnerabilities number
     * @param codeProject to edit cioperations
     * @param securityGatewayEntry to check vulnerabilities number
     */
    private void updateCiOperationWithSecurityGatewayResponse(CodeProject codeProject, SecurityGatewayEntry securityGatewayEntry) {
        Optional<CiOperations> ciOperations = findCiOperationsService.findByCodeProjectAndCommitId(codeProject, codeProject.getCommitid());
        ciOperations.ifPresent(operations -> updateCiOperationsService.updateCiOperations(operations, securityGatewayEntry, codeProject));
    }

    public ResponseEntity<?> loadGitleaksReport(GitleaksReport gitleaksReport, long codeProjectid, Principal principal) {
        Optional<CodeProject> codeProject = findCodeProjectService.findById(codeProjectid);
        if (codeProject.isPresent() && permissionFactory.canUserAccessProject(principal, codeProject.get().getProject())){
            log.info("[CICD] Received Gitleaks raport that contains {} findings for {} [{}]", gitleaksReport.getFindings().size(), codeProject.get().getName(), codeProject.get().getRepoUrl());
            if (gitleaksReport.getFindings().size() > 0 ){
                codeScanService.loadGitleaksReport(gitleaksReport, codeProject.get(), principal);
            } else {
                codeScanService.loadVulnsFromCICDToCodeProject(codeProject.get(), new ArrayList<>(), ScannerType.GITLEAKS);
            }
        } else {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
        return new ResponseEntity<>(HttpStatus.BAD_REQUEST);

    }

    public ResponseEntity<?> loadScaVulns(ProjectMetadata projectMetadata, long codeProjectid, Principal principal) throws UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, KeyManagementException {
        Optional<CodeProject> codeProject = findCodeProjectService.findById(codeProjectid);
        if (codeProject.isPresent() && permissionFactory.canUserAccessProject(principal, codeProject.get().getProject())){
            log.info("[CICD] Received info about SCA scan for {} [{}]", codeProject.get().getName(), codeProject.get().getRepoUrl());
            openSourceScanService.loadVulnerabilities(codeProject.get(), projectMetadata, principal);
        } else {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
        return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
    }

    public ResponseEntity<?> loadKicsReport(KicsReport kicsReport, long codeProjectid, Principal principal) {
        Optional<CodeProject> codeProject = findCodeProjectService.findById(codeProjectid);
        if (codeProject.isPresent() && permissionFactory.canUserAccessProject(principal, codeProject.get().getProject())){
            log.info("[CICD] Received KICS raport that contains {} findings for {} [{}]", kicsReport.getFindings().getTotal(), codeProject.get().getName(), codeProject.get().getRepoUrl());
            if (kicsReport.getFindings().getTotal() > 0 ){
                codeScanService.loadKicsReport(kicsReport, codeProject.get(), principal);
            } else {
                codeScanService.loadVulnsFromCICDToCodeProject(codeProject.get(), new ArrayList<>(), ScannerType.IAC);
            }
        } else {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
        return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
    }

    public ResponseEntity<?> startCheckmarxScan(ProjectMetadata projectMetadat, long codeProjectid, Principal principal) {
        Optional<CodeProject> codeProject = findCodeProjectService.findById(codeProjectid);
        if (codeProject.isPresent() && permissionFactory.canUserAccessProject(principal, codeProject.get().getProject())){
            CodeProjectBranch codeProjectBranch = getOrCreateCodeProjectBranchService.getOrCreateCodeProjectBranch(codeProject.get(), projectMetadat.getBranch());
            log.info("[CICD] Starting SAST scan for {} [{}]", codeProject.get().getName(), codeProject.get().getRepoUrl());
            codeScanService.runScan(codeProject.get(),codeProjectBranch, projectMetadat, principal);
        } else {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
        return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
    }
}
