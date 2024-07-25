package io.mixeway.api.cicd.controller;

import io.mixeway.api.cicd.model.GitleaksReport;
import io.mixeway.api.cicd.model.KicsReport;
import io.mixeway.api.cicd.model.LoadSCA;
import io.mixeway.api.cicd.model.ProjectMetadata;
import io.mixeway.api.cicd.service.CICDService;
import io.mixeway.api.cioperations.model.LoadVulnModel;
import io.mixeway.api.cioperations.model.ZapReportModel;
import io.mixeway.api.protocol.cioperations.GetInfoRequest;
import io.mixeway.api.protocol.cioperations.PrepareCIOperation;
import io.mixeway.api.protocol.securitygateway.SecurityGatewayResponse;
import io.mixeway.utils.Status;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.io.IOException;
import java.net.UnknownHostException;
import java.security.*;
import java.security.cert.CertificateException;

@RequiredArgsConstructor
@Controller
@RequestMapping("/v3/api/cicd")
@PreAuthorize("hasAuthority('ROLE_API')")
public class CICDController {
    private final CICDService cicdService;


    /**
     *
     * Request that meant to create CodeProject or return CodeProject by repoUrl contained in getInfoRequest
     *
     * @param getInfoRequest - info with repoURL and branch
     */
    @PostMapping(value = "/codeproject/info")
    public ResponseEntity<PrepareCIOperation> getCPInfo(@Valid @RequestBody GetInfoRequest getInfoRequest, Principal principal) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
        return cicdService.getCPInfo(getInfoRequest, principal);
    }

    /**
     *
     * Request that meant to
     * 1. Create or get proper branch for CodeProject with given ID
     * 2. Call SCA scanner to load vulnerabilities and link those with pair codeproject - codeprojectbranch
     *
     * @param loadSCA
     */
    @PostMapping(value = "/codeproject/load/sca")
    public ResponseEntity<Status> loadSca(@Valid @RequestBody LoadSCA loadSCA, Principal principal) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
        return cicdService.loadSca(loadSCA, principal);
    }


    /**
     *
     * Request that load vulnerabilities from arbitrary sources such as GitLeaks and KICS:
     * 1. Create or get proper branch for CodeProject with given ID
     * 2. Load vulnerabilities to DB and link those with pair CodeProject - CodeProjectBranch
     *
     */
    @PreAuthorize("hasAuthority('ROLE_API')")
    @PostMapping(value="/codeproject/loadvulns/{codeProjectId}")
    public ResponseEntity<Status> loadVulns (@RequestBody LoadVulnModel loadVulnModel,
                                             @PathVariable(value = "codeProjectId") Long id,
                                             Principal principal) throws Exception {
        return cicdService.loadVulnerabilitiesFromCICDToProject(
                loadVulnModel.getVulns(),
                id,
                loadVulnModel.getBranch(),
                loadVulnModel.getCommitId(),
                principal);
    }

    /**
     *
     * Request that start SAST Scan for given scope:
     * 1. Create or get proper branch for CodeProject with given ID
     * 2. Load vulnerabilities to DB and link those with pair CodeProject - CodeProjectBranch
     *
     */
    @PreAuthorize("hasAuthority('ROLE_API')")
    @PostMapping(value = "/codeproject/run/sast")
    public ResponseEntity<Status> performSastScanForCodeProject( @RequestBody LoadSCA loadSCA, Principal principal) throws UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, KeyManagementException {
        return cicdService.performSastScanForCodeProject(loadSCA, principal);
    }


    /**
     *
     * Request that load vulnerabilities from arbitrary sources such as ZAP:
     * 1. Create or get proper branch for CodeProject with given ID
     * 2. Load vulnerabilities to DB and link those with pair CodeProject - CodeProjectBranch
     * TODO Upload report ZAP with info regarding repoUrl to link repo with webapp
     *
     */

    @PreAuthorize("hasAuthority('ROLE_API')")
    @PostMapping(value="/loadvulns/zap/{ciid}")
    public ResponseEntity<Status> loadVulnsZap (@RequestBody ZapReportModel loadVulnModel,
                                                @PathVariable(value = "ciid") String ciid,
                                                Principal principal) throws Exception {
        return cicdService.loadVulnZap(loadVulnModel,ciid,principal);
    }
    @PreAuthorize("hasAuthority('ROLE_API')")
    @PostMapping(value="/loadvulns/zap/{id}")
    public ResponseEntity<Status> loadVulnsZap (@RequestBody ZapReportModel loadVulnModel,
                                                @PathVariable(value = "id") Long id,
                                                Principal principal) throws Exception {
        return cicdService.loadVulnZapId(loadVulnModel,id,principal);
    }

    /**
     * Validate State of security for given CodeProject and Branch
     */
    @CrossOrigin(origins="*")
    @PreAuthorize("hasAuthority('ROLE_API')")
    @PostMapping(value = "/codeproject/validate",produces = "application/json")
    public ResponseEntity<SecurityGatewayResponse> cicdValidate(@RequestBody LoadSCA loadSCA,
                                                                                    Principal principal) throws UnknownHostException {
        return cicdService.validate(loadSCA, principal);
    }

    /**
     * Validate State of security for given CodeProject and Branch
     */
    @CrossOrigin(origins="*")
    @PreAuthorize("hasAuthority('ROLE_API')")
    @PostMapping(value = "/asset/{id}/gitleaks",produces = "application/json")
    public ResponseEntity<?> loadGitleaksReport(@RequestBody GitleaksReport gitleaksReport,
                                                                @PathVariable("id") long codeProjectid,
                                                                Principal principal) throws UnknownHostException {
        return cicdService.loadGitleaksReport(gitleaksReport, codeProjectid, principal);
    }

    /**
     * Validate State of security for given CodeProject and Branch
     */
    @CrossOrigin(origins="*")
    @PreAuthorize("hasAuthority('ROLE_API')")
    @PostMapping(value = "/asset/{id}/sca",produces = "application/json")
    public ResponseEntity<?> loadScaVulns(@RequestBody ProjectMetadata projectMetadata,
                                          @PathVariable("id") long codeProjectid,
                                          Principal principal) throws IOException, UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
        return cicdService.loadScaVulns(projectMetadata, codeProjectid, principal);
    }

    /**
     * Validate State of security for given CodeProject and Branch
     */
    @CrossOrigin(origins="*")
    @PreAuthorize("hasAuthority('ROLE_API')")
    @PostMapping(value = "/asset/{id}/kics",produces = "application/json")
    public ResponseEntity<?> loadKicsReport(@RequestBody KicsReport kicsReport,
                                                @PathVariable("id") long codeProjectid,
                                                Principal principal) throws UnknownHostException {
        return cicdService.loadKicsReport(kicsReport, codeProjectid, principal);
    }
    /**
     * Validate State of security for given CodeProject and Branch
     */
    @CrossOrigin(origins="*")
    @PreAuthorize("hasAuthority('ROLE_API')")
    @PostMapping(value = "/asset/{id}/checkmarx/start",produces = "application/json")
    public ResponseEntity<?> startCheckmarxScan(@RequestBody ProjectMetadata projectMetadat,
                                            @PathVariable("id") long codeProjectid,
                                            Principal principal) throws UnknownHostException {
        return cicdService.startCheckmarxScan(projectMetadat, codeProjectid, principal);
    }
}
