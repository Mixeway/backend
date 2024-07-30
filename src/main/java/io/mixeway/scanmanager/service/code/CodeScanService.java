package io.mixeway.scanmanager.service.code;

import io.mixeway.api.cicd.model.*;
import io.mixeway.config.Constants;
import io.mixeway.db.entity.*;
import io.mixeway.db.entity.Scanner;
import io.mixeway.db.repository.*;
import io.mixeway.domain.service.cioperations.GetOrCreateCiOperationsService;
import io.mixeway.domain.service.cioperations.UpdateCiOperationsService;
import io.mixeway.domain.service.project.FindProjectService;
import io.mixeway.domain.service.project.GetOrCreateProjectService;
import io.mixeway.domain.service.projectvulnerability.DeleteProjectVulnerabilityService;
import io.mixeway.domain.service.projectvulnerability.GetProjectVulnerabilitiesService;
import io.mixeway.domain.service.scan.CreateScanService;
import io.mixeway.domain.service.scanmanager.code.*;
import io.mixeway.domain.service.scanner.GetScannerService;
import io.mixeway.domain.service.vulnmanager.VulnTemplate;
import io.mixeway.scanmanager.model.CodeAccessVerifier;
import io.mixeway.scanmanager.model.CodeScanRequestModel;
import io.mixeway.scanmanager.model.SASTRequestVerify;
import io.mixeway.utils.*;
import io.mixeway.utils.ScannerType;
import io.mixeway.utils.Status;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.apache.tomcat.util.bcel.Const;
import org.codehaus.jettison.json.JSONException;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.client.HttpClientErrorException;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.text.ParseException;
import java.util.*;

/**
 * @author gsiewruk
 */
@Service
@RequiredArgsConstructor
@Log4j2
public class CodeScanService {
    private final CodeAccessVerifier codeAccessVerifier;
    private final List<CodeScanClient> codeScanClients;
    private final VulnTemplate vulnTemplate;
    private final UpdateCiOperationsService updateCiOperations;
    private final PermissionFactory permissionFactory;
    private final CreateOrGetCodeProjectService createOrGetCodeProjectService;
    private final GetProjectVulnerabilitiesService getProjectVulnerabilitiesService;
    private final FindProjectService findProjectService;
    private final GetOrCreateProjectService getOrCreateProjectService;
    private final FindCodeProjectService findCodeProjectService;
    private final UpdateCodeProjectService updateCodeProjectService;
    private final GetScannerService getScannerService;
    private final OperateOnCodeProject operateOnCodeProject;
    private final GetOrCreateCodeProjectBranchService getOrCreateCodeProjectBranchService;
    private final CreateScanService createScanService;
    private final GetOrCreateCiOperationsService createCiOperationsService;
    private final SecurityQualityGateway securityQualityGateway;

    /**
     * Method for getting CodeVulns for given names
     *
     * @param projectId id of a Project entity
     * @param projectName name of CodeProject entity
     * @return List of a CodeVulns for a given CodeProject
     */
    public ResponseEntity<List<ProjectVulnerability>> getResultsForProject(long projectId, String projectName, Principal principal){
        Optional<Project> project = findProjectService.findProjectById(projectId);
        if (codeAccessVerifier.verifyIfCodeProjectInProject(projectId,projectName).getValid() &&
                project.isPresent() &&
                permissionFactory.canUserAccessProject(principal, project.get())){
            CodeProject cp = createOrGetCodeProjectService.getOrCreateCodeProject(project.get(), projectName, Constants.CODE_DEFAULT_BRANCH);

            return new ResponseEntity<>(getProjectVulnerabilitiesService.getProjectVulnerabilitiesForSource(cp, Constants.FORTIFY_NOT_AN_ISSUE), HttpStatus.OK);

        } else
            return new ResponseEntity<List<ProjectVulnerability>>(new ArrayList<>(), HttpStatus.PRECONDITION_FAILED);
    }

    /**
     * Method of putting CodeProject into scan queue by codeproject.id
     *
     * @param id of CodeProject entity
     * @return true if scan is properly put into queue and false if there is no such CodeProject
     */
    public boolean putCodeProjectToQueue(Long id, Principal principal) {
        Optional<CodeProject> codeProject = findCodeProjectService.findById(id);
        if (codeProject.isPresent() && permissionFactory.canUserAccessProject(principal, codeProject.get().getProject())){
            updateCodeProjectService.putCodeProjectToQueue(codeProject.get());
            return true;
        }
        return false;
    }

    /**
     * Method to return CodeVulns for given CodeGroup. It contains CodeVulns for each CodeProject
     * which is related with given CodeGroup
     *
     * @param projectId id of a Project entity
     * @param groupName name of CodeGroup entity
     * @return List of CodeVulns for given CodeGroup
     */
    public ResponseEntity<List<ProjectVulnerability>> getResultsForProject(long projectId, String groupName){

        if (codeAccessVerifier.verifyIfCodeProjectInProject(projectId,groupName).getValid()){
            Optional<Project> project = findProjectService.findProjectById(projectId);
            if (project.isPresent()) {
                Optional<CodeProject> codeProject = findCodeProjectService.findCodeProject(project.get(), groupName);
                if (codeProject.isPresent()){
                    List<ProjectVulnerability> projectVulnerabilities = getProjectVulnerabilitiesService.getProjectVulnerablitiesForCodeProject(codeProject.get(), Constants.FORTIFY_NOT_AN_ISSUE);
                    new ResponseEntity<>(projectVulnerabilities, HttpStatus.OK);
                }
            }

        } else
            new ResponseEntity<List<ProjectVulnerability>>(new ArrayList<>(), HttpStatus.PRECONDITION_FAILED);
        return null;
    }

    /**
     * Method which puts given CodeProject into scan queue.
     * If there are present objects if CodeProject and CodeGroup they are updated. When CodeScanRequest contains
     * informations about new objects they are created.
     *
     * @param codeScanRequest object passed from REST API
     * @return Status entity with proper HTTPStatus. CREATED when everytihng is ok and BAD_REQUEST if it is not
     */
    public ResponseEntity<Status> performScanFromScanManager(CodeScanRequestModel codeScanRequest, Principal principal) {
        if (codeScanRequest.getCiid() != null && !codeScanRequest.getCiid().equals("")){
            Project project = getOrCreateProjectService.getProjectId(codeScanRequest.getCiid(),codeScanRequest.getProjectName(),principal);
            String requestId = verifyAndCreateOrUpdateCodeProjectInformations(codeScanRequest,project);
            return new ResponseEntity<>(new Status("Scan requested",requestId), HttpStatus.CREATED);

        } else {
            return new ResponseEntity<>(new Status("Missing information about project."), HttpStatus.BAD_REQUEST);
        }
    }

    /**
     * Execute informations sent in CodeScanRequests. There result is to put CodeProject from requenst into scan queue by settin inQueue to true
     * There are three options:
     * 1. Both CodeProject and CodeGroup is new - create both and put CodeProject to queue
     * 2. CodeGroup exist and CodeProject is new - create CodeProject and put it to queue
     * 3. CodeGroup and CodeProject exists - put CodeProject to Queue
     *
     * @param codeScanRequest proper object of CodeScanRequest
     * @param project Project on which behalf request is being executed
     * @return requestId of created scan
     */
    private String verifyAndCreateOrUpdateCodeProjectInformations(CodeScanRequestModel codeScanRequest, Project project) {
        String requestId;
        Optional<CodeProject> codeProject = findCodeProjectService.findCodeProject(project, codeScanRequest.getCodeProjectName());

        if (codeProject.isPresent()){
            updateCodeProjectService.updateCodeProject(codeScanRequest,codeProject.get());
            CodeProject updatedCodeProject = updateCodeProjectService.updateCodeProjectAndPutToQueue(codeScanRequest,codeProject.get());
            requestId = updatedCodeProject.getRequestId();
        } else {
            CodeProject newCodeProject = createOrGetCodeProjectService.createCodeProject(codeScanRequest, project);
            newCodeProject = updateCodeProjectService.putCodeProjectToQueue(newCodeProject);
            requestId = newCodeProject.getRequestId();
        }
        return requestId;
    }


    /**
     * Method which put each codegroup in scan queue by Project.autoCodeScan = true
     */
    public void schedulerRunAutoScans() {
        log.info("Starting to run scheduled scans - scope Source Code [SAST]");
        List<Project> projects = findProjectService.findProjectsWithAutoCodeScan();
        Optional<Scanner> sastScanner = getScannerService.getCodeScanners();
        if ( sastScanner.isPresent() &&  sastScanner.get().getStatus()) {
            for (Project p : projects){
                for (CodeProject cp : p.getCodes()){
                    updateCodeProjectService.putCodeProjectToQueue(cp);
                }
            }
        }
    }

    /**
     * Method which is looking for CodeProject and CodeGroup with running = true
     * Verify if scan is done, and if so loads vulnerabilities
     */
    @Transactional
    public void getResultsForRunningScan() {
        List<Scanner> scanners = getScannerService.findAll();
        Optional<Scanner> sastScanner = getScannerService.getCodeScanners();
        if (sastScanner.isPresent()) {
            List<CodeProject> codeProjectsRunning = findCodeProjectService.findRunningCodeProjectsLimit5();
            for (CodeProject codeProject : codeProjectsRunning) {
                CodeProjectBranch codeProjectBranch  = getOrCreateCodeProjectBranchService.getOrCreateCodeProjectBranch(codeProject, codeProject.getActiveBranch() != null ? codeProject.getActiveBranch() : codeProject.getBranch());
                List<ProjectVulnerability> codeVulns = getProjectVulnerabilitiesService.getOldVulnsForCodeProjectAndSourceForBranch(codeProject, vulnTemplate.SOURCE_SOURCECODE,codeProjectBranch );
                for (CodeScanClient codeScanClient : codeScanClients) {
                    try {
                        if (codeScanClient.canProcessRequest(sastScanner.get()) && codeScanClient.isScanDone(codeProject)) {
                            //CodeProjectBranch codeProjectBranch = findCodeProjectBranchService.findBranchForProjectAndRunning(codeProject);

                            codeScanClient.loadVulnerabilities(sastScanner.get(), null, true, codeProject, codeVulns, codeProjectBranch);
                            // TODO: end codescan
                            updateCiOperations.updateCiOperationsForSAST(codeProject);
                            updateCodeProjectService.endScan(codeProject);
                            if (codeProject.getEnableJira()) {
                                log.info("[CodeScan] Automatic integration with BugTracker enabled, proceeding...");
                                vulnTemplate.processBugTracking(codeProject, vulnTemplate.SOURCE_SOURCECODE);
                            }
                            //deleteProjectVulnerabilityService.deleteRemovedVulnerabilitiesInCodeProject(codeProject);
                            //vulnTemplate.projectVulnerabilityRepository.deleteByStatusAndCodeProject(vulnTemplate.STATUS_REMOVED,codeProject);
                        } else {
                            log.debug("[CodeScan] Scan for {} is still running", codeProject.getName());
                        }
                    } catch (Exception e){
                        e.printStackTrace();
                        log.error("[CodeScanService] There is exception of {} during verifying codeproject off {}", e.getLocalizedMessage(), codeProject.getName());
                    }
                }

            }
        }
    }


    /**
     * Get the CodeProjects and CodeGroups with inQueue=true
     * Verify if scan can be run and then runs it.
     */
    @Transactional
    public void runFromQueue() {
        Optional<Scanner> codeScanner = getScannerService.getCodeScanners();
        if (codeScanner.isPresent() && codeScanner.get().getStatus()) {
            try {
                for (CodeProject cp : findCodeProjectService.findByInQueue(true)) {
                    if (operateOnCodeProject.canScanCodeProject(cp)) {
                        for (CodeScanClient codeScanClient : codeScanClients) {
                            if (codeScanClient.canProcessRequest(cp)) {
                                log.info("[CodeScan] Starting scan form queue [scope {}] {}", cp.getName(), cp.getName());
                                cp = updateCodeProjectService.removeFromQueueAndStart(cp);
                                codeScanClient.runScan( cp);
                                // TODO: create codescan
                            }
                        }
                    }
                }
            } catch (IndexOutOfBoundsException ex) {
                log.debug("Fortify configuration missing");
            } catch (HttpClientErrorException ex) {
                log.warn("HttpClientErrorException with code [{}] during cloud scan job synchro ", ex.getStatusCode().toString());
            } catch (ParseException | JSONException | CertificateException | UnrecoverableKeyException | NoSuchAlgorithmException | KeyManagementException | KeyStoreException | IOException e) {
                log.warn("Exception came up during running scan {}", e.getLocalizedMessage());
                e.printStackTrace();
            }
        }
    }

    /**
     * Get the CodeProjects and CodeGroups with inQueue=true
     * Verify if scan can be run and then runs it.
     */
    @Transactional
    public void runScan(CodeProject codeProject, CodeProjectBranch codeProjectBranch, ProjectMetadata projectMetadata, Principal principal) {
        Optional<Scanner> codeScanner = getScannerService.getCodeScanners();
        if (codeScanner.isPresent() && codeScanner.get().getStatus()) {
            try {
                if (operateOnCodeProject.canScanCodeProject(codeProject)) {
                    for (CodeScanClient codeScanClient : codeScanClients) {
                        if (codeScanClient.canProcessRequest(codeProject)) {
                            log.info("[CodeScan] Starting scan form CICD [scope {}] {}", codeProject.getName(), codeProject.getName());
                            codeProject = updateCodeProjectService.removeFromQueueAndStart(codeProject);
                            codeScanClient.runScan( codeProject, codeProjectBranch);
                            Scan scan = createScanService.createCodeScan(codeProject, projectMetadata.getBranch(),
                                    projectMetadata.getCommitId(),Constants.SAST_LABEL,principal );
                            CiOperations operations = createCiOperationsService.create(projectMetadata, codeProject);
                            updateCiOperations.putScanOnAPipeline(operations, scan, securityQualityGateway.buildGatewayResponse(new ArrayList<>()));

                            // TODO: create codescan
                        }
                    }
                }
            } catch (IndexOutOfBoundsException ex) {
                log.debug("Fortify configuration missing");
            } catch (HttpClientErrorException ex) {
                log.warn("HttpClientErrorException with code [{}] during cloud scan job synchro ", ex.getStatusCode().toString());
            } catch (ParseException | JSONException | CertificateException | UnrecoverableKeyException | NoSuchAlgorithmException | KeyManagementException | KeyStoreException | IOException e) {
                log.warn("Exception came up during running scan {}", e.getLocalizedMessage());
                e.printStackTrace();
            }
        }
    }


    /**
     * Method which run scan for given parameters
     *
     * @param id of project from REST API
     * @param projectName of CodeProject from REST API
     * @return ResponseEntity with HttpStatus.CREATED when scan is properly scheduled, HttpStatus.PRECONDITION_FAILED if it can be not queued.
     */
    @Deprecated
    public ResponseEntity<Status> createScanForCodeProject(Long id, String projectName) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, JSONException, KeyStoreException, ParseException, IOException {
        SASTRequestVerify sastRequestVerify = codeAccessVerifier.verifyIfCodeProjectInProject(id,projectName);
        if (sastRequestVerify.getValid()){
            for(CodeScanClient codeScanClient : codeScanClients){
                if (codeScanClient.canProcessRequest(sastRequestVerify.getCp())){
                    if (codeScanClient.runScan(sastRequestVerify.getCp())){
                        // TODO: Create codescan
                        return new ResponseEntity<>(new Status("OK"), HttpStatus.CREATED);
                    } else {
                        return new ResponseEntity<>(new Status("Queued"), HttpStatus.CREATED);
                    }
                }
            }
        } else {
            return new ResponseEntity<>(new Status("Scan for given resource is not yet configured."), HttpStatus.PRECONDITION_FAILED);
        }
        return new ResponseEntity<>(new Status("Something went wrong"), HttpStatus.PRECONDITION_FAILED);
    }

    /**
     * Used for CI Jobs integrated with Fortify SCA. Gets jobId of manualy executed CloudScan and link it with codeproject in order
     * to get properly vulnerabilities detected by Fortify SSC and CloudScan
     *
     * @param id of project from REST API
     * @param projectName of CodeProject from REST API
     * @param jobId of CloudScan job
     * @return ResponseEntity with HttpStatus.OK when jobId is properly set, HttpStatus.PRECONDITION_FAILED if not.
     */
    @Deprecated
    public ResponseEntity<Status> putInformationAboutJob(Long id, String projectName, String jobId) {
        SASTRequestVerify sastRequestVerify = codeAccessVerifier.verifyIfCodeProjectInProject(id,projectName);
        if (sastRequestVerify.getValid()){
            for(CodeScanClient codeScanClient : codeScanClients){
                if (codeScanClient.canProcessRequest(sastRequestVerify.getCp())){
                    codeScanClient.putInformationAboutScanFromRemote(sastRequestVerify.getCp(), jobId);
                    return new ResponseEntity<>(new Status("OK"), HttpStatus.OK);
                }
            }
        } else {
            return new ResponseEntity<>(new Status("Scan for given resource is not yet configured."), HttpStatus.PRECONDITION_FAILED);
        }
        return new ResponseEntity<>(new Status("Something went wrong"), HttpStatus.PRECONDITION_FAILED);
    }

    /**
     * Method which take List of RunScanForCodeProject objects and then it run scan for every scan from list
     *
     * @param id of Project
     * @param runScanForCodeProjects list of projects where whihch scan should be started
     * @param principal principal who is executing the request
     * @return ResponseEntity with HttpStatus.OK if scan is properly executed HttpStatus.PREDONDITION_FAILED if there is a problem
     */
    public ResponseEntity<Status> codescanrunSelectedCodeProjectsScan(Long id, List<RunScanForCodeProject> runScanForCodeProjects, Principal principal) {
        try {
            Optional<Project> project = findProjectService.findProjectById(id);
            if (project.isPresent() && permissionFactory.canUserAccessProject(principal, project.get())) {
                for (RunScanForCodeProject runScun : runScanForCodeProjects) {
                    Optional<CodeProject> codeProject = findCodeProjectService.findById(runScun.getId());
                    if (codeProject.isPresent() && codeProject.get().getProject() == project.get()) {
                        for(CodeScanClient codeScanClient : codeScanClients){
                            if (codeScanClient.canProcessRequest(codeProject.get())){
                                codeScanClient.runScan( codeProject.get());
                                // TODO: create codescan
                                break;
                            }
                        }
                    }
                }
                log.info("{} - Run SAST scan for {} - scope partial", LogUtil.prepare(principal.getName()), LogUtil.prepare(project.get().getName()));
                return new ResponseEntity<>(HttpStatus.OK);
            }
        } catch (IndexOutOfBoundsException | ParseException | JSONException | CertificateException | UnrecoverableKeyException | NoSuchAlgorithmException | KeyManagementException | KeyStoreException | IOException ioob){
            log.error("Problem with scanning selected projects reason is {}", ioob.getLocalizedMessage());
        }
        return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
    }

    /**
     * Calls Scanner API in order to get SAST Projects scanners
     * Assumes that there is only one scanner of SAST type
     *
     * @return List of SAST Projects from given scanner
     */
    public ResponseEntity<List<SASTProject>> getProjectFromSASTScanner() throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, JSONException, KeyStoreException, ParseException, IOException {
        Optional<Scanner>  scanners = getScannerService.getCodeScanners();
        if (scanners.isPresent()){
            for (CodeScanClient csc : codeScanClients){
                if (csc.canProcessRequest(scanners.get())){
                    return new ResponseEntity<>(csc.getProjects(scanners.get()), HttpStatus.OK);
                }
            }
        }
        return new ResponseEntity<>(new ArrayList<>(), HttpStatus.OK);
    }

    /**
     * Method which execute SAST Scanner API in order to create Project entity on scanne side
     * Assumes that there is only one type of SAST scanner
     *
     * @param id of CodeProject which should be created on SAST Scanner
     * @param projectId id of Project entity
     * @param principal
     * @return HttpStatus.CREATED when project is properly created or HttpStatus.PREDONDITION_FAILED when error occures
     */
    public ResponseEntity<Status> createProjectOnSASTScanner(Long id, Long projectId, Principal principal) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, JSONException, KeyStoreException, ParseException, IOException {
        Optional<Project> project = findProjectService.findProjectById(projectId);
        Optional<CodeProject> codeProject = findCodeProjectService.findById(id);
        Optional<Scanner> scanners = getScannerService.getCodeScanners();
        if (project.isPresent()
                && permissionFactory.canUserAccessProject(principal, project.get())
                && codeProject.isPresent()
                && project.get().getId().equals(codeProject.get().getProject().getId())
                && scanners.isPresent()){
            for (CodeScanClient csc : codeScanClients){
                if (csc.canProcessRequest(scanners.get()) && csc.createProject(scanners.get(), codeProject.get())){
                    return new ResponseEntity<>(new Status("created"), HttpStatus.CREATED);
                }
            }
        }
        return new ResponseEntity<>(HttpStatus.PRECONDITION_FAILED);
    }

    /**
     * Loading vulns from Mixeway scanner push to db
     * @param codeProject project with vulns
     * @param sastVulns list of vulns
     */
    @Transactional
    @Modifying
    public void loadVulnsFromCICDToCodeProject(CodeProject codeProject, List<VulnerabilityModel> sastVulns, ScannerType scannerType) {
        if (sastVulns.isEmpty())
            return;
        VulnerabilitySource vulnerabilitySource = null;
        if (scannerType.equals(ScannerType.SAST)){
            vulnerabilitySource = vulnTemplate.SOURCE_SOURCECODE;
        } else if (scannerType.equals(ScannerType.GITLEAKS)){
            vulnerabilitySource = vulnTemplate.SOURCE_GITLEAKS;
        } else if (scannerType.equals(ScannerType.IAC)){
            vulnerabilitySource = vulnTemplate.SOURCE_IAC;
        }
        List<ProjectVulnerability> oldVulnsForCodeProject = getProjectVulnerabilitiesService.getOldVulnsForCodeProjectAndSource(codeProject,vulnerabilitySource);
        List<ProjectVulnerability> vulnToPersist = new ArrayList<>();
        for (VulnerabilityModel vulnerabilityModel : sastVulns){
            Vulnerability vulnerability = vulnTemplate.createOrGetVulnerabilityService.createOrGetVulnerability(vulnerabilityModel.getName());

            ProjectVulnerability projectVulnerability = new ProjectVulnerability(codeProject,codeProject,vulnerability, vulnerabilityModel.getDescription(),null,
                    vulnerabilityModel.getSeverity(),null,vulnerabilityModel.getFilename()+":"+vulnerabilityModel.getLine(),
                    "", vulnerabilitySource, null,null );

            vulnToPersist.add(projectVulnerability);
        }
        vulnTemplate.vulnerabilityPersistList(oldVulnsForCodeProject, vulnToPersist);

        //deleteProjectVulnerabilityService.deleteProjectVulnerabilityWithStatus(codeProject.getProject(), vulnTemplate.STATUS_REMOVED, vulnerabilitySource);

        vulnTemplate.projectVulnerabilityRepository.flush();
        log.info("[CICD] SourceCode - Loading Vulns for {} completed type of {} number of vulns {}", codeProject.getName(), scannerType, vulnToPersist.size());
    }

    /**
     * Loading vulns from Mixeway scanner push to db - FOR V3 API
     * @param codeProject project with vulns
     * @param sastVulns list of vulns
     */
    @Transactional
    @Modifying
    public void loadVulnsFromCICDToCodeProjectForBranch(CodeProject codeProject, List<VulnerabilityModel> sastVulns, ScannerType scannerType,CodeProjectBranch codeProjectBranch) {
        if (sastVulns.isEmpty())
            return;
        VulnerabilitySource vulnerabilitySource = null;
        if (scannerType.equals(ScannerType.SAST)){
            vulnerabilitySource = vulnTemplate.SOURCE_SOURCECODE;
        } else if (scannerType.equals(ScannerType.GITLEAKS)){
            vulnerabilitySource = vulnTemplate.SOURCE_GITLEAKS;
        } else if (scannerType.equals(ScannerType.IAC)){
            vulnerabilitySource = vulnTemplate.SOURCE_IAC;
        }
        List<ProjectVulnerability> oldVulnsForCodeProject = getProjectVulnerabilitiesService.getOldVulnsForCodeProjectAndSourceForBranch(codeProject,vulnerabilitySource, codeProjectBranch);
        List<ProjectVulnerability> vulnToPersist = new ArrayList<>();
        for (VulnerabilityModel vulnerabilityModel : sastVulns){
            Vulnerability vulnerability = vulnTemplate.createOrGetVulnerabilityService.createOrGetVulnerability(vulnerabilityModel.getName());

            ProjectVulnerability projectVulnerability = new ProjectVulnerability(codeProject,codeProject,vulnerability, vulnerabilityModel.getDescription(),null,
                    vulnerabilityModel.getSeverity(),null,vulnerabilityModel.getFilename()+":"+vulnerabilityModel.getLine(),
                    "", vulnerabilitySource, null,codeProjectBranch );

            vulnToPersist.add(projectVulnerability);
        }
        vulnTemplate.vulnerabilityPersistList(oldVulnsForCodeProject, vulnToPersist);

        //deleteProjectVulnerabilityService.deleteProjectVulnerabilityWithStatus(codeProject.getProject(), vulnTemplate.STATUS_REMOVED, vulnerabilitySource);

        //vulnTemplate.projectVulnerabilityRepository.flush();
        log.info("[CICD] SourceCode - Loading Vulns for {} completed type of {} number of vulns {}", codeProject.getName(), scannerType, vulnToPersist.size());
    }

    public void loadGitleaksReport(GitleaksReport gitleaksReport, CodeProject codeProject, Principal principal){
        CodeProjectBranch codeProjectBranch = getOrCreateCodeProjectBranchService
                .getOrCreateCodeProjectBranch(
                        codeProject,
                        gitleaksReport.getProjectMetadata().getBranch()
                );
        List<ProjectVulnerability> oldVulnsForCodeProject = getProjectVulnerabilitiesService
                .getOldVulnsForCodeProjectAndSourceForBranch(
                        codeProject,
                        vulnTemplate.SOURCE_GITLEAKS,
                        codeProjectBranch
                );
        List<ProjectVulnerability> vulnToPersist = new ArrayList<>();
        for (GitleaksReportEntry entry : gitleaksReport.getFindings()){
            Vulnerability vulnerability = vulnTemplate.createOrGetVulnerabilityService.createOrGetVulnerability(entry.getRuleId() +  " detected");
            String description = entry.getDescription() +
                    "\n\n" +
                    "Author: " +
                    entry.getAuthor() +
                    "\n" +
                    "CommitId: " +
                    entry.getCommit() +
                    "\n" +
                    "File fingerprint: " +
                    entry.getFingerprint();

            ProjectVulnerability projectVulnerability = new ProjectVulnerability(codeProject,codeProject,vulnerability, description,"Rotate secrets as soon as possible, remove secrets from the repository",
                    Constants.VULN_CRITICALITY_CRITICAL,null,entry.getFile()+":"+entry.getStartLine(),
                    "", vulnTemplate.SOURCE_GITLEAKS, null,codeProjectBranch );

            vulnToPersist.add(projectVulnerability);
        }
        vulnTemplate.vulnerabilityPersistList(oldVulnsForCodeProject, vulnToPersist);
        Scan scan = createScanService.createCodeScan(codeProject, codeProjectBranch.getName(), gitleaksReport.getProjectMetadata().getCommitId(),
                Constants.SECRET_LABEL, principal);
        CiOperations operations = createCiOperationsService.create(gitleaksReport.getProjectMetadata(), codeProject);
        updateCiOperations.putScanOnAPipeline(operations, scan, securityQualityGateway.buildGatewayResponse(vulnToPersist));

    }

    public void loadKicsReport(KicsReport kicsReport, CodeProject codeProject, Principal principal) {
        CodeProjectBranch codeProjectBranch = getOrCreateCodeProjectBranchService
                .getOrCreateCodeProjectBranch(
                        codeProject,
                        kicsReport.getProjectMetadata().getBranch()
                );
        List<ProjectVulnerability> oldVulnsForCodeProject = getProjectVulnerabilitiesService
                .getOldVulnsForCodeProjectAndSourceForBranch(
                        codeProject,
                        vulnTemplate.SOURCE_IAC,
                        codeProjectBranch
                );
        List<ProjectVulnerability> vulnToPersist = new ArrayList<>();
            for (KicsQuery query : kicsReport.getFindings().getQueries()){
                Vulnerability vulnerability = vulnTemplate.createOrGetVulnerabilityService.createOrGetVulnerability(query.getName());

                for (KicsFile file : query.getFiles()){
                    String description = query.getDescription() +
                            "\n\n" +
                            "Category: " +
                            query.getCategory() +
                            "\n" +
                            "Evidence: " +
                            file.getActualValue();
                    ProjectVulnerability projectVulnerability = new ProjectVulnerability(codeProject,codeProject,vulnerability, description,file.getExpectedValue(),
                            query.getSeverity(),null,file.getName()+":"+file.getLine(),
                            "", vulnTemplate.SOURCE_IAC, null,codeProjectBranch );

                    vulnToPersist.add(projectVulnerability);
                }
            }

        vulnTemplate.vulnerabilityPersistList(oldVulnsForCodeProject, vulnToPersist);
        Scan scan = createScanService.createCodeScan(codeProject, codeProjectBranch.getName(), kicsReport.getProjectMetadata().getCommitId(),
                Constants.IAC_LABEL, principal);
        CiOperations operations = createCiOperationsService.create(kicsReport.getProjectMetadata(), codeProject);
        updateCiOperations.putScanOnAPipeline(operations, scan, securityQualityGateway.buildGatewayResponse(vulnToPersist));
    }
}
