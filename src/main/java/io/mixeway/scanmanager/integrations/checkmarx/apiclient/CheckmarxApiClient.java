package io.mixeway.scanmanager.integrations.checkmarx.apiclient;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.univocity.parsers.csv.CsvRoutines;
import io.mixeway.config.Constants;
import io.mixeway.db.entity.Scanner;
import io.mixeway.db.entity.*;
import io.mixeway.db.repository.*;
import io.mixeway.domain.service.vulnmanager.VulnTemplate;
import io.mixeway.scanmanager.integrations.checkmarx.model.*;
import io.mixeway.scanmanager.model.CodeRequestHelper;
import io.mixeway.scanmanager.model.TokenValidator;
import io.mixeway.scanmanager.service.code.CodeScanClient;
import io.mixeway.scanmanager.service.SecurityScanner;
import io.mixeway.utils.SASTProject;
import io.mixeway.utils.ScannerModel;
import io.mixeway.utils.SecureRestTemplate;
import io.mixeway.utils.VaultHelper;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.NoHttpResponseException;
import org.codehaus.jettison.json.JSONException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.*;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestTemplate;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.text.ParseException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.stream.Collectors;

@Component
public class CheckmarxApiClient implements CodeScanClient, SecurityScanner {
    DateTimeFormatter sdf = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS");
    private static final Logger log = LoggerFactory.getLogger(CheckmarxApiClient.class);
    private final ScannerTypeRepository scannerTypeRepository;
    private final ScannerRepository scannerRepository;
    private final VaultHelper vaultHelper;
    private final SecureRestTemplate secureRestTemplate;
    private final CodeProjectRepository codeProjectRepository;
    private final ProxiesRepository proxiesRepository;
    private final VulnTemplate vulnTemplate;
    private final TokenValidator tokenValidator = new TokenValidator();
    private final GitCredentialsRepository gitCredentialsRepository;

    CheckmarxApiClient(ScannerTypeRepository scannerTypeRepository, ScannerRepository scannerRepository, GitCredentialsRepository gitCredentialsRepository,
                       CodeProjectRepository codeProjectRepository, ProxiesRepository proxiesRepository, VulnTemplate vulnTemplate,
                       VaultHelper vaultHelper, SecureRestTemplate secureRestTemplate){
        this.vaultHelper = vaultHelper;
        this.gitCredentialsRepository = gitCredentialsRepository;
        this.scannerRepository = scannerRepository;
        this.proxiesRepository = proxiesRepository;
        this.scannerTypeRepository = scannerTypeRepository;
        this.codeProjectRepository = codeProjectRepository;
        this.vulnTemplate = vulnTemplate;
        this.secureRestTemplate = secureRestTemplate;
    }
    @Override
    public void loadVulnerabilities(Scanner scanner, String urlToGetNext, Boolean single, CodeProject codeProject, List<ProjectVulnerability> codeVulns, CodeProjectBranch codeProjectBranch) throws ParseException, JSONException, CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException {
        List<CxResultCsvTemplate> cxResults = downloadResultsForScan(scanner,codeProject);
        processVulnReportForCodeProject(cxResults,codeProject,codeVulns, codeProjectBranch);
    }

    @Override
    public Boolean runScan(CodeProject codeProject) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException, JSONException, ParseException {
        Optional<Scanner> cxSast = scannerRepository.findByScannerType(scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_CHECKMARX)).stream().findFirst();
        boolean hasToCreateProject = codeProject.getVersionIdAll() == 0 && codeProject.getRemoteid() ==0;
        if (cxSast.isPresent()){
            if (hasToCreateProject){
                createProject(cxSast.get(),codeProject);
            }
            setGitRepositoryForProject(cxSast.get(),codeProject);
            return createScan(cxSast.get(),codeProject);
        } else {
            log.error("[Checkmarx] Checkmarx detected but no scanener found");
            return false;
        }
    }

    @Override
    public Boolean runScan(CodeProject codeProject, CodeProjectBranch codeProjectBranch) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException, JSONException, ParseException {
        Optional<Scanner> cxSast = scannerRepository.findByScannerType(scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_CHECKMARX)).stream().findFirst();
        boolean hasToCreateProject = codeProject.getVersionIdAll() == 0 && codeProject.getRemoteid() ==0;
        if (cxSast.isPresent()){
            if (hasToCreateProject){
                createProject(cxSast.get(),codeProject);
            }
            setGitRepositoryForProject(cxSast.get(),codeProject, codeProjectBranch);

            return createScan(cxSast.get(),codeProject);
        } else {
            log.error("[Checkmarx] Checkmarx detected but no scanener found");
            return false;
        }
    }

    /**
     * condition has to be fixed
     */
    private void createBranch(Scanner scanner, CodeProject codeProject, CxBranch cxBranch) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, JSONException, KeyStoreException, ParseException, IOException {
        CodeRequestHelper codeRequestHelper = prepareRestTemplate(scanner);
        Long numberOfProjects = codeProjectRepository.getCodeGroupWithVersionIdSet();
        try {
            if (!isProjectAlreadyCreated(codeProject,scanner) && numberOfProjects < 500) {
                ResponseEntity<CxResponseId> response = codeRequestHelper
                        .getRestTemplate()
                        .exchange(scanner.getApiUrl() + Constants.CX_CREATE_PROJECT_API+"/"+codeProject.getVersionIdAll()+"/branch", HttpMethod.POST,
                                new HttpEntity<>(new CxProjectCreate(codeProject), codeRequestHelper.getHttpEntity().getHeaders()),
                                CxResponseId.class);
                if (response.getStatusCode().equals(HttpStatus.CREATED)) {
                    codeProject.setVersionIdAll((int) Objects.requireNonNull(response.getBody()).getId());
                    cxBranch.setCxid((int) Objects.requireNonNull(response.getBody()).getId());
                    //cxBranchRepository.save(cxBranch);
                    codeProjectRepository.save(codeProject);
                    log.info("[Checkmarx] Remote project branch created for {} - {}", codeProject.getName(), codeProject.getBranch());
                }
            }
        } catch (Exception e){
            log.error("[Checkmarx] Error Creating branch - {}", e.getLocalizedMessage());
        }
    }

    @Override
    public boolean isScanDone( CodeProject cp) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException, ParseException, JSONException {
        Optional<Scanner> cxSast = scannerRepository.findByScannerType(scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_CHECKMARX)).stream().findFirst();
        try {
            if (cxSast.isPresent()) {
                CxScan cxScan = getScanInfo(cxSast.get(), cp);
                if (cxScan.getStatus().getName().equals(Constants.CX_STATUS_FAILED)) {
                    cp.setRunning(false);
                    codeProjectRepository.saveAndFlush(cp);
                    log.warn("[Checkmarx] Scan for {} Failed, ending..", cp.getName());
                    return false;
                }
                boolean isScanFinished = cxScan.getStatus().getName().equals(Constants.CX_STATUS_FINISHED);
                boolean isReportGenerationStarged = isScanFinished && (StringUtils.isNotBlank(cp.getJobId()) || generateReport(cxSast.get(), cp));
                boolean isRaportGenerated = isReportGenerationStarged && checkReportState(cxSast.get(), cp);
                return isScanFinished && isReportGenerationStarged && isRaportGenerated;
            } else
                return false;
        } catch (NullPointerException e){
            log.warn("[Checkmarx] Nullpointer Exception during checking scan for {} deactivating it",cp.getName());
            cp.setRunning(false);
            cp.setJobId(null);
            codeProjectRepository.saveAndFlush(cp);
        }
        return false;
    }

    @Override
    public boolean canProcessRequest(CodeProject codeProject) {
        Optional<Scanner> cxSast = scannerRepository.findByScannerType(scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_CHECKMARX)).stream().findFirst();
        return cxSast.isPresent();
    }

    @Override
    public boolean initialize(Scanner scanner) throws Exception {

        return generateToken(scanner) && getTeam(scanner);
    }

    @Override
    public boolean canProcessRequest(Scanner scanner) {
        return scanner.getScannerType().getName().equals(Constants.SCANNER_TYPE_CHECKMARX) && scanner.getStatus();
}

    @Override
    public boolean canProcessInitRequest(Scanner scanner) {
        return scanner.getScannerType().getName().equals(Constants.SCANNER_TYPE_CHECKMARX);
    }

    @Override
    public boolean canProcessRequest(ScannerType scannerType) {
        return scannerType.getName().equals(Constants.SCANNER_TYPE_CHECKMARX);
    }

    @Override
    public Scanner saveScanner(ScannerModel scannerModel) throws Exception {
        List<Scanner>  scanners = scannerRepository.findByScannerTypeInAndStatus(scannerTypeRepository.getCodeScanners(), true);
        Optional<Proxies> proxies = proxiesRepository.findById(scannerModel.getProxy());
        if (scanners.stream().findFirst().isPresent()){
            throw new Exception(Constants.SAST_SCANNER_ALREADY_REGISTERED);
        } else {
            ScannerType scannerType = scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_CHECKMARX);
            Scanner checkmarx = new Scanner();
            checkmarx.setApiUrl(scannerModel.getApiUrl());
            String uuidToken = UUID.randomUUID().toString();
            //checkmarx.setPassword(UUID.randomUUID().toString());
            checkmarx.setUsername(scannerModel.getUsername());
            checkmarx.setStatus(false);
            checkmarx.setScannerType(scannerType);
            proxies.ifPresent(checkmarx::setProxies);
            // api key put to vault
            if (vaultHelper.savePassword(scannerModel.getPassword(), uuidToken)){
                checkmarx.setPassword(uuidToken);
            } else {
                checkmarx.setPassword(scannerModel.getPassword());
            }
            return scannerRepository.save(checkmarx);
        }

    }

    /**
     * configure granch and git URL for
     * @param scanner
     * @param codeProject
     */
    private void setGitRepositoryForProject(Scanner scanner, CodeProject codeProject) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, JSONException, KeyStoreException, ParseException, IOException {
        CodeRequestHelper codeRequestHelper = prepareRestTemplate(scanner);
        String passwordString = getPasswordStringForCodeProejct(codeProject);
        HttpEntity<CxSetGitRepo> cxSetGitRepoHttpEntity = new HttpEntity<>(new CxSetGitRepo(codeProject, passwordString), codeRequestHelper.getHttpEntity().getHeaders());
        ObjectMapper mapper = new ObjectMapper();
        log.debug("[Checkmarx] Setting git repo {}", mapper.writeValueAsString(cxSetGitRepoHttpEntity));
        codeRequestHelper.setHttpEntity(cxSetGitRepoHttpEntity);
        try {
            int remoteId = (codeProject.getRemoteid() == 0) ? codeProject.getVersionIdAll() : (codeProject.getVersionIdAll() == 0) ? codeProject.getRemoteid() : codeProject.getVersionIdAll();
            ResponseEntity<String> response = codeRequestHelper
                    .getRestTemplate()
                    .exchange(scanner.getApiUrl() + Constants.CX_GET_PROJECTS_API + "/" + remoteId + "/sourceCode/remoteSettings/git", HttpMethod.POST, codeRequestHelper.getHttpEntity(), String.class);
            log.info("[Checkmarx] Setting GIT repo for {} result {}", codeProject.getName(), response.getStatusCode());
        } catch (Exception e){
            log.error("[Checkmarx] Error setting GIT repo for project {} - {}",codeProject.getName(), e.getLocalizedMessage());
        }
    }
    /**
     * configure granch and git URL for
     * @param scanner
     * @param codeProject
     */
    private void setGitRepositoryForProject(Scanner scanner, CodeProject codeProject, CodeProjectBranch codeProjectBranch) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, JSONException, KeyStoreException, ParseException, IOException {
        CodeRequestHelper codeRequestHelper = prepareRestTemplate(scanner);
        String passwordString = getPasswordStringForCodeProejct(codeProject);
        HttpEntity<CxSetGitRepo> cxSetGitRepoHttpEntity = new HttpEntity<>(new CxSetGitRepo(codeProject, passwordString, codeProjectBranch), codeRequestHelper.getHttpEntity().getHeaders());
        ObjectMapper mapper = new ObjectMapper();
        log.debug("[Checkmarx] Setting git repo {}", mapper.writeValueAsString(cxSetGitRepoHttpEntity));
        codeRequestHelper.setHttpEntity(cxSetGitRepoHttpEntity);
        try {
            int remoteId = (codeProject.getRemoteid() == 0) ? codeProject.getVersionIdAll() : (codeProject.getVersionIdAll() == 0) ? codeProject.getRemoteid() : codeProject.getVersionIdAll();
            ResponseEntity<String> response = codeRequestHelper
                    .getRestTemplate()
                    .exchange(scanner.getApiUrl() + Constants.CX_GET_PROJECTS_API + "/" + remoteId + "/sourceCode/remoteSettings/git", HttpMethod.POST, codeRequestHelper.getHttpEntity(), String.class);
            log.info("[Checkmarx] Setting GIT repo for {} result {}", codeProject.getName(), response.getStatusCode());
        } catch (Exception e){
            log.error("[Checkmarx] Error setting GIT repo for project {} - {}",codeProject.getName(), e.getLocalizedMessage());
        }
    }

    /**
     * get auth string for particular project:
     * user:password if password auth is enabled
     * key if key auth is enabled
     * null when no auth is needed
     *
     * @param codeProject
     * @return
     */
    private String getPasswordStringForCodeProejct(CodeProject codeProject) throws MalformedURLException {
        boolean isPasswordAndUsernameNotBlank = StringUtils.isNotBlank(codeProject.getRepoUsername()) && StringUtils.isNotBlank(codeProject.getRepoPassword());
        boolean isPasswordANotBlank = StringUtils.isNotBlank(codeProject.getRepoPassword());
        if (isPasswordAndUsernameNotBlank){
            return codeProject.getRepoUsername()+":"+vaultHelper.getPassword(codeProject.getRepoPassword());
        } else if(isPasswordANotBlank){
            return vaultHelper.getPassword(codeProject.getRepoPassword());
        } else {
            URL repoUrl = new URL(codeProject.getRepoUrl());
            Optional<GitCredentials> gitCredentials = gitCredentialsRepository.findByUrl(repoUrl.getHost());
            if (gitCredentials.isPresent()){
                boolean isGlobalPasswordAndUsernameNotBlank = StringUtils.isNotBlank(gitCredentials.get().getUsername()) && StringUtils.isNotBlank(gitCredentials.get().getPassword());
                boolean isGlobalPasswordANotBlank = StringUtils.isNotBlank(gitCredentials.get().getPassword());

                if (isGlobalPasswordAndUsernameNotBlank) {
                    return gitCredentials.get().getUsername()+":"+vaultHelper.getPassword(gitCredentials.get().getPassword());
                } else if (isGlobalPasswordANotBlank){
                    return vaultHelper.getPassword(gitCredentials.get().getPassword());
                }
            }
        }
        return null;
    }

    /**
     * Function calling Checkmarx rest API login function
     *
     */
    private boolean generateToken(Scanner scanner) {
        try {
            MultiValueMap<String, String> formEncodedForLogin = createFormForLogin(scanner);
            RestTemplate restTemplate = secureRestTemplate.prepareClientWithCertificate(scanner);
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
            HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(formEncodedForLogin, headers);
            String API_GET_TOKEN = "/cxrestapi/auth/identity/connect/token";
            ResponseEntity<CxLoginResponse> response = restTemplate.exchange(scanner.getApiUrl() + API_GET_TOKEN, HttpMethod.POST, entity, CxLoginResponse.class);
            if (response.getStatusCode() == HttpStatus.OK) {
                LocalDateTime ldt = LocalDateTime.now().plusSeconds(Objects.requireNonNull(response.getBody()).getExpires_in());
                scanner.setFortifytokenexpiration(ldt.format(sdf));
                scanner.setFortifytoken(response.getBody().getAccess_token());
                if(!scanner.getStatus()){
                    scanner.setStatus(true);
                }
                scannerRepository.save(scanner);
                return true;
            } else {
                log.error("Checkmarx Authorization failure");
                return false;
            }
        } catch (Exception e){
            log.error("Error during getting teams from Checkmarx - {}", e.getLocalizedMessage());
            return false;
        }


    }

    private MultiValueMap<String, String> createFormForLogin(Scanner scanner) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add(Constants.CHECKMARX_LOGIN_FORM_USERNAME, scanner.getUsername());
        form.add(Constants.CHECKMARX_LOGIN_FORM_PASSWORD, vaultHelper.getPassword(scanner.getPassword()));
        form.add(Constants.CHECKMARX_LOGIN_FORM_GRANT_TYPE, Constants.CHECKMARX_LOGIN_FORM_GRANT_TYPE_VALUE);
        form.add(Constants.CHECKMARX_LOGIN_FORM_SCOPE,Constants.CHECKMARX_LOGIN_FORM_SCOPE_VALUE);
        form.add(Constants.CHECKMARX_LOGIN_FORM_CLIENTID, Constants.CHECKMARX_LOGIN_FORM_CLIENTID_VALUE);
        form.add(Constants.CHECKMARX_LOGIN_FORM_CLIENTSECRET, Constants.CHECKMARX_LOGIN_FORM_CLIENTSECRET_VALUE);
        return form;
    }
    private CodeRequestHelper prepareRestTemplate(Scanner scanner) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, JSONException, KeyStoreException, ParseException, IOException {
        try {
            if (tokenValidator.isTokenValid(scanner.getFortifytoken(), LocalDateTime.parse(scanner.getFortifytokenexpiration(), sdf))) {
                generateToken(scanner);
            }
        } catch (NullPointerException e){
            generateToken(scanner);
        }
        RestTemplate restTemplate = secureRestTemplate.prepareClientWithCertificate(scanner);
        HttpHeaders headers = new HttpHeaders();
        headers.set(Constants.HEADER_AUTHORIZATION, Constants.BEARER_TOKEN + " " + scanner.getFortifytoken());
        HttpEntity entity = new HttpEntity(headers);

        return new CodeRequestHelper(restTemplate,entity);
    }
    private boolean getTeam(Scanner scanner) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, JSONException, KeyStoreException, ParseException, IOException {
        CodeRequestHelper codeRequestHelper = prepareRestTemplate(scanner);
        try {
            ResponseEntity<List<CxTeamResponse>> response = codeRequestHelper
                    .getRestTemplate()
                    .exchange(scanner.getApiUrl() + Constants.CX_GET_TEAMS_API, HttpMethod.GET, codeRequestHelper.getHttpEntity(), new ParameterizedTypeReference<List<CxTeamResponse>>() {});
            if (response.getStatusCode().equals(HttpStatus.OK) && Objects.requireNonNull(response.getBody()).stream().findFirst().isPresent()) {
                scanner.setTeam(Objects.requireNonNull(Objects.requireNonNull(response.getBody()).stream().findFirst().orElse(null)).getId());
                scannerRepository.save(scanner);
                return true;
            }
        } catch (HttpClientErrorException e){
            log.error("Error during getting teams from Checkmarx - {}", e.getLocalizedMessage());
        }
        return false;
    }
    @Override
    public List<SASTProject> getProjects(Scanner scanner) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, JSONException, KeyStoreException, ParseException, IOException {
        CodeRequestHelper codeRequestHelper = prepareRestTemplate(scanner);
        List<SASTProject> sastProjects = new ArrayList<>();
        try {
            ResponseEntity<List<CxProject>> response = codeRequestHelper
                    .getRestTemplate()
                    .exchange(scanner.getApiUrl() + Constants.CX_GET_PROJECTS_API, HttpMethod.GET, codeRequestHelper.getHttpEntity(), new ParameterizedTypeReference<List<CxProject>>() {});
            if (response.getStatusCode().equals(HttpStatus.OK) && Objects.requireNonNull(response.getBody()).stream().findFirst().isPresent()) {
                for (CxProject project : response.getBody()){
                    sastProjects.add(new SASTProject(project.getId(),project.getName()));
                }
            }
        } catch (Exception e){
            log.error("[Checkmarx] Error during loading projects from Checkmarx - {}", e.getLocalizedMessage());
        }
        return sastProjects;
    }
    @Override
    @Transactional
    public boolean createProject(Scanner scanner, CodeProject codeProject) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, JSONException, KeyStoreException, ParseException, IOException {
        CodeRequestHelper codeRequestHelper = prepareRestTemplate(scanner);
        Long numberOfProjects = codeProjectRepository.getCodeGroupWithVersionIdSet();
        try {
            if (!isProjectAlreadyCreated(codeProject,scanner) && numberOfProjects < 500) {
                ResponseEntity<CxResponseId> response = codeRequestHelper
                        .getRestTemplate()
                        .exchange(scanner.getApiUrl() + Constants.CX_CREATE_PROJECT_API, HttpMethod.POST,
                                new HttpEntity<>(new CxProjectCreate(codeProject.getName(), scanner), codeRequestHelper.getHttpEntity().getHeaders()),
                                CxResponseId.class);
                if (response.getStatusCode().equals(HttpStatus.CREATED)) {
                    codeProject.setVersionIdAll((int) Objects.requireNonNull(response.getBody()).getId());
                    codeProject.setRemoteid((int) Objects.requireNonNull(response.getBody()).getId());
                    //updateBranch(codeProject);
                    codeProjectRepository.save(codeProject);
                    log.info("[Checkmarx] Remote project created for {}", codeProject.getName());
                    return true;
                }
            }
        } catch (Exception e){
            log.error("[Checkmarx] Error creating project - {}", e.getLocalizedMessage());
        }
        return codeProject.getVersionIdAll() > 0;
    }

//    private void updateBranch(CodeProject codeProject) {
//        Optional<CxBranch> cxBranch = cxBranchRepository.findByBranchAndCodeProject(codeProject.getBranch(), codeProject);
//        cxBranch.ifPresent(branch -> branch.setCxid(codeProject.getCodeGroup().getVersionIdAll()));
//    }

    public boolean isProjectAlreadyCreated(CodeProject codeProject, Scanner scanner) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, JSONException, KeyStoreException, ParseException, IOException {
        List<SASTProject> sastProjects = getProjects(scanner);
        List<SASTProject> filteredProject = sastProjects.stream().filter(p -> p.getName().equals(codeProject.getName())).collect(Collectors.toList());
        if (filteredProject.size() == 1){
            codeProject.setVersionIdAll((int) filteredProject.get(0).getId());
            codeProjectRepository.save(codeProject);
            log.info("[Checkmarx] No need to create new project on CX - project {} already exists", codeProject.getName());
            return true;
        } else if (filteredProject.size() == 0){
            return false;
        } else {
            log.warn("[Checkmarx] Something strage durign project creation, list of project with name `{}` is size of: {}", codeProject.getName(), filteredProject.size());
            return true;
        }
    }

    @Override
    public void putInformationAboutScanFromRemote(CodeProject codeProject, String jobId) {
        log.info("Checkmarx putInformationAboutScanFromRemote not yet implemented");
    }

    private boolean createProjectGitLink(Scanner scanner, CodeProject codeProject) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, JSONException, KeyStoreException, ParseException, IOException {
        CodeRequestHelper codeRequestHelper = prepareRestTemplate(scanner);
        try {
            ResponseEntity<String> response = codeRequestHelper
                    .getRestTemplate()
                    .exchange(scanner.getApiUrl() + Constants.CX_CREATE_GIT_FOR_PROJECT_API.replace(Constants.CX_PROJECTID, String.valueOf(codeProject.getVersionIdAll())), HttpMethod.POST,
                            new HttpEntity<>(new CxGitCreate(codeProject,vaultHelper.getPassword(codeProject.getRepoPassword())),codeRequestHelper.getHttpEntity().getHeaders()),
                            String.class);
            if (response.getStatusCode().equals(HttpStatus.NO_CONTENT) || response.getStatusCode().equals(HttpStatus.OK)) {
                log.info("CX - Successfull set GIT for {}", codeProject.getName());
                return true;
            }
        } catch (HttpClientErrorException e){
            log.error("Error during loading projects from Checkmarx - {}", e.getStatusCode());
        }
        return false;
    }
    private boolean createScan(Scanner scanner, CodeProject codeProject) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, JSONException, KeyStoreException, ParseException, IOException {
        CodeRequestHelper codeRequestHelper = prepareRestTemplate(scanner);
        try {
            ResponseEntity<CxResponseId> response = codeRequestHelper
                    .getRestTemplate()
                    .exchange(scanner.getApiUrl() + Constants.CX_CREATE_SCAN_API, HttpMethod.POST,
                            new HttpEntity<>(new CxCreateScan(codeProject),codeRequestHelper.getHttpEntity().getHeaders()),
                            CxResponseId.class);
            if (response.getStatusCode().equals(HttpStatus.CREATED) ) {
                codeProject.setRunning(true);
                codeProject.setScanid(Long.toString(Objects.requireNonNull(response.getBody()).getId()));
                codeProjectRepository.save(codeProject);
                log.info("[Checkmarx] Successfull Created and started scan for {}", codeProject.getName());
                return true;
            }
        } catch (HttpClientErrorException | HttpServerErrorException e){
            log.error("[Checkmarx] Error creating scan - {}", e.getStatusCode());
            codeProject.setRunning(false);
            codeProjectRepository.save(codeProject);

        } catch (ResourceAccessException e) {
            log.error("[Checkmarx] Error creating the scan - checkmarx not avaliable");
        }
        return false;
    }
    private CxScan getScanInfo(Scanner scanner, CodeProject codeProject) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, JSONException, KeyStoreException, ParseException, IOException {
        CodeRequestHelper codeRequestHelper = prepareRestTemplate(scanner);
        try {
            ResponseEntity<CxScan> response = codeRequestHelper
                    .getRestTemplate()
                    .exchange(scanner.getApiUrl() + Constants.CX_GET_SCAN_API.replace(Constants.CX_SCANID, codeProject.getScanid()), HttpMethod.GET,
                            codeRequestHelper.getHttpEntity(),
                           CxScan.class);
            if (response.getStatusCode().equals(HttpStatus.OK) ) {
                return response.getBody();
            }
        } catch (HttpClientErrorException e){
            log.error("[Checkmarx] Error getting scan Infos - {}", e.getStatusCode());
        }
        return null;
    }
    private boolean generateReport(Scanner scanner, CodeProject codeProject) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, JSONException, KeyStoreException, ParseException, IOException {
        CodeRequestHelper codeRequestHelper = prepareRestTemplate(scanner);
        try {
            ResponseEntity<CxResponseId> response = codeRequestHelper
                    .getRestTemplate()
                    .exchange(scanner.getApiUrl() + Constants.CX_GNERATE_REPORT_API, HttpMethod.POST,
                            new HttpEntity<>(new CxReportGenerate(codeProject),codeRequestHelper.getHttpEntity().getHeaders()),
                            CxResponseId.class);
            if (response.getStatusCode().equals(HttpStatus.ACCEPTED) ) {
                codeProject.setJobId(String.valueOf(Objects.requireNonNull(response.getBody()).getReportId()));
                codeProjectRepository.saveAndFlush(codeProject);
                log.info("[Checkmarx] Report generation for {} started, jobid {}", codeProject.getName(), codeProject.getJobId());
                return true;
            }
        } catch (HttpClientErrorException e){
            log.error("[Checkmarx] Error during report generation - {}", e.getStatusCode());
            codeProject.setScanid(null);
        }
        return false;
    }
    private boolean checkReportState(Scanner scanner, CodeProject codeProject) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, JSONException, KeyStoreException, ParseException, IOException {
        CodeRequestHelper codeRequestHelper = prepareRestTemplate(scanner);
        try {
            ResponseEntity<CxReportStatus> response = codeRequestHelper
                    .getRestTemplate()
                    .exchange(scanner.getApiUrl() + Constants.CX_GET_REPORT_STATUS_API.replace(Constants.CX_REPORTID,codeProject.getJobId()), HttpMethod.GET,
                            codeRequestHelper.getHttpEntity(),
                            CxReportStatus.class);
            if (response.getStatusCode().equals(HttpStatus.OK) ) {
                if (response.getBody().getStatus().getValue().equals(Constants.CX_STATUS_CREATED)){
                    log.info("[Checkmarx] Report generation state for {} is {}", codeProject.getName(), response.getBody().getStatus().getValue());
                    codeProject.setRunning(false);
                    codeProjectRepository.saveAndFlush(codeProject);
                    return true;
                }

            }
        } catch (HttpClientErrorException e){
            log.error("[Checkmarx] Error During checking report state - {}", e.getStatusCode());
            codeProject.setScanid(null);
        }
        return false;
    }
    private List<CxResultCsvTemplate> downloadResultsForScan(Scanner scanner, CodeProject codeProject) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, JSONException, KeyStoreException, ParseException, IOException {
        CodeRequestHelper codeRequestHelper = prepareRestTemplate(scanner);
        if (codeProject.getJobId() == null) {
            generateReport(scanner, codeProject);
        }
        try {
            ResponseEntity<String> response = codeRequestHelper
                    .getRestTemplate()
                    .exchange(scanner.getApiUrl() + Constants.CX_GET_RESULTS_API.replace(Constants.CX_REPORTID,codeProject.getJobId()), HttpMethod.GET,
                            codeRequestHelper.getHttpEntity(),
                            String.class);
            if (response.getStatusCode().equals(HttpStatus.OK) ) {
                codeProject.setRunning(false);
                codeProject.setJobId(null);
                codeProjectRepository.saveAndFlush(codeProject);
                log.info("[Checkmarx] Report for {} is ready to be downloaded", codeProject.getName());
                return processCsvReport(response.getBody(),codeProject);
            } else {
                log.info("[Checkmarx] Got {} during scan downloading {} - message {}", response.getStatusCode(), codeProject.getName(), response.getBody());
            }
        } catch (HttpClientErrorException e){
            log.error("[Checkmarx] Error during downloadig results for scan - {}", e.getStatusCode());
            codeProject.setScanid(null);
        } catch (NullPointerException npe ){
            log.warn("[Checkmarx] cannot download report for {} - no report Id available", codeProject.getName());
            codeProject.setScanid(null);
        }
        return new ArrayList<>();
    }

    private List<CxResultCsvTemplate> processCsvReport(String body, CodeProject codeProject) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, JSONException, KeyStoreException, ParseException, IOException {
       try {
           body = body.substring(3);
//           Map<String, String> mapping = new
//                   HashMap<>();
//           mapping.put(Constants.CX_REPORT_QUERY, "query");
//           mapping.put(Constants.CX_REPORT_DSTFILE, "dstLocation");
//           mapping.put(Constants.CX_REPORT_DSTLINENO, "dstLine");
//           mapping.put(Constants.CX_REPORT_ANALYSIS, "analysis");
//           mapping.put(Constants.CX_REPORT_SEVERITY, "severity");
//           mapping.put(Constants.CX_REPORT_DESCRIPTION, "description");
//           mapping.put(Constants.CX_REPORT_STATE, "state");
//           HeaderColumnNameTranslateMappingStrategy<CxResult> strategy =
//                   new HeaderColumnNameTranslateMappingStrategy<>();
//           strategy.setType(CxResult.class);
//           strategy.setColumnMapping(mapping);
//           CSVReader csvReader = null;
//           CsvToBean<CxResult> csvToBean = new CsvToBeanBuilder(new StringReader(body))
//                   .withType(CxResult.class)
//                   .withMappingStrategy(strategy)
//                   .withIgnoreLeadingWhiteSpace(true)
//                   .build();
//List<CxResult> results = csvToBean.parse()
           List<CxResultCsvTemplate> results = new CsvRoutines().parseAll(CxResultCsvTemplate.class,new ByteArrayInputStream(body.getBytes(StandardCharsets.UTF_8))).stream().filter(cxResult -> cxResult.getSeverity().equals("High") || cxResult.getSeverity().equals("Medium")).collect(Collectors.toList());
           results.forEach(f -> {
               try {
                   f.setDescription(getShortDescription(codeProject, f).getShortDescription());
               } catch (Exception e) {
                   log.error("[Checkmarx] Problem with setting description for one of {}", codeProject.getName());
               }
           });
           log.info("[Checkmarx] Loaded {} vulnerabilities for {}", results.size(),codeProject.getName());
           return results;
       }catch(Exception e){
           log.error("[Checkmarx] Error during csv parsing {}", e.getLocalizedMessage());
       }
       return new ArrayList<>();
    }

    /**
     * load vulnerabilities to database
     * @param results
     * @param codeProject
     */
    private void processVulnReportForCodeProject(List<CxResultCsvTemplate> results, CodeProject codeProject, List<ProjectVulnerability> oldVulns, CodeProjectBranch codeProjectBranch) {
        List<ProjectVulnerability> vulnsToPersist = new ArrayList<>();
        for (CxResultCsvTemplate cxVuln: results) {
            Vulnerability vulnerability = vulnTemplate.createOrGetVulnerabilityService.createOrGetVulnerability(cxVuln.getQuery());

            ProjectVulnerability projectVulnerability = new ProjectVulnerability(codeProject,codeProject,vulnerability,cxVuln.getDescription(),null,
                    cxVuln.getSeverity(),null,cxVuln.getDstLocation()+":"+cxVuln.getDstLine(),getTag(cxVuln.getAnalysis()), vulnTemplate.SOURCE_SOURCECODE, null, codeProjectBranch );

            vulnsToPersist.add(projectVulnerability);
        }
        vulnTemplate.vulnerabilityPersistList(oldVulns, vulnsToPersist);
    }

    private String getTag(String analysis) {
        switch (analysis) {
            case Constants.CX_ANALYSIS_TO_VERIFY:
                return null;
            case Constants.CX_ANALYSIS_NOT_EXPLOITABLE:
            case Constants.CX_ANALYSIS_FP:
                return Constants.FORTIFY_NOT_AN_ISSUE;
            case Constants.CX_ANALYSIS_CONFIRMED:
            case Constants.CX_ANALYSIS_URGENT:
                return Constants.FORTIFY_ANALYSIS_EXPLOITABLE;
        }
        return null;
    }

    /**
     * get single result
     */
    private CxVulnShortDescription getShortDescription(CodeProject codeProject,CxResultCsvTemplate cxResult) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, JSONException, KeyStoreException, ParseException, IOException {
        Optional<Scanner> cxSast = scannerRepository.findByScannerType(scannerTypeRepository.findByNameIgnoreCase(Constants.SCANNER_TYPE_CHECKMARX)).stream().findFirst();
        if (cxSast.isPresent()){
            CodeRequestHelper codeRequestHelper = prepareRestTemplate(cxSast.get());
            String v = "";
            String uri = "";
            try {
                v = cxResult.getDescription().substring(cxResult.getDescription().indexOf("pathid=") + 7);
                uri = "/cxrestapi/sast/scans/"+codeProject.getScanid()+"/results/"+v+"/shortDescription";
                ResponseEntity<CxVulnShortDescription> response = codeRequestHelper
                        .getRestTemplate()
                        .exchange(cxSast.get().getApiUrl() + uri
                                , HttpMethod.GET,
                                codeRequestHelper.getHttpEntity(),
                                CxVulnShortDescription.class);
                return response.getBody();
            } catch (Exception e){
                log.error("[Checkmarx] Error getShortDescription project {} - v-{}, uri-{}",codeProject.getName(), v,uri);
            }
        }
        return null;
    }

}
