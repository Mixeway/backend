package io.mixeway.scanmanager.service.webapp;

import io.mixeway.api.cioperations.model.ZapAlertModel;
import io.mixeway.api.cioperations.model.ZapInstancesModel;
import io.mixeway.api.cioperations.model.ZapReportModel;
import io.mixeway.api.cioperations.model.ZapSiteModel;
import io.mixeway.config.Constants;
import io.mixeway.db.entity.*;
import io.mixeway.db.entity.Scanner;
import io.mixeway.domain.service.project.FindProjectService;
import io.mixeway.domain.service.project.GetOrCreateProjectService;
import io.mixeway.domain.service.projectvulnerability.DeleteProjectVulnerabilityService;
import io.mixeway.domain.service.projectvulnerability.GetProjectVulnerabilitiesService;
import io.mixeway.domain.service.scanmanager.webapp.FindWebAppService;
import io.mixeway.domain.service.scanmanager.webapp.GetOrCreateWebAppService;
import io.mixeway.domain.service.scanmanager.webapp.UpdateWebAppService;
import io.mixeway.domain.service.scanner.GetScannerService;
import io.mixeway.domain.service.scanner.UpdateScannerService;
import io.mixeway.domain.service.vulnmanager.CreateOrGetVulnerabilityService;
import io.mixeway.domain.service.vulnmanager.VulnTemplate;
import io.mixeway.scanmanager.model.WebAppScanModel;
import io.mixeway.utils.*;
import io.mixeway.utils.Status;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.checkerframework.checker.nullness.Opt;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.client.HttpClientErrorException;

import java.security.Principal;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.stream.Collectors;

/**
 * @author gsiewruk
 */
@Service
@Log4j2
@RequiredArgsConstructor
public class WebAppScanService {
    private final List<WebAppScanClient> webAppScanClients;
    private final VulnTemplate vulnTemplate;
    private final PermissionFactory permissionFactory;
    private final FindProjectService findProjectService;
    private final UpdateWebAppService updateWebAppService;
    private final GetOrCreateWebAppService getOrCreateWebAppService;
    private final FindWebAppService findWebAppService;
    private final GetScannerService getScannerService;
    private final GetProjectVulnerabilitiesService getProjectVulnerabilitiesService;
    private final UpdateScannerService updateScannerService;
    private final GetOrCreateProjectService getOrCreateProjectService;
    private final CreateOrGetVulnerabilityService CreateOrGetVulnerabilityService;
    private final DeleteProjectVulnerabilityService deleteProjectVulnerabilityService;

    private SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");



    /**
     * Method which is processing webapp from REST API to create or update and put in queue.
     * It verify if there are number of patterns in URL to detect possible duplicates. For example urls which are different from each other
     * only by UUID. If there is no duplicate webapp is created. If duplicate is detected all headers and cookies are updated.
     * in the end application is put into scan queue.
     *
     * @param id of a project to link with webapp
     * @param webAppScanModelList model of app to create/update and scan
     * @param origin place which execute method. Necessary for Scan Strategy.
     * @return entity with status CREATED when scan is created, NOT_FOUND when there is no project and PRECONDITION_FAILED when duplicate detected
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public ResponseEntity<Status> processScanWebAppRequest(Long id, List<WebAppScanModel> webAppScanModelList, String origin, Principal principal) {
        synchronized (this) {
            String requestId = UUID.randomUUID().toString();
            Optional<Project> project = findProjectService.findProjectById(id);
            try {
                if (project.isPresent() && permissionFactory.canUserAccessProject(principal, project.get())) {
                    for (WebAppScanModel webAppScanModel : webAppScanModelList) {
                        WebApp webApp = getOrCreateWebAppService.getOrCreateWebApp(webAppScanModel.getUrl(), project.get(),webAppScanModel,origin,requestId);
                        updateWebAppService.updateAndPutWebAppToQueue(webApp,webAppScanModel,requestId,true);
                        //updateWebAppService.setCodeProjectLink(webApp,project.get(),webAppScanModel);
                        log.info("WebApp {} in project {} added to queue", webApp.getUrl(), project.get().getName());
                    }
                    return new ResponseEntity<>(new Status("Scan is requested", requestId), HttpStatus.CREATED);
                } else {
                    return new ResponseEntity<>(HttpStatus.NOT_FOUND);
                }
            } catch(Exception e){
                log.error("Problem occured during procesing web app scan request for project {} by {}", id, principal.getName());
                return new ResponseEntity<>(HttpStatus.PRECONDITION_FAILED);
            }

        }
    }

    /**
     * Finding WebApp with Runninng= true and check if scan is ended
     * then it decrease number of running scan for particular scanner
     *
     * @throws Exception
     */
    @Transactional
    public void scheduledCheckAndDownloadResults() throws Exception {
        List<WebApp> apps = findWebAppService.findRunningWebApps();
        for (WebApp app : apps) {
            Scanner scanner = getScannerService.getScannerForWebApp(app);
            try {
                if (scanner != null ) {
                    for (WebAppScanClient webAppScanClient : webAppScanClients) {
                        if (webAppScanClient.canProcessRequest(scanner) && webAppScanClient.isScanDone(scanner, app)) {
                            log.info("[WebAppScan] Scan for {} is done.", app.getUrl());
                            List<ProjectVulnerability> tmpVulns = getProjectVulnerabilitiesService.getProjectVulnerabilitiesForSource(app, null);
                            if (tmpVulns.size() > 0) {
                                vulnTemplate.projectVulnerabilityRepository.updateVulnState(tmpVulns.stream().map(ProjectVulnerability::getId).collect(Collectors.toList()),
                                        vulnTemplate.STATUS_REMOVED.getId());
                                tmpVulns.forEach(v -> v.setStatus(vulnTemplate.STATUS_REMOVED));
                            }
                            webAppScanClient.loadVulnerabilities(scanner,app, null, tmpVulns);
                            // TODO: end webappscan
                            updateScannerService.decreaseScanNumber(scanner);
                            updateWebAppService.updateRisk(app);

                            //vulnTemplate.projectVulnerabilityRepository.deleteByStatusAndProject(vulnTemplate.STATUS_REMOVED,app.getProject());
                            deleteProjectVulnerabilityService.deleteRemovedVulnerabilitiesInWebApp(app);
                            break;
                        }
                    }
                }
            } catch (HttpClientErrorException e) {
                if (e.getRawStatusCode() == 404) {
                    updateWebAppService.endScan(app);
                    updateScannerService.decreaseScanNumber(scanner);
                    log.warn("WebApp deleted manualy from scanner - {} {}", e.getRawStatusCode(), app.getUrl());
                } else {
                    updateWebAppService.endScan(app);
                    updateScannerService.decreaseScanNumber(scanner);
                    log.warn("HttpClientException with code {} for webapp {}", e.getRawStatusCode(), app.getUrl());
                }
            }
        }
    }

    /**
     * Method which takes WebApps with inQueue = true
     * Check if Scanner for particular App is limit free and then run the scan for this app.
     * If Limit is exceeded webapp is left inqueue
     *
     */
    @Transactional
    public void scheduledRunWebAppScanFromQueue() throws Exception {
        List<WebApp> webApps = findWebAppService.findInQueueWebApps();
        for (WebApp webApp : webApps){
            Scanner scanner = getScannerService.getScannerForWebApp(webApp);
            if (scanner != null && scanner.getRunningScans() < scanner.getScannerType().getScanLimit()){
                updateWebAppService.removeFromQueue(webApp);
                for (WebAppScanClient webAppScanClient : webAppScanClients){
                    if (webAppScanClient.canProcessRequest(scanner)){
                        //TODO create scan
                        webAppScanClient.runScan(webApp,scanner);
                        updateScannerService.increaseScanNumber(scanner);
                        break;
                    }
                }
                log.debug("Starget scan for {} taken from queue", webApp.getUrl());
            } else if (scanner == null) {
                updateWebAppService.removeFromQueue(webApp);
                log.info("Cannot find proper scanner to scan {} removeing from queue", webApp.getUrl());
            }
        }
    }

    /**
     * Gets all projects with set AutoWebAppScan to true and then put every webapp linked with particular project
     * with priority=0 into queue
     */
    @Transactional
    public void scheduledRunWebAppScan(int priority) {
        log.info("Starting scheduled scan for webapps");
        List<Project> projects = findProjectService.findProjectsWithAutoWebAppScan();
        for (Project p : projects) {
            for (WebApp webApp : p.getWebapps()) {
                if (webApp.getPriority() == priority) {
                    this.putSingleWebAppToQueue(webApp.getId(), () -> Constants.STRATEGY_SCHEDULER);
                }
            }
        }
    }

    public ResponseEntity<Status>putSingleWebAppToQueue(Long webAppId, Principal principal) {
        try {
            Optional<WebApp> webApp = findWebAppService.findById(webAppId);
            if (webApp.isPresent() && permissionFactory.canUserAccessProject(principal,webApp.get().getProject()) && getScannerService.getScannerForWebApp(webApp.get()) != null) {
                updateWebAppService.putWebAppToQueue(webApp.get(),UUID.randomUUID().toString());
                log.info("{} - Put in queue scan of webapps - scope single", LogUtil.prepare(principal.getName()));
                return new ResponseEntity<>(HttpStatus.CREATED);
            }
        } catch (Exception e){
            e.printStackTrace();
            return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
        }
        return new ResponseEntity<>(new Status("No Scanner for given resource"), HttpStatus.EXPECTATION_FAILED);
    }

    public ResponseEntity<Status> putSelectedWebAppsToQueue(Long id, List<RunScanForWebApps> runScanForWebApps, Principal principal) {
        Optional<Project> project = findProjectService.findProjectById(id);
        if (project.isPresent() && permissionFactory.canUserAccessProject(principal, project.get())){
            for (RunScanForWebApps selectedApp : runScanForWebApps){
                try{
                    Optional<WebApp> webApp = findWebAppService.findById(selectedApp.getWebAppId());
                    if (webApp.isPresent() && Objects.equals(webApp.get().getProject().getId(), project.get().getId()) && getScannerService.getScannerForWebApp(webApp.get())!=null){
                        updateWebAppService.putWebAppToQueue(webApp.get(), UUID.randomUUID().toString());
                        log.info("{} - Put to queue scan of webapps for project {} - scope partial", LogUtil.prepare(principal.getName()), LogUtil.prepare(project.get().getName()));
                    }
                } catch (Exception e){
                    return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
                }
            }
            return new ResponseEntity<>(HttpStatus.CREATED);

        }
        return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
    }


    //**ZAP integrations
    public List<ProjectVulnerability> ZapMapper(ZapReportModel zapReport, WebApp webApp){
        List<ProjectVulnerability> projectVulnerabilities = new ArrayList<>();
        for (ZapSiteModel site : zapReport.getSite()) {
            for (ZapAlertModel alert : site.getAlerts() ){
                if(!(alert.getRiskdesc().split(" \\(")[0].equals("Informational"))) {
                    for (ZapInstancesModel alertInstance : alert.getInstances()) {
                        Vulnerability vulnerability = CreateOrGetVulnerabilityService.createOrGetVulnerability(alert.getName());
                        ProjectVulnerability pv = new ProjectVulnerability(webApp, null, vulnerability, alert.getDesc(), alert.getSolution(), alert.getRiskdesc().split(" \\(")[0], null, alertInstance.getUri(), null, vulnTemplate.SOURCE_WEBAPP, null, null);
                        projectVulnerabilities.add(pv);
                    }
                }
            }
        }
        return projectVulnerabilities;
    }

    public void zapVulnsRemove(List<ProjectVulnerability> oldVulns){
        for (ProjectVulnerability projectVulnerability : oldVulns) {
            List<ProjectVulnerability> vulnsToRemove = oldVulns.stream().collect(Collectors.toList());
            if (vulnsToRemove.size() > 0) {
                vulnsToRemove.forEach(pv -> pv.setStatus(vulnTemplate.STATUS_REMOVED));
                vulnsToRemove.forEach(vulnTemplate.projectVulnerabilityRepository::saveAndFlush);
            }
        }
    }

    public ResponseEntity<Status> prepareAndLoadZapVulns(ZapReportModel loadVulnModel, String ciid, Principal principal) throws ParseException {

        if (loadVulnModel.getSite() != null && !Objects.equals(loadVulnModel.getSite().get(0).getName(), "")) {
            Project project = getOrCreateProjectService.getProjectId(ciid, loadVulnModel.getSite().get(0).getName().substring(8), principal);
            WebAppScanModel webAppScanModel = new WebAppScanModel();
            webAppScanModel.setUrl(loadVulnModel.getSite().get(0).getName());
            WebApp webApp = getOrCreateWebAppService.getOrCreateWebApp(loadVulnModel.getSite().get(0).getName(), project, webAppScanModel, "API", UUID.randomUUID().toString());
            List<ProjectVulnerability> oldVulns = vulnTemplate.projectVulnerabilityRepository.findByWebApp(webApp);
            List<ProjectVulnerability> newVulns = ZapMapper(loadVulnModel,webApp);
            zapVulnsRemove(oldVulns);
            vulnTemplate.vulnerabilityPersistList(oldVulns, newVulns);
            vulnTemplate.projectVulnerabilityRepository.deleteByStatus(vulnTemplate.STATUS_REMOVED);
            log.info("ZAP DAST vulnerabilities loaded/updated/removed for ciid {}",ciid);
            return new ResponseEntity<>(HttpStatus.OK);
        }
        else {
            log.error("Malformed ZAP DAST JSON report.");
            return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
        }
    }

    public ResponseEntity<Status> prepareAndLoadZapVulnsId(ZapReportModel loadVulnModel, Long id, Principal principal) throws ParseException {
        Optional<WebApp> webAppOptional = findWebAppService.findById(id);
        if (loadVulnModel.getSite() != null && webAppOptional.isPresent()) {
            WebApp webApp = webAppOptional.get();
            List<ProjectVulnerability> oldVulns = vulnTemplate.projectVulnerabilityRepository.findByWebApp(webApp);
            List<ProjectVulnerability> newVulns = ZapMapper(loadVulnModel,webApp);
            zapVulnsRemove(oldVulns);
            vulnTemplate.vulnerabilityPersistList(oldVulns, newVulns);
            vulnTemplate.projectVulnerabilityRepository.deleteByStatus(vulnTemplate.STATUS_REMOVED);
            log.info("[ZAP DAST] vulnerabilities loaded/updated/removed for webapp url {}",webApp.getUrl());
            return new ResponseEntity<>(HttpStatus.OK);
        }
        else {
            log.error("Malformed ZAP DAST JSON report.");
            return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
        }
    }

    public void createWebAppsForProject(Project project, RoutingDomain routingDomain) {
        Vulnerability vulnerability = vulnTemplate.vulnerabilityRepository.findByName(Constants.VULNERABILITY_HTTP_SERVER_DETECTED).orElse(null);
        if (vulnerability != null) {
            List<ProjectVulnerability> projectVulnerabilities = vulnTemplate.projectVulnerabilityRepository.findByProjectAndVulnerability(project, vulnerability);
            if (projectVulnerabilities.size() > 0){
                for (ProjectVulnerability pv : projectVulnerabilities) {
                    if (pv.getPort() != null && !Objects.equals(pv.getPort(), "") && pv.getPort().contains("/") && pv.getAnInterface() != null) {
                        String port = pv.getPort().split("/")[0].trim();
                        String url = "https://"+pv.getAnInterface().getPrivateip()+":"+port;
                        getOrCreateWebAppService.getOrCreateWebApp(url, project, routingDomain);
                    }
                }
            }
        }
    }
}
