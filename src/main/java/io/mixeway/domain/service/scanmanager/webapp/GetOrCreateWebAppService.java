package io.mixeway.domain.service.scanmanager.webapp;

import io.mixeway.api.project.model.WebAppPutModel;
import io.mixeway.config.Constants;
import io.mixeway.db.entity.*;
import io.mixeway.db.repository.*;
import io.mixeway.domain.service.assethistory.CreateAssetHistoryService;
import io.mixeway.scanmanager.model.CustomCookie;
import io.mixeway.scanmanager.model.RequestHeaders;
import io.mixeway.scanmanager.model.WebAppScanHelper;
import io.mixeway.scanmanager.model.WebAppScanModel;
import io.mixeway.utils.VaultHelper;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.apache.commons.lang3.StringUtils;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;

/**
 * @author gsiewruk
 */
@Service
@RequiredArgsConstructor
@Log4j2
public class GetOrCreateWebAppService {
    private final WebAppRepository webAppRepository;
    private final RoutingDomainRepository routingDomainRepository;
    private final VaultHelper vaultHelper;
    private final WebAppCookieRepository webAppCookieRepository;
    private final WebAppHeaderRepository webAppHeaderRepository;
    private final CreateAssetHistoryService createAssetHistoryService;

    private SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

    public WebApp getOrCreateWebApp(String url, Project project, RoutingDomain routingDomain){
        Optional<WebApp> webApp = webAppRepository.findByUrl( url);
        if (webApp.isPresent()){
            return webApp.get();
        } else {
            WebApp webAppNew = new WebApp();
            webAppNew.setUrl(url);
            webAppNew.setRoutingDomain(routingDomain);
            webAppNew.setRisk(0);
            webAppNew.setOrigin("SERCICE_DISCOVERY");
            webAppNew.setInQueue(false);
            webAppNew.setInserted(sdf.format(new Date()));
            webAppNew.setRunning(false);
            webAppRepository.save(webAppNew);
            log.info("[WebApp] Created webapp {} for {}", url, project.getName());
            return webAppNew;
        }
    }

    public WebApp getOrCreateWebApp(String url, Project project, WebAppScanModel webAppScanModel, String origin, String requestId) throws ParseException {
        String urlToCompareSimiliar = getUrltoCompare(url);
        String urlToCompareWithRegexx = WebAppScanHelper.normalizeUrl(url) + "$";
        List<WebApp> webAppOptional = webAppRepository.getWebAppBySimiliarUrlOrRegexUrl(urlToCompareSimiliar, urlToCompareWithRegexx, project.getId());
        Optional<WebApp> webApp = webAppRepository.findByProjectAndUrl(project, url);
        if (webApp.isPresent()) {
            return webApp.get();
        } else if (webAppOptional.size() == 1) {
            return webAppOptional.get(0);
        } else
            return createWebApp(url, project, webAppScanModel, origin, requestId);
    }

    public WebApp createWebApp(String url, Project project, WebAppScanModel webAppScanModel, String origin, String requestId) {
        WebApp webApp = new WebApp();
        webApp.setProject(project);
        webApp.setRunning(false);
        webApp.setOrigin(origin);
        if (StringUtils.isNotBlank(webAppScanModel.getRoutingDomain()))
            webApp.setRoutingDomain(routingDomainRepository.findByName(webAppScanModel.getRoutingDomain()));
        webApp.setInQueue(true);
        webApp.setRequestId(requestId);
        webApp.setInserted(sdf.format(new Date()));
        webApp.setPublicscan(webAppScanModel.getIsPublic());
        webApp.setUrl(webAppScanModel.getUrl());
        webApp.setUsername(webAppScanModel.getUsername());
        String uuidToken = UUID.randomUUID().toString();
        if (vaultHelper.savePassword(webAppScanModel.getPassword(), uuidToken)){
            webApp.setPassword(uuidToken);
        } else {
            webApp.setPassword(webAppScanModel.getPassword());
        }
        webApp = webAppRepository.saveAndFlush(webApp);
        this.createHeaderAndCookies(webAppScanModel.getHeaders(), webAppScanModel.getCookies(), webApp);
        log.info("Created WebApp '{}'", webApp.getUrl());
        return webApp;
    }

    /**
     * Check if url contains parameters and strip them from it
     *
     * @param url to compare
     * @return stripped url
     */
    private String getUrltoCompare(String url) {
        String urlToSend = url.split("\\?")[0];
        if (url.contains("?"))
            return urlToSend + "?";
        else
            return urlToSend;

    }



    /**
     * Method which creates headers and cookies for new webapp
     *
     * @param headers from request
     * @param cookies from request
     * @param webApp to link with headers and cookies
     */
    synchronized public void createHeaderAndCookies(List<RequestHeaders> headers, List<CustomCookie> cookies, WebApp webApp) {
        if (headers != null) {
            for (RequestHeaders header : headers) {
                createWebAppHeader(header.getHeaderName(), header.getHeaderValue(), webApp);
            }
        }
        if (cookies != null) {
            for (CustomCookie cookie : cookies) {
                createCookiesForWebApp(cookie, webApp);
            }
        }
    }

    /**
     * Method which use regex function of SQL to check for duplicates of given URL
     *
     * @param url to check for duplicates
     * @param id of system to check
     * @return list of webapplication which match regex
     */
    public List<WebApp> checkRegexes(String url, Long id) {
        return webAppRepository.getWebAppByRegexAsList(url + "$", id);
    }

    /**
     * Removes cookies from webapp
     *
     * @param webApp to get cookies
     */
    public void removeCookiesForWebApp(WebApp webApp) {
        webApp.setWebAppCookies(new HashSet<>());
        webAppRepository.save(webApp);
        webAppCookieRepository.deleteCookiesForWebApp(webApp.getId());
    }

    /**
     * Remove headers from webapp
     *
     * @param webApp to get headers
     */
    @Transactional
    public void removeHeadersForWebApp(WebApp webApp) {
        //webAppHeaderRepository.deleteHeaderForWebApp(webApp.getId());
        webApp.setHeaders(new HashSet<>());
        webAppRepository.save(webApp);
        webAppHeaderRepository.deleteByWebApp(webApp);

    }

    public void createWebAppHeader(String headerName, String headerValue, WebApp webApp) {
        WebAppHeader waHeaderNew = new WebAppHeader();
        waHeaderNew.setHeaderName(headerName);
        waHeaderNew.setHeaderValue(headerValue);
        waHeaderNew.setWebApp(webApp);
        webAppHeaderRepository.save(waHeaderNew);
        if (webApp.getHeaders() == null) {
            List<WebAppHeader> webAppHeaders = new ArrayList<>();
            webAppHeaders.add(waHeaderNew);
            webApp.setHeaders(new HashSet<>(webAppHeaders));

        } else {
            webApp.getHeaders().add(waHeaderNew);
        }
        webAppRepository.save(webApp);
    }

    public void createCookiesForWebApp(CustomCookie cookie, WebApp webApp) {
        WebAppCookies wac = new WebAppCookies();
        wac.setWebApp(webApp);
        wac.setCookie(cookie.getCookie());
        wac.setUrl(webApp.getUrl().split("/")[0] + "//" + webApp.getUrl().split("/")[2]);
        webAppCookieRepository.save(wac);
        if (webApp.getWebAppCookies() == null) {
            List<WebAppCookies> webAppCookies = new ArrayList<>();
            webAppCookies.add(wac);
            webApp.setWebAppCookies(new HashSet<>(webAppCookies));

        } else {
            webApp.getWebAppCookies().add(wac);
        }
        webAppRepository.save(webApp);
    }


    public WebApp createWebApp(Project project, WebAppPutModel webAppPutMode) {
        WebApp webApp = new WebApp();
        webApp.setUrl(webAppPutMode.getWebAppUrl());
        webApp.setRunning(false);
        webApp.setInQueue(false);
        webApp.setAppClient(webAppPutMode.getAppClient());
        webApp.setRoutingDomain(routingDomainRepository.getOne(webAppPutMode.getRoutingDomainForAsset()));
        webApp.setOrigin(Constants.STRATEGY_GUI);
        webApp.setPublicscan(webAppPutMode.isScanPublic());
        webApp.setProject(project);
        if (webAppPutMode.isPasswordAuthSet()){
            webApp.setUsername(webAppPutMode.getWebAppUsername());
            String uuidToken = UUID.randomUUID().toString();
            if (vaultHelper.savePassword(webAppPutMode.getWebAppPassword(), uuidToken)){
                webApp.setPassword(uuidToken);
            } else {
                webApp.setPassword(webAppPutMode.getWebAppPassword());
            }
        }
        webApp = webAppRepository.saveAndFlush(webApp);
        if (webAppPutMode.getWebAppHeaders() != null ) {
            for (String header : webAppPutMode.getWebAppHeaders().split(",")) {
                String[] headerValues = header.split(":");
                if (headerValues.length == 2) {
                    WebAppHeader waHeader = new WebAppHeader();
                    waHeader.setHeaderName(headerValues[0]);
                    waHeader.setHeaderValue(headerValues[1]);
                    waHeader.setWebApp(webApp);
                    webAppHeaderRepository.save(waHeader);
                }
            }
        }
        return webApp;
    }

    public WebApp createWebApp(Project project, String appUrl, String appName, RoutingDomain routingDomain, String headerName, String apiKeyName, String basicAuth) {
        WebApp webApp = getOrCreateWebApp(appUrl, project, routingDomain);
        webApp.setName(appName);
        webApp.setHeader(headerName);
        webApp.setBasicAuth(basicAuth);
        webApp.setApikey(apiKeyName);
        webApp.setProject(project);
        webApp = webAppRepository.save(webApp);
        createAssetHistoryService.create(webApp,0,0,0,0,0,0,0,0,0,0);

        return webApp;
    }
}
