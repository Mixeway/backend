package io.mixeway.scanmanager.service.code;

import io.mixeway.db.entity.CodeProject;
import io.mixeway.db.entity.CodeProjectBranch;
import io.mixeway.db.entity.ProjectVulnerability;
import io.mixeway.db.entity.Scanner;
import io.mixeway.utils.SASTProject;
import org.codehaus.jettison.json.JSONException;

import java.io.IOException;
import java.net.URISyntaxException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.text.ParseException;
import java.util.List;

public interface CodeScanClient {
    void loadVulnerabilities(Scanner scanner, String urlToGetNext, Boolean single, CodeProject codeProject, List<ProjectVulnerability> codeVulns, CodeProjectBranch codeProjectBranch) throws ParseException, JSONException, CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException, URISyntaxException;
    Boolean runScan(CodeProject codeProject) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException, JSONException, ParseException;
    Boolean runScan(CodeProject codeProject, CodeProjectBranch codeProjectBranch) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException, JSONException, ParseException;
    boolean isScanDone(CodeProject cp) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException, ParseException, JSONException;
    boolean canProcessRequest(CodeProject cp);
    boolean canProcessRequest(Scanner scanner);
    List<SASTProject> getProjects(Scanner scanner) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, JSONException, KeyStoreException, ParseException, IOException;
    boolean createProject(Scanner scanner, CodeProject codeProject) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyManagementException, JSONException, KeyStoreException, ParseException, IOException;
    void putInformationAboutScanFromRemote(CodeProject codeProject, String jobId);

    }
