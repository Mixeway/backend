package io.mixeway.api.dashboard.service;

import io.mixeway.api.dashboard.model.DashboardTopStatistics;
import io.mixeway.api.dashboard.model.ProjectDTO;
import io.mixeway.api.dashboard.model.Projects;
import io.mixeway.api.dashboard.model.SessionOwner;
import io.mixeway.api.protocol.OverAllVulnTrendChartData;
import io.mixeway.api.protocol.SourceDetectionChartData;
import io.mixeway.api.protocol.cioperations.InfoScanPerformed;
import io.mixeway.db.entity.*;
import io.mixeway.db.repository.CodeProjectRepository;
import io.mixeway.db.repository.UserRepository;
import io.mixeway.domain.service.asset.GetOrCreateAssetService;
import io.mixeway.domain.service.project.CreateProjectService;
import io.mixeway.domain.service.project.FindProjectService;
import io.mixeway.domain.service.project.GetOrCreateProjectService;
import io.mixeway.domain.service.scanmanager.code.CreateOrGetCodeProjectService;
import io.mixeway.domain.service.scanmanager.code.FindCodeProjectService;
import io.mixeway.domain.service.scanmanager.webapp.GetOrCreateWebAppService;
import io.mixeway.domain.service.vulnhistory.CreateVulnHistoryService;
import io.mixeway.domain.service.vulnmanager.CreateOrGetVulnerabilityService;
import io.mixeway.domain.service.vulnmanager.VulnTemplate;
import io.mixeway.scheduler.CodeScheduler;
import io.mixeway.scheduler.GlobalScheduler;
import io.mixeway.scheduler.NetworkScanScheduler;
import io.mixeway.scheduler.WebAppScheduler;
import io.mixeway.utils.ScannerType;
import io.mixeway.utils.Status;
import io.mixeway.utils.VulnerabilityModel;
import lombok.RequiredArgsConstructor;
import org.junit.jupiter.api.*;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.transaction.annotation.Transactional;

import java.security.Principal;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @author gsiewruk
 */
@SpringBootTest
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class DashboardServiceTest {
    private final DashboardService dashboardService;
    private final UserRepository userRepository;
    private final GetOrCreateProjectService getOrCreateProjectService;
    private final CreateVulnHistoryService createVulnHistoryService;
    private final FindProjectService findProjectService;
    private final CreateOrGetCodeProjectService createOrGetCodeProjectService;
    private final GetOrCreateWebAppService getOrCreateWebAppService;
    private final GetOrCreateAssetService getOrCreateAssetService;
    private final FindCodeProjectService findCodeProjectService;
    private final CreateOrGetVulnerabilityService createOrGetVulnerabilityService;
    private final VulnTemplate vulnTemplate;
    @Mock
    Principal principal;

    @MockBean
    GlobalScheduler globalScheduler;

    @MockBean
    NetworkScanScheduler networkScheduler;

    @MockBean
    CodeScheduler codeScheduler;

    @MockBean
    WebAppScheduler webAppScheduler;

    @BeforeAll
    public void prepareDB() {
        Mockito.when(principal.getName()).thenReturn("dashboard_service");
        User userToCreate = new User();
        userToCreate.setUsername("dashboard_service");
        userToCreate.setCommonName("dashboard_service");
        userToCreate.setPermisions("ROLE_ADMIN");
        userRepository.save(userToCreate);
        Project project = getOrCreateProjectService.getProjectId("dashboard_service", "dashboard_service", principal);
        for (int i=0; i<5; i++){

            createVulnHistoryService.create(project,"2022-03-0"+i+" 12:00:00",3L,4L,5L,6L, 7L);
        }
    }

    @Test
    void getVulnTrendData() {
        Mockito.when(principal.getName()).thenReturn("dashboard_service");
        List<OverAllVulnTrendChartData> overAllVulnTrendChartData = dashboardService.getVulnTrendData(principal);
        assertTrue(overAllVulnTrendChartData.size() > 0);
    }

    @Test
    void getSourceTrendData() {
        Mockito.when(principal.getName()).thenReturn("dashboard_service");
        SourceDetectionChartData sourceDetectionChartData = dashboardService.getSourceTrendData(principal);
        assertNotNull(sourceDetectionChartData);
    }

    @Test
    void getProjects() {
        Mockito.when(principal.getName()).thenReturn("dashboard_service");
        List<ProjectDTO> projects = dashboardService.getProjects(principal);
        assertTrue(projects.size() > 0);
    }

    @Test
    @Order(1)
    void putProject() {
        Mockito.when(principal.getName()).thenReturn("dashboard_service");

        ResponseEntity<Status> statusResponseEntity = dashboardService.putProject("dashboard_new_project","test desc","dashboard_new_project",0, principal);
        assertEquals(HttpStatus.CREATED, statusResponseEntity.getStatusCode());
        Optional<Project> project = findProjectService.findProjectByName("dashboard_new_project");
        assertTrue(project.isPresent());

    }

    @Test
    @Order(2)
    @Transactional
    void patchProject() {
        Mockito.when(principal.getName()).thenReturn("dashboard_service");
        List<Project> projectsX = findProjectService.findAll();
        Project project = getOrCreateProjectService.getProjectId("dashboard_new_project", "dashboard_new_project", principal);
        projectsX = findProjectService.findAll();
        Projects projects = new Projects();
        projects.setName("dashboard_new_project");
        projects.setCiid("dashboard_new_project");
        projects.setEnableVulnManage(1);
        projects.setDescription("edited");
        ResponseEntity<Status> statusResponseEntity = dashboardService.patchProject(project.getId(),projects, principal);
        assertEquals(HttpStatus.OK, statusResponseEntity.getStatusCode());
        Optional<Project> editedProject = findProjectService.findProjectByCiid("dashboard_new_project");
        assertTrue(editedProject.isPresent());
        assertTrue(editedProject.get().isEnableVulnManage());
        assertEquals("edited", editedProject.get().getDescription());

    }

    @Test
    @Order(3)
    void deleteProject() {
        Mockito.when(principal.getName()).thenReturn("dashboard_service");
        Project project = getOrCreateProjectService.getProjectId("dashboard_new_project", "dashboard_new_project", principal);
        ResponseEntity<Status> statusResponseEntity = dashboardService.deleteProject(project.getId(), principal);
        assertEquals(HttpStatus.OK, statusResponseEntity.getStatusCode());
        Optional<Project> editedProject = findProjectService.findProjectByName("dashboard_new_project");
        assertFalse(editedProject.isPresent());
    }

    @Test
    void getSessionOwner() {
        Mockito.when(principal.getName()).thenReturn("dashboard_service");
        ResponseEntity<SessionOwner> sessionOwnerResponseEntity = dashboardService.getSessionOwner("dashboard_service");
        assertEquals(HttpStatus.OK, sessionOwnerResponseEntity.getStatusCode());
        assertNotNull(sessionOwnerResponseEntity.getBody());
        assertEquals("dashboard_service",sessionOwnerResponseEntity.getBody().getName());
    }

    @Test
    void search() {
        //not working yet
    }

    @Test
    void getRootStatistics() {
        Mockito.when(principal.getName()).thenReturn("dashboard_service");
        ResponseEntity<DashboardTopStatistics> dashboardTopStatisticsResponseEntity = dashboardService.getRootStatistics(principal);
        assertEquals(HttpStatus.OK, dashboardTopStatisticsResponseEntity.getStatusCode());
        assertNotNull(dashboardTopStatisticsResponseEntity.getBody());
        assertTrue(dashboardTopStatisticsResponseEntity.getBody().getStatisticCard().getProjects() > 0);
    }

    @Test
    @Transactional
    void mergeTwoProjects() {
        Mockito.when(principal.getName()).thenReturn("dashboard_service");
        Project sourceProject = getOrCreateProjectService.getProjectByName("source_project", principal);
        Project destinationProject = getOrCreateProjectService.getProjectByName("destination_project", principal);
        CodeProject sourceCodeProject = createOrGetCodeProjectService.createCodeProject(sourceProject,"sourceProject","master");
        CodeProject destinationCodeProject = createOrGetCodeProjectService.createCodeProject(destinationProject,"destProject","master");
        Vulnerability vulnerability = createOrGetVulnerabilityService.createOrGetVulnerability("testvulnerability");
        for (int i =0 ; i <15 ; i++){
            ProjectVulnerability pv = new ProjectVulnerability();
            pv.setProject(sourceProject);
            pv.setCodeProject(sourceCodeProject);
            pv.setVulnerability(vulnerability);
            pv.setVulnerabilitySource(vulnTemplate.SOURCE_SOURCECODE);
            pv.setSeverity("High");
            vulnTemplate.projectVulnerabilityRepository.save(pv);
        }
        for (int i =0 ; i <5 ; i++){
            ProjectVulnerability pv = new ProjectVulnerability();
            pv.setProject(destinationProject);
            pv.setCodeProject(destinationCodeProject);
            pv.setVulnerability(vulnerability);
            pv.setVulnerabilitySource(vulnTemplate.SOURCE_SOURCECODE);
            pv.setSeverity("High");
            vulnTemplate.projectVulnerabilityRepository.save(pv);
        }
        ResponseEntity<Status> response = dashboardService.mergeTwoProjects(123L, 10000L, principal);
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());

        response = dashboardService.mergeTwoProjects(sourceProject.getId(), destinationProject.getId(), principal);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        Optional<Project> deletedSourceProject = findProjectService.findProjectById(sourceProject.getId());
        assertFalse(deletedSourceProject.isPresent());
        List<CodeProject> codeProjects = findCodeProjectService.findByProject(destinationProject);
        assertTrue(codeProjects.size() > 1);
        Stream<ProjectVulnerability> projectVulnerabilities = vulnTemplate.projectVulnerabilityRepository.findByProject(destinationProject);
        assertTrue(projectVulnerabilities.count() > 15);
    }
}