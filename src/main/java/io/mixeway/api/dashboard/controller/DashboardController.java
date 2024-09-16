package io.mixeway.api.dashboard.controller;


import io.mixeway.api.dashboard.model.*;
import io.mixeway.api.dashboard.service.DashboardService;
import io.mixeway.api.protocol.OverAllVulnTrendChartData;
import io.mixeway.api.protocol.SourceDetectionChartData;
import io.mixeway.utils.Status;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.security.Principal;
import java.util.List;

@RestController
@RequestMapping("/v2/api/dashboard")
public class DashboardController {

    private final DashboardService dashboardService;

    DashboardController(DashboardService dashboardService){
        this.dashboardService = dashboardService;
    }

    @PreAuthorize("hasAuthority('ROLE_USER')")
    @GetMapping(value = "/userinfo")
    public ResponseEntity<SessionOwner> getSesstionOwner(HttpServletRequest request) {
        Authentication auth =         SecurityContextHolder.getContext().getAuthentication();

        return dashboardService.getSessionOwner(request.getUserPrincipal().getName());

    }
    @PreAuthorize("hasAuthority('ROLE_USER')")
    @GetMapping(value = "/stat")
    public ResponseEntity<DashboardStat> getDashboardStat(){
        return dashboardService.getDashboardStat();
    }
    @PreAuthorize("hasAuthority('ROLE_USER')")
    @GetMapping(value = "/getvulntrenddata")
    public List<OverAllVulnTrendChartData> getVulnTrendData(Principal principal) throws IOException {
        return dashboardService.getVulnTrendData(principal);
    }

    @PreAuthorize("hasAuthority('ROLE_USER')")
    @GetMapping(value = "/getsourcetrenddata")
    public SourceDetectionChartData getSourceTrendData(Principal principal) throws IOException {

        return dashboardService.getSourceTrendData(principal);
    }

    @PreAuthorize("hasAuthority('ROLE_USER')")
    @GetMapping(value = "/projects")
    public List<ProjectDTO> getProjects(Principal principal) {
        return dashboardService.getProjects(principal);
    }

    @PreAuthorize("hasAuthority('ROLE_USER')")
    @PutMapping(value = "/projects/{projectName}/{projectDescription}/{ciid}/{enableVulnManage}")
    public ResponseEntity<Status> putProject(@PathVariable(value = "projectName") String projectName,
                                             @PathVariable(value="projectDescription") String projectDescription,
                                             @PathVariable(value="ciid") String ciid,
                                             @PathVariable(value="enableVulnManage") int enableVulnManage, Principal principal)  {
        return dashboardService.putProject(projectName, projectDescription, ciid, enableVulnManage, principal);
    }
    @PreAuthorize("hasAuthority('ROLE_USER')")
    @PatchMapping(value = "/projects/{projectId}")
    public ResponseEntity<Status> editProject(@PathVariable(value = "projectId") Long projectId,
                                      @RequestBody Projects projectObject, Principal principal) {
        return dashboardService.patchProject(projectId,projectObject,principal);
    }
    @PreAuthorize("hasAuthority('ROLE_USER')")
    @DeleteMapping(value = "/projects/{projectId}")
    public ResponseEntity<Status> deleteProject(@PathVariable(value = "projectId") Long projectId, Principal principal) {
        return dashboardService.deleteProject(projectId,principal);
    }
    @PreAuthorize("hasAuthority('ROLE_EDITOR_RUNNER')")
    @PostMapping(value = "/search")
    public ResponseEntity<SearchResponse> search(@RequestBody SearchRequest searchRequest, Principal principal) {
        return dashboardService.search(searchRequest);
    }
    @PreAuthorize("hasAuthority('ROLE_USER')")
    @GetMapping(value = "/statistics")
    public ResponseEntity<DashboardTopStatistics> getRootStatistics(Principal principal) {
        return dashboardService.getRootStatistics(principal);
    }
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    @GetMapping(value = "/merge/project/source/{source}/destination/{destination}")
    public ResponseEntity<Status> mergeTwoProjects(@PathVariable(value = "source") long sourceId, @PathVariable("destination") long destinationId, Principal principal){
        return dashboardService.mergeTwoProjects(sourceId, destinationId, principal);
    }

}
