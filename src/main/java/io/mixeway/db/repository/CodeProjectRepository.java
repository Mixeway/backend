package io.mixeway.db.repository;

import java.util.List;
import java.util.Optional;

import io.mixeway.db.entity.Project;
import org.springframework.data.jpa.repository.JpaRepository;

import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import io.mixeway.db.entity.CodeProject;

public interface CodeProjectRepository extends JpaRepository<CodeProject, Long> {
	@Query(value="select cp.* from codeproject cp, codegroup cg where cp.codegroup_id=cg.id and cg.project_id=?3 and cg.name=?2 and cp.name=?1", nativeQuery =true)
	Optional<CodeProject> getCodeProjectByNameCodeGroupNameAndProjectId(String codeProjectName,String codeGroupName,Long projectId);
	List<CodeProject> findByInQueue(Boolean inqueue);
	@Query(value = "delete from codeproject where id=?1", nativeQuery = true)
	@Modifying
	int removeCodeGroup(Long id);
	List<CodeProject> findByRequestId(String requestId);
	List<CodeProject> findBydTrackUuidNotNull();
	List<CodeProject> findByRunning(boolean running);
	List<CodeProject> findTop5ByRunning(boolean running);
	List<CodeProject> findByProjectAndRunning(Project project, boolean running);
	List<CodeProject> findByProject(Project project);
	@Query(value = "Select * from codeproject where dtrackuuid != ''", nativeQuery = true)
	List<CodeProject> getCodeProjectsWithOSIntegrationEnabled();
	Optional<CodeProject> findByName(String name);
	Optional<CodeProject> findByNameAndBranch(String name, String branch);
	@Query(value = "select cp.* from codeproject cp inner join codegroup cg on cp.codegroup_id = cg.id inner join project p on p.id=cg.project_id " +
			"where project_id=:project and cp.name=:name and cp.branch=:branch", nativeQuery = true)
	Optional<CodeProject> getCodeProjectByProjectNameAndBranch(@Param("project") Long project, @Param("name") String name, @Param("branch") String branch);
	@Query(value = "select cp.* from codeproject cp inner join project p on p.id=cp.project_id " +
			"where project_id=:project and cp.name=:name", nativeQuery = true)
	Optional<CodeProject> getCodeProjectByProjectName(@Param("project") Long project, @Param("name") String name);
	@Query(value = "select cp.* from codeproject cp where cp.codegroup_id in (select id from codegroup where project_id in :projects) and cp.name ilike :name", nativeQuery = true)
	Optional<CodeProject> getCodeProjectByNameAndPermissions(@Param("name") String codeProjectName, @Param("projects") List<Long> projectIds);

    Optional<CodeProject> findByRepoUrl(String url);
	@Query(value = "select count(*) from codeproject where versionidall > 0", nativeQuery = true)
	Long getCodeGroupWithVersionIdSet();

	Optional<CodeProject> findByProjectAndName(Project project, String groupName);

    Long countByInQueue(boolean b);

	Long countByRunning(boolean b);

	Optional<CodeProject> findByProjectAndRepoUrl(Project project, String repoUrl);

    Optional<CodeProject> findByRepoUrlOrRepoUrl(String repoUrl, String s);

    List<CodeProject> findByRepoUrlOrRepoUrlAndName(String repoUrl, String s, String name);
	List<CodeProject> findBydTrackUuidNotNullAndRepoUrlNotNull();
	@Query("select cp from CodeProject cp where cp.remotename is null and cp.repoUrl is not null and cp.dTrackUuid is null")
	List<CodeProject> getCodeProjectsForSynchro();

	@Modifying
	@Query("UPDATE CodeProject e SET e.branch = :branch WHERE e.id = :id")
	void updateCodeProjectBranch(@Param("id") Long id, @Param("branch") String branch);

    List<CodeProject> findByProjectIn(List<Project> enabledVulnManageProjects);

    List<CodeProject> findByParent(CodeProject codeProject);
}
