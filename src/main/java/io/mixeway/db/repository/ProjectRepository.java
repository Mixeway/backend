package io.mixeway.db.repository;

import java.util.List;
import java.util.Optional;

import io.mixeway.api.dashboard.model.ProjectDTO;
import io.mixeway.db.entity.Project;
import io.mixeway.db.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface ProjectRepository extends JpaRepository<Project, Long>{
	List<Project> findByNodesNotNull();
	Optional<List<Project>> findByCiid(String ciid);
	Optional<List<Project>> findByName(String name);
	Optional<List<Project>> findByNameIgnoreCase(String name);
	Optional<List<Project>> findByNameAndOwner(String name, User user);
	Optional<Project> findByIdAndApiKey(Long id, String apiKey);
	List<Project> findByApiKey(String apiKey);
	List<Project> findByAutoWebAppScan(boolean autoWebScan);
	List<Project> findByAutoCodeScan(boolean autoWebScan);
	List<Project> findByAutoInfraScan(boolean autoInfraScan);
	List<Project> findByContactListNotNull();
	@Query(value="SELECT distinct(regexp_split_to_table(contactlist, E',')) FROM project",nativeQuery = true)
	List<String> getUniqueContactListEmails();
	@Query(value = "select p from Project p where name = :name")
	Optional<Project> getProjectByName(@Param("name") String name);
	@Query(value="select p from Project p where contactlist like CONCAT('%',:email,'%')")
	List<Project> getUniqueContactListEmails(@Param("email") String email);
	List<Project> findByVulnAuditorEnable(boolean vulnAuditorEnable);
	List<Project> findByEnableVulnManage(boolean vulnManage);
	@Query(value = "select distinct p from Project p, Asset a, Interface i where i.scanRunning=true and i.asset=a and a.project=p")
	List<Project> getProjectWithInterfaceRunning();

	@Query(value = "select p from Project p where exists (select 1 from ProjectVulnerability pv where pv.project=p and pv.codeProject is not null)")
	List<Project> getProjectsWithoutCodeVulns();

	@Query(value="select distinct(p.id) from project p, asset a, interface i where p.id=a.project_id and i.asset_id=a.id and i.scanrunning=true", nativeQuery = true)
	List<Long> getProjectIdWithScanRunningOnInterface();


	@Query("SELECT new io.mixeway.api.dashboard.model.ProjectDTO(p.id, p.ciid, p.name, p.description, p.risk, " +
			"CASE WHEN p.enableVulnManage = true THEN 1 ELSE 0 END) " +
			"FROM Project p JOIN p.users u WHERE u.username = :username")
	List<ProjectDTO> findProjectDTOsByUsername(@Param("username") String username);

	@Query("SELECT new io.mixeway.api.dashboard.model.ProjectDTO(p.id, p.ciid, p.name, p.description, p.risk, " +
			"CASE WHEN p.enableVulnManage = true THEN 1 ELSE 0 END) " +
			"FROM Project p")
	List<ProjectDTO> findAllProjectDTOs();
}
