package io.mixeway.api.project.model;

import io.mixeway.db.entity.CodeProject;
import liquibase.pro.packaged.A;
import lombok.Data;
import lombok.extern.log4j.Log4j2;

import java.util.ArrayList;
import java.util.List;

@Data
@Log4j2
public class MixewayYamlConfigDto {
    Code code;
    WA webapp;

    public MixewayYamlConfigDto buildCodeResponse(CodeProject codeProject, List<CodeProject> childs) {
        try {
            this.code = new Code();
            this.code.id = codeProject.getParent()==null ? codeProject.getId() : codeProject.getParent().getId();
            this.code.name = codeProject.getParent()==null ? codeProject.getName() : codeProject.getParent().getName();
            List<App> apps = new ArrayList<>();
                for (CodeProject cp : childs) {
                    App app = new App();
                    app.setId(cp.getId());
                    app.setName(cp.getName());
                    app.setPath(cp.getPath());
                    app.setSca_name(cp.getRemotename());
                    apps.add(app);
                }
                this.code.apps = apps;
                if (code.apps.isEmpty()){
                    this.code.sca_name = codeProject.getRemotename();
                }

        } catch (NullPointerException e ){
            log.warn("generating mixeway.yaml for child");
        }
        return this;
    }

    @Data
    public static class Code {
        Long id;
        String name;
        String sca_name;
        List<App> apps;
    }
    @Data
    public static class App {
        Long id;
        String name;
        String path;
        String sca_name;
    }
    @Data
    public static class WA {
        Long id;
        String scanType;
        String backendUrl;
        String openApiFilePath;
    }
}
