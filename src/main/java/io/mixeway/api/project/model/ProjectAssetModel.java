package io.mixeway.api.project.model;

import io.mixeway.db.entity.CodeProject;
import io.mixeway.db.entity.Interface;
import io.mixeway.db.entity.WebApp;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

@Getter
@Setter
@NoArgsConstructor
public class ProjectAssetModel {
    Long id;
    String name;
    String target;
    String branch;
    String type;
    String path;
    String parent;
    String[] scope;
    AssetVulns vulnerabilities;

    public ProjectAssetModel convertCodeProject(CodeProject codeProject, int crit, int medium, int low){
        int sastScan = codeProject.getVersionIdAll() > 0 ? codeProject.getVersionIdAll() : codeProject.getRemoteid();
        List<String> sscope = new ArrayList<>();
        if(sastScan > 0){
            sscope.add("sast");
        }
        if(!Objects.equals(codeProject.getdTrackUuid(), "") && codeProject.getdTrackUuid() != null){
            sscope.add("sca");
        }
        if (codeProject.getParent() != null){
            int parentSast = codeProject.getParent().getVersionIdAll() > 0 ? codeProject.getParent().getVersionIdAll() : codeProject.getParent().getRemoteid();
            if (parentSast > 0) {
                sscope.add("sast");
            }
        }

        AssetVulns assetVulns = new AssetVulns();
        assetVulns.setCritical(crit);
        assetVulns.setMedium(medium);
        assetVulns.setLow(low);
        ProjectAssetModel projectAssetModel = new ProjectAssetModel();
        projectAssetModel.setName(codeProject.getName());
        projectAssetModel.setTarget(codeProject.getRepoUrl());
        projectAssetModel.setBranch(codeProject.getBranch());
        projectAssetModel.setType("codeProject");
        projectAssetModel.setId(codeProject.getId());
        projectAssetModel.setPath(codeProject.getPath());
        projectAssetModel.setVulnerabilities(assetVulns);
        projectAssetModel.setScope(sscope.toArray(new String[0]));
        if (codeProject.getParent() != null){
            projectAssetModel.setParent(codeProject.getParent().getName());
        }
        return projectAssetModel;
    }

    public ProjectAssetModel convertWebApp(WebApp webApp, int crit, int medium, int low, boolean dast){
        List<String> sscope = new ArrayList<>();
        if(dast){
            sscope.add("dast");
        }
        AssetVulns assetVulns = new AssetVulns();
        assetVulns.setCritical(crit);
        assetVulns.setMedium(medium);
        assetVulns.setLow(low);
        ProjectAssetModel projectAssetModel = new ProjectAssetModel();
        projectAssetModel.setName(webApp.getName());
        projectAssetModel.setTarget(webApp.getUrl());
        projectAssetModel.setType("webApp");
        projectAssetModel.setId(webApp.getId());
        projectAssetModel.setVulnerabilities(assetVulns);
        projectAssetModel.setScope(sscope.toArray(new String[0]));
        return projectAssetModel;
    }
    public ProjectAssetModel convertInterface(Interface intf, int crit, int medium, int low, boolean dast){
        List<String> sscope = new ArrayList<>();
        if(dast){
            sscope.add("network");
        }
        AssetVulns assetVulns = new AssetVulns();
        assetVulns.setCritical(crit);
        assetVulns.setMedium(medium);
        assetVulns.setLow(low);
        ProjectAssetModel projectAssetModel = new ProjectAssetModel();
        projectAssetModel.setName(intf.getAsset().getName());
        projectAssetModel.setTarget(intf.getPrivateip());
        projectAssetModel.setType("interface");
        projectAssetModel.setId(intf.getId());
        projectAssetModel.setVulnerabilities(assetVulns);
        projectAssetModel.setScope(sscope.toArray(new String[0]));
        return projectAssetModel;
    }
}
