--liquibase formatted sql

--changeset siewer:3
create table project(
  id serial primary key,
  name text,
  description text);

--changeset siewer:4
create table iaasapi(
  id serial primary key,
  iamurl text,
  serviceurl text,
  networkurl text,
  project_id int references project(id));

--changeset siewer:5
alter table iaasapi add column domain text;
alter table iaasapi add column username text;
alter table iaasapi add column password text;
alter table iaasapi add column tenantid text;

--changeset siewer:6
create table asset(
  id serial primary key,
  name text,
  assetid text,
  project_id int references project(id));

--changeset siewer:7
alter table asset add column origin text;

--changeset siewer:8
alter table asset add column active boolean;

--changeset siewer:9
create table interface (
  id serial primary key,
  privateip text,
  floatingip text,
  subnetid text,
  macaddr text,
  active boolean,
  asset_id int references asset(id));

--changeset siewer:10
alter table iaasapi add column token text;
alter table iaasapi add column tokenexpires text;

--changeset siewer:11
alter table iaasapi add column enabled boolean;

--changeset siewer:12
create table securitygroup(
  id serial primary key,
  name text,
  securitygroupid text);

create table securitygrouprule(
  id serial primary key,
  securitygroup_id int references securitygroup(id),
  direction text,
  type text,
  protocol text,
  ports text,
  destination text);

create table asset_securitygroup(
  asset_id int references asset(id),
  securitygroup_id int references securitygroup(id));

--changeset siewer:13
alter table securitygrouprule add column ruleid text;

--changeset siewer:14
alter table project add column ciid text;

--changeset siewer:15
alter table iaasapi add column status boolean;
update iaasapi set status = false;

--changeset siewer:16
create table proxies (
  id serial primary key,
  ip text,
  port text,
  description text);
alter table iaasapi add column external boolean;
update iaasapi set external=true;
insert into proxies (ip,port,description) values ('126.204.4.20','3128','BST lab proxy');

--changeset siewer:17
create table apitype(
  id serial primary key,
  url text,
  name text,
  description text);
create table apipermision(
  id serial primary key,
  cn text,
  ip text,
  project_id int references project(id));

insert into apitype (url, name , description) values ('cis-k8s','CIS k8s Benchmark','curl -k https://<stsc_url>/api/costam -X POST --cert <client_certificate> --key <client_private_key> -F file=@<file>');

--changeset siewer:18
alter table apipermision add column apitype_id int references apitype(id);

--changeset siewer:19
alter table apipermision add column enabled boolean;

--changeset siewer:20
create table node(
  id serial primary key,
  name text,
  type text,
  project_id int references project(id));
create table requirement(
  id serial primary key,
  code text unique,
  name text,
  severity int);
create table nodeaudit(
  id serial primary key,
  node_id int references node(id),
  requirement_id int references requirement(id),
  score text,
  updated text);

--changeset siewer:21
create table activity(
  id serial primary key,
  name text,
  inserted text);

--changeset siewer:22
alter table proxies add column username text;
alter table proxies add column password text;
create table nessus (
  id serial primary key,
  accesskey text,
  secretkey text,
  apiurl text,
  network text,
  status boolean,
  proxies_id int references proxies(id));
insert into proxies (ip,port,description) values ('126.204.4.20','3128','labproxy');

--changeset siewer:23
delete from proxies where description='labproxy';

--changeset siewer:24
create table nessusscantemplate(
  id serial primary key,
  name text,
  uuid text,
  nessus_id int references nessus(id));

create table nessusscanner(
  id serial primary key,
  expiration text,
  version text,
  scannerid int,
  nessus_id int references nessus(id));
update nessus set status = false;

--changeset siewer:25
alter table interface add column networktag text;
update interface set networktag = 'fe' where subnetid is not null;

--changeset siewer:26
create table nessusscan(
  id serial primary key,
  project_id int references project(id),
  nessusscanner_id int references nessusscanner(id),
  nessusscantemplate_id int references nessusscantemplate(id),
  nessus_id int references nessus(id),
  scanid int,
  running boolean,
  scheduled boolean,
  lastexecuted text,
  publicip boolean);

create table nessus_interface (
  nessusscan_id int references nessusscan(id),
  interface_id int references interface(id));

--changeset siewer:27
create table users (
  id serial primary key,
  commonname text unique,
  permisions text,
  lastloggeddate text,
  lastloggedip text);

--changeset siewer:28
alter table users add column enabled boolean;

--changeset siewer:29
alter table nessus add column usepublic boolean;

--changeset siewer:30
alter table nessusscan add column isautomatic boolean;

--changeset siewer:31
alter table nessusscan add column scanfrequency int;

--changeset siewer:32
alter table nessus add folderid int;

--changeset siewer:33
alter table nessus add username text;
alter table nessus add password text;
alter table nessus add configid text;
alter table nessusscan add targetid text;
alter table nessusscan add reportid text;
alter table nessusscan add taskid text;

--changeset siewer:34
create table infrastructurevuln(
  id serial primary key,
  interface_id int references interface(id),
  name text,
  threat text,
  port text,
  description text);

--changeset siewer:35
create table software(
  id serial primary key,
  name text,
  version text,
  asset_id int references asset(id));

--changeset siewer:36
create table codegroup(
  id serial primary key,
  project_id int references project(id),
  name text,
  basepath text,
  giturl text);
create table codeproject(
  id serial primary key,
  codegroup_id int references codegroup(id),
  name text);
create table codevuln(
  id serial primary key,
  codeproject_id int references codeproject(id),
  name text,
  filepath text,
  severity text,
  analysis text);
create table apis(
  url text,
  name text);

insert into apis (name, url) values ('FORTIFY_API','https://localhost:8445/');

--changeset siewer:37
alter table codegroup add column hasproject boolean;

--changeset siewer:38
alter table codevuln add column codegroup_id int references codegroup(id);

--changeset siewer:39
create table vulnhistory(
  id serial primary key,
  name text,
  vulnnumber int,
  inserted text);

--changeset siewer:40
alter table vulnhistory add column project_id int references project(id);

--changeset siewer:41
create table routingdomain(
  id serial primary key,
	name text
);
alter table iaasapi add column routingdomain_id int references routingdomain(id);
alter table interface add column routingdomain_id int references routingdomain(id);
alter table asset add column routingdomain_id int references routingdomain(id);
insert into routingdomain (name) values ('FE'), ('OpenWatt'), ('SK');

--changeset siewer:42
alter table nessus add column routingdomain_id int references routingdomain(id);

--changeset siewer:43
create table scannertype(
  id serial primary key,
	name text
);
alter table nessus add column scannertype_id int references scannertype(id);
insert into scannertype (name) values ('OpenVAS');
update nessus set scannertype_id=1;

--changeset siewer:44
insert into scannertype (name) values ('Nessus');

--changeset siewer:45
insert into scannertype (name) values ('Acunetix');

create table acunetix(
  id serial primary key,
  url text,
  apikey text,
  proxies_id int references proxies(id),
  profile text);

create table loginsequence(
  id serial primary key,
  loginsequencetext text);

create table webapp(
  id serial primary key,
  project_id int references project(id),
  url text,
  loginsequence_id int references loginsequence(id),
  lastexecuted text,
  target_id text,
  publicscan boolean);

create table webappscan(
  id serial primary key,
  acunetix_id int references acunetix(id),
  running boolean,
  scan_id text,
  type text,
  webapp_id int references webapp(id));

create table webappvuln(
  id serial primary key,
  webappscan_id int references webappscan(id),
  webapp_id int references webapp(id),
  name text,
  description text,
  location text,
  recommendation text);

--changeset siewer:46
alter table acunetix add column routingdomain_id int references routingdomain(id);

--changeset siewer:47
alter table acunetix add column scannertype_id int references scannertype(id);

--changeset siewer:48
alter table nessus add column apikey text;
alter table webappscan add column nessus_id int references nessus(id);

--changeset siewer:49
alter table loginsequence add column name text;

--changeset siewer:50
alter table webapp add column loginsequenceuploadurl text;

--changeset siewer:51
alter table webapp add column readytoscan boolean;

--changeset siewer:52
alter table webapp add column running boolean;

--changeset siewer:53
alter table webapp add column scanid text;

--changeset siewer:54
alter table webappscan add column project_id int references project(id);

--changeset siewer:55
create table webappheader(
  id serial primary key,
	headername text,
	headervalue text,
	webapp_id int references webapp(id));

--changeset siewer:56
alter table webappvuln add column severity text;

--changeset siewer:57
insert into apitype (url, name, description) values ('webapp', 'WebApps Service Discovery', '');

--changeset siewer:58
alter table webapp add column asset_id int references asset(id);

--changeset siewer:59
alter table webapp add column inqueue boolean;

--changeset siewer:60
update webapp set inqueue=false;

--changeset siewer:61
create table softwarepacket(
  id serial primary key,
	name text);
create table asset_softwarepacket(
  asset_id int references asset(id),
  softwarepacket_id int references softwarepacket(id));

--changeset siewer:62
alter table asset add os text;
alter table asset add osversion text;
alter table asset add fix text;

--changeset siewer:63
alter table softwarepacket add uptated boolean;

--changeset siewer:64
create table softwarepacketvulnerability (
  id serial primary key,
  name text,
  softwarepacket_id int references softwarepacket(id),
  score text);

--changeset siewer:65
alter table webapp add lastscan text;

--changeset siewer:66
alter table softwarepacketvulnerability add column fix text;

--changeset siewer:67
alter table webapp add column inserted text;

--changeset siewer:68
alter table infrastructurevuln add column inserted text;
alter table codevuln add column inserted text;
alter table softwarepacketvulnerability add column inserted text;

--changeset siewer:69
insert into scannertype (name) values ('Fortify SSC');

--changeset siewer:70
alter table nessus add column fortifytoken text;
alter table nessus add column fortifytokenexpiration text;

--changeset siewer:80
alter table codegroup add column versionid integer;

--changeset siewer:81
alter table codevuln add column description text;

--changeset siewer:82
alter table interface add column hostid integer;

--changeset siewer:83
alter table nodeaudit add column apitype_id int references apitype(id);
update nodeaudit set apitype_id=1;
insert into apitype (url,name) values ('cis-docker', 'CIS Docker Benchark');

--changeset siewer:8445/
alter table softwarepacketvulnerability add column project_id int references project(id);

--changeset siewer:84
alter table webapp add column codegroup_id int references codegroup(id);
alter table webapp add column codeproject_id int references codeproject(id);

--changeset siewer:85
alter table vulnhistory add column codevulnnumber int;
alter table vulnhistory add column webappvulnnumber int;
alter table vulnhistory add column auditvulnnumber int;
alter table vulnhistory rename vulnnumber to infrastructurevulnnumber;

--changeset siewer:86
truncate table vulnhistory;

--changeset siewer:87
insert into apitype (url,name,description) values ('sast','Statyczne analizy kodu źródłowego - zlecanie','Statyczne analizy kodu źródłowego - zlecanie');

--changeset siewer:88
create table codescan(
  id serial primary key,
  inQueue boolean,
  codegroup_id int references codegroup(id),
  inserted text,
  running boolean,
  codeproject_id int references codeproject(id)
);

--changeset siewer:89
alter table project add column contactlist text;

--changeset siewer:90
alter table asset add column assettype text;
update asset set assettype='SINGLE';

--changeset siewer:91
alter table interface add column pool text;
alter table interface add column autocreated boolean;
update interface set autocreated=false;
--changeset siewer:92
insert into scannertype (name) values ('Nexpose');
--changeset siewer:93
alter table nessus add column engineId int;
alter table nessus add column template text;

--changeset siewer:94
create table journal (
  id serial primary key,
  name text,
  inserted timestamp not null default now(),
  users_id int references users(id),
  project_id int references project(id)
);

--changeset siewer:95
alter table journal add column cnname text;

--changeset siewer:96
alter table journal alter column inserted drop not null;

--changeset siewer:97
alter table project add column webappautodiscover boolean;

--changeset siewer:98
alter table webapp add column autostart boolean;

--changeset siewer:99
alter table webappvuln add column codeproject_id int references codeproject(id);

--changeset siewer:100
create table cioperations(
  id serial primary key,
  project_id int references project(id),
  codeproject_id int references codeproject(id),
  codegroup_id int references codegroup(id),
  inserted timestamp default now(),
  vulnnumber int,
  result text
);

--changeset siewer:101
alter table codegroup add column repourl text;
alter table codegroup add column repousername text;
alter table codegroup add column repopassword text;
alter table codegroup add column running boolean;
alter table codegroup add column jobid text;
alter table codegroup add column inqueue boolean;
alter table codegroup add column auto boolean;
alter table codeproject add column repourl text;
alter table codeproject add column repousername text;
alter table codeproject add column repopassword text;

--changeset siewer:102
alter table codeproject add column technique text;
alter table codegroup add column technique text;
insert into scannertype (name) values ('Fortify SCA Rest API');

--changeset siewer:103
alter table codegroup add column versionidall int;
alter table codegroup add column versionidsingle int;
update codegroup set versionidall=versionid;
alter table codegroup drop column versionid;

--changeset siewer:104
update codegroup set versionidsingle=0;
--changeset siewer:105
alter table codegroup add column requestid text;
alter table codegroup add column scanid text;

--changeset siewer:106
alter table codegroup add column scope text;

--changeset siewer:107
alter table codeproject add column skipallscan boolean;
update codeproject set skipallscan=false;

--changeset siewer:108
alter table codeproject add column additionalpath text;

--changeset siewer:109
create table webappcookies(
    id serial primary key,
    webapp_id int references webapp(id),
    cookie text,
    url text
);
--changeset siewer:110
alter table codeproject add column inqueue boolean;
update codeproject set inqueue=false;
--changeset siewer:111
create table fortifysingleapp(
    id serial primary key,
    requestid text,
    codeproject_id int references codeproject(id),
    codegroup_id int references codegroup(id),
    jobtoken text,
    finished boolean,
    downloaded boolean
);
--changeset siewer:112
alter table nessus add column rfwscannerip text;

--changeset siewer:113
create table status(
    id serial primary key,
    name text
);
insert into status (name) values ('NEW'),('EXISTING');
create table service(
    id serial primary key,
    port int,
    name text,
    netproto text,
    appproto text,
    interface_id int references interface(id),
    status_id int references status(id)
);
alter table infrastructurevuln add column status_id int references status(id);

--changeset siewer:114
alter table nessusscan add column requestid text;
alter table asset add column requestid text;

--changeset siewer:115
alter table interface add column scanrunning boolean;
alter table project add column autowebappscan boolean;
update interface set scanrunning=false;
update project set autowebappscan=false;

--changeset siewer:116
alter table project add column autocodescan boolean;
update project set autocodescan = false;

--changeset siewer:117
alter table asset_securitygroup drop constraint "asset_securitygroup_asset_id_fkey", add constraint "asset_securitygroup_asset_id_fkey" foreign key ("asset_id") references "asset"(id) on delete cascade;

--changeset siewer:118
alter table project add column apikey text;

--changeset siewer:119
alter table users add column username text;
alter table users add column password text;

--changeset siewer:120
alter table users add column logins int;
alter table users add column failedlogins int;
update users set logins = 0;
update users set failedlogins = 0;

--changeset siewer:121
alter table codeproject add column commitid text;

--changeset siewer:122
alter table interface drop constraint interface_asset_id_fkey, add constraint interface_asset_id_fkey foreign key ("asset_id") references "asset"(id) on delete cascade;

--changeset siewer:123
alter table vulnhistory drop constraint vulnhistory_project_id_fkey, add constraint vulnhistory_project_id_fkey foreign key ("project_id") references "project"(id) on delete cascade;

--changeset siewer:124
alter table webappvuln drop constraint "webappvuln_webapp_id_fkey", add constraint "webappvuln_webapp_id_fkey" foreign key ("webapp_id") references "webapp"(id) on delete cascade;
alter table webappheader drop constraint "webappheader_webapp_id_fkey", add constraint "webappheader_webapp_id_fkey" foreign key ("webapp_id") references "webapp"(id) on delete cascade;
alter table webappcookies drop constraint "webappcookies_webapp_id_fkey", add constraint "webappcookies_webapp_id_fkey" foreign key ("webapp_id") references "webapp"(id) on delete cascade;

--changeset siewer:125
create table settings (
    id serial primary key,
    initialized boolean
);
insert into settings (initialized) values (false);

--changeset siewer:126
alter table codeproject add column running boolean;
update codeproject set running=false;

--changeset siewer:127
insert into apitype (url, name , description) values ('mvndependencycheck','Download for MVN Dependency Check by owasp','');

--changeset siewer:128
create table codeproject_softwarepacket(
    codeproject_id int references codeproject(id),
    softwarepacket_id int references softwarepacket(id));
alter table softwarepacketvulnerability add column description text;
alter table softwarepacketvulnerability add column severity text;

--changeset siewer:129
alter table vulnhistory add column softwarepacketvulnnumber int;
update vulnhistory set  softwarepacketvulnnumber=0;

--changeset siewer:130
alter table project add column autoinfrascan boolean;
update project set autoinfrascan= false;

--changeset siewer:131
alter table codeproject add column branch text;

--changeset siewer:133
alter table infrastructurevuln drop constraint infrastructurevuln_interface_id_fkey, add constraint infrastructurevuln_interface_id_fkey foreign key ("interface_id") references "interface"(id) on delete cascade;
alter table service drop constraint service_interface_id_fkey, add constraint service_interface_id_fkey foreign key ("interface_id") references "interface"(id) on delete cascade;
alter table nessus_interface drop constraint nessus_interface_interface_id_fkey, add constraint nessus_interface_interface_id_fkey foreign key ("interface_id") references "interface"(id) on delete cascade;

--changeset siewer:134
alter table codevuln drop constraint codevuln_codeproject_id_fkey, add constraint codevuln_codeproject_id_fkey foreign key ("codeproject_id") references codeproject(id) on delete cascade;
alter table codevuln drop constraint codevuln_codegroup_id_fkey, add constraint codevuln_codegroup_id_fkey foreign key ("codegroup_id") references codegroup(id) on delete cascade;

--changeset siewer:135
alter table codegroup add column if not exists hasprojects boolean;

--changeset siewer:136
alter table codeproject add column requestid text;
alter table webapp add column requestid text;

--changeset siewer:137
alter table nessusscan drop constraint nessusscan_nessus_id_fkey, add constraint nessusscan_nessus_id_fkey foreign key ("nessus_id") references nessus(id) on delete cascade;
alter table nessus_interface drop constraint nessus_interface_nessusscan_id_fkey, add constraint nessus_interface_nessusscan_id_fkey foreign key ("nessusscan_id") references nessusscan(id) on delete cascade;

--changeset siewer:138
alter table webapp add constraint unique_url unique (url);

--changeset siewer:139
alter table webapp drop constraint unique_url;
alter table webapp add constraint unique_url unique(project_id,url);

--changeset siewer:140
alter table settings add column smtphost text;
alter table settings add column smtpport int default 0;
alter table settings add column smtpusername text;
alter table settings add column smtppassword text;
alter table settings add column smtpauth boolean;
alter table settings add column smtptls boolean;
alter table settings add column passwordauth boolean;
alter table settings add column certificateauth boolean;

--changeset siewer:141
ALTER TABLE nessus ADD COLUMN IF NOT EXISTS rfwpassword text;
ALTER TABLE nessus ADD COLUMN IF NOT EXISTS rfwuser text;
ALTER TABLE nessus ADD COLUMN IF NOT EXISTS rfwurl text;
ALTER TABLE nessus ADD COLUMN IF NOT EXISTS scannerid text;

--changeset siewer:142
alter table settings add column masterapikey text;

--changeset siewer:143
update settings set smtpport = 0;

--changeset siewer:144
alter table settings drop column if exists certificate_auth;
alter table settings drop column if exists master_api_key;
alter table settings drop column if exists password_auth;
alter table settings drop column if exists smtp_auth;
alter table settings drop column if exists smtp_password;
alter table settings drop column if exists smtp_host;
alter table settings drop column if exists smtp_tls;
alter table settings drop column if exists smtp_username;

--changeset siewer:145
alter table codevuln add column status_id int references status(id);
alter table webappvuln add column status_id int  references status(id);
alter table nodeaudit add column status_id int references status(id);
alter table softwarepacketvulnerability add column status_id int references status(id);

--changeset siewer:146
update settings set certificateauth=true, passwordauth=true;

--changeset siewer:147
create table bugtrackertype (
    id serial primary key,
    name text
);
insert into bugtrackertype (name) values ('JIRA');
create table bugtracker (
    id serial primary key,
    bugtrackertype_id int references bugtrackertype(id),
    url text,
    username text,
    projectid text,
    issuetype text,
    vulns text,
    project_id int references project(id)
);

--changeset siewer:148
alter table bugtracker add column autostrategy text;

--changeset siewer:149
alter table bugtracker add column asignee text;

--changeset siewer:150
alter table infrastructurevuln add column ticketid int;
alter table webappvuln add column ticketid int;
alter table codevuln add column ticketid int;
alter table softwarepacketvulnerability add column ticketid int;
update infrastructurevuln set ticketid = 0;
update webappvuln set ticketid = 0;
update softwarepacketvulnerability set ticketid = 0;
update codevuln set ticketid = 0;

--changeset siewer:151
alter table infrastructurevuln drop column ticketid;
alter table webappvuln drop column ticketid;
alter table codevuln drop column ticketid;
alter table softwarepacketvulnerability drop column ticketid;
alter table infrastructurevuln add column ticketid text;
alter table webappvuln add column ticketid text;
alter table codevuln add column ticketid text;
alter table softwarepacketvulnerability add column ticketid text;

--changeset siewer:152
alter table codevuln add column externalid int;

--changest siewer:153
alter table bugtracker add column proxies_id int references proxies(id);

--changeset siewer:154
insert into scannertype (name) values ('OpenVAS Socket');

--changeset siewer:155
alter table bugtracker drop constraint bugtracker_project_id_fkey, add constraint bugtracker_project_id_fkey foreign key ("project_id") references project(id) on delete cascade;

--changeset siewer:156
alter table settings add column infraautocron text;
alter table settings add column webappautocron text;
alter table settings add column codeautocron text;

--changeset siewer:157
update settings set infraautocron='0 0 10,21 * * *';
update settings set webappautocron='0 55 1 * * FRI';
update settings set codeautocron='0 40 23 * * *';

--changeset siewer:158
alter table settings add column domain text;

--changeset siewer:159
alter table scannertype add column authapikey boolean;
alter table scannertype add column authsecrettoken boolean;
alter table scannertype add column authaccesstoken boolean;
alter table scannertype add column authusername boolean;
alter table scannertype add column authpassword boolean;
alter table scannertype add column authcloudctrltoken boolean;
update scannertype set authapikey=false,authsecrettoken=false,authaccesstoken=false,authusername=true,authpassword=true,authcloudctrltoken=false where name='OpenVas Socket';
update scannertype set authapikey=false,authsecrettoken=false,authaccesstoken=false,authusername=true,authpassword=true,authcloudctrltoken=false where name='OpenVas';
update scannertype set authapikey=false,authsecrettoken=false,authaccesstoken=false,authusername=true,authpassword=true,authcloudctrltoken=false where name='Nexpose';
update scannertype set authapikey=false,authsecrettoken=false,authaccesstoken=false,authusername=true,authpassword=true,authcloudctrltoken=false where name='Fortify SSC';
update scannertype set authapikey=false,authsecrettoken=false,authaccesstoken=false,authusername=false,authpassword=false,authcloudctrltoken=true where name='Fortify SCA Rest API';
update scannertype set authapikey=true,authsecrettoken=false,authaccesstoken=false,authusername=false,authpassword=false,authcloudctrltoken=false where name='Acunetix';
update scannertype set authapikey=false,authsecrettoken=true,authaccesstoken=true,authusername=false,authpassword=false,authcloudctrltoken=false where name='Nessus';
insert into scannertype (name, authaccesstoken,authapikey,authcloudctrltoken,authpassword,authusername,authsecrettoken) values ('OWASP Dependency Track',false,true,false,false,false,false);
alter table codeproject add column dtrackuuid text;

--changeset siewer:160
alter table settings add column trendemailcron text;
update settings set trendemailcron='0 0 14 * * FRI';

--changeset siewer:161
insert into scannertype (name, authapikey, authsecrettoken, authaccesstoken, authusername,authpassword,authcloudctrltoken) values ('Checkmarx', false,false,false,true,true,false);

--changeset siewer:162
alter table nessus add column team text;

--changeset siewer:163
update scannertype set authapikey=false,authsecrettoken=false,authaccesstoken=false,authusername=true,authpassword=true,authcloudctrltoken=false where name='OpenVAS Socket';
update scannertype set authapikey=false,authsecrettoken=false,authaccesstoken=false,authusername=true,authpassword=true,authcloudctrltoken=false where name='OpenVAS';

--changeset siewer:164
create table user_project (
    users_id int references users(id),
    project_id int references project(id)
);

--changeset:siewer:165
drop table user_project;
create table user_project (
    users_id int references users(id) on delete cascade,
    project_id int references project(id) on delete cascade
);

--changeset siewer:166
alter table user_project drop constraint user_project_project_id_fkey, add constraint user_project_project_id_fkey foreign key ("project_id") references project(id) on delete cascade;
alter table user_project drop constraint user_project_users_id_fkey, add constraint user_project_users_id_fkey foreign key ("users_id") references users(id) on delete cascade;

--changeset siewer:167
insert into user_project (users_id ,project_id) select u.id, p.id from users u, project p where u.permisions='ROLE_USER';


--changeset siewer:168
alter table cioperations add column sastcrit int;
alter table cioperations add column sasthigh int;
alter table cioperations add column opensourcehigh int;
alter table cioperations add column opensourcecrit int;
alter table cioperations add column imagecrit int;
alter table cioperations add column imagehigh int;
alter table cioperations add column commitId text;
alter table cioperations add column imageId text;
alter table cioperations add column sastscan boolean;
alter table cioperations add column opensourcescan boolean;
alter table cioperations add column imagescan boolean;

--changeset siewer:169
alter table cioperations add column ended timestamp;

--changeset siewer:170
delete from cioperations;
alter table nessusscan drop constraint "nessusscan_nessusscantemplate_id_fkey", add constraint "nessusscan_nessusscantemplate_id_fkey" foreign key ("nessusscantemplate_id") references "nessusscantemplate"(id) on delete cascade;
alter table nessusscantemplate drop constraint "nessusscantemplate_nessus_id_fkey", add constraint "nessusscantemplate_nessus_id_fkey" foreign key ("nessus_id") references "nessus"(id) on delete cascade;

--changeset siewer:171
create table webappscanstrategy (
    id serial primary key,
    apiscans_id int references scannertype(id),
    scheduledscans_id int references scannertype(id),
    guiscans_id int references scannertype(id)
);
insert into webappscanstrategy (apiscans_id, scheduledscans_id, guiscans_id) values (null, null, null);

--changeset siewer:172
alter table scannertype add column category text ;
update scannertype set category='NETWORK' where name='OpenVAS Socket';
update scannertype set category='NETWORK' where name='OpenVAS';
update scannertype set category='NETWORK' where name='Nexpose';
update scannertype set category='CODE' where name='Fortify SSC';
update scannertype set category='CODE' where name='Fortify SCA Rest API';
update scannertype set category='WEBAPP' where name='Acunetix';
update scannertype set category='NETWORK' where name='Nessus';
update scannertype set category='OPENSOURCE' where name='OWASP Dependency Track';

--changeset siewer:173
alter table webapp add column routingdomain_id int references routingdomain(id);

--changeset siewer:174
alter table webapp add column origin text;

--changeset siewer:175
alter table nessus add column runningscans int;
update nessus set runningscans = 0;

--changeset siewer:176
insert into scannertype (name,authcloudctrltoken, authpassword, authusername, authaccesstoken, authsecrettoken, authapikey) values ('Burp Enterprise Edition', false,false, false,false,false,true);

--changeset siewer:177
alter table scannertype add column scanlimit int;
update scannertype set scanlimit=0;
update scannertype set scanlimit=25 where name='Acunetix';
update scannertype set scanlimit=5 where name='Burp Enterprise Edition';

--changeset siewer:178
update webapp set inqueue=false where inqueue is null;

--changeset siewer:179
update scannertype set category='WEBAPP' where name='Burp Enterprise Edition';
update scannertype set category='CODE' where name='Checkmarx';

--changeset siewer:180
alter table project add column risk int;
alter table interface add column risk int;
alter table webapp add column risk int;
alter table codeproject add column risk int;
update project set risk=0;
update interface set risk=0;
update webapp set risk=0;
update codeproject set risk=0;

--changeset siewer:181
alter table webapp add column username text;
alter table webapp add column password text;

--changeset siewer:182
alter table codeproject_softwarepacket drop constraint "codeproject_softwarepacket_codeproject_id_fkey", add constraint "codeproject_softwarepacket_codeproject_id_fkey" foreign key ("codeproject_id") references "codeproject"(id) on delete cascade;

--changeset siewer:183
alter table cioperations drop constraint "cioperations_codeproject_id_fkey", add constraint "cioperations_codeproject_id_fkey" foreign key ("codeproject_id") references codeproject("id") on delete cascade;

--changeset siewer:184
alter table fortifysingleapp drop constraint "fortifysingleapp_codeproject_id_fkey", add constraint "fortifysingleapp_codeproject_id_fkey" foreign key ("codeproject_id") references codeproject("id") on delete cascade;

--changeset siewer:185
alter table infrastructurevuln add column grade int;
alter table softwarepacketvulnerability add column grade int;
alter table webappvuln add column grade int;
alter table codevuln add column grade int;

--changeset siewer:186
update infrastructurevuln set grade =-1;
update softwarepacketvulnerability set grade =-1;
update codevuln set grade =-1;
update webappvuln set grade =-1;

--changeset siewer:187
alter table webapp add column priority int;
update webapp set priority=0;

--changeset siewer:188
alter table project add column enablevulnmanage boolean;
update project set enablevulnmanage=true;

--changeset siewer:189
create table vulnerability(
    id serial primary key,
    name text,
    description text,
    refs text,
    recommendation text,
    impact text,
    vector text
);
create table vulnerabilitysource(
    id serial primary key,
    name text
);
insert into vulnerabilitysource (name) values ('OpenSource'), ('SourceCode'), ('WebApplication'), ('Network');
create table projectvulnerability(
    id serial primary key,
    vulnerability_id int references vulnerability(id),
    project_id int references project(id) on delete cascade,
    webapp_id int references webapp(id) on delete cascade,
    codeproject_id int references codeproject(id) on delete cascade,
    interface_id int references interface(id) on delete cascade,
    softwarepacket_id int references softwarepacket(id) on delete cascade,
    description text,
    recommendation text,
    severity text,
    inserted text,
    location text,
    externalid int,
    ticketid int,
    status_id int references status(id),
    analysis text,
    port text,
    grade int,
    vulnerabilitysource_id int references vulnerabilitysource(id) on delete cascade
);
insert into vulnerability (name) select name from codevuln union select name from infrastructurevuln union select name from webappvuln union select name from softwarepacketvulnerability;

insert into projectvulnerability (vulnerability_id,project_id,webapp_id, description, recommendation, severity, status_id, grade,vulnerabilitysource_id,inserted, location)
    select vuln.id, webapp.project_id, webappvuln.webapp_id, webappvuln.description, webappvuln.recommendation, webappvuln.severity, webappvuln.status_id,
           webappvuln.grade, source.id, webapp.lastexecuted, webappvuln.location from vulnerability vuln, webapp webapp, webappvuln webappvuln, vulnerabilitysource source where webapp.id=webappvuln.webapp_id
            and source.name='WebApplication' and vuln.name=webappvuln.name;

insert into projectvulnerability (vulnerability_id, project_id, interface_id, description, severity,inserted, status_id, grade,vulnerabilitysource_id, location,port)
    select vuln.id, a.project_id, v.interface_id, v.description, v.threat, v.inserted, v.status_id, v.grade, source.id, a.name,v.port from vulnerability vuln, asset a, interface i,
        infrastructurevuln v, vulnerabilitysource source where v.interface_id = i.id and i.asset_id=a.id and vuln.name=v.name and source.name='Network';

insert into projectvulnerability (vulnerability_id, project_id, codeproject_id, location, severity, analysis, inserted, description, status_id, externalid, vulnerabilitysource_id)
    select vuln.id, cg.project_id, v.codeproject_id, v.filepath, v.severity, v.analysis, v.inserted, v.description, v.status_id, v.externalid, source.id from
        vulnerability vuln, codegroup cg, codevuln v, vulnerabilitysource source where v.codegroup_id=cg.id and vuln.name=v.name and source.name='SourceCode';

insert into projectvulnerability (vulnerability_id, softwarepacket_id, severity, description, status_id, grade, inserted, project_id, vulnerabilitysource_id, location,codeproject_id)
    select vuln.id, v.softwarepacket_id, v.severity, v.description, v.status_id, v.grade, v.inserted, cg.project_id, source.id, p.name, csp.codeproject_id from
        softwarepacketvulnerability v, vulnerability vuln, vulnerabilitysource source, softwarepacket p, codeproject_softwarepacket csp, codeproject cp, codegroup cg
        where p.id=v.softwarepacket_id and vuln.name=v.name and source.name='OpenSource' and csp.softwarepacket_id=p.id and cp.id=csp.codeproject_id and cg.id=cp.codegroup_id;

--changeset siewer:190
insert into vulnerabilitysource (name) values ('OSPackage');

--changeset siewer:191
update projectvulnerability set externalid=0 where externalid is null;
update projectvulnerability set ticketid=0 where ticketid is null;

--changeset siewer:192
update projectvulnerability set grade=-1 where grade is null;

--changeset siewer:193
alter table project add column vulnauditorenable boolean;
update project set vulnauditorenable=true;
alter table project add column networkdc text;
alter table codegroup add column appclient text;
alter table webapp add column appclient text;

--changeset siewer:194
alter table project add column appclient text;
alter table settings add column vulnauditorenable boolean;
update settings set  vulnauditorenable=false;

--changeset siewer:195
insert into status (name) values ('REMOVED');
alter table settings add column vulnauditorurl text;
update settings set vulnauditorurl='https://localhost:8445';

--changeset siewer:196
update codeproject set skipallscan=true where skipallscan is null;

--changeset siewer:197
alter table nessusscan add column retries int;
update nessusscan set retries=0;

--changeset siewer:198
create table iaasapitype (
    id serial primary key,
    name text
);
insert into iaasapitype (name) values ('OpenStack'), ('AWS EC2');
alter table iaasapi add column iaasapitype_id int references iaasapitype(id) on delete cascade ;
update iaasapi set iaasapitype_id = 1;
--changeset siewer:grade_based_gateway
create table securitygatway (
    id serial primary key,
    grade boolean,
    high int,
    critical int,
    medium int,
    vuln int
);
insert into securitygatway (grade, high, critical, medium, vuln) values (false,5,3,100,2);

--changeset siewer:aws_ec2_integration
alter table iaasapi add column region text;
alter table iaasapi add column vpcid text;

--changeset siewer:api_key_cicd_user
alter table users add column apikey text;

--changeset siewer:feature_scanner
delete from scannertype where name='OpenVAS Socket';

--changeset siewer:project_for_editor_runner
insert into user_project (select u.id, p.id from project p, users u where u.permisions ='ROLE_EDITOR_RUNNER');

--changeset siewer:project_owner
alter table project add column owner_id int references users(id);
update project set owner_id = (select id from users where name='admin');

--changeset siewer:project_owner_fix
update project set owner_id = (select id from users where name='username');

--changeset siewer:add_gitleaks
insert into vulnerabilitysource (name) values ('GitLeaks');

--changeset siewer:add_git_credentials
create table gitcredentials (
    id serial primary key,
    url text,
    username text,
    password text
);

--changeset siewer:cx_branches
create table cxbranch (
    id serial primary key,
    codeproject_id int references codeproject(id),
    branch text,
    cxid int
);
insert into cxbranch (codeproject_id, branch, cxid) select cp.id, cp.branch, cg.versionidall from codeproject cp, codegroup cg where cp.codegroup_id = cg.id and cg.versionidall>0;

--changeset siewer:cx_branches_2
alter table codegroup add column remoteid int;
update codegroup set remoteid =0;
update codegroup set remoteid=versionidall;

--changeset siewer:cis_openscap
create table cisrequirement(
    id serial primary key,
    name text,
    type text
);
alter table projectvulnerability add column cisrequirement_id int references cisrequirement(id);
update projectvulnerability set cisrequirement_id=null;
insert into vulnerabilitysource (name) values ('CISBenchmark');

--changeset siewer:cis_openscap2
insert into routingdomain (name) values ('Default');

--changeset siewer:vulnerability_severity_customization
alter table vulnerability add column severity text;
alter table cisrequirement add column severity text;
update cisrequirement set severity = 'Medium';

--changeset siewer:add_queue_to_nessuscan
alter table nessusscan add column inqueue boolean;
update scannertype set scanlimit=5 where name='OpenVAS';

--changeset siewer:change_ticket_type
update projectvulnerability set ticketid = null;
alter table projectvulnerability alter column ticketid type text;

--changeset siewer:add_jira_option_to_code_project
alter table codeproject add column enablejira boolean;
update codeproject set enablejira=false;

--changeset siewer:remove_code_group
alter table codeproject add column versionidall int;
alter table codeproject add column versionidsingle int;
alter table codeproject add column jobid text;
alter table codeproject add column scanid text;
alter table codeproject add column scope text;
alter table codeproject add column remoteid int;
alter table codeproject add column appclient text;
alter table codeproject add column auto boolean;
alter table codeproject add column project_id int references project(id);

update codeproject set project_id=cg.project_id,versionidall=cg.versionidall, versionidsingle=cg.versionidsingle, jobid=cg.jobid, scanid=cg.scanid, scope=cg.scope,remoteid=cg.remoteid,appclient=cg.appclient from codegroup cg where cg.id=codeproject.codegroup_id;

alter table codeproject drop column codegroup_id;
alter table codescan drop column codegroup_id;
alter table codevuln drop column codegroup_id;
alter table webapp drop column codegroup_id;
alter table fortifysingleapp drop column codegroup_id;
alter table cioperations drop column codegroup_id;
drop table codegroup;

--changeset siewer:fix_code_project_status
update codeproject set running=false where running is null;
update codeproject set inqueue=false where inqueue is null;

--changeset siewer:add_columns_to_nessusscan
alter table nessusscan add column inserted text;
alter table nessusscan add column updated text;

--changeset siewer:add_webapp_and_code_scan_entity
alter table codescan add column updated text;
alter table webappscan add column inserted text;
alter table webappscan add column updated text;

--changeset siewer:add_nexus_iq
insert into scannertype (name, authaccesstoken,authapikey,authcloudctrltoken,authpassword,authusername,authsecrettoken,scanlimit) values ('Nexus-IQ',false,false,false,true,true,false,0);

--changeset siewer:change_nexus
update scannertype set  category='OPENSOURCE' where name='Nexus-IQ';
alter table codeproject add column remotename text;

--changeset siewer:bugtracker_epic
alter table bugtracker add column epic text;

--changeset siewer:everno
create table projectvulnerability_AUD(
                                         id bigint not null,
                                         REV integer not null,
                                         REVTYPE int,
                                         inserted text,
                                         inserted_MOD text,
                                         analysis text,
                                         analysis_MOD text,
                                         location text,
                                         location_MOD text,
                                         description text,
                                         description_MOD text,
                                         severity text,
                                         severity_MOD text,
                                         ticketid text,
                                         ticketid_MOD text,
                                         ticket_id text,
                                         ticket_id_MOD text,
                                         status_id int,
                                         status_MOD boolean,
                                         vulnerability_id int,
                                         vulnerability_MOD boolean,
                                         interface_id int,
                                         an_interface_MOD boolean,
                                         codeproject_id int,
                                         code_project_mod boolean,
                                         project_id int,
                                         project_mod boolean,
                                         vulnerabilitysource_id int,
                                         vulnerability_source_mod boolean,
                                         webapp_id int,
                                         web_app_mod boolean,
                                         softwarepacket_id int,
                                         software_packet_mod boolean,
                                         cisrequirement_id int,
                                         cis_requirement_mod boolean,
                                         primary key (id, REV)

);

create table REVINFO (
                         REV integer generated by default as identity,
                         REVTSTMP bigint,
                         primary key (REV)
);
alter table projectvulnerability_AUD
    add constraint FK5ecvi1a0ykunrriib7j28vpdj
        foreign key (REV)
            references REVINFO;

--changeset siewer:envers-error-fix
CREATE SEQUENCE hibernate_sequence START 1;

--changeset siewer:add-scantype-iac
insert into vulnerabilitysource (name) values ('IaC');

--changeset siewer:add-codeproject-branch
create table codeprojectbranch (
    id serial primary key,
    codeproject_id int references codeproject(id),
    name text,
    inserted text
);

alter table projectvulnerability add column codeprojectbranch_id int references codeprojectbranch(id);

--changeset siewer:add-active-branch
alter table codeproject add column activebranch text;

--changeset siewer:add-crated-time
ALTER TABLE projectvulnerability ADD created TEXT;
UPDATE projectvulnerability SET created = TO_CHAR(NOW(), 'YYYY-MM-DD HH24:MI:SS');

--changeset siewer:fix-created-time
UPDATE projectvulnerability SET created = created || '.000' WHERE created IS NOT NULL;

--changeset siewer:extend-history
alter table vulnhistory add column resolvedvulnerabilities int;
alter table vulnhistory add column avgtimetofix int;
alter table vulnhistory add column percentresolvedcriticals int;

alter table vulnhistory add column codecritvuln int;
alter table vulnhistory add column codehighvuln int;
alter table vulnhistory add column codemediumvuln int;
alter table vulnhistory add column codelowvuln int;

alter table vulnhistory add column scacritvuln int;
alter table vulnhistory add column scahighvuln int;
alter table vulnhistory add column scamediumvuln int;
alter table vulnhistory add column scalowvuln int;

alter table vulnhistory add column webappcritvuln int;
alter table vulnhistory add column webapphighvuln int;
alter table vulnhistory add column webappmediumvuln int;
alter table vulnhistory add column webapplowvuln int;

alter table vulnhistory add column assetcritvuln int;
alter table vulnhistory add column assethighvuln int;
alter table vulnhistory add column assetmediumvuln int;
alter table vulnhistory add column assetlowvuln int;

--changeset siewer:fixes
ALTER TABLE bugtracker ADD COLUMN IF NOT EXISTS password text;

--changeset siewer:history_for_assets
alter table vulnhistory add column asset_id int;
update vulnhistory set  asset_id=0;

--changeset siewer:prepare_codeproject_for_multiprojects
alter table codeproject add column contain_embeded boolean default false;
alter table codeproject add column parent_id int references codeproject(id);
alter table codeproject add column path text;

--changeset siewer:prepare_webapp
alter table webapp add column basicauth text;
alter table webapp add column apikey text;
alter table webapp add column header text;
alter table webapp add column name text;

--changeset siewer:scanning_api
create table scan(
    id serial primary key,
    inserted text,
    triggerer text,
    type text,
    codeproject_id int references codeproject(id) ON DELETE CASCADE,
    webapp_id int references webapp(id) ON DELETE CASCADE,
    interface_id int references interface(id) ON DELETE CASCADE,
    branch text,
    commitid text,
    vulncrit int,
    vulnmedium int,
    vulnlow int
);

--changeset siewer:asset_history
create table assethistory(
    id serial primary key,
    inserted text,
    codeproject_id int references codeproject(id) ON DELETE CASCADE,
    webapp_id int references webapp(id) ON DELETE CASCADE,
    interface_id int references interface(id) ON DELETE CASCADE,
    scavulns int,
    sastvulns int,
    iacvulns int,
    secretvulns int,
    dastvulns int,
    networkvulns int

);

--changeset siewer:asset_ci_operation
alter table cioperations add column webapp_id int references webapp(id) ON DELETE CASCADE;
alter table cioperations add column interface_id int references interface(id) ON DELETE CASCADE;

--changeset siewer:add_inserted_to_scannable
alter table codeproject add column inserted text;
alter table interface add column inserted text;
UPDATE codeproject SET inserted = to_char(NOW(), 'YYYY-MM-DD HH24:MI:SS');
UPDATE interface SET inserted = to_char(NOW(), 'YYYY-MM-DD HH24:MI:SS');

--changeset siewer:modify_ci_operations
alter table cioperations add column dastscan_id int references scan(id);
alter table cioperations add column sastscan_id int references scan(id);
alter table cioperations add column scascan_id int references scan(id);
alter table cioperations add column secretscan_id int references scan(id);
alter table cioperations add column iacscan_id int references scan(id);
alter table cioperations add column branch text;

--changeset siewer:metrics
create table metric(
    id serial primary key,
    activevulnavg int,
    activevulnno int,
    fixedvulnno int,
    fixedvulnpercent int,
    fixtime int,
    projectwithcicdno int,
    projectwithcicdpercent int,
    securejobno int,
    securejobpercent int,
    bugtrackingintegratedno int,
    bugtrackingintegratedpercent int,
    project_id int references project(id) ON DELETE CASCADE
)

--changeset siewer:extend_history
alter table assethistory add column crit int;
alter table assethistory add column high int;
alter table assethistory add column medium int;
alter table assethistory add column low int;

--changeset siewer:extend_history_fix
update assethistory set crit=0 where crit is null;
update assethistory set high=0 where high is null;
update assethistory set medium=0 where medium is null;
update assethistory set low=0 where low is null;

--changeset siewer:add_indexes
CREATE INDEX idx_project_vulnerability_project_id ON projectvulnerability (project_id);
CREATE INDEX idx_project_vulnerability_status_id ON projectvulnerability (status_id);
CREATE INDEX idx_project_vulnerability_grade ON projectvulnerability (grade);

--changeset siewer:add_new_indexes
CREATE INDEX idx_user_id ON users (id);
CREATE INDEX idx_users_project_users ON user_project(users_id);
CREATE INDEX idx_users_project_project ON user_project(project_id);
