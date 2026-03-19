# ShadowLab Platform Guide

ShadowLab yerli isleyen, API-first yanasmasi ile qurulmus, amma gundelik istifade terefi esasen desktop uzerinden verilen bir cybersecurity operations platformasidir. Layihe yalniz sade monitorinq aleti deyil. Hazir veziyyetde o, host telemetry toplamaq, subheli prosesleri arasdirmaq, persistence izlerini gormek, threat-intel enrichment etmek, case acmaq, investigation aparmaq, report cixarmaq ve security-ops nezaretini saxlamaq ucun vahid is muhiti verir.

Bu senedin meqsedi layihenin ne oldugunu, bu gun hansi seviyyeye geldiyini, icinde hansi bolmelerin oldugunu ve bir operatorun onu nece istifade edeceyini bir yerde, daha teqdimatliq formada gostermekdir.

## ShadowLab bu gun nedir

Layihenin merkezinde FastAPI backend dayanir. Butun esas emeliyyatlar burada idare olunur. PySide6 ile yazilmis desktop client ise hemin backend-in operator uzudur. Neticede hem lokal lab seraitinde rahat islemek olur, hem de arxitektura gelecekde basqa client-ler ve ya automation ucun aciq qalir.

Hazir mehsul bir nece istiqameti birlesdirir. Bir terefde telemetry, process investigation, response, persistence ve threat-intel hisseleri var. Diger terefde ise artiq enterprise seviyyeye yaxin investigation layer qurulub. Bu hissede case board, assignment, task, note, story, activity feed, notification center, scoped graph correlation, executive export ve security-ops nezareti movcuddur.

## Layihede neler edilib

Bu repository artiq ilkin prototip merhelesini kecib. Hazirda esas tebeqeler qurulub.

Evvelce backend tebeqesi formalasdirilib. Burada process investigation, triage, threat enrichment, persistence review, incidents, graph, timeline, artifacts, deception, telemetry fabric ve enterprise workflow ucun route-lar var.

Sonra desktop tebeqesi genislendirilib. Bu hisse artiq yalniz sade process viewer deyil. Burada coxsayli tab-lar, role-aware controls, auth-enabled giris, lokal scroll davranisi ve enterprise operator workflow-u var.

Daha sonra enterprise investigation hissesi sifirdan ShadowLab-a uygun sekilde qurulub. Buraya case board, assignments, checklist-style tasks, notes, stories, pins, saved views, case activity, scoped graph correlation, timeline, notification center ve investigation report export daxildir.

Security terefde de vacib duzelisler edilib. Role-based API key axini duzeldilib. Desktop auth disabled olduqda ozunu saxta admin kimi aparmir. Approval one-time-use axini reserve ve finalize modeli ile sertlesdirilib. Agir enterprise refresh davranisi da UI freeze yaratmamaq ucun yumsaldilib.

## Arxitektura nece qurulub

`api/` qovlugu butun esas route-lari saxlayir. `services/` qovlugunda investigation, graph, response, telemetry, incident ve enterprise mentiqi yasayir. `database.py` hem lokal SQLite, hem de PostgreSQL kecidine uygun persistence qatini idare edir. `desktop/` operator UI-ni saxlayir. `docs/` istifadeye ve emeliyyatlara aid senedleri toplayir. `scripts/` ise auth startup, packaging, migration ve verification helper-lerini saxlayir.

Bu dizaynin ustunluyu odur ki, UI ve backend bir-birinden ayri qalir. Yeni senin mehsulun sadece bir interface yox, arxitektura baximindan genislenebilen platformadir.

## Desktop daxilinde hansi bolmeler var

`Dashboards` ve `Overview` operatora umumi veziyyeti gosterir. Burada monitor output, telemetry hissi ve umumi veziyyet oxunur.

`Processes` esas investigation giris noqtelerinden biridir. Burada process profiline baxmaq, process tree gormek, strings cixarmaq, internals, YARAify, sandbox trace, AI analysis ve one-click triage isletmek mumkundur.

`Advanced Hunt` daha derin axtaris ve operator yonumlu arasdirma hissesidir.

`Persistence` bolmesi autorun, scheduled task, service ve uygun persistence izlerini gormek ve lazim geldikde remediation etmek ucun nezerde tutulub.

`Threat Intel` hash ve IP enrichment axinini idare edir. Bu hisse VirusTotal, MalwareBazaar, AbuseIPDB ve YARAify tipli provider-lerle isleyen enrichment modellerine baglanir.

`Deception` honeypot ve canary kimi lab-oriented detection ve bait workflow-larini idare edir.

`Network`, `Hosts`, `Graph` ve `Timeline` bolmeleri hadiseleri daha genis kontekstde gormek ucundur. Burada elaqeler, host inventory, graph correlation ve zaman xetti kimi baxislar formalasir.

`Quarantine`, `History` ve `Artifacts` arasdirmanin ve response-un neticelerini saxlamaq ucun vacib hisselerdir. Buradan ne bas verdiyini, ne tutuldugunu ve hansi materiallarin toplandigini izlemek olur.

`Enterprise` artiq ayrica investigation suite kimi davranir. Bu hisse iki daxili bolmeye ayrilib. `Enterprise Ops` case-centric is axinini idare edir. `Enterprise Intel` ise case-in intelligence ve correlation terefini gosterir.

`Security Ops` integrity, observability, readiness, secret rotation ve report kimi operational tehlukesizlik nezaretlerini saxlayir.

`Scenarios` ve `About / FAQ` ise test ve mehsul teqdimati terefini tamamlayir.

## Enterprise hissesi konkret ne verir

`Enterprise Ops` bolmesinde operator case secir ve ya yaradir. Sonra board uzerinden case-in umumi veziyyetini gorur. Kim bu case uzerinde isleyir, hansi task-lar aciqdir, hansilar gecikib, ne activity bas verib, hansi notification-lar vacibdir, bunlarin hamisi eyni yerde toplanir. Report export da buradan idare olunur.

`Enterprise Intel` daha analitik baxis verir. Burada critical asset gorunusu, detection lifecycle hissesi, notes, stories, case timeline, entity links ve scoped graph correlation toplanir. Yeni case yalniz "ticket" kimi deyil, arasdirma obyektine cevrilir.

Bu, ShadowLab-i sade defensive lab aletinden cixarib mini SOC investigation platformasina yaxinlasdirir.

## Birbasa nece istifade olunur

En sade yol evvelce backend-i qaldirmaqdir. Eger yalniz lokal test isteyirsense `python app.py` kifayetdir. Eger real role-based davranisi yoxlamaq isteyirsense `scripts/start_shadowlab_auth.ps1` ile baslatmaq daha dogrudur.

Sonra `python desktop/main.py` ile desktop acilir. Desktop acildiqdan sonra auth aktivdirse uygun API key daxil edilir. Oradan operator evvelce `Overview` ve `Dashboards` bolmelerine baxa biler. Subheli activity gorende `Processes` ve `Advanced Hunt` uzerine kecib daha derin yoxlama aparir.

Eger hadise incident ve ya case seviyyesine qalxirsa, `Enterprise` daxilinde case yaradilir. Daha sonra task-lar verilir, note ve story yazilir, evidence pin edilir, graph correlation baxilir ve sonda report export olunur.

Eger operational hardening ve ya platform health maraqlidirsa, `Security Ops` bolmesine kecilir. Burada integrity, observability, secrets ve readiness hisseleri yoxlanilir.

## Tovsiye olunan operator axini

Birinci merhelede overview ve dashboards ile umumi veziyyeti yoxlamaq mentiqlidir. Ikinci merhelede process investigation aparilir. Ucuncu merhelede lazim gelse persistence, threat intel, graph ve timeline ile context genislendirilir. Dorduncu merhelede case acilir ve enterprise workflow baslayir. Besinci merhelede report ve artifacts cixarilir. Altinci merhelede security-ops terefinden platforma ve evidence butovluyu yoxlanir.

Bu axin platformanin bugunku guclu terefini gosterir. ShadowLab tekce data gostermir, operatora nece islemek lazim oldugunu da strukturlasdirir.

## Vizual bolme

Asagidaki sekiller desktop daxilindeki bolmeleri section sirasina yaxin axinda gosterir. Her sekilden sonra hemin bolmenin ne ucun istifade olundugu qisa formada izah edilir.

### Dashboards Workspace

![Dashboards Workspace](../images/dashboards-workspace.png)

Bu ekran operatora platformanin umumi veziyyetini ilk baxisda gosterir. Burada live metrics, auth ve policy statusu, threat snapshot ve timeline xulaseleri bir yerde toplanir. Dashboards bolmesi adeten ilkin yoxlama noqtesi kimi isleyir. Operator burada hansı istiqamete kecmeli oldugunu tez mueyyenlesdirir.

### Overview Telemetry Dashboard

![Overview Telemetry Dashboard](../images/overview-telemetry-dashboard.png)

Overview hissesi telemetry axinini daha konkret sekilde oxumaq ucundur. CPU trendi, incident xulaseleri ve cari monitor neticeleri burada daha aydin gorunur. Bu ekran anomaliya ve ya davranis deyisikliyini erkenden gormek ucun rahatdir. Operator ekser hallarda buradan prosese ve ya hadise seviyyesine kecid edir.

### Process Intelligence Workspace

![Process Intelligence Workspace](../images/process-intelligence-workspace.png)

Bu bolme subheli proseslerin esas arasdirma merkezidir. Sol terefde process siyahisi, sag terefde ise secilen prosese aid derin melumat gosterilir. Buradan triage, strings, YARA, sandbox, memory analysis ve diger investigation emeliyyatlari basladila biler. Yani proses seviyyesinde real analiz isi en cox burada gorulur.

### Advanced Hunt Workspace

![Advanced Hunt Workspace](../images/advanced-hunt-workspace.png)

Advanced Hunt daha derin operator axtarislari ucun qurulub. Bu section panel esasli ish muhiti kimi davranir ve internals, strings, YARA, process tree ve AI analyst neticelerini birlesdirir. Operator burada xam telemetry-ni daha analitik baxisla oxuya bilir. Bu hisse sadə baxisdan cixib aktif hunt senarilerine kecmek ucun istifade olunur.

### Persistence Workspace

![Persistence Workspace](../images/persistence-workspace.png)

Persistence bolmesi sistemde qaliciliq mexanizmlerini izlemege komek edir. Autorun, service, scheduled task ve benzeri izler burada gosterilir. Eger riskli bir persistence elementi tapilarsa, remediation axini da bu hisseden basladila biler. Bu section post-exploitation izlerini tutmaq ucun vacibdir.

### Threat Intel Workspace

![Threat Intel Workspace](../images/threat-intel-workspace.png)

Threat Intel ekrani hash, IP ve process context-i xarici enrichment ile birlesdirir. Operator bir obyekt secib onu VirusTotal, MalwareBazaar ve YARAify tipli menbelerle yoxlaya bilir. Bu bolme lokal siqnali daha genis threat konteksti ile tamamlamaq ucundur. Belece araşdırma daha inamli qerar vermeye yaxinlasir.

### Deception And Evidence Workspace

![Deception And Evidence Workspace](../images/deception-evidence-workspace.png)

Bu ekran deception workflow-larini ve evidence capture prosesini bir yerde saxlayir. Honeypot ve canary emeliyyatlari, evidence siyahisi ve output pencereleri operatora eyni panelde verilir. Lab muhitinde aldadici obyektler qurmaq ve neticeleri toplamaq ucun bu section rahatdir. Xususen test ve demonstration senarilerinde boyuk rol oynayir.

### Network Workspace

![Network Workspace](../images/network-workspace.png)

Network section paket ve elaqe kontekstini gormek ucun nezerde tutulub. Burada connection table, discovered devices ve network output hisseleri secilmis trafiki daha aydin edir. Operator hostdaki hereketi sadece proses yox, sebeke baximindan da qiymetlendire bilir. Bu da lateral hereket ve ya xarice cixis kimi hallari gormeye komek edir.

### Hosts Inventory Workspace

![Hosts Inventory Workspace](../images/hosts-inventory-workspace.png)

Hosts bolmesi qeydiyyatdan kecmis hostlari ve agent veziyyetini toplu sekilde gosterir. Platform, IP, role, API status ve version kimi melumatlar burada cox rahat oxunur. Birden cox host olan lab ve ya mini fleet senarisinde bu ekran vacibdir. Operator hansI hostun online oldugunu ve hansinin diqqet istediyini tez anlaya bilir.

### Graph Workspace

![Graph Workspace](../images/graph-workspace.png)

Graph hissesi hadise ve obyektler arasindaki elaqeleri vizual sekilde gosterir. Entity nodes, entity edges ve operator findings birlikde baxildigina gore correlation daha asan olur. Bu section tek obyekt yox, butov hadise modelini gormek ucundur. Xususen case seviyyesinde araşdırmada boyuk deyer verir.

### Timeline Event Story Workspace

![Timeline Event Story Workspace](../images/timeline-event-story-workspace.png)

Timeline bolmesi hadiseleri zaman ardicilligi ile oxumaq ucundur. Burada event summary, timeline story ve detail paneli araşdırmaya xronoloji baxis verir. Operator hansı hadisenin hansindan once bas verdiyini bu section-da daha rahat izləyir. Bu da incident narrativi qurmaq ucun cox faydalidir.

### Quarantine Alert Workspace

![Quarantine Alert Workspace](../images/quarantine-alert-workspace.png)

Quarantine bolmesi izolasiya olunmus obyektleri ve alert neticelerini idare edir. Restore, delete ve webhook kimi emeliyyatlar burada birbasa operatorun ixtiyarina verilir. Response terefini daha nizamli saxlamaq ucun bu ekran vacibdir. Xususen artıq hereket edilmis obyektlerin son taleyini izlemek ucun yararlidir.

### History And Incident Log

![History And Incident Log](../images/history-incident-log.png)

History section platformada bas veren incident, audit ve telemetry izlerini toplu sekilde gosterir. Burada action cədvelleri, severity, owner ve event detallari birlikde gorunur. Operator geriye donub hadisenin izini surmek isteyende bu hisseden istifade edir. Bu ekran cavablandirma ve retrospektiv analiz ucun cox deyerlidir.

### Artifacts And Evidence Store

![Artifacts And Evidence Store](../images/artifacts-evidence-store.png)

Artifacts bolmesi toplanmis fayllari, report-lari ve forensic cixislarini saxlamaq ucundur. Artifact preview ve detail pencereleri operatora secilen obyektin ne oldugunu aydin gosterir. Investigation sonunda toplanan materiallarin mərkəzi deposu kimi isleyir. Bu da export ve sonradan baxis prosesini asanlasdirir.

### Enterprise Case Ops Workspace

![Enterprise Case Ops Workspace](../images/enterprise-case-ops-workspace.png)

Enterprise Ops case-centric is axininin esas panelidir. Burada case controls, assignment, task, note, story, approval ve export kimi emeliyyatlar bir araya gelir. SOC tipli araşdırma nizamini qurmaq ucun bu section merkez rol oynayir. Operator ferdI tapşiriqlardan cixib komanda esasli case idaresine burada kecir.

### Security Ops Platform Readiness

![Security Ops Platform Readiness](../images/security-ops-platform-readiness.png)

Security Ops hissesi platformanin oz saglamligini ve idarə olunan security controls-u gosterir. Integrity, observability, migrations, secret rotation ve readiness kimi emeliyyatlar bu section-da cemlenir. Bu ekran mehsulun sadece detection deyil, eyni zamanda operational maturity terefini de vurğulayir. Administrator ucun burada vacib nezaret noqteleri var.

### Attack Scenario Simulator

![Attack Scenario Simulator](../images/attack-scenario-simulator.png)

Scenarios bolmesi test ve demonstrasiya ucun qurulub. Buradan secilmis adversary profile ve muddet ile senari run etmek mumkundur. Bu section telemetriyanin, detection-larin ve workflow-larin kontrollu sekilde yoxlanmasina imkan verir. Xususen demo, lab ve regression test senarilerinde faydalidir.

### Enterprise Ops Snapshot

![Enterprise Ops Snapshot](../images/enterprise-ops-snapshot.png)

Bu ekran enterprise daxilinde daha yuxari seviyyeli operativ gorunusu temsil edir. Open cases, assignments, high-risk assets ve operational snapshot kimi bloklar case workload-u xulaselendirir. Menecer ve ya lead analyst ucun bu section daha umumi yönlendirme vasitesidir. Buradan komanda diqqetini hara vermeli oldugu daha tez belli olur.

### About Creator Profile

![About Creator Profile](../images/about-creator-profile.png)

About / FAQ bolmesi mehsulun kim terefinden yaradildigini ve ne meqsedle quruldugunu izah edir. Burada creator profile, portfolyo ve qisa FAQ birlikde verilir. Bu section daha cox teqdimat, onboarding ve repo tanitimi ucun lazim olur. Teknik hisseden sonra mehsula insan merkezi kontekst verir.

## Bu senedi ne ucun istifade etmek olar

Bu guide hem mehsul teqdimati ucun, hem onboarding ucun, hem de GitHub-da "layihe tam olaraq ne edir" sualina cavab vermek ucun uygundur. README daha qisa giris rolunda qala biler. Bu sened ise daha genis ve mehsul yonumlu izah rolunu oynayar.
