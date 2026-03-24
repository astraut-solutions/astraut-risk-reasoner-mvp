# Security Requirements 12_2025_de - PDF Summary

- Total PDFs: **65**
- Basis: automated text extraction from PDF content (without OCR).

## Categories
- 01_General_Requirements: 7
- 02_Architecture: 3
- 03_Operating_Systems: 5
- 04_Virtualization: 5
- 05_Databases: 6
- 06_Server_Applications: 2
- 07_Application_Servers: 2
- 08_Web_Servers: 5
- 09_Endpoints: 5
- 10_Network_Components: 7
- 11_Third_Party_Access: 2
- 12_Mobile_Applications: 2
- 13_Operational_Security_Requirements: 2
- 14_Web_Services: 3
- 15_Cloud: 9

## Cross-cutting Requirement Focus Areas
- patching: in 16 documents
- cloud: in 14 documents
- auth: in 6 documents
- network: in 6 documents
- crypto: in 5 documents
- logging: in 5 documents
- hardening: in 4 documents
- access: in 1 documents

## Per PDF: Short Summary and Requirement Points
### Technical Baseline Protection of IT/NT Systems
- File: `01_General_Requirements/3_01_Technischer_Basisschutz_von_IT-_NT-Systemen_v9.0.pdf`
- Short Summary: Richtlinie mit grundsaetzlichen requirements fuer die Absicherung von IT- und NT-Systemen. 1.
- Key Requirement Points:
  - setzungsempfehlung fuer Einheiten, die nicht am PSA-Verfahren teilnehmen. Diese requirements must bereits
  - Ein solcher Support must umfassen, dass der Hersteller
  - Der security vulnerability support must fuer die gesamte Dauer bestehen, in der das betroffene Produkt im Ein-
  - Wird ein Produkt innerhalb von Support-Phasen eingesetzt, die Einschraenkungen unterliegen, must explizit sicherge-
  - vertraglich vereinbarter security vulnerability support unter Umstaenden nicht verfuegbar. Grundsaetzlich must
  - Die auf dem System eingesetzte Software must aus trusted sources bezogen und vor der Installation auf
  - Software und Hardware des Systems must von einem security vulnerability support
  - Eingesetzte Software must aus trusted sources bezogen und auf integrity geprueft

### Cryptographic Algorithms and Security Protocols
- File: `01_General_Requirements/3_50_Kryptographische_Algorithmen_und_Sicherheitsp_v8.0.pdf`
- Short Summary: Cryptographic Algorithms and Security Protocols 1.
- Key Requirement Points:
  - Policy) in Einheiten, die nicht am PSA-Verfahren teilnehmen. Diese requirements must bereits waehrend der Pla-
  - confidentiality und integrity. should kryptografische Methoden eingesetzt werden, um Anonymisierungs- bzw. Pseud-
  - Jede Abweichung must mit der security organization der Deutschen Telekom Gruppe abgestimmt und vereinbart
  - Eigene Implementierungen von kryptographischen Algorithmen should vermieden werden. Stattdessen must eta-
  - Algorithmen implementiert haben. Wenn eigene Implementierungen erforderlich sind, must Best Practices beach-
  - Fuer die Implementierung von kryptografischen Verfahren must etablierte und aktuelle Krypto-
  - klar abgegrenzten Modulen zu implementieren. Die Auswahl und Konfiguration der Verfahren must not fest im Code
  - hinterlegt sein, sondern must ueber konfigurierbare, autorisierte Schnittstellen moeglich sein.

### Use of Public Clouds
- File: `01_General_Requirements/3_66_Verwendung_von_Public_Clouds_v5.0.pdf`
- Short Summary: Dieses document behandelt die sichere Nutzung von Public Cloud-Diensten. Die requirements in diesem document sind meist grob umrissen, sodass sie die meisten Cloudanbietern und use cases abdecken koennen. This document enthaelt keine technischen Implementierungsdetails fuer bestimmte Cloudanbieter. Copyright © 2025 by Deutsche Telekom AG. Alle Rechte, auch die des auszugsweisen Nachdrucks, der fotomechanischen Wiedergabe (einschliesslich Mikrokopie) sowie der Auswertung
- Key Requirement Points:
  - setzungsempfehlung fuer Einheiten, die nicht am PSA-Verfahren teilnehmen. Diese requirements must bereits
  - haengt vom verwendeten Servicemodell ab, z. B. must der Cloud-Anbieter bei der Verwendung von IaaS den Hypervi-
  - (Mandant) die virtuellen Maschinen und die darin laufende Software ordnungsgemaess sichern must.
  - Kunden noch entsprechend konfiguriert werden must) und solche, die der Kunde zusaetzlich zu anderen Diensten
  - klassifizieren. Dabei must nicht nur die Datenverfuegbarkeit, sondern auch der Lebenszyklus der Daten beruecksichtigt
  - Alle Nutzer, einschliesslich der Betreiber einer Landing Zone und insbesondere des Applikationsbetriebs, must sich
  - Bevor eine Applikation in der Cloud betrieben werden darf, must die relevante documentation der
  - traege mit dem CSP unterzeichnet werden. Wenn ein BSI-C5-Auditbericht vorhanden ist, must dieser ebenfalls ausge-

### CI/CD Chains
- File: `01_General_Requirements/3_68_CICD_Ketten_v1.3.pdf`
- Short Summary: This document covers security of CICD chains and secure usage of CICD chains for development, testing and produc- tion of systems which use CICD chains. 1.
- Key Requirement Points:
  - de-/Befehlsinjektion, Konfigurationsfehler, usw. Die CICD-Kette in Kombination mit DevOps-Praktiken must nicht nur
  - Ketten verwenden. Die CICD-Kette must die Funktionalitaet und vernuenftige Standardwerte bereitstellen, aber die Sy-
  - ausgeschlossen werden must, z. B. Denial-of-Service).
  - den. Dies must vollstaendig separat erfolgen. Zusaetzlich zu den typischen betrieblichen Problemen koennte dies
  - Damit die CICD-Kette mehrere Software und Systeme (und natuerlich auch Benutzer) hosten kann, must sie die Man-
  - Die CICD-Kette must eine vollstaendige Trennung zwischen einem gehosteten System und allen anderen gehosteten
  - Die CICD-Kette must voellig getrennt von Software und Systemen behandelt werden, die die CICD-
  - Die CICD-Kette must mandantenfaehig sein.

### IAM
- File: `01_General_Requirements/3_69_IAM_(Identity_Access_Management)_-_Framework_v6.0.pdf`
- Short Summary: Ein Identity- and Access Management (IAM) - Framework sorgt fuer eine zentrale Verwaltung von Identitaeten und Zu- griffsrechten fuer unterschiedliche Systeme und Applikationen. authentication und authorization der User sind zen- trale Funktionen des IAM-Frameworks. Das IAM-Framework befasst sich weiterhin mit der Verwaltung von Benutzer- daten, die einzelnen Personen zugeordnet sind. Dabei ist die Identitaet eine Sammlung von personenbezogenen
- Key Requirement Points:
  - Die Komponenten must nicht zwangslaeufig von einem Softwarehersteller bereitgestellt werden. Vielmehr werden
  - Ein Passwort oder auch Kennwort ist eine Zeichenfolge, die zur authentication verwendet wird. Damit should die Identi-
  - arbeitung, Nutzung oder Speicherung should ausdruecklich verhindert werden.
  - werden must. Diese requirement erweitert die requirement aus dem technischen Basisschutz dahingehend, dass fuer
  - fuer privilegierte (z.B. administrative) Accounts verwendet werden must. Im Folgenden eine nicht abschliessende Liste
  - Dieses Requirement ist eine Erweiterung des Req. 19 (Benutzerkonten must gegen unautorisierte Nutzung durch
  - signaturbasierte Schutzmechanismen zur Verfuegung stehen. Aus diesem Grund must alle IT-Systeme des IAM Fra-
  - Eine Anmeldung an den Systemen eines IAM Frameworks aus betrieblichen Gruenden must mit

### Machine Learning
- File: `01_General_Requirements/3_81_Machine_Learning_v4.0.pdf`
- Short Summary: Dieses document beschreibt die security requirements an Machine Learning Algorithmen. 1.
- Key Requirement Points:
  - Dieses document wurde auf Basis der Vorgaben aus den im Konzern gueltigen Sicherheitsrichtlinien erstellt. Es ist zu
  - ren koennen, die ebenfalls beachtet werden must.
  - zungsempfehlung fuer Einheiten, die nicht am PSA-Verfahren teilnehmen. Diese requirements must bereits waeh-
  - Wichtig zu beachten, ist ebenfalls, dass nicht jedes Produkt, jede einzelne requirement erfuellen must. Dieses Doku-
  - die er erfuellen should, klar definiert ist, dass der Kontext, in dem er verwendet werden should, vollstaendig verstanden wird
  - Art der Daten, welche verarbeitet werden should
  - Die Aufgabe des Algorithmus, der Kontext, in dem dieser verwendet werden should, und die
  - bedingungen, unter denen der Algorithmus Entscheidungen treffen darf, must klar definiert

### Private Clouds
- File: `01_General_Requirements/3_86_Private_Clouds_v1.0.pdf`
- Short Summary: Ziel dieses Dokuments ist es, eine Sicherheitsgrundlage fuer die Architektur einer sicheren Private Cloud-Umgebung zu schaffen, speziell im Hinblick auf moderne cloud-native Workloads. Darueber hinaus ist dieses document in Teilen fuer Cloud-Kunden bestimmt, die eben jene Cloud-Plattformen nutzen. Alle hier im document aufgefuehrten Anforde- rungen sind fuer den modernen Cloud-Einsatz und Cloud-native Workloads gedacht und mit dem Zero-Trust-Ansatz
- Key Requirement Points:
  - Cloud-Funktionen, die fuer die Cloud-Verwaltung, Speicher- und Netzwerkfunktionen verwendet werden, must in se-
  - Ein physischer Server must not mehr als eine Art von Cloud-Funktion ausfuehren.
  - In konvergenten Clouds must jede Cloud-Funktion in einer separaten virtuellen Maschine
  - Fuer hyperkonvergente Clouds sind moeglicherweise zusaetzliche Sicherheitsmassnahmen erforderlich, einschliesslich Sy-
  - Funktion (und virtuelle Maschine) must ihren eigenen Verschluesselungsschluessel fuer die Datenspeicherung verwen-
  - den. Darueber hinaus must ein Schluesselverwaltungssystem vorhanden sein und der Prozess must so gestaltet wer-
  - In hyperkonvergenten Clouds must jede Cloud-Funktion logisch getrennt sein und fuer jede
  - on unterschiedliche Verschluesselungsschluessel verwenden. Die keys must not auf den fuer

### 1. Introduction
- File: `02_Architecture/3_14_Architektur_von_Systemen_v3.2.pdf`
- Short Summary: security requirements fuer die Architektur von IT- und NT-Systemen. Inhaltsverzeichnis 1.
- Key Requirement Points:
  - setzungsempfehlung in Einheiten, die nicht am PSA-Verfahren teilnehmen. Diese requirements must bereits waeh-
  - bzgl. confidentiality, availability, integrity oder Datenschutz, sogenannte "Kritische Systeme", must von anderen
  - requirements an eine physische Trennung (z. B. bei besonders hohem Schutzbedarf) sind zu pruefen und entspre-
  - Motivation: Eine Kompromittierung eines Systems mit geringem Schutzbedarf ist eher wahrscheinlich. Dies must not
  - zanlagen must entschieden werden, ob diese einen eher produktiven Charakter haben oder eher einer Testumge-
  - Testaktivitaeten mit Sicherheitsbezug wie Penetrationstests und die Durchfuehrung von Netzwerk-Scans must jeder-
  - Systeme must ihrem Schutzbedarf entsprechend voneinander getrennt werden.
  - Produktionssysteme must von Test- und Entwicklungssystemen vollstaendig getrennt sein.

### Access and Transport Network Architecture
- File: `02_Architecture/3_57_Architektur_accesss-_und_Transportnetz_v2.1.pdf`
- Short Summary: In diesem document werden security requirements beschrieben, die fuer die Absicherung von IP-basierten Zu- gangs- und Transportnetzen umgesetzt werden must. 1.
- Key Requirement Points:
  - gangs- und Transportnetzen umgesetzt werden must.
  - fuer Einheiten, die nicht am PSA-Verfahren teilnehmen. Diese requirements must bereits waehrend der Planungs-
  - Das Produktivnetz und dessen Systeme must komplett von Test- und Entwicklungssystemen getrennt werden. Hier-
  - beider Systemarten nicht umgangen werden kann. Des weiteren must sichergestellt werden, dass eine sicherheitsre-
  - must. Dies ist notwendig, um moeglichst restriktive Regeln fuer die Kommunikation umsetzen zu koennen.
  - Adressen werden u.a. fuer die Übertragung des Signalisierungsverkehrs genutzt. Diese Adressen must nicht oder
  - ternet erreichbar sein. Daher must die Erreichbarkeit beschraenkt werden. Hierfuer gibt es verschiedene Loesungsansaet-
  - Das Produktivnetz und dessen Systeme must von Test- und Entwicklungssystemen vollstaendig

### Data Center and Cloud Infrastructure Architecture
- File: `02_Architecture/3_58_Architektur_Rechenzentrums-_und_Cloud-Infrastrukturen_v3.0.pdf`
- Short Summary: security requirements fuer die Architektur von Cloud- und Rechenzentrumsinfrastrukturen. Der Schwerpunkt liegt auf Netzen und System-Trennungen, insbesondere im Bereich Systemmanagement. Dies gilt sowohl fuer physische als auch fuer virtuelle Rechenzentren ("Cloud") und betrifft alle Arten von Infrastrukturkomponenten (Netze, Storage, Com- puting, Monitoring usw.). Copyright © 2025 by Deutsche Telekom AG. Alle Rechte, auch die des auszugsweisen Nachdrucks, der fotomechanischen Wiedergabe (einsch
- Key Requirement Points:
  - setzungsempfehlung fuer Einheiten, die nicht am PSA-Verfahren teilnehmen. Diese requirements must bereits
  - Insbesondere Systeme mit einem hohen Schutzbedarf must immer von anderen Systemen getrennt sein, d. h. auch
  - Motivation: Eine Kompromittierung eines wenig geschuetzten Systems ist eher wahrscheinlich. Dies must not dazu fueh-
  - Zur Unterstuetzung der geforderten Trennung im Schichtenmodell must alle extern erreichbaren Maschinen sowie
  - must sichergestellt werden, dass ein Zugriff auf einen internen Bereich nicht von extern moeglich ist.
  - Motivation: Interne Daten und Systeme must not von extern kompromittiert werden koennen. Umsetzung der Prinzi-
  - Eine Rechenzentrumsinfrastruktur oder Cloud-Plattform must eine Trennung der darin
  - Falls Systeme von extern (Nicht-DTAG, z. B. aus dem Internet) erreichbar sind, must diese auf

### Secure Shell (SSH
- File: `03_Operating_Systems/3_04_Secure_Shell_(SSH)_v5.0.pdf`
- Short Summary: security requirements fuer SSH Server, SFTP Server und das SSH Protokoll. 1.
- Key Requirement Points:
  - am PSA-Verfahren teilnehmen. Diese requirements must bereits waehrend der Planungs- und Entscheidungspro-
  - SSHv1 must permanent in der Konfiguration des SSH-Servers deaktiviert werden. Mit OpenSSH 7.4 wurde die Unter-
  - Daemon fest. Dieser Wert must auf "
  - Die Version 2 vom SSH-Protokoll must verwendet werden. (Ab OpenSSH 7.4+ automatisch erfuellt).
  - SSH MaxStartups must auf "10:30:100" oder weniger eingestellt sein. (OpenSSH
  - Veraltete und unsichere Chiffren und Algorithmen must not benutzt werden. Die folgenden Chiffren koennen fuer
  - men sind MD5 und SHA1. Die folgenden MAC-Algorithmen sind zugelassen und must entsprechend fuer den SSH-
  - Veraltete und unsichere Algorithmen must not benutzt werden. Die folgenden Algorithmen koennen fuer SSH genutzt

### Windows Server
- File: `03_Operating_Systems/3_15_Windows_Server_v10.0.pdf`
- Short Summary: Windows Server 1.
- Key Requirement Points:
  - zungsempfehlung fuer Einheiten, die nicht am PSA-Verfahren teilnehmen. Diese requirements must bereits waeh-
  - Ein solcher Support must umfassen, dass der Hersteller
  - Der security vulnerability support must fuer die gesamte Dauer bestehen, in der das betroffene Produkt im Ein-
  - Wird ein Produkt innerhalb von Support-Phasen eingesetzt, die Einschraenkungen unterliegen, must explizit sicherge-
  - vertraglich vereinbarter security vulnerability support unter Umstaenden nicht verfuegbar. Grundsaetzlich must
  - Software und Hardware des Systems must von einem security vulnerability support
  - Kritische Windows Server Systeme must mit einer Windows Server Version im Long-Term
  - Server Release zu wechseln, must zwingend eine Neuinstallation durchgefuehrt werden.

### Operating Systems
- File: `03_Operating_Systems/3_37_Operating Systems_v9.0.pdf`
- Short Summary: Generische security requirements an Operating Systems fuer Server. 1.
- Key Requirement Points:
  - setzungsempfehlung in Einheiten, die nicht am PSA-Verfahren teilnehmen. Diese requirements must bereits waeh-
  - nen Einsatzumfeld nicht erforderlich sind.
  - Entsprechend must unmittelbar nach der Installation saemtliche auf einem System nicht erforderliche Dienste voll-
  - staendig deaktiviert werden. Es must sichergestellt werden, dass diese Dienste auch nach einem Neustart des Systems
  - Ein bereitgestellter Dienst must grundsaetzlich auf allen Schnittstellen des Systems vollstaendig deaktiviert werden,
  - ueber die eine Erreichbarkeit des Dienstes fuer den ordnungsgemaessen Operations des Systems nicht erforderlich ist. Die
  - Die Erreichbarkeit eines Dienstes ueber die erforderlichen Schnittstellen must zudem auf legitime Kommunikations-
  - Nicht benoetigte Dienste must deaktiviert werden.

### Container
- File: `03_Operating_Systems/3_64_Container_v4.0.pdf`
- Short Summary: Dieses document beschreibt die funktionalen security requirements, die zum Sichern von Containern verwendet werden, zusaetzlich zu den CIS-Benchmarks, die auch implementierungsorientierte requirements abdecken. - Key Requirement Points:
  - zungsempfehlung fuer Einheiten, die nicht am PSA-Verfahren teilnehmen. Diese requirements must bereits waeh-
  - Container should unveraenderlich sein, daher duerfen sie zur Laufzeit nicht veraendert werden. Anstatt Container im Live-
  - Operations zu patchen, must das Image gepatched und redeployed werden. Container Images must ueber eine vorhan-
  - dene CI/CD Pipeline geaendert werden. Diese Pipeline must den Sicherheitsanforderungenden fuer CI/CD folgen
  - Motivation: Container should unveraenderlich sein, daher duerfen sie zur Laufzeit nicht veraendert werden. Anstatt Contai-
  - ner im Livebetrieb zu patchen, must das Image gepatched und redeployed werden. Container Images must ueber
  - eine vorhandene CI/CD Pipeline geaendert werden. Diese Pipeline must den Sicherheitsanforderungenden fuer CI/CD
  - alpine, must sie das letzte verwenden, da es die spezifischste Referenz ist.

### Linux OS fuer Server
- File: `03_Operating_Systems/3_65_Linux_OS_fuer_Server_v9.1.pdf`
- Short Summary: security requirements fuer Linux OS fuer Server inklusive requirements fuer IPTables, Mandatory Access Control etc. 1.
- Key Requirement Points:
  - setzungsempfehlung fuer Einheiten, die nicht am PSA-Verfahren teilnehmen. Diese requirements must bereits
  - und der verwendeten Software benoetigen Workstations unterschiedliche requirements. Container-Images must
  - nen Einsatzumfeld nicht erforderlich sind.
  - Entsprechend must unmittelbar nach der Installation saemtliche auf einem System nicht erforderliche Dienste voll-
  - staendig deaktiviert werden. Es must sichergestellt werden, dass diese Dienste auch nach einem Neustart des Systems
  - Ein bereitgestellter Dienst must grundsaetzlich auf allen Schnittstellen des Systems vollstaendig deaktiviert werden,
  - ueber die eine Erreichbarkeit des Dienstes fuer den ordnungsgemaessen Operations des Systems nicht erforderlich ist. Die
  - Die Erreichbarkeit eines Dienstes ueber die erforderlichen Schnittstellen must zudem auf legitime Kommunikations-

### Orchestrator
- File: `04_Virtualization/3_34_Orchestrator_v5.0.pdf`
- Short Summary: Dieses document beschreibt die funktionalen security requirements, die zum Sichern von Orchestratoren ver- wendet werden, zusaetzlich zu den CIS-Benchmark- und Hardening-Handbuechern, die auch die implementierungsori- entierten requirements abdecken. Copyright © 2025 by Deutsche Telekom AG. Alle Rechte, auch die des auszugsweisen Nachdrucks, der fotomechanischen Wiedergabe (einschliesslich Mikrokopie) sowie der Auswertung
- Key Requirement Points:
  - zungsempfehlung fuer Einheiten, die nicht am PSA-Verfahren teilnehmen. Diese requirements must bereits waeh-
  - Der PatchmanagementProzess in einer Cloud-Umgebung must so implementiert werden, dass das Patchen aller
  - Cloud-Komponenten unter Einhaltung der SLA fuer die Mandanten moeglich ist. Wenn die SLA dies erfordert, must der
  - Alle Komponenten der Cloud-Umgebung must in das Patch-Management-Verfahren einbezogen werden, z. B. Ma-
  - Es must einen Patch-Management-Prozess fuer die gesamte Cloud-Umgebung geben.
  - (Überwachung, Protokollierung, Jump Hosts usw.) must ebenfalls in das Verfahren einbezogen werden.
  - Auch in solchen Faellen, in denen eine kurzfristige Korrektur erforderlich ist, must das regulaere Pruefverfahren eingehal-
  - Die Control plane besteht aus den folgenden logischen Komponenten, die gehaertet werden must:

### IT-Virtualisierung
- File: `04_Virtualization/3_35_IT-Virtualisierung_v8.0.pdf`
- Short Summary: Aufgrund des breiten Spektrums von Virtualisierungs-Loesungen, ist dieses document fuer folgende Varianten gueltig: - Servervirtualisierung - Clientvirtualisierung - Clientbasierte Virtualisierungsloesungen - Desktopvirtualisierung - Applikationsvirtualisierung - Application Streaming - Terminal Services Copyright © 2025 by Deutsche Telekom AG. Alle Rechte, auch die des auszugsweisen Nachdrucks, der fotomechanischen Wiedergabe (einschliesslich Mikrokopie) sowie der Auswertung
- Key Requirement Points:
  - zungsempfehlung fuer Einheiten, die nicht am PSA-Verfahren teilnehmen. Diese requirements must bereits waeh-
  - findliche Umgebung und deren Systeme erhalten should. Der transparente Benutzerzugang wird also auf dem Terminal-
  - welche Voraussetzungen diese erfuellen must, ist nicht Regelungsbestandteil dieser security requirement.
  - Die auf dem System eingesetzte Software must aus trusted sources bezogen und vor der Installation auf
  - (1) Bietet der Bereitstellungs-Server verschiedene Formen von Downloads an, must durch encryption
  - sftp), must die zugehoerig praesentierten Server-Zertifikate oder Server-Keys/Fingerprints bei jedem Down-
  - Die Integritaetspruefung should sicherstellen, dass die erhaltene Software frei von Manipulationen und Schadsoftwa-
  - re-Befall ist. Sofern vorhanden, must zur Pruefung die vom Hersteller implementierten Mechanismen verwendet wer-

### Hyper-V Server
- File: `04_Virtualization/3_49_Hyper-V_Server_v8.0.pdf`
- Short Summary: Hyper-V Server 1.
- Key Requirement Points:
  - zungsempfehlung fuer Einheiten, die nicht am PSA-Verfahren teilnehmen. Diese requirements must bereits waeh-
  - nen Einsatzumfeld nicht erforderlich sind.
  - Entsprechend must unmittelbar nach der Installation saemtliche auf einem System nicht erforderliche Dienste voll-
  - staendig deaktiviert werden. Es must sichergestellt werden, dass diese Dienste auch nach einem Neustart des Systems
  - Ein bereitgestellter Dienst must grundsaetzlich auf allen Schnittstellen des Systems vollstaendig deaktiviert werden,
  - ueber die eine Erreichbarkeit des Dienstes fuer den ordnungsgemaessen Operations des Systems nicht erforderlich ist. Die
  - Die Erreichbarkeit eines Dienstes ueber die erforderlichen Schnittstellen must zudem auf legitime Kommunikations-
  - Nicht benoetigte Dienste must deaktiviert werden.

### Container
- File: `04_Virtualization/3_64_Container_v5.0.pdf`
- Short Summary: Dieses document beschreibt die funktionalen security requirements, die zum Sichern von Containern verwendet werden, zusaetzlich zu den CIS-Benchmarks, die auch implementierungsorientierte requirements abdecken. - Key Requirement Points:
  - zungsempfehlung fuer Einheiten, die nicht am PSA-Verfahren teilnehmen. Diese requirements must bereits waeh-
  - Container should unveraenderlich sein, daher duerfen sie zur Laufzeit nicht veraendert werden. Anstatt Container im Live-
  - Operations zu patchen, must das Image gepatched und redeployed werden. Container Images must ueber eine vorhan-
  - dene CI/CD Pipeline geaendert werden. Diese Pipeline must den Sicherheitsanforderungenden fuer CI/CD folgen
  - Motivation: Container should unveraenderlich sein, daher duerfen sie zur Laufzeit nicht veraendert werden. Anstatt Contai-
  - ner im Livebetrieb zu patchen, must das Image gepatched und redeployed werden. Container Images must ueber
  - eine vorhandene CI/CD Pipeline geaendert werden. Diese Pipeline must den Sicherheitsanforderungenden fuer CI/CD
  - zanlagen must entschieden werden, ob diese einen eher produktiven Charakter haben oder eher einer Testumge-

### Microservice (Container basierter Web Service
- File: `04_Virtualization/3_84_Microservice_(Container_basierter_Web_Service)_v7.1.pdf`
- Short Summary: Unter Mikroservice ist typischerweise ein Softwarekomponente gemeint, die als Docker Container ein Application Programming Interface (API) in Form einer REST-API bereitstellt. Der Mikroservice interagiert nur mit anderen Ser- vicen oder Systemen. Das document fasst alle fuer diesen Mikroservice relevanten requirements zusammen. Da- durch wird es ermoeglicht, den Mikroservice mit genau einem SoC (Statement of Compliance) in einem SDSK (
- Key Requirement Points:
  - Container should unveraenderlich sein, daher duerfen sie zur Laufzeit nicht veraendert werden. Anstatt Container im Live-
  - Operations zu patchen, must das Image gepatched und redeployed werden. Container Images must ueber eine vorhan-
  - dene CI/CD Pipeline geaendert werden. Diese Pipeline must den Sicherheitsanforderungenden fuer CI/CD folgen
  - Motivation: Container should unveraenderlich sein, daher duerfen sie zur Laufzeit nicht veraendert werden. Anstatt Contai-
  - ner im Livebetrieb zu patchen, must das Image gepatched und redeployed werden. Container Images must ueber
  - eine vorhandene CI/CD Pipeline geaendert werden. Diese Pipeline must den Sicherheitsanforderungenden fuer CI/CD
  - alpine, must sie das letzte verwenden, da es die spezifischste Referenz ist.
  - Images must in der Registry auf bekannte Sicherheitsluecken gescannt werden.

### Database Systems
- File: `05_Databases/3_16_Datenbanksysteme_v9.0.pdf`
- Short Summary: Datenbanksysteme - Allgemeine security requirements 1.
- Key Requirement Points:
  - zungsempfehlung fuer Einheiten, die nicht am PSA-Verfahren teilnehmen. Diese requirements must bereits waeh-
  - Die auf dem System eingesetzte Software must aus trusted sources bezogen und vor der Installation auf
  - (1) Bietet der Bereitstellungs-Server verschiedene Formen von Downloads an, must durch encryption
  - sftp), must die zugehoerig praesentierten Server-Zertifikate oder Server-Keys/Fingerprints bei jedem Down-
  - Die Integritaetspruefung should sicherstellen, dass die erhaltene Software frei von Manipulationen und Schadsoftwa-
  - re-Befall ist. Sofern vorhanden, must zur Pruefung die vom Hersteller implementierten Mechanismen verwendet wer-
  - Abgleich von kryptografischen Hash Werten (z. B. SHA256, SHA512) der erhaltenen Software gegen should-
  - Eingesetzte Software must aus trusted sources bezogen und auf integrity geprueft

### MySQL / Maria Datenbanksysteme
- File: `05_Databases/3_24_MySQL_Maria_Datenbanksysteme_v9.0.pdf`
- Short Summary: security requirements fuer MySQL-Datenbanksysteme inklusive Forks wie MariaDB 1.
- Key Requirement Points:
  - zungsempfehlung fuer Einheiten, die nicht am PSA-Verfahren teilnehmen. Diese requirements must bereits waeh-
  - finden. Darueber hinaus must sich die unterstuetzten Plattformen der MySQL Enterprise Edition innerhalb des MyS-
  - Die eingesetzte MySQL / Maria DB Version must sich in der Active- oder Extended-Lifecycle
  - od gemaess der MySQL Lifecycle Policy befinden bzw. es must kommerzieller Support fuer diese
  - Die Default Datenbanken wie test must geloescht werden.
  - Es must sichergestellt sein, dass keine Benutzerkonten ohne Benutzername (Anonymous
  - Motivation: Defaultpasswoerter fuer Datenbanken stellen ein hohes Sicherheitsrisiko dar. Der Administrator must sie
  - Wichtig ist es, den GRANT-Prozess fuer einen neuen Benutzer mit einem leeren Passwort zu verhindern. Daher must

### Oracle-Datenbanksysteme
- File: `05_Databases/3_29_Oracle-Datenbanksysteme_v9.0.pdf`
- Short Summary: Dieses document wurde auf Basis der Vorgaben aus den im Konzern gueltigen Sicherheitsrichtlinien erstellt. Ausge- hend von der security requirement Datenbanksysteme  Allgemeine security requirements enthaelt es, mit dem Ziel eines einheitlichen Sicherheitsstandards, herstellerspezifische security requirements an Oracle-Datenbanksysteme. Copyright © 2025 by Deutsche Telekom AG. Alle Rechte, auch die des auszugsweisen Nachdrucks, der fotomechanischen Wiedergabe (einschliesslich Mikrokopie)
- Key Requirement Points:
  - zungsempfehlung fuer Einheiten, die nicht am PSA-Verfahren teilnehmen. Diese requirements must bereits waeh-
  - Die verwendete Datenbank-Software must vom Hersteller fuer den produktiven Einsatz empfohlen
  - das DBMS installiert sein bzw. must deaktiviert werden.
  - Ist die Verwendung des Oracle HTTP Servers erforderlich, so must die Verantwortlichen sicherstellen, dass dieser
  - minstanz wie das DBMS installiert sein bzw. must deaktiviert werden.
  - Wird Oracle Application Express benoetigt, so must die Verantwortlichen sicherstellen, dass dieser auf einem dedi-
  - Nicht benoetigte Komponenten des Oracle-DBMS must not installiert werden.
  - Der Oracle HTTP Server must not auf dem DBMS-Server installiert sein bzw. must deaktiviert

### Microsoft SQL Server
- File: `05_Databases/3_30_Microsoft_SQL_Server_v8.0.pdf`
- Short Summary: Microsoft SQL Server 1.
- Key Requirement Points:
  - zungsempfehlung fuer Einheiten, die nicht am PSA-Verfahren teilnehmen. Diese requirements must bereits waeh-
  - Die Version des MS SQL Servers must fuer den produktiven Operations lizensierbar sein.
  - Die SQL Server Version must derart in Support befinden, dass Security Patches bereitgestellt
  - Bekannte Beispieldatenbanken (pubs, Northwind bzw. jede AdventureWorks-Datenbank) must not auf Produkti-
  - Das Standard-DB-Administratorkonto (sa) must deaktiviert werden.
  - Installierte Beispieldatenbanken must aus der SQL Server Installation entfernt werden.
  - Die Berechtigungen auf einem System must so weit eingeschraenkt werden, dass ein Benutzer nur auf Daten zugrei-
  - Neben dem Zugriff auf Daten must auch die Ausfuehrung von Anwendungen und deren Bestandteilen mit moeglichst

### PostgreSQL Datenbanken
- File: `05_Databases/3_60_PostgreSQL_Datenbanken_v10.0.pdf`
- Short Summary: Dieses Papier beschreibt security requirements an die Entwicklung / Operations von PostgreSQL Datenbanken. 1.
- Key Requirement Points:
  - setzungsempfehlung fuer Einheiten, die nicht am PSA-Verfahren teilnehmen. Diese requirements must bereits
  - In Produktionsumgebungen must eine durch die Community bzw. kommerziellen Hersteller
  - Die Berechtigungen der Verzeichnisse must wie folgt gesetzt werden:
  - Zusaetzlich must die umask des postgres Benutzers auf 0077 gesetzt werden, damit neue Fileen automatisch mit
  - Falls erforderlich, koennen die Berechtigungen mit den Linux Kommandos chmod und chown angepasst werden.
  - Ein Datenbankdienst must not mit Root-Rechten oder anderen administrativen Rechten des
  - Das PostgreSQL "data_directory" Verzeichnis und Konfigurationsdateien must exklusiv dem
  - triebssystem Account der Datenbank zugewiesen werden. Anderen Systemuser must die

### Hadoop
- File: `05_Databases/3_98_Hadoop_v2.0.pdf`
- Short Summary: 1.
- Key Requirement Points:
  - Die auf dem System eingesetzte Software must aus trusted sources bezogen und vor der Installation auf
  - Eingesetzte Software must aus trusted sources bezogen und auf integrity geprueft
  - (1) Bietet der Bereitstellungs-Server verschiedene Formen von Downloads an, must durch encryption
  - sftp), must die zugehoerig praesentierten Server-Zertifikate oder Server-Keys/Fingerprints bei jedem Down-
  - Die Integritaetspruefung should sicherstellen, dass die erhaltene Software frei von Manipulationen und Schadsoftwa-
  - re-Befall ist. Sofern vorhanden, must zur Pruefung die vom Hersteller implementierten Mechanismen verwendet wer-
  - Abgleich von kryptografischen Hash Werten (z. B. SHA256, SHA512) der erhaltenen Software gegen should-
  - Software aus oeffentlichen Registries must vor dem Einsatz einer erweiterten Integritaetspruefung unterzogen werden.

### Web-Anwendungen
- File: `06_Server_Applications/3_06_Web-Anwendungen_v8.0.pdf`
- Short Summary: Dieses document basiert auf Vorgaben aus den im Konzern gueltigen Sicherheitsrichtlinien und definiert die Sicher- heitsanforderungen an eine sichere Implementierung von Web-Anwendungen. Die hier beschriebenen Anforderun- gen must erfuellt werden, um sicherzustellen, dass eine Web-Anwendung nicht ohne Weiteres von Angreifern missbraucht werden kann. Copyright © 2025 by Deutsche Telekom AG. Alle Rechte, auch die des auszugsweisen Nachdrucks, der fotomechanischen Wiedergabe (einschliesslich Mikroko
- Key Requirement Points:
  - gen must erfuellt werden, um sicherzustellen, dass eine Web-Anwendung nicht ohne Weiteres von Angreifern
  - aus als Umsetzungsempfehlung fuer Einheiten, die nicht am PSA-Verfahren teilnehmen. Diese requirements must
  - Solche Komponenten must bei der Installation des Systems gezielt abgewaehlt (nicht mit installiert) werden oder -
  - oder die Funktion des Systems nicht erforderlich ist.
  - Solche Funktionen must unmittelbar nach der initialen Installation ueber die Konfigurationseinstellungen der Softwa-
  - Solche Funktionen, wie beispielsweise nicht benoetigte Schnittstellen, must ebenfalls unmittelbar nach der initialen
  - rend des normalen Operations nicht aktiv sein must.
  - Nicht benoetigte Funktionen in der eingesetzten Software und Hardware must deaktiviert

### SAP Netweaver Umgebungen
- File: `06_Server_Applications/3_22_SAP_Netweaver_Umgebungen_v13.0.pdf`
- Short Summary: Das Requirement ist gueltig fuer: Netweaver SAP-Systeme SAP HANA SAProuter SAP Web Dispatcher Fiori-Applikation-Server, Fiori-Apps 1.
- Key Requirement Points:
  - zungsempfehlung fuer Einheiten, die nicht am PSA-Verfahren teilnehmen. Diese requirements must bereits waeh-
  - Wenn es sich bei dem System ausschliesslich um ein SAP Netweaver System handelt, must bei den Systemeigen-
  - Bei der Auswahl von dem Anwendungstyp "SAP" must im Bereich "Datensicherheit" der Systemeigenschaften bei der
  - nen Einsatzumfeld nicht erforderlich sind.
  - Entsprechend must unmittelbar nach der Installation saemtliche auf einem System nicht erforderliche Dienste voll-
  - staendig deaktiviert werden. Es must sichergestellt werden, dass diese Dienste auch nach einem Neustart des Systems
  - Ein bereitgestellter Dienst must grundsaetzlich auf allen Schnittstellen des Systems vollstaendig deaktiviert werden,
  - ueber die eine Erreichbarkeit des Dienstes fuer den ordnungsgemaessen Operations des Systems nicht erforderlich ist. Die

### Application Server
- File: `07_Application_Servers/3_10_Application_Server_v7.0.pdf`
- Short Summary: Dieses document wurde auf Basis der Vorgaben aus den im Konzern gueltigen Sicherheitsrichtlinien erstellt und defi- niert die requirements an eine sichere Implementierung von Application Servern. Die hier beschriebenen Anforde- rungen must erfuellt werden, um sicherzustellen, dass ein Application Server nicht ohne weiteres von Angreifern missbraucht werden kann. Copyright © 2025 by Deutsche Telekom AG. Alle Rechte, auch die des auszugsweisen Nachdrucks, der fotomechanischen Wiedergabe (einschli
- Key Requirement Points:
  - rungen must erfuellt werden, um sicherzustellen, dass ein Application Server nicht ohne weiteres von Angreifern
  - setzungsempfehlung fuer Einheiten, die nicht am PSA-Verfahren teilnehmen. Diese requirements must bereits
  - Falls das nicht der Fall ist, must die security requirements an Webserver durch den Application Server oder ei-
  - Ein solcher Support must umfassen, dass der Hersteller
  - Der security vulnerability support must fuer die gesamte Dauer bestehen, in der das betroffene Produkt im Ein-
  - Wird ein Produkt innerhalb von Support-Phasen eingesetzt, die Einschraenkungen unterliegen, must explizit sicherge-
  - vertraglich vereinbarter security vulnerability support unter Umstaenden nicht verfuegbar. Grundsaetzlich must
  - Die auf dem System eingesetzte Software must aus trusted sources bezogen und vor der Installation auf

### Tomcat Application Server
- File: `07_Application_Servers/3_39_Tomcat_Application_Server_v7.0.pdf`
- Short Summary: Dieses document wurde auf Basis der Vorgaben aus den im Konzern gueltigen Sicherheitsrichtlinien erstellt und defi- niert die requirements an eine sichere Implementierung von Tomcat Application Servern. Die hier beschriebenen requirements must erfuellt werden, um sicherzustellen, dass ein Tomcat Application Server nicht ohne weiteres von Angreifern missbraucht werden kann. Copyright © 2025 by Deutsche Telekom AG. Alle Rechte, auch die des auszugsweisen Nachdrucks, der fotomechanischen Wiederga
- Key Requirement Points:
  - requirements must erfuellt werden, um sicherzustellen, dass ein Tomcat Application Server nicht ohne weiteres
  - setzungsempfehlung fuer Einheiten, die nicht am PSA-Verfahren teilnehmen. Diese requirements must bereits
  - Falls das nicht der Fall ist, must die security requirements an Webserver durch den Application Server oder ei-
  - Der security vulnerability support must fuer die gesamte Dauer bestehen, in der die Software im Einsatz ver-
  - Die auf dem System eingesetzte Software must aus trusted sources bezogen und vor der Installation auf
  - Die Integritaetspruefung should sicherstellen, dass die erhaltene Software frei von Manipulationen ist. Das erfolgt durch den
  - Abgleich von kryptografischen Hash Werten (z. B. SHA256, SHA512) der erhaltenen Software gegen should-Werte, die
  - Fuer die eingesetzte Tomcat-Version must security vulnerability support durch die

### Webserver
- File: `08_Web_Servers/3_03_Webserver_v8.0.pdf`
- Short Summary: Diese security requirements basieren auf den im Konzern gueltigen Sicherheitsrichtlinien und definieren die Anfor- derungen an eine sichere Implementierung von Webservern. Die hier beschriebenen requirements must erfuellt werden, um sicherzustellen, dass ein Webserver nicht ohne weiteres von Angreifern missbraucht werden kann. Copyright © 2025 by Deutsche Telekom AG. Alle Rechte, auch die des auszugsweisen Nachdrucks, der fotomechanischen Wiedergabe (einschliesslich Mikrokopie) sowie der Ausw
- Key Requirement Points:
  - derungen an eine sichere Implementierung von Webservern. Die hier beschriebenen requirements must erfuellt
  - zungsempfehlung fuer Einheiten, die nicht am PSA-Verfahren teilnehmen. Diese requirements must bereits waeh-
  - Ein solcher Support must umfassen, dass der Hersteller
  - Der security vulnerability support must fuer die gesamte Dauer bestehen, in der das betroffene Produkt im Ein-
  - Wird ein Produkt innerhalb von Support-Phasen eingesetzt, die Einschraenkungen unterliegen, must explizit sicherge-
  - vertraglich vereinbarter security vulnerability support unter Umstaenden nicht verfuegbar. Grundsaetzlich must
  - Die auf dem System eingesetzte Software must aus trusted sources bezogen und vor der Installation auf
  - Software und Hardware des Systems must von einem security vulnerability support

### Microsoft IIS
- File: `08_Web_Servers/3_32_Microsoft_IIS_v8.0.pdf`
- Short Summary: Diese security requirement basiert auf den im Konzern gueltigen Sicherheitsrichtlinien und definiert die Anforderun- gen an eine sichere Implementierung von Microsoft IIS Webservern. Die hier beschriebenen requirements must erfuellt werden, um sicherzustellen, dass ein Microsoft IIS Webserver nicht ohne weiteres von sachkundigen Angrei- fern missbraucht werden kann. Copyright © 2025 by Deutsche Telekom AG. Alle Rechte, auch die des auszugsweisen Nachdrucks, der fotomechanischen Wiedergabe (ei
- Key Requirement Points:
  - gen an eine sichere Implementierung von Microsoft IIS Webservern. Die hier beschriebenen requirements must
  - zungsempfehlung fuer Einheiten, die nicht am PSA-Verfahren teilnehmen. Diese requirements must bereits waeh-
  - Ein solcher Support must umfassen, dass der Hersteller
  - Der security vulnerability support must fuer die gesamte Dauer bestehen, in der das betroffene Produkt im Ein-
  - Wird ein Produkt innerhalb von Support-Phasen eingesetzt, die Einschraenkungen unterliegen, must explizit sicherge-
  - vertraglich vereinbarter security vulnerability support unter Umstaenden nicht verfuegbar. Grundsaetzlich must
  - Die auf dem System eingesetzte Software must aus trusted sources bezogen und vor der Installation auf
  - Software und Hardware des Systems must von einem security vulnerability support

### Apache-Webserver
- File: `08_Web_Servers/3_36_Apache-Webserver_v8.0.pdf`
- Short Summary: Diese security requirement basiert auf den im Konzern gueltigen Sicherheitsrichtlinien und definiert die Anforderun- gen an eine sichere Implementierung von Apache-Webservern. Die hier beschriebenen requirements must er- fuellt werden, um sicherzustellen, dass ein Apache-Webserver nicht ohne weiteres von sachkundigen Angreifern missbraucht werden kann. Copyright © 2025 by Deutsche Telekom AG. Alle Rechte, auch die des auszugsweisen Nachdrucks, der fotomechanischen Wiedergabe (einschliesslich M
- Key Requirement Points:
  - gen an eine sichere Implementierung von Apache-Webservern. Die hier beschriebenen requirements must
  - zungsempfehlung fuer Einheiten, die nicht am PSA-Verfahren teilnehmen. Diese requirements must bereits waeh-
  - Ein solcher Support must umfassen, dass der Hersteller
  - Der security vulnerability support must fuer die gesamte Dauer bestehen, in der das betroffene Produkt im Ein-
  - Wird ein Produkt innerhalb von Support-Phasen eingesetzt, die Einschraenkungen unterliegen, must explizit sicherge-
  - vertraglich vereinbarter security vulnerability support unter Umstaenden nicht verfuegbar. Grundsaetzlich must
  - Die auf dem System eingesetzte Software must aus trusted sources bezogen und vor der Installation auf
  - Software und Hardware des Systems must von einem security vulnerability support

### Load Balancer als Webserver
- File: `08_Web_Servers/3_59_Load_Balancer_als_Webserver_v5.0.pdf`
- Short Summary: Dieses document wurde auf Basis der Vorgaben aus den im Konzern gueltigen Sicherheitsrichtlinien erstellt. Es defi- niert die requirements an eine sichere Konfiguration von Load Balancern, die als Webserver genutzt werden. Die hier beschriebenen requirements must erfuellt werden, um sicherzustellen, dass die Webserver-Funktionalitaet des Load Balancers nicht ohne weiteres von sachkundigen Angreifern missbraucht werden kann.
- Key Requirement Points:
  - hier beschriebenen requirements must erfuellt werden, um sicherzustellen, dass die Webserver-Funktionalitaet des
  - zungsempfehlung fuer Einheiten, die nicht am PSA-Verfahren teilnehmen. Diese requirements must bereits waeh-
  - taet eines Proxies erforderlich ist.
  - Ein solcher Support must umfassen, dass der Hersteller
  - Der security vulnerability support must fuer die gesamte Dauer bestehen, in der das betroffene Produkt im Ein-
  - Wird ein Produkt innerhalb von Support-Phasen eingesetzt, die Einschraenkungen unterliegen, must explizit sicherge-
  - vertraglich vereinbarter security vulnerability support unter Umstaenden nicht verfuegbar. Grundsaetzlich must
  - Bekannte Schwachstellen in Software- und Hardware Komponenten must mittels Installation von verfuegbaren Sy-

### NGINX
- File: `08_Web_Servers/3_80_NGINX_v7.0.pdf`
- Short Summary: Diese security requirement basiert auf den im Konzern gueltigen Sicherheitsrichtlinien und definiert die Anforderun- gen an eine sichere Implementierung von Nginx Webservern. Die hier beschriebenen requirements must erfuellt werden, um sicherzustellen, dass ein Nginx Webserver nicht ohne weiteres von Angreifern missbraucht werden kann. Copyright © 2025 by Deutsche Telekom AG. Alle Rechte, auch die des auszugsweisen Nachdrucks, der fotomechanischen Wiedergabe (einschliesslich Mikrokopie) sowie 
- Key Requirement Points:
  - gen an eine sichere Implementierung von Nginx Webservern. Die hier beschriebenen requirements must erfuellt
  - zungsempfehlung fuer Einheiten, die nicht am PSA-Verfahren teilnehmen. Diese requirements must bereits waeh-
  - Ein solcher Support must umfassen, dass der Hersteller
  - Der security vulnerability support must fuer die gesamte Dauer bestehen, in der das betroffene Produkt im Ein-
  - Wird ein Produkt innerhalb von Support-Phasen eingesetzt, die Einschraenkungen unterliegen, must explizit sicherge-
  - vertraglich vereinbarter security vulnerability support unter Umstaenden nicht verfuegbar. Grundsaetzlich must
  - Software und Hardware des Systems must von einem security vulnerability support
  - Die Standardfehlerseiten must durch benutzerspezifisch definierte Fehlerseiten ersetzt werden.

### Client Computer
- File: `09_Endpoints/3_19_Client_Computer_v7.0.pdf`
- Short Summary: requirements zur Absicherung von Client Computern. 1.
- Key Requirement Points:
  - zungsempfehlung fuer Einheiten, die nicht am PSA-Verfahren teilnehmen. Diese requirements must bereits waeh-
  - Dieses Anforderungspapier bietet die Grundlage welche Mindestanforderungen an einen Client erfuellt sein must,
  - chungen von Projekten must im SDSK entsprechend dokumentiert und durch das Sicherheitsmanagement der
  - Die auf dem System eingesetzte Software must aus trusted sources bezogen und vor der Installation auf
  - Die Sicherheitsmechanismen des BIOS/EFI must vorhanden sein und zur sicheren Nutzung
  - Eingesetzte Software must aus trusted sources bezogen und auf integrity geprueft
  - (1) Bietet der Bereitstellungs-Server verschiedene Formen von Downloads an, must durch encryption
  - sftp), must die zugehoerig praesentierten Server-Zertifikate oder Server-Keys/Fingerprints bei jedem Down-

### Endgeraete
- File: `09_Endpoints/3_33_Endgeraete_v5.3.pdf`
- Short Summary: Endgeraete 1.
- Key Requirement Points:
  - zungsempfehlung fuer Vorgaben in Einheiten, die nicht am PSA-Verfahren teilnehmen. Diese requirements must
  - Das Geraet must sicherstellen, dass Benutzer ueber den sicherheitsrelevanten Zustand und Zustandsaenderungen infor-
  - einer Entscheidung gefragt wird (prompting). Die integrity und Authentizitaet dieser Informationen must durch das Ge-
  - raet sichergestellt werden. Falls erforderlich, kann das Geraet dazu sicherheitsrelevante Ereignisse protokollieren.
  - Der Benutzer must wissen, in welchem Zustand sich sein Geraet befindet, wenn dieser Zustand Einfluss auf
  - TLS im Gegensatz zu Klartext-HTTP), die unterschiedliche Sicherheitseigenschaften aufweisen, must anzei-
  - Das Geraet must den Benutzer ueber den sicherheitsrelevanten Zustand informieren.
  - eignisse mit Zeitangabe informiert, dann must das Endgeraet ueber eine verlaessliche Systemzeit (

### Homegateway
- File: `09_Endpoints/3_40_Homegateway_v3.6.pdf`
- Short Summary: Homegateway 1.
- Key Requirement Points:
  - zungsempfehlung fuer Einheiten, die nicht am PSA-Verfahren teilnehmen. Diese requirements must bereits waeh-
  - sche Telekom Gruppe an das Endgeraet umfasst. In der Regel ist es nicht erforderlich, zusaetzliche Funktionalitaeten in
  - Ein Home Gateway basiert oftmals auf einem bestehenden Design, und der Lieferant must Softwarekomponenten
  - der Deutsche Telekom Gruppe geforderte Funktionalitaet bereitgestellt wird. In diesem Fall must die Deutsche Tele-
  - und must ueberarbeitet werden. Daher ist es unerlaesslich, dass die Deutsche Telekom Gruppe von jeder zusaetzlichen
  - Die Übersicht der Netzwerkdienste must alle aktiven Dienste auf jedwedem Netzwerkinterface des Home Gateways
  - lediglich an das localhost Interface gebunden sind, must hier nicht betrachtet werden.
  - Die Übersicht must jeweils pro Netzwerkdienst das Interface, an das der Dienst gebunden ist, den tcp/udp Port, das

### Mobile Endgeraete
- File: `09_Endpoints/3_44_Mobile_Endgeraete_v6.3.pdf`
- Short Summary: Mobile Endgeraete 1.
- Key Requirement Points:
  - setzungsempfehlung fuer Einheiten, die nicht am PSA-Verfahren teilnehmen. Diese requirements must bereits
  - Das Geraet must sicherstellen, dass Benutzer ueber den sicherheitsrelevanten Zustand und Zustandsaenderungen infor-
  - einer Entscheidung gefragt wird (prompting). Die integrity und Authentizitaet dieser Informationen must durch das Ge-
  - raet sichergestellt werden. Falls erforderlich, kann das Geraet dazu sicherheitsrelevante Ereignisse protokollieren.
  - Der Benutzer must wissen, in welchem Zustand sich sein Geraet befindet, wenn dieser Zustand Einfluss auf
  - TLS im Gegensatz zu Klartext-HTTP), die unterschiedliche Sicherheitseigenschaften aufweisen, must anzei-
  - Das Geraet must den Benutzer ueber den sicherheitsrelevanten Zustand informieren.
  - eignisse mit Zeitangabe informiert, dann must das Endgeraet ueber eine verlaessliche Systemzeit (

### COTS Residential Gateways
- File: `09_Endpoints/3_71_COTS_Residential_Gateways_v1.1.pdf`
- Short Summary: 1.
- Key Requirement Points: No clear must/should statements automatically detected.

### Proxyserver
- File: `10_Network_Components/3_12_Proxyserver_v8.0.pdf`
- Short Summary: Dieses document wurde auf Basis der Vorgaben aus den im Konzern gueltigen Sicherheitsrichtlinien erstellt. Es defi- niert die security requirements fuer den sicheren Operations von Proxyservern in der Deutschen Telekom Gruppe. Es ist von entscheidender Bedeutung, diese requirements zu erfuellen. Nur so laesst sich sicherstellen, dass sich Proxy- server nicht ohne Weiteres von Angreifern missbrauchen lassen. Copyright © 2025 by Deutsche Telekom AG.
- Key Requirement Points:
  - zungsempfehlung fuer Einheiten, die nicht am PSA-Verfahren teilnehmen. Diese requirements must bereits waeh-
  - nen Einsatzumfeld nicht erforderlich sind.
  - Entsprechend must unmittelbar nach der Installation saemtliche auf einem System nicht erforderliche Dienste voll-
  - staendig deaktiviert werden. Es must sichergestellt werden, dass diese Dienste auch nach einem Neustart des Systems
  - Ein bereitgestellter Dienst must grundsaetzlich auf allen Schnittstellen des Systems vollstaendig deaktiviert werden,
  - ueber die eine Erreichbarkeit des Dienstes fuer den ordnungsgemaessen Operations des Systems nicht erforderlich ist. Die
  - Die Erreichbarkeit eines Dienstes ueber die erforderlichen Schnittstellen must zudem auf legitime Kommunikations-
  - Nicht benoetigte Dienste must deaktiviert werden.

### Routers and Switches
- File: `10_Network_Components/3_23_Router_und_Switche_v8.0.pdf`
- Short Summary: In diesem document werden die spezifischen technischen security requirements fuer Routers and Switches be- schrieben. 1.
- Key Requirement Points:
  - zungsempfehlung fuer Einheiten, die nicht am PSA-Verfahren teilnehmen. Diese requirements must bereits waeh-
  - ne unverschluesselte Datenuebertragung oder unzureichende authentication. Diese Dienste must komplett deakti-
  - antwortet werden, sondern must auf einen Port, auf dem das verschluesselte HTTPS-Protokoll genutzt wird, umgeleitet
  - Discovery Protokolle wie das Cisco Discovery Protocol (CDP) oder Link Layer Discovery Protocol (LLDP) must kom-
  - plett deaktiviert werden. In begruendeten Ausnahmefaellen duerfen diese Protokolle genutzt werden. Hierbei must aller-
  - Endgeraeten must Discovery Protokolle deaktiviert werden.
  - Die IPv4- und IPv6-Adressen fuer alle Schnittstellen must fest konfiguriert werden. Dies bedeutet, dass eine automati-
  - Unsichere und nicht genutzte Dienste und Protokolle must deaktiviert werden.

### Operational Security Policies for Mobile Networks
- File: `10_Network_Components/3_38_Operational_Security_Policies_for_Mobile_Netw_v1.4.pdf`
- Short Summary: 1.
- Key Requirement Points: No clear must/should statements automatically detected.

### Netzelemente
- File: `10_Network_Components/3_42_Netzelemente_v8.0.pdf`
- Short Summary: Dieses document beinhaltet security requirements fuer Netzelemente, die Transport-, Switching- oder Routing- Funktionen gemaess OSI-Schicht 2 und 3 fuer Mobilfunk- und Festnetzdienste bereitstellen. - Key Requirement Points:
  - zungsempfehlung fuer Einheiten, die nicht am PSA-Verfahren teilnehmen. Diese requirements must bereits waeh-
  - ne unverschluesselte Datenuebertragung oder unzureichende authentication. Diese Dienste must komplett deakti-
  - antwortet werden, sondern must auf einen Port, auf dem das verschluesselte HTTPS-Protokoll genutzt wird, umgeleitet
  - Discovery Protokolle wie das Cisco Discovery Protocol (CDP) oder Link Layer Discovery Protocol (LLDP) must kom-
  - plett deaktiviert werden. In begruendeten Ausnahmefaellen duerfen diese Protokolle genutzt werden. Hierbei must aller-
  - Endgeraeten must Discovery Protokolle deaktiviert werden.
  - Die IPv4- und IPv6-Adressen fuer alle Schnittstellen must fest konfiguriert werden. Dies bedeutet, dass eine automati-
  - Unsichere und nicht genutzte Dienste und Protokolle must deaktiviert werden.

### SNMP
- File: `10_Network_Components/3_45_SNMP_v8.0.pdf`
- Short Summary: SNMP 1.
- Key Requirement Points:
  - zungsempfehlung fuer Einheiten, die nicht am PSA-Verfahren teilnehmen. Diese requirements must bereits waeh-
  - Es must SNMP in der Version 3 verwendet werden.
  - Solche vordefinierten Authentisierungsmerkmale must unmittelbar nach der Übernahme bzw. Installation des Sy-
  - Saemtliche Benutzerkonten des Systems must vor einer unberechtigten Nutzung geschuetzt werden.
  - Es must mindestens zwei Authentisierungsmerkmale miteinander kombiniert werden.
  - Der SNMP Server must verhindern, dass zu kleine Werte fuer die Laenge des HMAC verwendet
  - Vordefinierte Authentisierungsmerkmale must geaendert werden.
  - Benutzerkonten must mit mindestens zwei Authentisierungsmerkmalen aus unterschiedlichen

### Network-based Storage Systems
- File: `10_Network_Components/3_55_Netzbasierte_Speichersysteme_v8.0.pdf`
- Short Summary: Network-based Storage Systems 1.
- Key Requirement Points:
  - zungsempfehlung fuer Einheiten, die nicht am PSA-Verfahren teilnehmen. Diese requirements must bereits waeh-
  - austauschen. Wenn an einem FC-Switch ausschliesslich Hosts angeschlossen sind, must der F-Porttyp bei allen Ports
  - Bei Systemen mit einem hohem Schutzbedarf must eine gegenseitige authentication der FC-
  - Der accesssmodus zur Default-Zone must fuer hinzukommende FC-Komponenten verweigert
  - Die Porttypen (z. B. E-, F-Port) must bei allen Ports fuer den jeweiligen Einsatz fest definiert
  - Hardware-enforcement based Zoning must verwendet werden.
  - Die Hardware-enforcement based Zoning Konfiguration must auf Basis von Port-WWNs (WWPN)
  - Es must die Port Security fuer alle FC-Ports des Frontends aktiviert werden.

### Cisco Smart Licensing Infrastrukturen
- File: `10_Network_Components/3_70_Cisco_Smart_Licensing_Infrastrukturen_v6.0.pdf`
- Short Summary: Richtlinie mit requirements fuer die Absicherung von Cisco Smart Licensing Infrastrukturen sowie der Smart Licen- sing Funktionen in entsprechenden Cisco Produkten. 1.
- Key Requirement Points:
  - zungsempfehlung fuer Einheiten, die nicht am PSA-Verfahren teilnehmen. Diese requirements must bereits waeh-
  - Diese Kommunikation must ueber eine lokal installierte "Cisco SSM On-Prem" Instanz kanalisiert werden.
  - nicht im zentralen CSSM und in Richtung des Herstellers sichtbar machen zu must und erhoeht somit die Vertrau-
  - Eine Cisco SSM On-Prem Instanz must in einer abgegrenzten Netzwerk-Zone platziert werden und darf sich diese
  - Instanz auftretende Netzwerk-Kommunikation must kontrollierbar und reglementierbar sein, um im taeglichen Operations
  - (CSSM) im Internet must ueber eine lokale "SSM On-Prem" Instanz geleitet werden.
  - Cisco SSM On-Prem Instanzen must in einer separaten DMZ platziert werden, die
  - Saemtliche eingehenden und ausgehenden Netzwerk-Verbindungen einer Cisco SSM On-Prem Instanz must durch

### Third-Party Companies
- File: `11_Third_Party_Access/3_11_Third-party companies_v2.1.pdf`
- Short Summary: Third-party companies 1.
- Key Requirement Points:
  - zungsempfehlung fuer Einheiten, die nicht am PSA-Verfahren teilnehmen. Diese requirements must bereits waeh-
  - Der Identitaetsmanagementprozess must eingefuehrt und nachvollziehbar dokumentiert sein. Informationen ueber die-
  - sen Prozess must die Fremdfirma auf Anfrage der Deutschen Telekom Gruppe umgehend bereitstellen koennen. Die
  - Zuweisung von Identitaeten must dem Berechtigungskonzept folgen, das die Deutsche Telekom Gruppe bereitstellt.
  - Die Fremdfirma must sicherstellen, dass die autorisierten Nutzer, die im Zusammenhang des Auftrages access zu IT-
  - Erbringen Third-party companies Dienstleistungen, must die Auftraggeber die fuer die IT-/NT-Systeme
  - Die Fremdfirma must ueber einen technischen und organisatorischen
  - Die Fremdfirma must in der Lage sein, der Deutschen Telekom Gruppe jederzeit detaillierte

### Third-Party Access Connections
- File: `11_Third_Party_Access/3_20_Third-Party Access Connections_v8.0.pdf`
- Short Summary: Zu den daily requirements an die Unternehmen der Deutschen Telekom Gruppe gehoert es, Third-party companies Zu- gang zu internen IT/NT-Systemen zu gewaehren. Die accesssszenarien reichen je nach Zielsystem und gewuenschter Aktivitaet vom einfachen Webzugang bis hin zu Sessions mit interaktiven Anzeigen. Es ist eine erfolgskritische Aufga- be zur Aufrechterhaltung eines angemessenen Schutzniveaus fuer IT/NT-Systeme und Daten, diese Verbindungen
- Key Requirement Points:
  - zungsempfehlung fuer Einheiten, die nicht am PSA-Verfahren teilnehmen. Diese requirements must bereits waeh-
  - umgekehrt geben. Eine accesssplattform fuer Third-party companies in einer DMZ (3rd Party Access Platform, 3PAP) must ueber
  - die fuer die Durchsetzung der security requirements erforderlichen Funktionen verfuegen. Die 3PAP must immer
  - Es must fuer einen effektiven Kontrollpunkt zur Umsetzung der security requirements gesorgt werden.
  - Die einzelnen Funktionselemente must in verschiedenen, durch ein Firewall-Gateway geschuetzten (V)LANs unter-
  - Alle Verbindungen must in einer DMZ terminiert werden.
  - Die Netztrennung der 3PAP und angrenzender Dienste must sich an deren spezifischen
  - Die 3PAP must mit zustandsorientierten (stateful) Firewall-Gateways geschuetzt werden.

### Client-Anwendungen
- File: `12_Mobile_Applications/3_54_Client-Anwendungen_v7.0.pdf`
- Short Summary: Unter die Bezeichnung Client-Anwendung faellt jede Anwendung/Applikation oder auch kurz allgemein App ge- nannt, welche auf mobiler oder Desktop Hardware ausgefuehrt wird. Die Ausfuehrung kann dabei autark oder in Kom- munikationsbeziehung mit einem Backend nach dem Client-Server-Modell stattfinden. Copyright © 2025 by Deutsche Telekom AG. Alle Rechte, auch die des auszugsweisen Nachdrucks, der fotomechanischen Wiedergabe (einschliesslich Mikrokopie) sowie der Auswertung
- Key Requirement Points:
  - zungsempfehlung in Einheiten, die nicht am PSA-Verfahren teilnehmen. Diese requirements must bereits waeh-
  - Die auf dem System eingesetzte Software must aus trusted sources bezogen und vor der Installation auf
  - (1) Bietet der Bereitstellungs-Server verschiedene Formen von Downloads an, must durch encryption
  - sftp), must die zugehoerig praesentierten Server-Zertifikate oder Server-Keys/Fingerprints bei jedem Down-
  - Die Integritaetspruefung should sicherstellen, dass die erhaltene Software frei von Manipulationen und Schadsoftwa-
  - re-Befall ist. Sofern vorhanden, must zur Pruefung die vom Hersteller implementierten Mechanismen verwendet wer-
  - Abgleich von kryptografischen Hash Werten (z. B. SHA256, SHA512) der erhaltenen Software gegen should-
  - Eingesetzte Software must aus trusted sources bezogen und auf integrity geprueft

### 1. Introduction
- File: `12_Mobile_Applications/4_1_1_OWASP_Mobile_Application_Security_Verificati_v1.1.pdf`
- Short Summary: Android / iOS requirements nach dem OWASP Mobile Application Security Verification Standard und OWASP Mo- bile Application Security Testing Guide . Dieses document enthaelt requirements fuer Softwarearchitekten und - ent- wickler, die mobile Anwendungen sicher entwickeln moechten. Es dient als Industriestandard, um die Sicherheit mobi- ler Anwendungen zu ueberpruefen. Es klaert auch die Rolle von Softwareschutzmechanismen bei der mobilen
- Key Requirement Points:
  - zungsempfehlung in Einheiten, die nicht am PSA-Verfahren teilnehmen. Diese requirements must bereits waeh-
  - Jenseits der in diesem document beschriebenen requirements, ist zu beruecksichtigen, dass fuer die Distribution von
  - terprise Appstore zu nutzen ist. Ausserdem must bei Eigenentwicklungen solcher Apps das SDK fuer Container ver-
  - Alle Komponenten der mobilen App sind identifiziert und fuer den Operations der App erforderlich.
  - gen. In beiden Faellen must gewaehrleistet sein, dass das Schluesselmaterial adaequat geschuetzt uebermittelt und gespei-
  - dates schnellstmoeglich ausgerollt werden must Apps ueber entsprechend eigene Mechanismen verfuegen.
  - must not in den Logs enthalten sein. Logs koennen typischerweise mit Dritten geteilt werden, bspw. fuer notwendige
  - gung des Anwenders und aktiven Nutzung eines anderen Dienstes vorausgeht, should sichergestellt werden, dass die

### External Hosting
- File: `13_Operational_Security_Requirements/3_08_Externes_Hosting_v2.7.pdf`
- Short Summary: External Hosting 1.
- Key Requirement Points:
  - zungsempfehlung fuer Einheiten, die nicht am PSA-Verfahren teilnehmen. Diese requirements must bereits waeh-
  - gen Landesgesellschaft sein. Der Ansprechpartner must fuer technische/nicht technische Aspekte zur Verfuegung ste-
  - Im Fall eines Sicherheitsvorfalls must schnell und kompetent gehandelt werden koennen. Zur Vermeidung
  - Im Fall eines Sicherheitsvorfalls must unverzueglich gehandelt werden koennen. Eine staendige Erreichbar-
  - Motivation: Im Fall eines Sicherheitsvorfalls must schnell und kompetent gehandelt werden koennen. Zur Vermei­dung
  - Der Hosting Provider/SaaS Provider must einen entscheidungsbefugten Ansprechpartner fuer alle
  - Der Hosting Provider/SaaS Provider must eine telefonische 7x24 Stunden-Erreichbarkeit fuer alle
  - Sicherheitsthemen sicherstellen. Der HostingProvider/SaaS Provider must diese Erreichbarkeit

### Operations
- File: `13_Operational_Security_Requirements/3_61_Betrieb_v4.0.pdf`
- Short Summary: requirements fuer einen sicheren Operations von Systemen. 1.
- Key Requirement Points:
  - setzungsempfehlung fuer Einheiten, die nicht am PSA-Verfahren teilnehmen. Diese requirements must bereits
  - B. Einspielen von Patches) must zeitnah gemaess zuvor getroffenen Regelungen bearbeitet werden. Dazu must ein
  - Der jeweilige (technische) Systemverantwortliche must sicherstellen, dass dieser Kontakt benannt ist und in der Lage
  - Motivation: Im Fall eines Sicherheitsvorfalls must schnell und kompetent gehandelt werden koennen. Zur Vermeidung
  - Es must fuer jedes System einen Verantwortlichen geben, der dieses in der Betriebsphase
  - Es must eine Kontaktmoeglichkeit geben, ueber die zu den vereinbarten Zeiten sicherheitsbezogene
  - nen Risikos abzustimmen. Es must eine adaequate authorization sowie eine angemessene documentation der Ände-
  - on must hinsichtlich der Änderungen angepasst werden.

### Web Services
- File: `14_Web_Services/3_02_Web_Services_v9.1.pdf`
- Short Summary: Dieses document wurde auf Basis der Vorgaben aus den im Konzern gueltigen Sicherheitsrichtlinien erstellt und rich- tet sich an alle Systeme, die interoperable Interaktionen von Applikation zu Applikation ueber ein Netzwerk unterstuet- zen. Neben den Konzernvorgaben werden ebenfalls die Empfehlungen des Open Web Appliaction Security Project als In- dustriestandard inkludiert. URLs wurden verifiziert (Stand 12.06.2025) Copyright © 2025 by Deutsche Telekom AG.
- Key Requirement Points:
  - zungsempfehlung fuer Einheiten, die nicht am PSA-Verfahren teilnehmen. Diese requirements must bereits waeh-
  - Ein solcher Support must umfassen, dass der Hersteller
  - Der security vulnerability support must fuer die gesamte Dauer bestehen, in der das betroffene Produkt im Ein-
  - Wird ein Produkt innerhalb von Support-Phasen eingesetzt, die Einschraenkungen unterliegen, must explizit sicherge-
  - vertraglich vereinbarter security vulnerability support unter Umstaenden nicht verfuegbar. Grundsaetzlich must
  - Die auf dem System eingesetzte Software must aus trusted sources bezogen und vor der Installation auf
  - Software und Hardware des Systems must von einem security vulnerability support
  - Eingesetzte Software must aus trusted sources bezogen und auf integrity geprueft

### Web Service Gateway
- File: `14_Web_Services/3_13_Web_Service_Gateway_v8.1.pdf`
- Short Summary: Dieses document wurde auf Basis der Vorgaben aus den im Konzern gueltigen Sicherheitsrichtlinien erstellt und rich- tet sich an alle Systeme, die Gateways fuer Web Service Dienste bereitstellen. - Key Requirement Points:
  - zungsempfehlung fuer Einheiten, die nicht am PSA-Verfahren teilnehmen. Diese requirements must bereits waeh-
  - Dank Camara und TM Forum haben sich die HTTP-Rest APIs als Quasi-Industriestandard etabliert, und es ist zu erwar-
  - Die auf dem System eingesetzte Software must aus trusted sources bezogen und vor der Installation auf
  - (1) Bietet der Bereitstellungs-Server verschiedene Formen von Downloads an, must durch encryption
  - sftp), must die zugehoerig praesentierten Server-Zertifikate oder Server-Keys/Fingerprints bei jedem Down-
  - Die Integritaetspruefung should sicherstellen, dass die erhaltene Software frei von Manipulationen und Schadsoftwa-
  - re-Befall ist. Sofern vorhanden, must zur Pruefung die vom Hersteller implementierten Mechanismen verwendet wer-
  - Abgleich von kryptografischen Hash Werten (z. B. SHA256, SHA512) der erhaltenen Software gegen should-

### Web Service via TARDIS
- File: `14_Web_Services/3_18_Web_Service_ueber_TARDIS_v6.1.pdf`
- Short Summary: Dieses document enthaelt nur eine Teilmenge der requirements aus dem Web Service document und darf deshalb ausschliesslich fuer Web Services angewandt werden die exklusiv ueber das TARDIS Gateway bereitgestellt werden. Das TARDIS Gateway erfuellt die verbliebenen requirements, deshalb ist eine erneute Betrachtung nicht notwendig. Dieses document wurde auf Basis der Vorgaben aus den im Konzern gueltigen Sicherheitsrichtlinien erstellt und
- Key Requirement Points:
  - zungsempfehlung fuer Einheiten, die nicht am PSA-Verfahren teilnehmen. Diese requirements must bereits waeh-
  - Ein solcher Support must umfassen, dass der Hersteller
  - Der security vulnerability support must fuer die gesamte Dauer bestehen, in der das betroffene Produkt im Ein-
  - Wird ein Produkt innerhalb von Support-Phasen eingesetzt, die Einschraenkungen unterliegen, must explizit sicherge-
  - vertraglich vereinbarter security vulnerability support unter Umstaenden nicht verfuegbar. Grundsaetzlich must
  - Software und Hardware des Systems must von einem security vulnerability support
  - Werden bei einem Web Service besonders schuetzenswerte Daten verarbeitet, so must diese
  - Ein Web Service must vor Manipulation / Replay Attacken geschuetzt werden, wenn dieser ueber

### Verwendung von SaaS Public Clouds
- File: `15_Cloud/3_82_Verwendung_von_SaaS_Public_Clouds_v1.0.pdf`
- Short Summary: Dieses document behandelt den sicheren Einsatz von SaaS-Diensten (Software as a service) fuer den Konzern. Die An- forderungen in diesem document sind generisch und gelten fuer alle SaaS-Cloudanbieter und SaaS-use cases. - Key Requirement Points:
  - setzungsempfehlung fuer Einheiten, die nicht am PSA-Verfahren teilnehmen. Diese requirements must bereits
  - haengt vom verwendeten Servicemodell ab, z. B. must der Cloud-Anbieter bei der Verwendung von IaaS den Hypervi-
  - (Mandant) die virtuellen Maschinen und die darin laufende Software ordnungsgemaess sichern must.
  - Kunden noch entsprechend konfiguriert werden must) und solche, die der Kunde zusaetzlich zu anderen Diensten
  - klassifizieren. Dabei must nicht nur die Datenverfuegbarkeit, sondern auch der Lebenszyklus der Daten beruecksichti-
  - Alle Nutzer, einschliesslich der Betreiber einer Landing Zone und insbesondere des Applikationsbetriebs, must sich
  - Bevor eine Applikation in der Cloud betrieben werden darf, must die relevante documentation der
  - traege mit dem CSP unterzeichnet werden. Wenn ein BSI-C5-Auditbericht vorhanden ist, must dieser ebenfalls ausge-

### M365 Allgemeine requirements
- File: `15_Cloud/8_00_M365_Allgemeine_Anforderungen_v1.2.pdf`
- Short Summary: Microsoft 365 (M365) ist die Cloud Plattform von Microsoft, welche durch das Zusammenspiel verschiedener Ser- vices es ermoeglicht, Kommunikations- und Digitalisierungsloesungen im Digital Workplace zu erstellen. Neben den On- line Versionen von beispielsweise Word oder Excel stehen neben verschiedenen Services fuer Collaboration (MS Teams, Sharepoint Online), und der eigenen Produktivitaet (Mail, Calendar, Notes) auch Tools fuer die digitale
- Key Requirement Points:
  - am PSA-Verfahren teilnehmen. Diese requirements must bereits waehrend der Planungs- und Entscheidungspro-
  - det wird, must Modern Authentication im M365 Tenant aktiviert werden:
  - Um eine Verwendung von schwachen Authentifizierungen, sogenannten legacy Authentication zu unterbinden, must
  - Um die Übernahme eines Accounts z.B. durch einen Password Leak zu verhindern, must jeder Account, der sich ueber
  - Modern Authentication must aktiviert werden
  - Conditional Access (CA) must verwendet werden um die Verwendung von legacy Authentication
  - Multi Factor Authentication (MFA) must unter Verwendung von Conditional Access (CA) fuer jeden
  - Um das Verwenden schwacher oder leaked Passwoerter zu unterbinden must die Password Protection fuer Active Di-

### M365 Power BI
- File: `15_Cloud/8_01_M365_Power_BI_v4.0.pdf`
- Short Summary: Power BI ist eine Sammlung von Softwarediensten, Apps und Data Connectors, die zusammenwirken, um nicht ver- bundene Datenquellen in kohaerente, visuell ueberzeugende und interaktive Einblicke umzuwandeln. Die Daten koen- nen als Excel-Kalkulationstabelle oder als eine hybride Sammlung von cloudbasierten und lokalen Data Warehouse- Instanzen vorliegen. Mit Power BI ist es moeglich, Verbindungen zwischen Ihren Datenquellen herstellen, wichtige
- Key Requirement Points:
  - am PSA-Verfahren teilnehmen. Diese requirements must bereits waehrend der Planungs- und Entscheidungspro-
  - Es must sichergestellt werden, dass auf einen Arbeitsbereich, der Power BI Dataflows enthaelt, nur Berichts-Entwickler
  - Es must, fuer Power BI Dataflows und Berichte getrennte Arbeitsbereiche genutzt werden.
  - Dataflow-Besitzer dies erfaehrt. Dies should mit dieser requirement verhindert werden.
  - Es must ebenfalls in der Systembeschreibung dokumentiert werden, dass diese Funktionalitaet nicht verwendet wer-
  - worden ist, should durch diese requirement die Verarbeitung / Manipulation von DTAG Information durch 3rd Party Ser-
  - Die Power BI Dataflow Funktion "AutoML" (Automatisiertes Machine Learning) must not
  - Das Recht der Registrierung eines Data Gateways im gewuenschten Tenant must auf wenige Mitarbeiter begrenzt sein.

### M365 Power Apps
- File: `15_Cloud/8_02_M365_Power_Apps_v1.2.pdf`
- Short Summary: Power Apps ist eine Suite von Apps, Diensten und Konnektoren sowie eine Datenplattform, die eine Umgebung fuer die schnelle Entwicklungsumgebung bereitstellt, in der benutzerdefinierte Apps fuer Geschaeftsanforderungen erstellt werden koennen. Durch die Nutzung von Power Apps koennen schnell benutzerdefinierte Geschaeftsanwendungen er- stellt werden, die eine Verbindung zu verschiedenen Online und OnPrem-Datenquellen herstellen, wie
- Key Requirement Points:
  - am PSA-Verfahren teilnehmen. Diese requirements must bereits waehrend der Planungs- und Entscheidungspro-
  - Vor der Verwendung der non-blockable Data Connectors must diese im Rahmen eines PSA Verfahrens beschrie-
  - angebunden, so must eine Authentication am externen System durchgefuehrt werden.
  - Interne Systeme der Organisation must vor einer Anbindung durch einen Data Connector im Rahmen eines PSA
  - Non-blockable Data Connectors must durch einen Approval Prozess abgenommen werden
  - Im Rahmen des Operations der Power Apps must Audit Logs und die Anomalie Erkennung aktiviert und an das SIEM
  - Audit Logs & Anomalie Erkennung must aktiviert werden

### M365 Power Automate
- File: `15_Cloud/8_03_M365_Power_Automate_v2.2.pdf`
- Short Summary: Power Automate ist ein Dienst, mit dem automatisierte Workflows zwischen Apps und Diensten erstellt werden koen- nen, um z. B. Fileen zu synchronisieren, Benachrichtigungen zu erhalten und/oder Daten zu sammeln. - Key Requirement Points:
  - am PSA-Verfahren teilnehmen. Diese requirements must bereits waehrend der Planungs- und Entscheidungspro-
  - Vor der Verwendung der blockable Data Connectors must diese im Rahmen eines PSA Verfahrens beschrieben
  - must eine Authentication am externen System durchgefuehrt werden.
  - Interne Systeme der Organisation must vor einer Anbindung durch einen Data Connector im Rahmen eines PSA
  - Blockable Data Connectors must durch einen Approval Prozess abgenommen werden
  - Im Rahmen des Operations der Power Apps must Audit Logs und die Anomalie Erkennung aktiviert und an das SIEM
  - Audit Logs & Anomalie Erkennung must aktiviert werden
  - must eine CA Policy erstellt und aktiviert werden die nur berechtigten Rollen und/oder Accounts Zugriff auf den Com-

### M365 Sharepoint Online
- File: `15_Cloud/8_04_M365_Sharepoint_Online_v1.2.pdf`
- Short Summary: SharePoint ist ein Website-basiertes System zur Zusammenarbeit, das Workflow-Anwendungen, Listen-Datenbanken und andere Webparts und Sicherheitsfunktionen nutzt, um die Zusammenarbeit von Geschaeftsteams zu ermoeglichen. SharePoint gestattet dem Unternehmen, das die Plattform einsetzt, ausserdem die Kontrolle des Zugriffs auf Informa- tionen und die geschaeftseinheitsuebergreifende Automatisierung von Workflow-Prozessen. Die Microsoft Cloud-Version von SharePoint, SharePoint Online, verfuegt ueber zahl
- Key Requirement Points:
  - am PSA-Verfahren teilnehmen. Diese requirements must bereits waehrend der Planungs- und Entscheidungspro-
  - Tenant-Level ist must die Security Controls auf Site-Collection Level implementiert werden.
  - Erfolgt der Zugriff auf SPO von nicht-gemanagten Devices, so must die Zugriffe restriktiver gestaltet werden. Aus
  - diesem Grund must fuer den Zugriff auf SPO von nicht-gemanagten Devices eine Conditional Access (CA) Policy ab-
  - Fuer den Zugriff auf SPO must die folgenden Session Timeouts konfiguriert werden:
  - Die Security Controls fuer den restriktiven Zugriff must auf Site-Collection Level implementiert
  - Fuer den Zugriff auf SPO von nicht-gemanagten Devices must eine Conditional Access (CA) Policy
  - Session Timeouts must implementiert werden

### M365 Dynamics
- File: `15_Cloud/8_05_M365_Dynamics_v1.2.pdf`
- Short Summary: M365 Dynamics ist eine Suite verschiedener CRM und ERP Anwendungen, die dabei unterstuetzt, eine Organisation zu verwalten und durch KI-gestuetzte Insights bessere Ergebnisse zu erzielen. 1.
- Key Requirement Points:
  - am PSA-Verfahren teilnehmen. Diese requirements must bereits waehrend der Planungs- und Entscheidungspro-
  - Änderungen an den durch den Plattformbetrieb vorgegebenen Security Roles must explizit an geeigneter Stelle im
  - Die Architektur bzw. das Environment, welches M365 Dynamics verwendet, must explizit an geeigneter Stelle im
  - Die Konfiguration aller verwendeten MS Dynamics Apps ("Module") must explizit an geeigneter Stelle im SDSK doku-
  - Änderungen der Security Roles must dokumentiert werden
  - Das jeweilige Environment der Applikation must dokumentiert werden
  - Die Konfiguration der verwendeten MS Dynamic Apps ("Module") must dokumentiert werden
  - Wenn in der Fachapplikation eine Teams Integration erforderlich ist, so must diese explizit an geeigneter Stelle im

### M365 Dataverse
- File: `15_Cloud/8_06_M365_Dataverse_v2.2.pdf`
- Short Summary: M365 Dataverse ermoeglicht die Integration von Daten aus verschiedenen Quellen in einen einzigen Speicher, der dann in unterschiedlichen Services wie M365 Power Apps, M365 Power Automate, M365 Power BI oder M365 Dyna- mics verwendet werden kann. - Key Requirement Points:
  - am PSA-Verfahren teilnehmen. Diese requirements must bereits waehrend der Planungs- und Entscheidungspro-
  - Es duerfen nur berechtigte Personen bzw. Applikationen auf das Dataverse zugreifen. Aus diesem Grund must eine CA
  - Fuer den Zugriff auf das Dataverse must eine Conditional Access (CA) Policy implementiert werden
  - Um den Zugriff auf die Daten kontrollieren und einschraenken zu koennen, must fuer jede einzelne Database eine ad-
  - Es must sichergestellt sein, dass die Forms einer Tabelle im Dataverse nicht von jedem innerhalb der Organisation er-
  - reicht werden kann. Aus diesem Grund must die entsprechende Option auf "Specify Security Roles" gesetzt und die
  - must die folgenden Fileen als Anhaenge blockiert werden:
  - Record-level security in Dataverse must verwendet werden

### M365 Exchange Online
- File: `15_Cloud/8_07_M365_Exchange_Online_v2.2.pdf`
- Short Summary: Microsoft Exchange Online ist eine gehostete Messagingloesung, die E-Mails, Kalender, Kontakte und Aufgaben von PCs, dem Web und mobilen Geraeten uebermittelt. Es ist vollstaendig in Azure Active Directory integriert, sodass Admini- stratoren Gruppenrichtlinien sowie andere Verwaltungstools verwenden koennen, um Exchange Online Features in ih- rer gesamten Umgebung zu verwalten. Copyright © 2025 by Deutsche Telekom AG. Alle Rechte, auch die des auszugsweisen Nachdrucks, der fotomechanischen Wiedergab
- Key Requirement Points:
  - am PSA-Verfahren teilnehmen. Diese requirements must bereits waehrend der Planungs- und Entscheidungspro-
  - Um einen sicheren, verschluesselten Email-Verkehr via S/MIME zu ermoeglichen, must eine sichere PKI Infrastruktur be-
  - Um einen sicheren, verschluesselten Email-Verkehr via S/MIME zu ermoeglichen, must eine sichere
  - Um zu verhindern, dass Malware ueber Attachments in Emails verteilt wird, must der Common Attachment Filter akti-
  - Um (uebernommene) Accounts, die Spam Emails versenden, zu identifizieren und zu blockieren, must die Exchange
  - Der Common Attachment Types Filter must verwendet werden
  - Exchange Online Spam Policies must verwendet werden
  - Um gefaelschte Emails, die aussehen, als ob sie von der eigenen Organisation kommen, zu verhindern, must DKIM ver-

## Folder-wise Requirement Summary

Note: points are condensed from extracted must/should statements.

### 01_General_Requirements
- Scope: 7 PDFs
- Main Requirements:
  - Cloud Governance
  - Secure Development/Tests
  - Patch-/Lifecycle-Management
  - Authentisierung/IAM
  - encryption/Krypto
- Example Requirements:
  - setzungsempfehlung fuer Einheiten, die nicht am PSA-Verfahren teilnehmen. Diese requirements must bereits
  - Ein solcher Support must umfassen, dass der Hersteller

### 02_Architecture
- Scope: 3 PDFs
- Main Requirements:
  - Cloud Governance
- Example Requirements:
  - setzungsempfehlung in Einheiten, die nicht am PSA-Verfahren teilnehmen. Diese requirements must bereits waeh-
  - bzgl. confidentiality, availability, integrity oder Datenschutz, sogenannte "Kritische Systeme", must von anderen

### 03_Operating_Systems
- Scope: 5 PDFs
- Main Requirements:
  - encryption/Krypto
  - Patch-/Lifecycle-Management
  - Logging/Audit
  - Systemhaertung/Konfiguration
- Example Requirements:
  - am PSA-Verfahren teilnehmen. Diese requirements must bereits waehrend der Planungs- und Entscheidungspro-
  - SSHv1 must permanent in der Konfiguration des SSH-Servers deaktiviert werden. Mit OpenSSH 7.4 wurde die Unter-

### 04_Virtualization
- Scope: 5 PDFs
- Main Requirements:
  - Cloud Governance
  - Patch-/Lifecycle-Management
- Example Requirements:
  - zungsempfehlung fuer Einheiten, die nicht am PSA-Verfahren teilnehmen. Diese requirements must bereits waeh-
  - Der PatchmanagementProzess in einer Cloud-Umgebung must so implementiert werden, dass das Patchen aller

### 05_Databases
- Scope: 6 PDFs
- Main Requirements:
  - Patch-/Lifecycle-Management
  - Authentisierung/IAM
- Example Requirements:
  - zungsempfehlung fuer Einheiten, die nicht am PSA-Verfahren teilnehmen. Diese requirements must bereits waeh-
  - Die auf dem System eingesetzte Software must aus trusted sources bezogen und vor der Installation auf

### 06_Server_Applications
- Scope: 2 PDFs
- Main Requirements: No clear keyword focus areas automatically detected.
- Example Requirements:
  - gen must erfuellt werden, um sicherzustellen, dass eine Web-Anwendung nicht ohne Weiteres von Angreifern
  - aus als Umsetzungsempfehlung fuer Einheiten, die nicht am PSA-Verfahren teilnehmen. Diese requirements must

### 07_Application_Servers
- Scope: 2 PDFs
- Main Requirements:
  - Patch-/Lifecycle-Management
- Example Requirements:
  - rungen must erfuellt werden, um sicherzustellen, dass ein Application Server nicht ohne weiteres von Angreifern
  - setzungsempfehlung fuer Einheiten, die nicht am PSA-Verfahren teilnehmen. Diese requirements must bereits

### 08_Web_Servers
- Scope: 5 PDFs
- Main Requirements:
  - Patch-/Lifecycle-Management
- Example Requirements:
  - derungen an eine sichere Implementierung von Webservern. Die hier beschriebenen requirements must erfuellt
  - zungsempfehlung fuer Einheiten, die nicht am PSA-Verfahren teilnehmen. Diese requirements must bereits waeh-

### 09_Endpoints
- Scope: 5 PDFs
- Main Requirements:
  - encryption/Krypto
  - Netzwerkhaertung/Segmentierung
- Example Requirements:
  - zungsempfehlung fuer Einheiten, die nicht am PSA-Verfahren teilnehmen. Diese requirements must bereits waeh-
  - Dieses Anforderungspapier bietet die Grundlage welche Mindestanforderungen an einen Client erfuellt sein must,

### 10_Network_Components
- Scope: 7 PDFs
- Main Requirements:
  - Netzwerkhaertung/Segmentierung
  - Logging/Audit
  - Systemhaertung/Konfiguration
- Example Requirements:
  - zungsempfehlung fuer Einheiten, die nicht am PSA-Verfahren teilnehmen. Diese requirements must bereits waeh-
  - nen Einsatzumfeld nicht erforderlich sind.

### 11_Third_Party_Access
- Scope: 2 PDFs
- Main Requirements:
  - Netzwerkhaertung/Segmentierung
- Example Requirements:
  - zungsempfehlung fuer Einheiten, die nicht am PSA-Verfahren teilnehmen. Diese requirements must bereits waeh-
  - Der Identitaetsmanagementprozess must eingefuehrt und nachvollziehbar dokumentiert sein. Informationen ueber die-

### 12_Mobile_Applications
- Scope: 2 PDFs
- Main Requirements: No clear keyword focus areas automatically detected.
- Example Requirements:
  - zungsempfehlung in Einheiten, die nicht am PSA-Verfahren teilnehmen. Diese requirements must bereits waeh-
  - Die auf dem System eingesetzte Software must aus trusted sources bezogen und vor der Installation auf

### 13_Operational_Security_Requirements
- Scope: 2 PDFs
- Main Requirements:
  - Cloud Governance
- Example Requirements:
  - zungsempfehlung fuer Einheiten, die nicht am PSA-Verfahren teilnehmen. Diese requirements must bereits waeh-
  - gen Landesgesellschaft sein. Der Ansprechpartner must fuer technische/nicht technische Aspekte zur Verfuegung ste-

### 14_Web_Services
- Scope: 3 PDFs
- Main Requirements:
  - Patch-/Lifecycle-Management
- Example Requirements:
  - zungsempfehlung fuer Einheiten, die nicht am PSA-Verfahren teilnehmen. Diese requirements must bereits waeh-
  - Ein solcher Support must umfassen, dass der Hersteller

### 15_Cloud
- Scope: 9 PDFs
- Main Requirements:
  - Cloud Governance
  - Logging/Audit
  - Systemhaertung/Konfiguration
  - Authentisierung/IAM
- Example Requirements:
  - setzungsempfehlung fuer Einheiten, die nicht am PSA-Verfahren teilnehmen. Diese requirements must bereits
  - haengt vom verwendeten Servicemodell ab, z. B. must der Cloud-Anbieter bei der Verwendung von IaaS den Hypervi-

