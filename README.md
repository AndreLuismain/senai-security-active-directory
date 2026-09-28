# Automação e Segurança de Redes com Active Directory e APIs

[![Windows Server 2022](https://img.shields.io/badge/Windows_Server-2022-blue?logo=windows)](https://www.microsoft.com/windows-server)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%20%7C%207+-5391FE?logo=powershell)](https://learn.microsoft.com/powershell/)
[![Java](https://img.shields.io/badge/Java-21%20LTS-ED8B00?logo=openjdk)](https://openjdk.org/)
[![Spring Boot](https://img.shields.io/badge/Spring_Boot-3.3.4-6DB33F?logo=springboot)](https://spring.io/projects/spring-boot)
[![Active Directory](https://img.shields.io/badge/Directory_Service-AD%20DS%20%2F%20LDAP-0078D4?logo=microsoft)](https://learn.microsoft.com/azure/active-directory-domain-services/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Este repositório consolida a implementação prática, a automação e a modernização do Trabalho de Conclusão de Curso (TCC) intitulado:

> **"Implementação de Active Directory e políticas de grupo em ambientes corporativos e educacionais"**  
> *Autores: André Luís, Maria Gabriella, Júlia Silva e Thales Costa.*

O objetivo central deste projeto é viabilizar a transição da infraestrutura clássica de redes para os paradigmas modernos de **Infraestrutura como Código (IaC)** e **Engenharia de Software**, sanando vulnerabilidades críticas de governança e controle de acesso através de scripts PowerShell e uma API REST em Java/Spring Boot conectada via protocolo LDAP.

---

## 1. O Problema: Vulnerabilidade e Falta de Governança

Empresas e instituições de ensino frequentemente sofrem com a concessão desmedida de privilégios e a carência de governança de acessos. Usuários comuns costumam operar com privilégios excessivos, tendo capacidade de executar comandos administrativos, conectar mídias externas não homologadas e realizar downloads arbitrários.

Conforme evidenciado na pesquisa acadêmica:
* **Grandes Ameaças e Ransomwares:** Incidentes históricos como o ataque ao Grupo Fleury (2021) e à JBS (que demandou US$ 11 milhões em resgate) demonstram como o movimento lateral e a ausência de privilégio mínimo causam impactos severos.
* **Escalada no Setor Educacional:** Entre 2021 e 2022, os ciberataques contra o setor de educação cresceram **122%** no Brasil e **114%** no mundo.
* **Mortalidade Empresarial:** Cerca de **70%** das PMEs sofreram ataques cibernéticos em 2022, das quais **60%** fecharam as portas em até 6 meses após o incidente por falta de preparo e continuidade de negócios.

---

## 2. A Solução Arquitetural

A arquitetura resolve esses vetores combinando **Active Directory Domain Services (AD DS)** no **Windows Server 2022**, **Diretivas de Grupo (GPOs)** rígidas e uma **API de Gestão de Identidades** orientada a serviços.

```
                      +------------------------------------------+
                      |   Portais Externos / RH / Acadêmico      |
                      +--------------------+---------------------+
                                           |
                                   [HTTPS / REST]
                                   Basic Auth / JWT
                                           v
                      +--------------------+---------------------+
                      |   Identity API (Java 21 / Spring Boot)   |
                      |   - Spring Data LDAP / LdapTemplate      |
                      |   - Sanitização & Proteção de Injeção    |
                      +--------------------+---------------------+
                                           |
                                [LDAP / LDAPS :389/:636]
                                           v
+-------------------------------------------------------------------------------+
|                      WINDOWS SERVER 2022 (Domain Controller)                  |
|                                                                               |
|  [Active Directory Domain Services]               [Group Policy Management]   |
|   ├── OU=SenaiCorp                                 ├── GPO-SEC-01 (CMD Block) |
|   │   ├── OU=Departamentos (TI, RH, Fin, Adm)      ├── GPO-SEC-02 (Downloads) |
|   │   ├── OU=Educacional (Professores, Alunos)     ├── GPO-SEC-03 (Password)  |
|   │   ├── OU=Computadores                          ├── GPO-SEC-04 (Directories)|
|   │   └── OU=Grupos (GRP_TI, GRP_Alunos...)        └── GPO-SEC-05 (USB Deny)  |
|                                                                               |
|  [Storage Seguro com ABE - Access-Based Enumeration]                          |
|   └── C:\Shares\Departamentos$                                                |
+-------------------------------------------------------------------------------+
```

### Especificações Técnicas de Hardware Documentadas:
* **Processador:** 1,4 GHz, 64-bit (compatível com conjunto x64, suporte a DEP/NX).
* **Memória RAM:** Mínimo de 4 GB.
* **Armazenamento:** Mínimo de 32 GB livres em partição NTFS.
* **Rede:** Adaptador Ethernet de 1 Gbps configurado com IPv4 Estático.

---

## 3. Matriz de Diretivas de Grupo (GPOs) Codificadas

As cinco políticas indispensáveis do TCC foram transcritas em automação PowerShell declarativa:

| ID | Diretiva de Segurança | Alvo de Registro / Política | Efeito Prático no Ambiente |
|---|---|---|---|
| **01** | **Bloqueio do Prompt de Comando (CMD)** | `HKCU\Software\Policies\Microsoft\Windows\System` -> `DisableCMD = 1` | Impede o acesso ao `cmd.exe` e a execução de arquivos de lote (`.bat`, `.cmd`), barrando ferramentas de enumeração e movimento lateral. |
| **02** | **Interrupção de Downloads Inseguros** | `HKCU\...\Internet Settings\Zones\3` -> `1803 = 3`<br>`HKLM\...\Windows\System` -> `EnableSmartScreen = 1` | Bloqueia downloads diretos da internet e ativa o Windows Defender SmartScreen em modo restrito contra arquivos suspeitos. |
| **03** | **Bloqueio de Troca de Senha pelos Usuários** | `HKCU\...\Policies\System` -> `DisableChangePassword = 1` | Remove o botão "Alterar Senha" da interface Ctrl+Alt+Del, centralizando o ciclo de credenciais na TI/RH. |
| **04** | **Bloqueio de Diretórios e Isolamento** | `HKCU\...\Policies\Explorer` -> `NoViewOnDrive = 4`<br>`NoDrives = 4` + **SMB ABE** | Oculta e restringe o disco local `C:` aos usuários comuns e ativa a Enumeração Baseada em Acesso (ABE), tornando invisíveis os dados de outros setores. |
| **05** | **Bloqueio de Dispositivos Externos (USB)** | `HKLM & HKCU\...\RemovableStorageDevices` -> `Deny_All = 1` | Bloqueia a montagem, leitura e execução de quaisquer unidades de armazenamento USB/Pendrives não autorizados. |

---

## 4. Estrutura do Repositório

```
senai-security-project/
├── scripts/
│   └── powershell/
│       ├── Install-AD.ps1           # Instalação, DNS e promoção a Domain Controller
│       ├── Apply-SecurityGPOs.ps1   # Codificação das 5 GPOs do TCC + ABE nos compartilhamentos
│       ├── Create-OUs-Users.ps1     # Provisionamento hierárquico em lote de OUs, Grupos e Contas
│       └── users-sample.csv         # Dataset de exemplo com perfis corporativos e educacionais
├── src/
│   └── api-java-ad/                 # Projeto Spring Boot 3 + Java 21 para orquestração LDAP
│       ├── pom.xml                  # Dependências (Data LDAP, Security, Validation, OpenAPI)
│       └── src/
│           ├── main/
│           │   ├── java/com/senai/security/ad/
│           │   │   ├── ApiJavaAdApplication.java
│           │   │   ├── config/       # LdapConfig, SecurityConfig, OpenApiConfig
│           │   │   ├── controller/   # ActiveDirectoryUserController (/api/v1/users)
│           │   │   ├── dto/          # Requests, Responses, Envelopes e Error DTOs
│           │   │   ├── exception/    # GlobalExceptionHandler e exceções negociais
│           │   │   ├── model/        # ActiveDirectoryUser (mapeamento UAC e atributos LDAP)
│           │   │   └── service/      # ActiveDirectoryUserService e implementação
│           │   └── resources/
│           │       ├── application.properties
│           │       └── application.yml
│           └── test/
│               └── java/com/senai/security/ad/controller/ActiveDirectoryUserControllerTest.java
└── README.md
```

---

## 5. Como Executar a Infraestrutura como Código (PowerShell)

### Passo 1: Instalação do Active Directory Domain Services
Execute o script em uma sessão de PowerShell como **Administrador** no Windows Server 2022:

```powershell
Set-ExecutionPolicy RemoteSigned -Scope Process -Force
cd scripts\powershell
.\Install-AD.ps1 -DomainName "corp.senai.local" -NetbiosName "SENAI"
```
*O servidor será promovido a Controlador de Domínio raiz da floresta e reiniciado automaticamente.*

### Passo 2: Provisionamento de Unidades Organizacionais e Usuários em Lote
Após o reinício do servidor:

```powershell
.\Create-OUs-Users.ps1 -CsvPath ".\users-sample.csv" -DomainName "corp.senai.local"
```
*Cria a OU raiz `SenaiCorp`, estrutura as sub-OUs (`Departamentos`, `Educacional`), cria os grupos globais (`GRP_TI`, `GRP_Alunos`...) e importa os usuários com flags de segurança.*

### Passo 3: Aplicação Rigorosa das Diretivas de Grupo (GPOs)
```powershell
.\Apply-SecurityGPOs.ps1 -DomainName "corp.senai.local" -ForceUpdate
```
*Gera as 5 GPOs de segurança, vincula-as ao domínio/OU raiz, cria as pastas departamentais com Access-Based Enumeration (ABE) e força o `gpupdate /force`.*

---

## 6. Como Executar a API de Integração (Java / Spring Boot)

### Pré-requisitos
* **Java 21 LTS** ou superior instalado (`java -version`).
* **Apache Maven 3.9+** instalado (`mvn -version`).
* Conectividade de rede com o servidor Active Directory na porta `389` (LDAP) ou `636` (LDAPS).

### Configuração
Edite o arquivo `src/api-java-ad/src/main/resources/application.properties` ou passe as variáveis de ambiente:

```bash
export LDAP_URL="ldap://192.168.1.10:389"
export LDAP_BASE="dc=corp,dc=senai,dc=local"
export LDAP_USERNAME="cn=Administrator,cn=Users,dc=corp,dc=senai,dc=local"
export LDAP_PASSWORD="SuaSenhaSegura2026!"
```

### Inicialização
```bash
cd src/api-java-ad
mvn clean spring-boot:run
```

Acesse a interface interativa do Swagger UI em:
👉 **`http://localhost:8080/swagger-ui.html`**

---

## 7. Referência dos Endpoints da API REST

Todas as chamadas para `/api/**` requerem autenticação **HTTP Basic** (`admin_api:AdminSecret2026!` por padrão).

### 1. Criar Usuário no Active Directory
* **Método:** `POST`
* **Rota:** `/api/v1/users`
* **Corpo (JSON):**
```json
{
  "samAccountName": "aluno.novo",
  "firstName": "Aluno",
  "lastName": "Teste",
  "email": "aluno.novo@corp.senai.local",
  "department": "Educacional",
  "jobTitle": "Estudante de Seguranca",
  "initialPassword": "S3cur3P@ssw0rd!2026",
  "targetOu": "OU=Alunos,OU=Educacional,OU=SenaiCorp,DC=corp,DC=senai,DC=local",
  "mustChangePasswordOnLogon": false,
  "cannotChangePassword": true
}
```

### 2. Bloquear / Suspender Usuário no AD
* **Método:** `PATCH`
* **Rota:** `/api/v1/users/{username}/status`
* **Corpo (JSON):**
```json
{
  "enabled": false,
  "reason": "Bloqueio preventivo de seguranca por violacao de politicas de rede"
}
```

### 3. Desbloquear Conta Bloqueada (Lockout Reset)
* **Método:** `POST`
* **Rota:** `/api/v1/users/{username}/unlock`

### 4. Consultar Detalhes de um Usuário
* **Método:** `GET`
* **Rota:** `/api/v1/users/{username}`

### 5. Listar Usuários por Departamento
* **Método:** `GET`
* **Rota:** `/api/v1/users?department=TI`

---

## 8. Segurança e Melhores Práticas Aplicadas

1. **Proteção contra LDAP Injection:** As consultas são estritamente sanitizadas e parametrizadas através da API de critérios do `LdapQueryBuilder`.
2. **Manipulação Segura de Credenciais no AD:** Codificação de senhas em padrão nativo `unicodePwd` (UTF-16LE entre aspas duplas) exigido pelo protocolo do Active Directory.
3. **Mapeamento Preciso de Flags UAC:** Controle cirúrgico da máscara de bits `userAccountControl` (`UF_NORMAL_ACCOUNT = 512`, `UF_ACCOUNTDISABLE = 2`).
4. **Idempotência nos Scripts:** Todos os scripts PowerShell realizam checagem prévia de existência de recursos (GPOs, OUs, Grupos e Contas) antes de tentar criá-los.
5. **Auditoria e Logs:** Geração de registros com timestamp em `C:\Logs\` para rastreabilidade de todas as alterações administrativas.

---

## 9. Licença

Este projeto é disponibilizado sob a licença [MIT](LICENSE).
