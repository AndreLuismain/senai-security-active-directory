<#
.SYNOPSIS
    Script de automacao para criacao, configuracao e vinculacao das Diretivas de Grupo (GPOs)
    de alta seguranca no Active Directory.

.DESCRIPTION
    Este script implementa as diretivas de seguranca rigorosas fundamentadas no TCC:
    "Implementacao de Active Directory e politicas de grupo em ambientes corporativos e educacionais".
    
    Ele codifica e automatiza a aplicacao das seguintes 5 politicas essenciais:
    1. Bloqueio de acesso ao Prompt de Comando (CMD / Scripts nao autorizados).
    2. Interrupcao e restricao de downloads de fontes inseguras e arquivos executaveis.
    3. Bloqueio de troca de senha pelos usuarios comuns (centralizacao de credenciais).
    4. Restricao de acesso a dados de outros setores e bloqueio de unidades locais (isolamento departamental com ABE).
    5. Bloqueio total de conexao de dispositivos de armazenamento externo (pendrives/USB nao autorizados).

.PARAMETER DomainName
    Nome de dominio FQDN (Padrao: corp.senai.local).

.PARAMETER TargetOU
    Distinguished Name da Unidade Organizacional alvo (Padrao: OU=SenaiCorp,DC=corp,DC=senai,DC=local).

.PARAMETER DepartmentalSharesPath
    Caminho local no servidor para criar e configurar o repositorio de arquivos departamentais seguros.
    Padrao: C:\Shares\Departamentos.

.PARAMETER ForceUpdate
    Executa 'gpupdate /force' ao termino para forcar a propagacao imediata das politicas.

.EXAMPLE
    .\Apply-SecurityGPOs.ps1 -DomainName "corp.senai.local" -ForceUpdate

.NOTES
    Autor: Andre Luis e equipe de Seguranca & Redes SENAI
    Versao: 1.0.0
    Data: 2026-09-28
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $false, Position = 0)]
    [string]$DomainName = "corp.senai.local",

    [Parameter(Mandatory = $false, Position = 1)]
    [string]$TargetOU = "OU=SenaiCorp,DC=corp,DC=senai,DC=local",

    [Parameter(Mandatory = $false)]
    [string]$DepartmentalSharesPath = "C:\Shares\Departamentos",

    [Parameter(Mandatory = $false)]
    [switch]$ForceUpdate
)

$ErrorActionPreference = "Stop"
$ScriptLogDir = "C:\Logs\GPO-Automation"
$ScriptLogFile = "$ScriptLogDir\Apply-GPOs_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

if (-not (Test-Path -Path $ScriptLogDir)) {
    New-Item -ItemType Directory -Path $ScriptLogDir -Force | Out-Null
}

function Write-Log {
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [Parameter(Mandatory = $false)][ValidateSet("INFO", "WARN", "ERROR", "SUCCESS")][string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    switch ($Level) {
        "INFO"    { Write-Host $logEntry -ForegroundColor Cyan }
        "WARN"    { Write-Host $logEntry -ForegroundColor Yellow }
        "ERROR"   { Write-Host $logEntry -ForegroundColor Red }
        "SUCCESS" { Write-Host $logEntry -ForegroundColor Green }
    }
    
    Add-Content -Path $ScriptLogFile -Value $logEntry -Encoding UTF8
}

Write-Log "=========================================================================="
Write-Log "   APLICACAO AUTOMATIZADA DE GPOs DE SEGURANCA - ACTIVE DIRECTORY        "
Write-Log "   Conforme Diretrizes do TCC SENAI (Corporativo e Educacional)           "
Write-Log "=========================================================================="

# 1. VERIFICACAO DE MODULOS
Write-Log "Verificando modulos GroupPolicy e ActiveDirectory..."
if (-not (Get-Module -ListAvailable -Name GroupPolicy)) {
    Write-Log "Instalando recurso GPMC (Group Policy Management Console)..." "WARN"
    Install-WindowsFeature -Name GPMC -IncludeManagementTools | Out-Null
}
Import-Module GroupPolicy
Import-Module ActiveDirectory

function Get-OrCreateGPO {
    param([string]$GPOName, [string]$Comment = "")
    $existingGpo = Get-GPO -Name $GPOName -Domain $DomainName -ErrorAction SilentlyContinue
    if ($null -eq $existingGpo) {
        Write-Log "Criando nova GPO: '$GPOName'..." "INFO"
        return (New-GPO -Name $GPOName -Comment $Comment -Domain $DomainName)
    } else {
        Write-Log "GPO '$GPOName' ja existe. Atualizando parametros..." "INFO"
        return $existingGpo
    }
}

function Link-GPOToTarget {
    param([string]$GPOName, [string]$TargetScope)
    try {
        $existingLink = Get-GPLink -Target $TargetScope -Domain $DomainName -ErrorAction SilentlyContinue |
                        Where-Object { $_.DisplayName -eq $GPOName }
        if ($null -eq $existingLink) {
            Write-Log "Vinculando GPO '$GPOName' a '$TargetScope'..." "INFO"
            New-GPLink -Name $GPOName -Target $TargetScope -Domain $DomainName -LinkEnabled Yes -Enforced Yes | Out-Null
            Write-Log "GPO '$GPOName' vinculada com sucesso." "SUCCESS"
        }
    } catch {
        Write-Log "Aviso ao vincular GPO '$GPOName': $_" "WARN"
    }
}

# 2. GPO 1: BLOQUEIO DO PROMPT DE COMANDO (CMD)
$gpoCmdName = "GPO-SEC-01-Bloqueio-CMD"
Get-OrCreateGPO -GPOName $gpoCmdName -Comment "GPO TCC: Bloqueia acesso ao prompt de comando e execucao de scripts de lote."
Set-GPRegistryValue -Name $gpoCmdName `
    -Key "HKCU\Software\Policies\Microsoft\Windows\System" `
    -ValueName "DisableCMD" `
    -Type DWord `
    -Value 1 `
    -Domain $DomainName | Out-Null
Write-Log "GPO 1 (Bloqueio CMD - DisableCMD=1) configurada." "SUCCESS"

# 3. GPO 2: RESTRICAO DE DOWNLOADS INSEGUROS E SMARTSCREEN
$gpoDownloadName = "GPO-SEC-02-Restricao-Downloads-Inseguros"
Get-OrCreateGPO -GPOName $gpoDownloadName -Comment "GPO TCC: Bloqueia download de arquivos executaveis e ativa SmartScreen."
Set-GPRegistryValue -Name $gpoDownloadName `
    -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" `
    -ValueName "1803" `
    -Type DWord `
    -Value 3 `
    -Domain $DomainName | Out-Null

Set-GPRegistryValue -Name $gpoDownloadName `
    -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" `
    -ValueName "ScanWithAntiVirus" `
    -Type DWord `
    -Value 3 `
    -Domain $DomainName | Out-Null

Set-GPRegistryValue -Name $gpoDownloadName `
    -Key "HKLM\Software\Policies\Microsoft\Windows\System" `
    -ValueName "EnableSmartScreen" `
    -Type DWord `
    -Value 1 `
    -Domain $DomainName | Out-Null

Set-GPRegistryValue -Name $gpoDownloadName `
    -Key "HKLM\Software\Policies\Microsoft\Windows\System" `
    -ValueName "ShellSmartScreenLevel" `
    -Type String `
    -Value "Block" `
    -Domain $DomainName | Out-Null
Write-Log "GPO 2 (Restricao de Downloads e SmartScreen) configurada." "SUCCESS"

# 4. GPO 3: BLOQUEIO DE TROCA DE SENHA PELOS USUARIOS
$gpoPasswordName = "GPO-SEC-03-Bloqueio-Troca-Senha"
Get-OrCreateGPO -GPOName $gpoPasswordName -Comment "GPO TCC: Desativa e remove 'Alterar Senha' do menu Ctrl+Alt+Del."
Set-GPRegistryValue -Name $gpoPasswordName `
    -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" `
    -ValueName "DisableChangePassword" `
    -Type DWord `
    -Value 1 `
    -Domain $DomainName | Out-Null
Write-Log "GPO 3 (Bloqueio Troca de Senha) configurada." "SUCCESS"

# 5. GPO 4: BLOQUEIO DE DIRETORIOS E ISOLAMENTO DE UNIDADES LOCAIS
$gpoDirectoryName = "GPO-SEC-04-Bloqueio-Diretorios-Isolamento"
Get-OrCreateGPO -GPOName $gpoDirectoryName -Comment "GPO TCC: Oculta e restringe acesso a disco C: e unidades nao homologadas."
Set-GPRegistryValue -Name $gpoDirectoryName `
    -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
    -ValueName "NoViewOnDrive" `
    -Type DWord `
    -Value 4 `
    -Domain $DomainName | Out-Null

Set-GPRegistryValue -Name $gpoDirectoryName `
    -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
    -ValueName "NoDrives" `
    -Type DWord `
    -Value 4 `
    -Domain $DomainName | Out-Null
Write-Log "GPO 4 (Restricao de Unidades Locais no Windows Explorer) configurada." "SUCCESS"

# 6. GPO 5: BLOQUEIO DE DISPOSITIVOS EXTERNOS (USB REMOVABLE STORAGE)
$gpoUsbName = "GPO-SEC-05-Bloqueio-Dispositivos-Externos"
Get-OrCreateGPO -GPOName $gpoUsbName -Comment "GPO TCC: Bloqueia totalmente pendrives e armazenamento USB."
Set-GPRegistryValue -Name $gpoUsbName `
    -Key "HKLM\Software\Policies\Microsoft\Windows\RemovableStorageDevices" `
    -ValueName "Deny_All" `
    -Type DWord `
    -Value 1 `
    -Domain $DomainName | Out-Null

Set-GPRegistryValue -Name $gpoUsbName `
    -Key "HKCU\Software\Policies\Microsoft\Windows\RemovableStorageDevices" `
    -ValueName "Deny_All" `
    -Type DWord `
    -Value 1 `
    -Domain $DomainName | Out-Null
Write-Log "GPO 5 (Bloqueio USB Removivel Deny_All) configurada." "SUCCESS"

# 7. VINCULACAO DAS GPOS
$allGpos = @($gpoCmdName, $gpoDownloadName, $gpoPasswordName, $gpoDirectoryName, $gpoUsbName)
$targetContainer = $TargetOU
if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$TargetOU'" -ErrorAction SilentlyContinue)) {
    $targetContainer = (Get-ADDomain -Identity $DomainName).DistinguishedName
}

foreach ($gpo in $allGpos) {
    Link-GPOToTarget -GPOName $gpo -TargetScope $targetContainer
}

# 8. COMPARTILHAMENTO DE DIRETORIOS COM ACCESS-BASED ENUMERATION (ABE)
Write-Log "Provisionando armazenamento seguro com Access-Based Enumeration (ABE)..."
$departments = @("Administracao", "Financeiro", "RecursosHumanos", "TI", "Educacional-Professores", "Educacional-Alunos")

if (-not (Test-Path -Path $DepartmentalSharesPath)) {
    New-Item -ItemType Directory -Path $DepartmentalSharesPath -Force | Out-Null
}

$shareName = "Departamentos$"
if (-not (Get-SmbShare -Name $shareName -ErrorAction SilentlyContinue)) {
    New-SmbShare -Name $shareName `
        -Path $DepartmentalSharesPath `
        -FullAccess "Administrators", "Domain Admins" `
        -ChangeAccess "Authenticated Users" `
        -FolderEnumerationMode AccessBased `
        -Description "Compartilhamento Corporativo com Isolamento ABE" | Out-Null
    Write-Log "Compartilhamento SMB Departamentos$ criado com ABE ativado." "SUCCESS"
}

foreach ($dept in $departments) {
    $deptPath = Join-Path -Path $DepartmentalSharesPath -ChildPath $dept
    if (-not (Test-Path -Path $deptPath)) {
        New-Item -ItemType Directory -Path $deptPath -Force | Out-Null
    }

    $acl = Get-Acl -Path $deptPath
    $acl.SetAccessRuleProtection($true, $false)
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")))
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")))

    $groupName = "GRP_$dept"
    if (Get-ADGroup -Filter "SamAccountName -eq '$groupName'" -ErrorAction SilentlyContinue) {
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("$DomainName\$groupName", "Modify", "ContainerInherit,ObjectInherit", "None", "Allow")))
    }
    Set-Acl -Path $deptPath -AclObject $acl
}

if ($ForceUpdate) {
    Write-Log "Executando gpupdate /force..." "INFO"
    Start-Process -FilePath "gpupdate.exe" -ArgumentList "/force" -Wait -NoNewWindow
    Write-Log "gpupdate executado com sucesso." "SUCCESS"
}

Write-Log "Todas as 5 GPOs de seguranca foram configuradas e aplicadas!" "SUCCESS"
