<#
.SYNOPSIS
    Script de automacao para provisionamento e promocao do Active Directory Domain Services (AD DS)
    no Windows Server 2022.

.DESCRIPTION
    Este script faz parte do projeto de Infraestrutura como Codigo (IaC) fundamentado no TCC:
    "Implementacao de Active Directory e politicas de grupo em ambientes corporativos e educacionais".
    
    Ele valida os pre-requisitos de hardware e permissoes de sistema recomendados pela Microsoft e
    especificados na pesquisa academica, instala os recursos de AD DS, DNS e Ferramentas de
    Gerenciamento Remoto de Servidor (RSAT/GPMC), e promove a maquina a Controlador de Dominio (DC)
    raiz de uma nova floresta.

.PARAMETER DomainName
    Nome FQDN da nova floresta do Active Directory (Exemplo: corp.senai.local).

.PARAMETER NetbiosName
    Nome NetBIOS para o dominio (Exemplo: SENAI).

.PARAMETER DSRMPassword
    Senha segura para o Modo de Restauracao dos Servicos de Diretorio (DSRM).
    Se nao fornecida, o script solicitara de forma interativa e mascarada.

.PARAMETER ForestMode
    Nivel funcional da floresta (Padrao: WinThreshold - compativel com Windows Server 2016/2019/2022).

.PARAMETER DomainMode
    Nivel funcional do dominio (Padrao: WinThreshold).

.PARAMETER DatabasePath
    Caminho para a base de dados do Active Directory (Padrao: C:\Windows\NTDS).

.PARAMETER SysvolPath
    Caminho para a pasta SYSVOL (Padrao: C:\Windows\SYSVOL).

.PARAMETER LogPath
    Caminho para os logs de transacao do NTDS (Padrao: C:\Windows\NTDS).

.PARAMETER SkipHardwareCheck
    Ignora a verificacao rigorosa de requisitos minimos de hardware (util para ambientes de laboratorio/VMs).

.PARAMETER NoReboot
    Evita a reinicializacao automatica apos a conclusao da instalacao.

.EXAMPLE
    .\Install-AD.ps1 -DomainName "corp.senai.local" -NetbiosName "SENAI"

.NOTES
    Autor: Andre Luis e equipe de Seguranca & Redes SENAI
    Versao: 1.0.0
    Data: 2026-09-28
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $false, Position = 0, HelpMessage = "Nome de dominio totalmente qualificado (FQDN).")]
    [ValidatePattern('^([a-zA-Z0-9]+(-[a-zA-Z0-9]+)*\.)+[a-zA-Z]{2,}$')]
    [string]$DomainName = "corp.senai.local",

    [Parameter(Mandatory = $false, Position = 1, HelpMessage = "Nome NetBIOS do dominio (max. 15 caracteres).")]
    [ValidateLength(1, 15)]
    [string]$NetbiosName = "SENAI",

    [Parameter(Mandatory = $false, HelpMessage = "Senha para o DSRM em formato SecureString.")]
    [System.Security.SecureString]$DSRMPassword,

    [Parameter(Mandatory = $false)]
    [ValidateSet("WinThreshold", "WindowsServer2016")]
    [string]$ForestMode = "WinThreshold",

    [Parameter(Mandatory = $false)]
    [ValidateSet("WinThreshold", "WindowsServer2016")]
    [string]$DomainMode = "WinThreshold",

    [Parameter(Mandatory = $false)]
    [string]$DatabasePath = "C:\Windows\NTDS",

    [Parameter(Mandatory = $false)]
    [string]$SysvolPath = "C:\Windows\SYSVOL",

    [Parameter(Mandatory = $false)]
    [string]$LogPath = "C:\Windows\NTDS",

    [Parameter(Mandatory = $false)]
    [switch]$SkipHardwareCheck,

    [Parameter(Mandatory = $false)]
    [switch]$NoReboot
)

$ErrorActionPreference = "Stop"
$ScriptLogDir = "C:\Logs\AD-Installation"
$ScriptLogFile = "$ScriptLogDir\Install-AD_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

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
Write-Log "   INICIANDO AUTOMACAO DE INSTALACAO DO ACTIVE DIRECTORY - WINDOWS SERVER   "
Write-Log "   Projeto: Senai Security - Infraestrutura como Codigo (IaC)             "
Write-Log "=========================================================================="
Write-Log "Arquivo de log: $ScriptLogFile"

# 1. VERIFICACAO DE PRIVILEGIOS ADMINISTRATIVOS
Write-Log "Validando privilegios administrativos de execucao..."
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Log "ERRO CRITICO: Este script deve ser executado em uma sessao com privilegios de Administrador elevado." "ERROR"
    throw "Acesso negado. Execute o PowerShell como Administrador."
}
Write-Log "Privilegios de Administrador confirmados." "SUCCESS"

# 2. VERIFICACAO DE REQUISITOS DE HARDWARE E SISTEMA (Conforme TCC)
if (-not $SkipHardwareCheck) {
    Write-Log "Verificando requisitos minimos de hardware e sistema operacional..."
    
    $cpu = Get-CimInstance -ClassName Win32_Processor | Select-Object -First 1
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    
    Write-Log "CPU: $($cpu.Name) | Arquitetura: $($cpu.AddressWidth) bits | Clock Base: $($cpu.MaxClockSpeed) MHz"
    if ($cpu.AddressWidth -ne 64) {
        Write-Log "Processador nao e de 64 bits. Windows Server 2022 requer arquitetura x64." "ERROR"
        throw "Incompatibilidade de arquitetura de hardware."
    }
    
    $totalRamGB = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
    Write-Log "Memoria RAM Total Detectada: $totalRamGB GB"
    if ($totalRamGB -lt 3.5) {
        Write-Log "Memoria RAM abaixo do recomendado pela pesquisa ($totalRamGB GB < 4 GB). Prossiga com atencao." "WARN"
    }
    
    $systemDrive = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DeviceID -eq $env:SystemDrive }
    $freeSpaceGB = [math]::Round($systemDrive.FreeSpace / 1GB, 2)
    Write-Log "Espaco Livre no Disco do Sistema ($env:SystemDrive): $freeSpaceGB GB"
    if ($freeSpaceGB -lt 20) {
        Write-Log "Espaco em disco insuficiente para instalacao segura do AD DS ($freeSpaceGB GB livres)." "ERROR"
        throw "Espaco em disco insuficiente."
    }
    
    $activeNics = Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -ne $null -and $_.NetAdapter.Status -eq "Up" }
    if ($activeNics) {
        foreach ($nic in $activeNics) {
            $isDhcp = (Get-NetIPAddress -InterfaceIndex $nic.InterfaceIndex -AddressFamily IPv4).PrefixOrigin -eq "Dhcp"
            if ($isDhcp) {
                Write-Log "ATENCAO: A interface '$($nic.InterfaceAlias)' esta configurada para obter IP via DHCP." "WARN"
                Write-Log "Recomenda-se enfaticamente configurar um endereco IPv4 ESTATICO antes de promover a DC." "WARN"
            } else {
                Write-Log "Interface '$($nic.InterfaceAlias)' possui IP Estatico: $($nic.IPv4Address.IPAddress)." "SUCCESS"
            }
        }
    }
}

# 3. VERIFICACAO SE O SERVIDOR JA E DOMAIN CONTROLLER
$domainRole = (Get-CimInstance -ClassName Win32_ComputerSystem).DomainRole
if ($domainRole -ge 4) {
    Write-Log "Este servidor ja e um Controlador de Dominio. Nenhuma acao de promocao necessaria." "INFO"
    return
}

# 4. INSTALACAO DOS RECURSOS DO WINDOWS
Write-Log "Instalando recursos necessarios (AD-Domain-Services, DNS, GPMC, RSAT)..."
$requiredFeatures = @(
    "AD-Domain-Services",
    "DNS",
    "GPMC",
    "RSAT-AD-Tools",
    "RSAT-ADDS",
    "RSAT-ADDS-Tools",
    "RSAT-AD-AdminCenter"
)

foreach ($feature in $requiredFeatures) {
    $check = Get-WindowsFeature -Name $feature
    if (-not $check.Installed) {
        Write-Log "Instalando recurso: $feature..."
        Install-WindowsFeature -Name $feature -IncludeManagementTools | Out-Null
        Write-Log "Recurso $feature instalado." "SUCCESS"
    } else {
        Write-Log "Recurso $feature ja instalado." "INFO"
    }
}

# 5. PREPARACAO DA SENHA DSRM
if (-not $DSRMPassword) {
    Write-Log "Solicitando senha para Modo de Restauracao (DSRM)..." "INFO"
    $DSRMPassword = Read-Host -Prompt "Informe a Senha DSRM:" -AsSecureString
}

# 6. PROMOCAO DO ACTIVE DIRECTORY
Write-Log "Promovendo servidor a DC Raiz da Floresta '$DomainName'..."
$installParams = @{
    DomainName                    = $DomainName
    DomainNetbiosName             = $NetbiosName
    ForestMode                    = $ForestMode
    DomainMode                    = $DomainMode
    DatabasePath                  = $DatabasePath
    LogPath                       = $LogPath
    SysvolPath                    = $SysvolPath
    InstallDns                    = $true
    CreateDnsDelegation           = $false
    SafeModeAdministratorPassword = $DSRMPassword
    Force                         = $true
    NoRebootOnCompletion          = $NoReboot
}

if ($PSCmdlet.ShouldProcess($DomainName, "Promover servidor a DC Raiz")) {
    Import-Module ADDSDeployment
    Install-ADDSForest @installParams
    Write-Log "Promocao concluida com sucesso!" "SUCCESS"
}
