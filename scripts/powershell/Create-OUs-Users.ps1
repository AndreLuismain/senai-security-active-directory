<#
.SYNOPSIS
    Script de automacao para provisionamento em lote da estrutura de Unidades Organizacionais (OUs),
    Grupos de Seguranca e Usuarios no Active Directory a partir de arquivo CSV.

.DESCRIPTION
    Este script compoe o pipeline de Infraestrutura como Codigo (IaC) do projeto TCC SENAI:
    "Implementacao de Active Directory e politicas de grupo em ambientes corporativos e educacionais".

.PARAMETER CsvPath
    Caminho para o arquivo CSV contendo os dados dos usuarios (Padrao: .\users-sample.csv).

.PARAMETER DomainName
    Nome de dominio FQDN (Padrao: corp.senai.local).

.PARAMETER RootOUName
    Nome da Unidade Organizacional raiz do projeto (Padrao: SenaiCorp).

.EXAMPLE
    .\Create-OUs-Users.ps1 -CsvPath ".\users-sample.csv" -DomainName "corp.senai.local"

.NOTES
    Autor: Andre Luis e equipe de Seguranca & Redes SENAI
    Versao: 1.0.0
    Data: 2026-09-28
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $false, Position = 0)]
    [string]$CsvPath = "$PSScriptRoot\users-sample.csv",

    [Parameter(Mandatory = $false, Position = 1)]
    [string]$DomainName = "corp.senai.local",

    [Parameter(Mandatory = $false)]
    [string]$RootOUName = "SenaiCorp"
)

$ErrorActionPreference = "Stop"
$ScriptLogDir = "C:\Logs\User-Provisioning"
$ScriptLogFile = "$ScriptLogDir\Create-OUs-Users_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

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

Write-Log "Iniciando provisionamento hierarquico de OUs, grupos e usuarios..."
Import-Module ActiveDirectory

$domainObj = Get-ADDomain -Identity $DomainName
$domainDN = $domainObj.DistinguishedName
$rootOUDN = "OU=$RootOUName,$domainDN"

function Ensure-ADOU {
    param([string]$OUName, [string]$ParentDN)
    $fullDN = "OU=$OUName,$ParentDN"
    $ouExists = Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$fullDN'" -ErrorAction SilentlyContinue
    if (-not $ouExists) {
        Write-Log "Criando OU: '$fullDN'..." "INFO"
        New-ADOrganizationalUnit -Name $OUName -Path $ParentDN -ProtectedFromAccidentalDeletion $true | Out-Null
        Write-Log "OU '$fullDN' criada com sucesso." "SUCCESS"
    }
    return $fullDN
}

# Criar OU raiz e sub-OUs
Ensure-ADOU -OUName $RootOUName -ParentDN $domainDN | Out-Null

$subOUs = @(
    "Departamentos",
    "Departamentos\TI",
    "Departamentos\Financeiro",
    "Departamentos\RecursosHumanos",
    "Departamentos\Administracao",
    "Educacional",
    "Educacional\Professores",
    "Educacional\Alunos",
    "Computadores",
    "Grupos"
)

foreach ($relPath in $subOUs) {
    $segments = $relPath -split '\\'
    $currentParent = $rootOUDN
    foreach ($seg in $segments) {
        $currentParent = Ensure-ADOU -OUName $seg -ParentDN $currentParent
    }
}

# Criar Grupos Globais de Seguranca
$groupsOUDN = "OU=Grupos,$rootOUDN"
$securityGroups = @(
    @{ Name = "GRP_TI"; Description = "Acesso aos recursos de TI" },
    @{ Name = "GRP_Financeiro"; Description = "Acesso ao setor Financeiro" },
    @{ Name = "GRP_RecursosHumanos"; Description = "Acesso ao setor de RH" },
    @{ Name = "GRP_Administracao"; Description = "Acesso a Administracao" },
    @{ Name = "GRP_Educacional-Professores"; Description = "Acesso de Docentes" },
    @{ Name = "GRP_Educacional-Alunos"; Description = "Acesso de Alunos" }
)

foreach ($grp in $securityGroups) {
    $grpName = $grp.Name
    if (-not (Get-ADGroup -Filter "SamAccountName -eq '$grpName'" -ErrorAction SilentlyContinue)) {
        New-ADGroup -Name $grpName -GroupScope Global -GroupCategory Security -Path $groupsOUDN -Description $grp.Description | Out-Null
        Write-Log "Grupo '$grpName' criado." "SUCCESS"
    }
}

# Importar usuarios do CSV
Write-Log "Importando registros do CSV: $CsvPath..."
$usersData = Import-Csv -Path $CsvPath -Encoding UTF8

foreach ($row in $usersData) {
    $sam = $row.SamAccountName.Trim()
    $displayName = "$($row.FirstName.Trim()) $($row.LastName.Trim())"
    $upn = $row.UserPrincipalName.Trim()
    $groupName = $row.GroupName.Trim()
    
    $ouRelPath = $row.OU.Trim().Replace('/', '\')
    $ouSegments = $ouRelPath -split '\\'
    $targetOUPath = ""
    for ($i = $ouSegments.Count - 1; $i -ge 0; $i--) {
        $targetOUPath += "OU=$($ouSegments[$i]),"
    }
    $targetOUDN = "$targetOUPath$rootOUDN"

    if (Get-ADUser -Filter "SamAccountName -eq '$sam'" -ErrorAction SilentlyContinue) {
        Write-Log "Usuario '$sam' ja existe. Ignorando." "WARN"
        continue
    }

    try {
        $securePwd = ConvertTo-SecureString $row.InitialPassword.Trim() -AsPlainText -Force
        New-ADUser -Name $displayName `
                   -GivenName $row.FirstName.Trim() `
                   -Surname $row.LastName.Trim() `
                   -DisplayName $displayName `
                   -SamAccountName $sam `
                   -UserPrincipalName $upn `
                   -EmailAddress $row.Email.Trim() `
                   -Department $row.Department.Trim() `
                   -Title $row.JobTitle.Trim() `
                   -Path $targetOUDN `
                   -AccountPassword $securePwd `
                   -Enabled $true `
                   -ChangePasswordAtLogon ([System.Convert]::ToBoolean($row.MustChangePassword)) `
                   -CannotChangePassword ([System.Convert]::ToBoolean($row.CannotChangePassword)) | Out-Null

        Write-Log "Usuario '$sam' criado com sucesso na OU '$targetOUDN'." "SUCCESS"

        if ($groupName -and (Get-ADGroup -Filter "SamAccountName -eq '$groupName'" -ErrorAction SilentlyContinue)) {
            Add-ADGroupMember -Identity $groupName -Members $sam | Out-Null
            Write-Log "Usuario '$sam' adicionado ao grupo '$groupName'." "SUCCESS"
        }
    } catch {
        Write-Log "Erro ao criar usuario '$sam': $_" "ERROR"
    }
}
Write-Log "Provisionamento em lote concluido com sucesso!" "SUCCESS"
