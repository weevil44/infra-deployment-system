<#
.DESCRIPTION
Reads the incoming git commit delta and builds the lists of resources that will be deployed

Pass in a comma separated list of environment folder names which will be stored in standard and restricted lists
to allow for some deployments to follow tighter approval standards

This is to allow for a generic an largely pipeline controlled translation.

.PARAMETER WorkingDirectory
Allow you to provide an explicit working directory and override the default
This is not typically necessary

.OUTPUTS
named pipeline variables for each of the list types provided
#>

# use the environment variable if a working directory is not passed in
[CmdletBinding()]
param(
    [string]$WorkingDirectory = $env:SYSTEM_DEFAULTWORKINGDIRECTORY
)

# import the local modules
Import-Module (Get-ChildItem -Recurse "$WorkingDirectory\pipeline\modules" | Where-Object { ($_.Name -like "*.psm1") } | Select-Object FullName).FullName

if ( $WorkingDirectory -ne "" ) {
  Write-LoggerIDS -type "info" -message "Writing explicit working directory provided"
  Write-LoggerIDS -type "info" -message "$workingDirectory"
  Set-Location $WorkingDirectory
}

# this would put it into a comma separated string
$changedFiles = @( git diff HEAD HEAD~ --name-only )

$deploymentLists = @{}
$deploymentListNames = @("standard", "restricted")
ForEach( $deploymentListName in $deploymentListNames ) {
  # build an array of objects to hold the lists
  $deploymentLists[$deploymentListName] = [PSCustomObject]@{
    DeploymentType = "$deploymentListName"
    ParameterFiles = @()
  }
}

ForEach ( $changedFile in $changedFiles ) {

    if ( -not $changedFile.EndsWith(".json")) {
        # skip any files that are not json files 
        Write-LoggerIDS -type "info" -message "Skipping [$($changedFile)]"
        continue
    }

    if ( $changedFile.StartsWith("templates/")) {
        # skip any templates, the parameter file should be modified to deploy a template change 
        # if we allowed this, it would need parse each file for the template reference that matches the file 
        Write-LoggerIDS -type "info" -message "Skipping [$($changedFile)]"
        Write-LoggerIDS -type "info" -message "To redeploy a template change, modify the parameter file"
        continue
    }

    if ( -not (Test-Path -Path $workingDirectory/$changedFile -PathType leaf)) {
      # will have to handle these later to enable deletions
      Write-LoggerIDS -type "info" -message Write-Host "Skipping deleted file [$($changedFile)]"
      Write-LoggerIDS -type "info" -message "Deletions are not supported"
      continue
    }

    $parameterObject = Get-Content -Raw $WorkingDirectory/$changedFile | ConvertFrom-Json
    $templateFile = $parameterObject.deploymentParameters.templateFile
    $deploymentType = $deploymentListNames[0] 
    # force deployments using custom templates to be deployed separately for security purposes
    $restrictedDeploymentType = "my-restricted-type"   # change this to the name of your restricted deployment type 
    if (($changedFile.Contains($restrictedDeploymentType)) -Or $templateFile.StartsWith(".\$deploymentListNames[0]\")) {
      $deploymentType = $deploymentListNames[1] 
    } else {
      $deploymentType = $deploymentListNames[0] 
    }
    Write-LoggerIDS -type "info" -message "Adding [$($changedFile)] to $deploymentType deployment list"
    $deploymentLists[$deploymentType].ParameterFiles += $changedFile
}

# convert the list to pipeline variables so they can be used in later stages
ForEach( $deploymentListName in $deploymentListNames ) {
  $transportList = ""
  if ($deploymentListName -eq $deploymentListNames[1]) {
    # we need to set variables used in other stages as outputs so they can be referenced there
    $isOutput = ";isOutput=true"
  } else {
    $isOutput = ""
  }

  $deploymentList = $deploymentLists[$deploymentListName]
  if ( $deploymentList.ParameterFiles.Count -gt 0 ) {
    $listChanged = "true"
    $changeMessage = "Registered"
  } else {
    $listChanged = "false"
    $changeMessage = "No"
  }
  Write-Output "##vso[task.setvariable variable=$($depoymentListName)Changed$isOutput]$listChanged"
  Write-LoggerIDS -type "info" -message "$changeMessage changes for $deploymentListName environment"

  # convert the object to a string so it can be passed to the other pipeline tasks
  $transportList = ConvertTo-TransportStringIDS -transportObj $deploymentList
  if ($deploymentListName -eq 'standard') {
    $env:standardDeploymentList = $transportList  # for local testing
  }
  Write-Output "##vso[task.setvariable variable=$($deploymentListName)DeploymentList$isOutput]${transportList}"
}
