# this is the module that stores test executed during every deployment
# tests for a specifie service are found under services
function Test-CustomTemplateIDS {
  Param(
    [Parameter(Mandatory = $true)][PSCustomObject]$parameterObj	
  )

  $templateFile = $parameterObj.deploymentParameters.templateFile
  if ($templateFile.StartsWith('.\')) {
    $isCustom = $false
  } else {
    $isCustom = $true
  }

  return $isCustom
}

function Test-DeploymentIDS {
  Param(
    [Parameter(Mandatory = $true)][string]$deploymentType,
    [Parameter(Mandatory = $true)][PSCustomObject]$parameterObj	
  )

  Write-Host "deploymentType: $deploymentType"
  Write-Host "parameterObj"
  $parameterObj
}