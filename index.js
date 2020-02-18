const core = require('@actions/core')
const AWS = require('aws-sdk')

const getFindings = async (ECR, repository, tag) => {
  // XXX: We catch all errors and assume they are "no scan results"... but there
  // could be many reasons for the API call to fail. The catch logic should be
  // more discriminating in what it swallows.
  return ECR.describeImageScanFindings({
    imageId: {
      imageTag: tag
    },
    repositoryName: repository
  }).promise().catch(() => null)
}

const main = async () => {
  core.debug('Entering main')
  const repository = core.getInput('repository', { required: true })
  const tag = core.getInput('tag', { required: true })
  const failThreshold = core.getInput('fail_threshold')
  if (
    failThreshold !== 'critical' &&
    failThreshold !== 'high' &&
    failThreshold !== 'medium' &&
    failThreshold !== '' && // default -- equivalent to medium
    failThreshold !== 'low' &&
    failThreshold !== 'informational'
  ) {
    throw new Error('failThreshold input value is invalid')
  }
  core.debug(`Repository:${repository}, Tag:${tag}`)
  const ECR = new AWS.ECR()

  let findings
  let status = 'IN_PROGRESS'

  core.debug('Checking for existing findings')
  findings = await getFindings(ECR, repository, tag)
  if (findings === null) {
    console.log('Requesting image scan')
    await ECR.startImageScan({
      imageId: {
        imageTag: tag
      },
      repositoryName: repository
    }).promise()
    core.debug('Requested image scan')

    let n = 0
    while (status === 'IN_PROGRESS') {
      if (n > 0) {
        await new Promise((resolve) => {
          setTimeout(resolve, 5000)
        })
      }
      console.log('Polling ECR for image scan findings...')
      findings = await getFindings(ECR, repository, tag)
      status = findings.imageScanStatus.status
      core.debug(`Scan status: ${status}`)
      n++
    }
  }

  const counts = findings.imageScanFindings.findingSeverityCounts
  const critical = counts.CRITICAL || 0
  const high = counts.HIGH || 0
  const medium = counts.MEDIUM || 0
  const low = counts.LOW || 0
  const informational = counts.INFORMATIONAL || 0
  const unknown = counts.UNKNOWN || 0
  const total = critical + high + medium + low + informational + unknown
  core.setOutput('critical', critical.toString())
  core.setOutput('high', high.toString())
  core.setOutput('medium', medium.toString())
  core.setOutput('low', low.toString())
  core.setOutput('informational', informational.toString())
  core.setOutput('unknown', unknown.toString())
  core.setOutput('total', total.toString())

  if (
    (failThreshold === 'informational' && total > 0) ||
    (failThreshold === 'low' && critical + high + medium + low > 0) ||
    ((failThreshold === 'medium' || failThreshold === '') && critical + high + medium > 0) ||
    (failThreshold === 'high' && critical + high > 0) ||
    (failThreshold === 'critical' && critical > 0)
  ) {
    throw new Error(`Detected vulnerabilities with severity equal to or greater than the fail_threshold ${failThreshold}. Informational: ${informational} Low: ${low} Medium: ${medium} High: ${high} Critical: ${critical}`)
  }
  console.log()
}

(async function () {
  try {
    await main()
  } catch (error) {
    core.setFailed(error.message)
  }
}())
