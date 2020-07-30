const core = require('@actions/core')
const AWS = require('aws-sdk')

const getFindings = async (ECR, repository, tag) => {
  return ECR.describeImageScanFindings({
    imageId: {
      imageTag: tag
    },
    repositoryName: repository
  }).promise().catch(
    (err) => {
      if (err.code === 'ScanNotFoundException') { return null }
      throw err
    })
}

const main = async () => {
  core.debug('Entering main')
  const repository = core.getInput('repository', { required: true })
  const tag = core.getInput('tag', { required: true })
  const failThreshold = core.getInput('fail_threshold') || 'high'
  if (
    failThreshold !== 'critical' &&
    failThreshold !== 'high' &&
    failThreshold !== 'medium' &&
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
  const undefined = counts.UNDEFINED || 0
  const total = critical + high + medium + low + informational + undefined
  core.setOutput('critical', critical.toString())
  core.setOutput('high', high.toString())
  core.setOutput('medium', medium.toString())
  core.setOutput('low', low.toString())
  core.setOutput('informational', informational.toString())
  core.setOutput('undefined', undefined.toString())
  core.setOutput('total', total.toString())
  console.log('Vulnerabilities found:')
  console.log(`${critical.toString().padStart(3, ' ')} Critical`)
  console.log(`${high.toString().padStart(3, ' ')} High`)
  console.log(`${medium.toString().padStart(3, ' ')} Medium`)
  console.log(`${low.toString().padStart(3, ' ')} Low`)
  console.log(`${informational.toString().padStart(3, ' ')} Informational`)
  console.log(`${undefined.toString().padStart(3, ' ')} Undefined`)
  console.log('=================')
  console.log(`${total.toString().padStart(3, ' ')} Total`)

  const numFailingVulns =
    failThreshold === 'informational' ? total
      : failThreshold === 'low' ? critical + high + medium + low
        : failThreshold === 'medium' ? critical + high + medium
          : failThreshold === 'high' ? critical + high
            : /* failThreshold === 'critical' ? */ critical

  if (numFailingVulns > 0) {
    throw new Error(`Detected ${numFailingVulns} vulnerabilities with severity >= ${failThreshold} (the currently configured fail_threshold).`)
  }
}

(async function () {
  try {
    await main()
  } catch (error) {
    core.setFailed(error.message)
  }
}())
