const core = require('@actions/core')
const AWS = require('aws-sdk')

/**
 * @typedef {{
 *  critical: number,
 *  high: number,
 *  medium: number,
 *  low: number,
 *  informational: number,
 *  undefined: number,
 *  total: number }} IgnoredCounts
 *
 * @typedef {{ severity: string }} ImageScanFinding https://docs.aws.amazon.com/AmazonECR/latest/APIReference/API_ImageScanFinding.html
 */

const getFindings = async (ECR, repository, tag, useMaxResults = false) => {
  return ECR.describeImageScanFindings({
    imageId: {
      imageTag: tag
    },
    maxResults: useMaxResults ? 1000 : undefined, // Valid range: 1-1000, default: 100
    repositoryName: repository
  }).promise().catch(
    (err) => {
      if (err.code === 'ScanNotFoundException') { return null }
      throw err
    })
}

/**
 * Tally findings by severity.
 * @param {ImageScanFinding[]} ignoredFindings
 * @returns {IgnoredCounts} counts
 */
const countIgnoredFindings = (ignoredFindings) =>
  ignoredFindings.reduce(
    (counts, finding) => {
      const updatedCount = { ...counts }
      updatedCount[finding.severity] = counts[finding.severity] + 1
      updatedCount.total++
      return updatedCount
    },
    { critical: 0, high: 0, medium: 0, low: 0, informational: 0, undefined: 0, total: 0 }
  )

/**
 * Returns display text for a severity level.
 * @param {string} severity
 * @param {IgnoredCounts} counts
 * @returns {string}
 */
const getCount = (severity, counts) =>
  counts[severity] ? `(${counts[severity]} ignored)` : ''

/**
 * Build an array with CVE IDs to ignore in the counts.
 * @param {string | string[]} list - Comma separated list or array of CVE IDs.
 * @returns {string[]} Array of CVE IDs
 */
const parseIgnoreList = (list) => {
  if (Array.isArray(list)) return list
  if (!list) return []
  return list.split(',').map((d) => d.trim())
}

const main = async () => {
  core.debug('Entering main')
  const repository = core.getInput('repository', { required: true })
  const tag = core.getInput('tag', { required: true })
  const failThreshold = core.getInput('fail_threshold') || 'high'
  const ignoreList = parseIgnoreList(core.getInput('ignore_list'))

  if (
    failThreshold !== 'critical' &&
    failThreshold !== 'high' &&
    failThreshold !== 'medium' &&
    failThreshold !== 'low' &&
    failThreshold !== 'informational'
  ) {
    throw new Error('fail_threshold input value is invalid')
  }
  core.debug(`Repository:${repository}, Tag:${tag}, Ignore list:${ignoreList}`)
  const ECR = new AWS.ECR()

  core.debug('Checking for existing findings')
  let status = null
  let findings = await getFindings(ECR, repository, tag, !!ignoreList.length)
  if (findings) {
    status = findings.imageScanStatus.status
    console.log(`A scan for this image was already requested, the scan's status is ${status}`)
    if (status == 'FAILED') {
      throw new Error(`Image scan failed: ${findings.imageScanStatus.description}`)
    }
  } else {
    console.log('Requesting image scan')
    await ECR.startImageScan({
      imageId: {
        imageTag: tag
      },
      repositoryName: repository
    }).promise()
    status = 'IN_PROGRESS'
  }

  let firstPoll = true
  while (status === 'IN_PROGRESS') {
    if (!firstPoll) {
      await new Promise((resolve) => {
        setTimeout(resolve, 5000)
      })
    }
    console.log('Polling ECR for image scan findings...')
    findings = await getFindings(ECR, repository, tag)
    status = findings.imageScanStatus.status
    core.debug(`Scan status: ${status}`)
    firstPoll = false
  }

  // Sanity check
  if (status !== 'COMPLETE') {
    throw new Error(`Unhandled scan status "${status}". API response: ${JSON.stringify(findings)}`)
  }

  const findingsList = findings.imageScanFindings.findings
  const ignoredFindings = findingsList.filter(({ name }) =>
    ignoreList.includes(name)
  )

  if (ignoreList.length !== ignoredFindings.length) {
    throw new Error(`Ignore list contains CVE IDs that were not returned in the findings result set. They may be invalid or no longer be current vulnerabilities.`)
  }

  const ignoredCounts = countIgnoredFindings(ignoredFindings)
  const counts = findings.imageScanFindings.findingSeverityCounts
  const critical = counts.CRITICAL || 0
  const high = counts.HIGH || 0
  const medium = counts.MEDIUM || 0
  const low = counts.LOW || 0
  const informational = counts.INFORMATIONAL || 0
  const indeterminate = counts.UNDEFINED || 0
  const ignored = ignoreList.length
  const total = critical + high + medium + low + informational + indeterminate
  core.setOutput('critical', critical.toString())
  core.setOutput('high', high.toString())
  core.setOutput('medium', medium.toString())
  core.setOutput('low', low.toString())
  core.setOutput('informational', informational.toString())
  core.setOutput('undefined', indeterminate.toString())
  core.setOutput('ignored', ignored.toString())
  core.setOutput('total', total.toString())
  console.log('Vulnerabilities found:')
  console.log(`${critical.toString().padStart(3, ' ')} Critical ${getCount(  'CRITICAL',  ignoredCounts)}`)
  console.log(`${high.toString().padStart(3, ' ')} High ${getCount(  'HIGH',  ignoredCounts)}`)
  console.log(`${medium.toString().padStart(3, ' ')} Medium ${getCount(  'MEDIUM',  ignoredCounts)}`)
  console.log(`${low.toString().padStart(3, ' ')} Low ${getCount('LOW', ignoredCounts)}`)
  console.log(`${informational.toString().padStart(3, ' ')} Informational ${getCount(  'INFORMATIONAL',  ignoredCounts)}`)
  console.log(`${indeterminate.toString().padStart(3, ' ')} Undefined`)
  console.log('=================')
  console.log(`${total.toString().padStart(3, ' ')} Total ${getCount(  'TOTAL',  ignoredCounts)}`)

  const numFailingVulns =
    failThreshold === 'informational' ? total - ignoredCounts.INFORMATIONAL
      : failThreshold === 'low' ? critical + high + medium + low - ignoredCounts.LOW
        : failThreshold === 'medium' ? critical + high + medium - ignoredCounts.MEDIUM
          : failThreshold === 'high' ? critical + high - ignoredCounts.HIGH
            : /* failThreshold === 'critical' ? */ critical - ignoredCounts.CRITICAL

  if (numFailingVulns > 0) {
    throw new Error(`Detected ${numFailingVulns} vulnerabilities with severity >= ${failThreshold} (the currently configured fail_threshold).`)
  }
}

;(async function () {
  try {
    await main()
  } catch (error) {
    core.setFailed(error.message)
  }
})()
