const core = require('@actions/core')
const AWS = require('aws-sdk')
const proxy = require('proxy-agent');

/**
 * @typedef {{
 *  critical: number,
 *  high: number,
 *  medium: number,
 *  low: number,
 *  informational: number,
 *  undefined: number,
 *  total: number }} IgnoredCounts
 */

/**
 * Get paginated AWS JS SDK results
 * @param {*} fn
 * @author https://advancedweb.hu/how-to-paginate-the-aws-js-sdk-using-async-generators/
 */
const getPaginatedResults = async (fn) => {
  const EMPTY = Symbol('empty');
  const res = [];
  for await (const lf of (async function*() {
    let NextMarker = EMPTY;
    while (NextMarker || NextMarker === EMPTY) {
      const { marker, results } = await fn(NextMarker !== EMPTY ? NextMarker : undefined);
      yield* results;
      NextMarker = marker;
    }
  })()) {
    res.push(lf);
  }
  return res;
};

/**
 * @param {AWS.ECR} ECR
 * @param {string} repository
 * @param {string} tag
 * @returns {AWS.Request|AWS.AWSError|null} Results, Error or `null`.
 */
const getFindings = async (ECR, repository, tag) => {
  let findings = await ECR.describeImageScanFindings({
    imageId: {
      imageTag: tag
    },
    repositoryName: repository
  }).promise().catch(
    (err) => {
      if (err.code === 'ScanNotFoundException') { return null }
      throw err
  });
  
  // If there are no vulns found, ECR will respond with an empty array here: findings.imageScanFindings.findings
  // This implies that the scan was a basic scan, but it's not, so we need to add an empty enhancedFindings array.
  if (findings.imageScanFindings.findings && findings.imageScanFindings.findings.length == 0){
    findings.imageScanFindings.enhancedFindings = [];
  }
  
  if (!'enhancedFindings' in findings.imageScanFindings) {
    throw new Error(`Basic scan not supported. Please enable enhanced scanning in ECR.`);
  }

  return findings;
}

/**
 * Method to collect all scan results.
 * @param {AWS.ECR} ECR
 * @param {string} repository
 * @param {string} tag
 * @returns {AWS.ECR.ImageScanFinding[]|AWS.AWSError|null} Results, Error or `null`.
 */
const getAllFindings = async (ECR, repository, tag) => {
  return await getPaginatedResults(async (NextMarker) => {
    const findings = await ECR.describeImageScanFindings({
      imageId: {
        imageTag: tag
      },
      maxResults: 1000, // Valid range: 1-1000, default: 100
      repositoryName: repository,
      nextToken: NextMarker
    }).promise().catch(
      (err) => {
        core.debug(`Error: ${err}`);
        if (err.code === 'ScanNotFoundException') { return null }
        throw err
      })

    return {
      marker: findings.nextToken,
      results: findings.imageScanFindings.enhancedFindings,
    };
  })
};

/**
 * Tally findings by severity.
 * @param {AWS.ECR.ImageScanFinding[]} ignoredFindings
 * @returns {IgnoredCounts} counts
 */
const countIgnoredFindings = (ignoredFindings) =>
  ignoredFindings.reduce(
    (counts, finding) => {
      const updatedCount = { ...counts }
      const severity = finding.severity.toLowerCase()
      updatedCount[severity]++
      updatedCount.total++
      return updatedCount
    },
    { critical: 0, high: 0, medium: 0, low: 0, informational: 0, undefined: 0, total: 0 }
  )

/**
 * Returns display text for a severity level.
 * @param {keyof IgnoredCounts} severity
 * @param {IgnoredCounts} counts
 * @returns {string}
 */
const getCount = (severity, counts) =>
  counts[severity] ? `(${counts[severity]} ignored)` : ''

/**
 * Build an array with CVE IDs to ignore in the counts.
 * @param {string | string[]} list - Comma/space/newline-separated list or array of CVE IDs.
 * @returns {string[]} Array of CVE IDs
 */
const parseIgnoreList = (list) => {
  if (Array.isArray(list)) return list // when GitHub Actions allow arrays to be passed in.
  if (!list) return []

  const ignoreList =
    list
      .trim() // remove trailing newlines if any
      .replace(/\n|\s/g, ',') // replace newlines or spaces with commas, if any
      .split(',') // build the array
      .map((i) => i.trim()) // ensure each item doesn't contain any white-space
      .filter(Boolean) // remove empty items

  return ignoreList
}

function configureGlobalProxy(proxyUrl) {
  core.debug("Using proxy URL: " + proxyUrl);
  AWS.config.update({
    httpOptions: { agent: proxy(proxyUrl) }
  });
}

function countFailingVulnerabilities(failThreshold, foundCounts, ignoredCounts) {
    let count = foundCounts.critical - ignoredCounts.critical;
    if (failThreshold === 'critical') {
        return count;
    }
    count += foundCounts.high - ignoredCounts.high;
    if (failThreshold === 'high') {
        return count;
    }
    count += foundCounts.medium - ignoredCounts.medium;
    if (failThreshold === 'medium') {
        return count;
    }
    count += foundCounts.low - ignoredCounts.low;
    if (failThreshold === 'low') {
        return count;
    }
    return count + foundCounts.informational - ignoredCounts.informational;
}

const main = async () => {
  core.debug('Entering main')
  const repository = core.getInput('repository', { required: true })
  const tag = core.getInput('tag', { required: true })
  const failThreshold = core.getInput('fail_threshold') || 'high'
  const ignoreList = parseIgnoreList(core.getInput('ignore_list'))
  const missedCVELogLevel = core.getInput('missedCVELogLevel') || 'error'

  //Validate missedCVELogLevel
  if (
    missedCVELogLevel !== 'warn' &&
    missedCVELogLevel !== 'error'
  ) {
    throw new Error('missedCVELogLevel input value is invalid. It must be either "warn" or "error".')
  }

  const proxyUrl = process.env.HTTPS_PROXY || process.env.https_proxy
  if (proxyUrl !== undefined) {
    configureGlobalProxy(proxyUrl)
  }
  
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
  core.debug(`Findings: ${JSON.stringify(findings)}`)
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
    status = 'PENDING'
  }

  let firstPoll = true
  while (status === 'PENDING' || status === 'IN_PROGRESS') {
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
  if (status !== 'COMPLETE' && status !== 'ACTIVE') {
    throw new Error(`Unhandled scan status "${status}". API response: ${JSON.stringify(findings)}`)
  }

  const allFindingsList = !!ignoreList.length ? await getAllFindings(ECR, repository, tag) : []; // only fetch all findings if we have an ignore list
  let ignoredFindings = [];
  ignoredFindings = allFindingsList.filter(({ packageVulnerabilityDetails }) => ignoreList.includes(packageVulnerabilityDetails.vulnerabilityId));

  if (ignoreList.length !== ignoredFindings.length) {
    const missedIgnores = ignoreList.filter(vulnerabilityId => !ignoredFindings.map(({ packageVulnerabilityDetails }) => packageVulnerabilityDetails.vulnerabilityId).includes(vulnerabilityId));
    console.log('The following CVEs were not found in the result set:');
    missedIgnores.forEach(miss => console.log(`  ${miss}`));
    if (missedCVELogLevel === 'error') {
      throw new Error(`Ignore list contains CVE IDs that were not returned in the findings result set. They may be invalid or no longer be current vulnerabilities.`);
    } else {
      core.warning(`Ignore list contains CVE IDs that were not returned in the findings result set. They may be invalid or no longer be current vulnerabilities.`);
    }  
  }

  const ignoredCounts = countIgnoredFindings(ignoredFindings)
  const findingsDetails = findings.imageScanFindings.enhancedFindings || []
  const counts = findings.imageScanFindings.findingSeverityCounts || {} // If no findings, default to empty object instead of undefined
  const critical = counts.CRITICAL || 0
  const high = counts.HIGH || 0
  const medium = counts.MEDIUM || 0
  const low = counts.LOW || 0
  const informational = counts.INFORMATIONAL || 0
  const indeterminate = counts.UNDEFINED || 0
  const ignored = ignoredFindings.length
  const total = critical + high + medium + low + informational + indeterminate
  core.setOutput('findingsDetails', JSON.stringify(findingsDetails))
  core.setOutput('critical', critical.toString())
  core.setOutput('high', high.toString())
  core.setOutput('medium', medium.toString())
  core.setOutput('low', low.toString())
  core.setOutput('informational', informational.toString())
  core.setOutput('undefined', indeterminate.toString())
  core.setOutput('ignored', ignored.toString())
  core.setOutput('total', total.toString())
  core.startGroup('Findings')
  findingsDetails.forEach((findingDetail, index) => {
    console.log(`${index + 1}. ${findingDetail.packageVulnerabilityDetails.vulnerabilityId} (${findingDetail.packageVulnerabilityDetails.vendorSeverity}) ${JSON.stringify(findingDetail.packageVulnerabilityDetails.cvss)} ${JSON.stringify(findingDetail.packageVulnerabilityDetails.vulnerablePackages)}`);
  });
  core.endGroup()
  console.log('Vulnerabilities found:')
  console.log(`${critical.toString().padStart(3, ' ')} Critical ${getCount('critical', ignoredCounts)}`)
  console.log(`${high.toString().padStart(3, ' ')} High ${getCount('high', ignoredCounts)}`)
  console.log(`${medium.toString().padStart(3, ' ')} Medium ${getCount('medium', ignoredCounts)}`)
  console.log(`${low.toString().padStart(3, ' ')} Low ${getCount('low', ignoredCounts)}`)
  console.log(`${informational.toString().padStart(3, ' ')} Informational ${getCount('informational', ignoredCounts)}`)
  console.log(`${indeterminate.toString().padStart(3, ' ')} Undefined ${getCount('undefined', ignoredCounts)}`)
  console.log('=================')
  console.log(`${total.toString().padStart(3, ' ')} Total ${getCount('total', ignoredCounts)}`)

  const numFailingVulns = countFailingVulnerabilities(
    failThreshold,
    { informational, low, medium, high, critical },
    ignoredCounts,
  )

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
