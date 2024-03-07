# ECR Image Scan Github Action

Scan an image uploaded to ECR and fail if vulnerabilities are found.

## IMPORTANT UPDATE: Enhanced/Basic Scanning Support from v3.0.0

As of version `3.0.0`, only enhanced scanning is supported. Basic scanning support has been removed from this version onwards. If you still need basic scanning support, please use version `^2.0.1`. To enable enhanced scanning, check out the [AWS documentation](https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning-enhanced.html).


## Quick Start

```yaml
      - name: Scan Docker image
        id: docker-scan
        uses: alexjurkiewicz/ecr-scan-image@v3.0.0
        with:
          repository: myorg/myimage
          tag: v1.2.3
          fail_threshold: high
```

## Inputs

| Input  | Required? | Description |
| ------ | --------- | ----------- |
| repository | :white_check_mark:  | ECR repository, eg myorg/myimage |
| tag    | :white_check_mark: | Image tag to scan |
| fail_threshold | | Fail if any vulnerabilities equal to or over this severity level are detected. Valid values: `critical`, `high`, `medium`, `low`, `informational`. Default value is `high`. |
| ignore_list | | List of CVE IDs to ignore.<br/>:warning: **Note**: The `ignore_list` can either be a multi-line string (like the example below) or a list (separated using commas or spaces) containing CVE IDs to be ignored. |

## Outputs

| Output | Description |
| ------ | ----------- |
| total | Total number of vulnerabilities detected. |
| critical | Number of critical vulnerabilities detected. |
| high | Number of high vulnerabilities detected. |
| medium | Number of medium vulnerabilities detected. |
| low | Number of low vulnerabilities detected. |
| informational | Number of informational vulnerabilities detected. |
| unknown | Number of unknown vulnerabilities detected. |
| findingsDetails | Details of findings. |

## Required ECR permissions

To use this GitHub action in your workflow, your ECR role/user will need to have the following permissions:
- `ecr:DescribeImageScanFindings`
- `ecr:StartImageScan` (unless [**scan on push**](https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning.html#scanning-repository) is enabled)

## Example

This example builds a docker image, uploads it to AWS ECR, then scans it for vulnerabilities.

```yaml
on:
  # Trigger on any GitHub release.
  # If you want to trigger on tag creation, use `create`. However, this also
  # fires for branch creation events which will break this example workflow.
  - release
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Configure AWS Credentials
        uses: aws-actions/configure-aws-credentials@v1
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: us-west-2
      - name: Login to Amazon ECR
        id: login-ecr
        uses: aws-actions/amazon-ecr-login@v1
      - name: Build & Push Docker image
        id: docker-build
        env:
          ECR_REGISTRY: ${{ steps.login-ecr.outputs.registry }}
          ECR_REPOSITORY: myorg/myimage
          # Use the git tag as the image tag.
          # github.ref format is like `refs/tags/v0.0.1`, so we strip the the
          # `refs/tags/` prefix and export this for later use.
          IMAGE_TAG: ${{ github.ref }}
        run: |
          tag=${IMAGE_TAG##refs/tags/}
          echo "Tag is $tag"
          echo "::set-output name=tag::$tag"
          docker build -t $ECR_REGISTRY/$ECR_REPOSITORY:$tag .
          docker push $ECR_REGISTRY/$ECR_REPOSITORY:$tag
      - name: Scan Docker image
        id: docker-scan
        uses: alexjurkiewicz/ecr-scan-image@v1.7.1
        with:
          repository: myorg/myimage
          tag: ${{ steps.docker-build.outputs.tag }}
          # fail_threshold: medium
          # ignore_list: |
          #   CVE-2014-7654321
          #   CVE-2014-456132
      # Access scan results in later steps
      - run: echo "${{ steps.docker-scan.outputs.total }} total vulnerabilities."
```

## Development

This action is implemented as a Docker rather than a Javascript action because [that would require committing node\_modules to the repository](https://help.github.com/en/actions/building-actions/creating-a-javascript-action#commit-tag-and-push-your-action-to-github).

You can test the action by running it locally like so:

```sh
docker build -t ecr-scan-image:dev .
docker run -t \
  -e INPUT_REPOSITORY=myorg/myapp \
  -e INPUT_TAG=test-tag \
  -e INPUT_FAIL_THRESHOLD=critical \
  -e AWS_ACCESS_KEY_ID=xxx \
  -e AWS_SECRET_ACCESS_KEY=xxx \
  -e AWS_REGION=xxx \
  ecr-scan-image:dev
```
