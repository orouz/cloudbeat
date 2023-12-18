#!/bin/bash
set -euo pipefail

MANIFEST_PATH="packages/cloud_security_posture/manifest.yml"
INTEGRATION_REPO="orouz/integrations"

checkout_integration_repo() {
    # gh auth login --with-token 
    gh repo clone $INTEGRATION_REPO
    cd integrations
}

replace_manifest_version_vars() {
    MINOR_VERSION=$(echo $NEXT_CLOUDBEAT_VERSION | cut -d '.' -f1,2)
    echo "MINOR_VERSION is $MINOR_VERSION"

    PATCH_VERSION=$NEXT_CLOUDBEAT_VERSION
    echo "PATCH_VERSION is $PATCH_VERSION"

    # cis_gcp
    sed -i'' -E "s/cloudshell_git_branch=[0-9]+\.[0-9]+/cloudshell_git_branch=$MINOR_VERSION/g" $MANIFEST_PATH

    # cis_aws + vuln_mgmt_aws
    sed -i'' -E "s/cloudformation-cnvm-[0-9]+\.[0-9]+\.[0-9]+/cloudformation-cnvm-$PATCH_VERSION/g" $MANIFEST_PATH
    sed -i'' -E "s/cloudformation-cspm-ACCOUNT_TYPE-[0-9]+\.[0-9]+\.[0-9]+/cloudformation-cspm-ACCOUNT_TYPE-$PATCH_VERSION/g" $MANIFEST_PATH

    # cis_azure
    sed -i'' -E "s/cloudbeat%2F[0-9]+\.[0-9]+/cloudbeat%2F$MINOR_VERSION/g" $MANIFEST_PATH
}

create_integrations_pr() {
    local BRANCH="bump-to-$NEXT_CLOUDBEAT_VERSION"
    git config --global user.email "elasticmachine@users.noreply.github.com"
    git config --global user.name "Elastic Machine"
    git checkout -b "$BRANCH" main
    git add $MANIFEST_PATH
    git commit -m "Bump integration manifest to $NEXT_CLOUDBEAT_VERSION"
    git push origin $BRANCH
    
    gh pr create --title "[Cloud Security] Update integration manifest" \
  --body "Automated PR" \
  --base "main" \
  --head "$BRANCH" \
  --repo "$INTEGRATION_REPO"
}

checkout_integration_repo
replace_manifest_version_vars
create_integrations_pr
