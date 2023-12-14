


# Bump integration version
# PR to integration repo to change template URLS
# PR to integration repo to change kibana condition
# PR to integration repo to change to preview version / production version

export MANIFEST_PATH="packages/cloud_security_posture/manifest.yml"

replace_manifest_version_vars() {
    MINOR_VERSION=$(echo $VERSION | cut -d '.' -f1,2)
    echo "MINOR_VERSION is $MINOR_VERSION"

    PATCH_VERSION=$VERSION
    echo "PATCH_VERSION is $PATCH_VERSION"

    # cis_gcp
    sed -i'' -E "s/cloudshell_git_branch=[0-9]+\.[0-9]+/cloudshell_git_branch=$MINOR_VERSION/g" $MANIFEST_PATH

    # cis_aws + vuln_mgmt_aws
    sed -i'' -E "s/cloudformation-cnvm-[0-9]+\.[0-9]+\.[0-9]+/cloudformation-cnvm-$PATCH_VERSION/g" $MANIFEST_PATH
    sed -i'' -E "s/cloudformation-cspm-ACCOUNT_TYPE-[0-9]+\.[0-9]+\.[0-9]+/cloudformation-cspm-ACCOUNT_TYPE-$PATCH_VERSION/g" $MANIFEST_PATH

    # cis_azure
    sed -i'' -E "s/cloudbeat%2F[0-9]+\.[0-9]+/cloudbeat%2F$PATCH_VERSION/g" $MANIFEST_PATH
}

create_integrations_pr() {
    local BRANCH="bump-to-$CLOUDBEAT_VERSION"
    git checkout -b "$BRANCH" main
    git add $MANIFEST_PATH
    git commit -m "Bump integration manifest to $CLOUDBEAT_VERSION"
    git push origin $BRANCH
    gh auth login --with-token $GITHUB_CI_TOKEN
    gh pr create --title "[Cloud Security] Update integration manifest" \
             --body "Automated PR" \
             --base "main" \
             --head "$BRANCH"
}

replace_manifest_version_vars
create_integrations_pr

# bump_integration_version() { 
#     # NEXT_INTEGRATION_VERSION
#     # update manifest
#     # add change log entry 
# }

