#!/bin/bash
set -euo pipefail

export NEXT_CLOUDBEAT_BRANCH="bump-to-$NEXT_CLOUDBEAT_VERSION"
export NEXT_MINOR_VERSION=$(echo $NEXT_CLOUDBEAT_VERSION | cut -d '.' -f1,2)
export CURRENT_MINOR_VERSION=$(echo $CURRENT_CLOUDBEAT_VERSION | cut -d '.' -f1,2)

echo "NEXT_CLOUDBEAT_VERSION: $NEXT_CLOUDBEAT_VERSION"
echo "NEXT_MINOR_VERSION: $NEXT_MINOR_VERSION"
echo "CURRENT_CLOUDBEAT_VERSION: $CURRENT_CLOUDBEAT_VERSION"
echo "CURRENT_MINOR_VERSION: $CURRENT_MINOR_VERSION"

create_release_branch() {
  if git fetch origin "$CURRENT_MINOR_VERSION" 2>/dev/null; then
    echo "• Release branch '$CURRENT_MINOR_VERSION' already exists, not creating a new one from main"
  else
    echo "• Create and push a new release branch $CURRENT_MINOR_VERSION from main"
    git fetch origin main
    git checkout -b "$CURRENT_MINOR_VERSION" origin/main
    echo "Push release branch $CURRENT_MINOR_VERSION to origin"
    git push origin $CURRENT_MINOR_VERSION

    # git checkout main
    # git pull --rebase origin main
    # git checkout -b "$CURRENT_MINOR_VERSION" origin/main
    # git log --merges --oneline --pretty=format:"%h %an %ad %s" --date=format-local:"%d/%m/%H:%M"
    # echo "Push release branch $CURRENT_MINOR_VERSION to origin"
    # git push origin $CURRENT_MINOR_VERSION
  fi
}

update_version_mergify() {
  echo "• Add a new entry to .mergify.yml"
  cat <<EOF >>.mergify.yml
  - name: backport patches to $CURRENT_MINOR_VERSION branch
    conditions:
      - merged
      - label=backport-v$CURRENT_CLOUDBEAT_VERSION
    actions:
      backport:
        assignees:
          - "{{ author }}"
        branches:
          - "$CURRENT_MINOR_VERSION"
        labels:
          - "backport"
        title: "[{{ destination_branch }}](backport #{{ number }}) {{ title }}"
EOF
}

update_version_arm_template() {
  echo "• Update ARM templates with new version"
  local single_account_file="deploy/azure/ARM-for-single-account.json"
  local organization_account_file="deploy/azure/ARM-for-organization-account.json"

  echo "• Replace defaultValue for ElasticAgentVersion in ARM templates"
  jq --indent 4 ".parameters.ElasticAgentVersion.defaultValue = \"$NEXT_CLOUDBEAT_VERSION\"" $single_account_file >tmp.json && mv tmp.json $single_account_file
  jq --indent 4 ".parameters.ElasticAgentVersion.defaultValue = \"$NEXT_CLOUDBEAT_VERSION\"" $organization_account_file >tmp.json && mv tmp.json $organization_account_file

  echo "• Replace cloudbeat/main with cloudbeat/$NEXT_MINOR_VERSION in ARM templates"
  sed -i'' -E "s/cloudbeat\/main/cloudbeat\/$NEXT_MINOR_VERSION/g" $single_account_file
  sed -i'' -E "s/cloudbeat\/main/cloudbeat\/$NEXT_MINOR_VERSION/g" $organization_account_file

  echo "• Generate dev ARM templates"
  ./deploy/azure/generate_dev_template.py --template-type single-account
  ./deploy/azure/generate_dev_template.py --template-type organization-account
}

update_version_beat() {
  echo "• Update version/version.go with new version"
  sed -i'' -E "s/const defaultBeatVersion = .*/const defaultBeatVersion = \"$NEXT_CLOUDBEAT_VERSION\"/g" version/version.go
}

create_cloudbeat_versions_pr() {
  echo "• Create PR for cloudbeat versions"
  git add .
  git commit -m "Bump cloudbeat to $NEXT_CLOUDBEAT_VERSION"
  git push origin "$NEXT_CLOUDBEAT_BRANCH"

  cat <<EOF >cloudbeat_pr_body
Bump cloudbeat version - \`$NEXT_CLOUDBEAT_VERSION\`

> [!NOTE]  
> This is an automated PR
EOF

  gh pr create --title "Bump cloudbeat version" \
    --body-file cloudbeat_pr_body \
    --base "main" \
    --head "$NEXT_CLOUDBEAT_BRANCH" \
    --label "backport-skip"
}

bump_cloudbeat() {
  git fetch origin main
  git checkout -b "$NEXT_CLOUDBEAT_BRANCH" origin/main
  update_version_mergify
  update_version_arm_template
  update_version_beat
  create_cloudbeat_versions_pr
}

# We need to bump hermit seperately because we need to wait for the snapshot build to be available
bump_hermit() {
  echo "• Bump hermit cloudbeat version"
  local BRANCH="bump-hermit-to-$NEXT_CLOUDBEAT_VERSION"
  git checkout -b "$BRANCH" origin/main

  sed -i'' -E "s/\"CLOUDBEAT_VERSION\": .*/\"CLOUDBEAT_VERSION\": \"$NEXT_CLOUDBEAT_VERSION\",/g" bin/hermit.hcl
  git add bin/hermit.hcl
  git commit -m "Bump cloudbeat to $NEXT_CLOUDBEAT_VERSION"
  git push origin "$BRANCH"

  cat <<EOF >hermit_pr_body
Bump cloudbeat version - \`$NEXT_CLOUDBEAT_VERSION\`

> [!IMPORTANT]  
> to be merged after snapshot build for $NEXT_CLOUDBEAT_VERSION is available

> [!NOTE]  
> This is an automated PR
EOF

  echo "• Create a PR for cloudbeat hermit version"
  gh pr create --title "Bump hermit cloudbeat version" \
    --body-file hermit_pr_body \
    --base "main" \
    --head "$BRANCH" \
    --label "backport-skip"
}

upload_cloud_formation_templates() {
  echo "• Upload cloud formation templates for $CURRENT_CLOUDBEAT_VERSION"
  aws configure set aws_access_key_id $AWS_ACCESS_KEY_ID
  aws configure set aws_secret_access_key $AWS_SECRET_ACCESS_KEY
  aws configure set region us-east-2
  scripts/publish_cft.sh
}

create_release_branch

# bump_cloudbeat
# bump_hermit
# upload_cloud_formation_templates
