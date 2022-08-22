# !/bin/bash
#
# Script runs below steps to prepare a new release branch:
# - Fetch the latest main branch from remote origin (it must point to github.com/intel/trusted-certificate-issuer).
# - Create a new branch with current main HEAD.
# - Run needed make targets to generate manifests with the new version.
# - Modify helm charts with new version.
# - Commit the changes.
# - And return back to the previous branch.
#
set -o pipefail
set -o errexit

SOURCE=$(dirname "$(readlink -f "$0")")
REPO_ROOT=$(dirname $SOURCE)

VERSION=
pwd=$(pwd)
current_branch=$(git branch --show-current)
release_branch=

function Usage {
    echo "Usage:"
    echo "   $0 --version <semver version>"
}

for opt in $@
do
    case "$opt" in
    --version)
        shift ; VERSION=$1 ;;
    -h | --help)
        Usage ; exit ;;
    -*) shift ; echo "Unrecognized option $opt" ;;
    esac
done

if [ -z "$VERSION" ]; then
    echo "ERROR: No release version set."
    Usage
    exit
fi

function Cleanup {
    git checkout $current_branch
    if [ ! -z "$release_branch" ] ; then
        git branch -D "$release_branch"
    fi
    cd "$pwd"
}
trap Cleanup EXIT

echo "Using release VERSION=$VERSION"

release_branch="release-v$VERSION"

cd "$REPO_ROOT"
git fetch origin
git checkout -b $release_branch $(git show --oneline origin/main | cut -f1 -d ' ')
make generate deploy-manifests REGISTRY="intel" IMG_TAG=$VERSION
sed -i -e "s;\(.*version: \).*;\1$VERSION;g" -e 's;\(.*appVersion: \).*;\1"'$VERSION'";g' ./charts/Chart.yaml
sed -i "s;\(.*tag: \).*;\1$VERSION;g" ./charts/values.yaml
git checkout ./config/manager/kustomization.yaml
git add ./deployment ./charts && git commit -m "Release v$VERSION"
# Unset release_branch so that Cleanup does not delete the branch.
release_branch=""

echo ========================
echo "Created new release branch $release_branch. Review and run 'git push origin $release_branch'."
echo =======================

