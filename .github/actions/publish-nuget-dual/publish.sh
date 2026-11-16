#!/usr/bin/env bash
set -euo pipefail

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Required command '$1' is unavailable." >&2
    exit 1
  fi
}

for command_name in curl dotnet jq sha256sum unzip; do
  require_command "$command_name"
done

if [[ -z "${GITHUB_TOKEN_INPUT:-}" || -z "${INCURSA_API_KEY:-}" || -z "${NUGET_API_KEY:-}" ]]; then
  echo "The GitHub and publication credentials are required." >&2
  exit 1
fi

if [[ -z "${GITHUB_REPOSITORY:-}" || -z "${GITHUB_SHA:-}" ]]; then
  echo "GitHub repository and commit metadata are required." >&2
  exit 1
fi

repository_visibility=$(curl --fail --silent --show-error \
  -H 'Accept: application/vnd.github+json' \
  -H "Authorization: Bearer ${GITHUB_TOKEN_INPUT}" \
  "https://api.github.com/repos/${GITHUB_REPOSITORY}" | jq -r '.visibility')
if [[ "$repository_visibility" != "public" ]]; then
  echo "Dual public publication is allowed only from a public repository." >&2
  exit 1
fi

package_directory=$(realpath "${PACKAGES_DIRECTORY}")
if [[ ! -d "$package_directory" ]]; then
  echo "Package directory '$package_directory' does not exist." >&2
  exit 1
fi

mapfile -t package_files < <(find "$package_directory" -maxdepth 1 -type f -name '*.nupkg' ! -name '*.symbols.nupkg' -print | LC_ALL=C sort)
if (( ${#package_files[@]} == 0 )); then
  echo "No .nupkg files were found in '$package_directory'." >&2
  exit 1
fi

mapfile -t expected_ids < <(printf '%s\n' "$EXPECTED_PACKAGE_IDS" | tr ',' '\n' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | sed '/^$/d' | LC_ALL=C sort -fu)
if (( ${#expected_ids[@]} == 0 )); then
  echo "At least one expected package ID is required." >&2
  exit 1
fi

work_directory=$(mktemp -d "${RUNNER_TEMP:-/tmp}/incursa-nuget-publish.XXXXXX")
cleanup() {
  rm -rf -- "$work_directory"
}
trap cleanup EXIT

manifest_entries="$work_directory/manifest.jsonl"
actual_ids="$work_directory/actual-ids.txt"
: > "$manifest_entries"
: > "$actual_ids"

read_nuspec_value() {
  local package_file=$1
  local element_name=$2
  local nuspec
  nuspec=$(unzip -Z1 "$package_file" | awk 'tolower($0) ~ /\.nuspec$/ { print; exit }')
  if [[ -z "$nuspec" ]]; then
    echo "Package '$(basename "$package_file")' has no nuspec." >&2
    return 1
  fi

  unzip -p "$package_file" "$nuspec" \
    | tr -d '\r\n' \
    | grep -o "<${element_name}>[^<]*</${element_name}>" \
    | head -n 1 \
    | sed "s:</\?${element_name}>::g"
}

normalized_digest() {
  local package_file=$1
  local entry
  local entry_hash
  local digest_input="$work_directory/digest-input"
  : > "$digest_input"

  while IFS= read -r entry; do
    if [[ "${entry,,}" == ".signature.p7s" || "${entry,,}" == */.signature.p7s ]]; then
      continue
    fi
    entry_hash=$(unzip -p "$package_file" "$entry" | sha256sum | awk '{print $1}')
    printf '%s\t%s\n' "$entry" "$entry_hash" >> "$digest_input"
  done < <(unzip -Z1 "$package_file" | LC_ALL=C sort)

  sha256sum "$digest_input" | awk '{print $1}'
}

declare -A package_ids=()
declare -A package_versions=()
for package_file in "${package_files[@]}"; do
  package_id=$(read_nuspec_value "$package_file" id)
  package_version=$(read_nuspec_value "$package_file" version)
  if [[ -z "$package_id" || -z "$package_version" ]]; then
    echo "Could not read package ID and version from '$(basename "$package_file")'." >&2
    exit 1
  fi
  if [[ -n "${package_ids[$package_id]:-}" ]]; then
    echo "Package ID '$package_id' appears more than once." >&2
    exit 1
  fi

  package_ids[$package_id]=$package_file
  package_versions[$package_id]=$package_version
  printf '%s\n' "$package_id" >> "$actual_ids"
  package_sha=$(sha256sum "$package_file" | awk '{print $1}')
  jq -cn \
    --arg id "$package_id" \
    --arg version "$package_version" \
    --arg file "$(basename "$package_file")" \
    --arg sha256 "$package_sha" \
    '{id:$id,version:$version,file:$file,sha256:$sha256}' >> "$manifest_entries"
done

LC_ALL=C sort -fu -o "$actual_ids" "$actual_ids"
printf '%s\n' "${expected_ids[@]}" > "$work_directory/expected-ids.txt"
if ! diff -u "$work_directory/expected-ids.txt" "$actual_ids"; then
  echo "Package files do not exactly match the approved package-ID allowlist." >&2
  exit 1
fi

jq -s \
  --arg repository "$GITHUB_REPOSITORY" \
  --arg commit "$GITHUB_SHA" \
  --arg generatedAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  '{schemaVersion:1,repository:$repository,commit:$commit,generatedAt:$generatedAt,packages:.}' \
  "$manifest_entries" > "$package_directory/publication-manifest.json"

incursa_package_base=$(curl --fail --silent --show-error "$INCURSA_SOURCE" \
  | jq -r '.resources[] | select(."@type" | startswith("PackageBaseAddress/")) | ."@id"' \
  | head -n 1)
if [[ -z "$incursa_package_base" || "$incursa_package_base" == "null" ]]; then
  echo "Incursa service index has no PackageBaseAddress resource." >&2
  exit 1
fi

download_with_retry() {
  local url=$1
  local destination=$2
  local retry
  for retry in {1..120}; do
    if curl --fail --silent --show-error --location --output "$destination" "$url"; then
      return 0
    fi
    echo "Read-back attempt $retry did not find the package yet; retrying."
    sleep 5
  done
  return 1
}

download_if_present() {
  local url=$1
  local destination=$2
  local status
  status=$(curl --silent --show-error --location --output "$destination" --write-out '%{http_code}' "$url")
  case "$status" in
    200)
      return 0
      ;;
    404)
      return 1
      ;;
    *)
      echo "Package read-back returned unexpected HTTP $status from '$url'." >&2
      exit 1
      ;;
  esac
}

verify_incursa_package() {
  local package_file=$1
  local package_id=$2
  local package_version=$3
  local id_lower=${package_id,,}
  local version_lower=${package_version,,}
  local package_url="${incursa_package_base%/}/${id_lower}/${version_lower}/${id_lower}.${version_lower}.nupkg"
  local downloaded="$work_directory/incursa-${id_lower}-${version_lower}.nupkg"
  local mode=${4:-existing}

  if [[ "$mode" == "published" ]]; then
    download_with_retry "$package_url" "$downloaded"
  elif ! download_if_present "$package_url" "$downloaded"; then
    return 1
  fi
  if [[ "$(sha256sum "$package_file" | awk '{print $1}')" != "$(sha256sum "$downloaded" | awk '{print $1}')" ]]; then
    echo "Incursa feed content mismatch for $package_id $package_version." >&2
    exit 1
  fi
  return 0
}

verify_nuget_package() {
  local package_file=$1
  local package_id=$2
  local package_version=$3
  local id_lower=${package_id,,}
  local version_lower=${package_version,,}
  local package_url="https://api.nuget.org/v3-flatcontainer/${id_lower}/${version_lower}/${id_lower}.${version_lower}.nupkg"
  local downloaded="$work_directory/nuget-${id_lower}-${version_lower}.nupkg"
  local mode=${4:-existing}

  if [[ "$mode" == "published" ]]; then
    download_with_retry "$package_url" "$downloaded"
  elif ! download_if_present "$package_url" "$downloaded"; then
    return 1
  fi
  if [[ "$(normalized_digest "$package_file")" != "$(normalized_digest "$downloaded")" ]]; then
    echo "NuGet.org content mismatch for $package_id $package_version." >&2
    exit 1
  fi
  return 0
}

for package_id in "${expected_ids[@]}"; do
  package_file=${package_ids[$package_id]}
  package_version=${package_versions[$package_id]}
  if verify_incursa_package "$package_file" "$package_id" "$package_version"; then
    echo "Incursa already contains the verified package $package_id $package_version."
  else
    dotnet nuget push "$package_file" --api-key "$INCURSA_API_KEY" --source "$INCURSA_SOURCE" --skip-duplicate
    verify_incursa_package "$package_file" "$package_id" "$package_version" published
    echo "Published and verified $package_id $package_version on the Incursa public feed."
  fi
done

declare -A nuget_submitted=()
for package_id in "${expected_ids[@]}"; do
  package_file=${package_ids[$package_id]}
  package_version=${package_versions[$package_id]}
  if verify_nuget_package "$package_file" "$package_id" "$package_version"; then
    echo "NuGet.org already contains the verified package $package_id $package_version."
  else
    dotnet nuget push "$package_file" --api-key "$NUGET_API_KEY" --source "$NUGET_SOURCE" --skip-duplicate
    nuget_submitted[$package_id]=1
    echo "Submitted $package_id $package_version to NuGet.org for validation and indexing."
  fi
done

for package_id in "${expected_ids[@]}"; do
  if [[ -n "${nuget_submitted[$package_id]:-}" ]]; then
    package_file=${package_ids[$package_id]}
    package_version=${package_versions[$package_id]}
    verify_nuget_package "$package_file" "$package_id" "$package_version" published
    echo "Published and verified $package_id $package_version on NuGet.org."
  fi
done

echo "Dual-feed publication completed for ${#package_files[@]} package(s)."
