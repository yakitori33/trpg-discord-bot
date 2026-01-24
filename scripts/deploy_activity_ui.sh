#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

load_dotenv() {
  local path="$1"
  if [[ -f "${path}" ]]; then
    set -a
    # shellcheck disable=SC1090
    source "${path}"
    set +a
  fi
}

# Optional: allow running the script without manually exporting variables.
load_dotenv "${REPO_ROOT}/.env"
load_dotenv "${REPO_ROOT}/scenario-weaver/.env"

ensure_scenario_weaver() {
  if [[ -f "${REPO_ROOT}/scenario-weaver/package.json" ]]; then
    return
  fi

  # If scenario-weaver is a git submodule, it may not be checked out yet.
  if [[ -f "${REPO_ROOT}/.gitmodules" ]]; then
    echo "[boot] scenario-weaver is missing; initializing git submodule..."
    env -u GITHUB_TOKEN -u GH_TOKEN git submodule update --init --recursive scenario-weaver
  fi

  if [[ ! -f "${REPO_ROOT}/scenario-weaver/package.json" ]]; then
    echo "ERROR: scenario-weaver is missing. Clone it or init submodules first."
    echo "  - git submodule update --init --recursive"
    echo "  - or: git clone https://github.com/yakitori33/scenario-weaver.git scenario-weaver"
    exit 1
  fi
}

has_dune_font() {
  local fonts_dir="public/fonts"
  local candidates=(
    "${fonts_dir}/dune-rise.woff2"
    "${fonts_dir}/dune.woff2"
    "${fonts_dir}/dune-rise.woff"
    "${fonts_dir}/dune.woff"
    "${fonts_dir}/dune-rise.ttf"
    "${fonts_dir}/dune.ttf"
    "${fonts_dir}/dune-rise.otf"
    "${fonts_dir}/dune.otf"
  )
  for f in "${candidates[@]}"; do
    if [[ -f "${f}" ]]; then
      return 0
    fi
  done
  return 1
}

prepare_dune_font() {
  local fonts_dir="public/fonts"

  if [[ -n "${DUNE_RISE_FONT_FILE:-}" ]]; then
    if [[ ! -f "${DUNE_RISE_FONT_FILE}" ]]; then
      echo "ERROR: DUNE_RISE_FONT_FILE does not exist: ${DUNE_RISE_FONT_FILE}"
      exit 1
    fi
    mkdir -p "${fonts_dir}"
    cp "${DUNE_RISE_FONT_FILE}" "${fonts_dir}/dune-rise.woff2"
    echo "[info] Copied Dune Rise font into ${fonts_dir}/dune-rise.woff2"
  fi

  if ! has_dune_font; then
    echo "[warn] Dune Rise font files not found under ${fonts_dir}/"
    echo "       Logo will fall back to Orbitron."
    echo "       Place one of: dune-rise.woff2 / dune.woff2 (or woff/ttf/otf) under scenario-weaver/public/fonts/"
  fi
}

verify_dune_font_dist() {
  if has_dune_font; then
    if [[ -d "dist/fonts" ]] && compgen -G "dist/fonts/dune*.*" > /dev/null; then
      return 0
    fi
    echo "[warn] Dune font files were not copied into dist/fonts/ (check Vite public/ handling)."
  fi
}

STACK_NAME="${STACK_NAME:-discord-trpg-ui}"
REGION="${REGION:-${AWS_REGION:-${AWS_DEFAULT_REGION:-us-east-1}}}"
TEMPLATE_FILE="${TEMPLATE_FILE:-activity-ui.yaml}"

normalize_version() {
  local raw="$1"
  if [[ -z "${raw}" || "${raw}" == "None" ]]; then
    echo ""
    return 0
  fi

  # New style: "035"
  if [[ "${raw}" =~ ^[0-9]+$ ]]; then
    printf '%03d\n' "$((10#${raw}))"
    return 0
  fi

  # Legacy style: "1.0.35" -> "035"
  if [[ "${raw}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    local patch="${raw##*.}"
    printf '%03d\n' "$((10#${patch}))"
    return 0
  fi

  echo "${raw}"
}

next_version() {
  local current="$1"
  local normalized
  normalized="$(normalize_version "${current}")"
  if [[ -z "${normalized}" ]]; then
    printf '%03d\n' 1
    return 0
  fi
  if [[ "${normalized}" =~ ^[0-9]+$ ]]; then
    printf '%03d\n' "$((10#${normalized} + 1))"
    return 0
  fi
  # Unknown format: reset to 001
  printf '%03d\n' 1
}

CURRENT_FE_VERSION="$(
  aws cloudformation describe-stacks \
    --stack-name "${STACK_NAME}" \
    --region "${REGION}" \
    --query 'Stacks[0].Outputs[?OutputKey==`FrontendBuildVersion`].OutputValue' \
    --output text 2>/dev/null || true
)"

if [[ -n "${VITE_FRONTEND_BUILD_VERSION:-}" ]]; then
  FRONTEND_BUILD_VERSION="$(normalize_version "${VITE_FRONTEND_BUILD_VERSION}")"
elif [[ -n "${FRONTEND_BUILD_VERSION:-}" ]]; then
  FRONTEND_BUILD_VERSION="$(normalize_version "${FRONTEND_BUILD_VERSION}")"
elif [[ "${SKIP_BUILD:-}" == "1" ]]; then
  FRONTEND_BUILD_VERSION="$(normalize_version "${CURRENT_FE_VERSION:-000}")"
else
  FRONTEND_BUILD_VERSION="$(next_version "${CURRENT_FE_VERSION}")"
fi

export VITE_FRONTEND_BUILD_VERSION="${FRONTEND_BUILD_VERSION}"

echo "[1/4] Deploy infra (S3 + CloudFront): stack=${STACK_NAME} region=${REGION}"
aws cloudformation deploy \
  --stack-name "${STACK_NAME}" \
  --template-file "${TEMPLATE_FILE}" \
  --region "${REGION}" \
  --parameter-overrides "FrontendBuildVersion=${FRONTEND_BUILD_VERSION}"

echo "[2/4] Read outputs"
BUCKET_NAME="$(aws cloudformation describe-stacks --stack-name "${STACK_NAME}" --region "${REGION}" --query 'Stacks[0].Outputs[?OutputKey==`ActivityUiBucketName`].OutputValue' --output text)"
DIST_ID="$(aws cloudformation describe-stacks --stack-name "${STACK_NAME}" --region "${REGION}" --query 'Stacks[0].Outputs[?OutputKey==`ActivityUiDistributionId`].OutputValue' --output text)"
DOMAIN_NAME="$(aws cloudformation describe-stacks --stack-name "${STACK_NAME}" --region "${REGION}" --query 'Stacks[0].Outputs[?OutputKey==`ActivityUiDomainName`].OutputValue' --output text)"

if [[ -z "${BUCKET_NAME}" || -z "${DIST_ID}" || -z "${DOMAIN_NAME}" ]]; then
  echo "ERROR: Missing stack outputs. Check stack outputs for ${STACK_NAME}."
  exit 1
fi

echo "[3/4] Build UI"
if [[ "${SKIP_BUILD:-}" == "1" ]]; then
  echo "SKIP_BUILD=1: skipping UI build (will upload existing scenario-weaver/dist)"
else
  ensure_scenario_weaver
  pushd scenario-weaver >/dev/null

  export VITE_ACTIVITY_MODE="${VITE_ACTIVITY_MODE:-discord}"
  export VITE_FRONTEND_BUILD_VERSION="${VITE_FRONTEND_BUILD_VERSION}"

  if [[ -z "${VITE_DISCORD_CLIENT_ID:-}" && -n "${DISCORD_APPLICATION_ID:-}" ]]; then
    export VITE_DISCORD_CLIENT_ID="${DISCORD_APPLICATION_ID}"
  fi

  if [[ -z "${VITE_DISCORD_CLIENT_ID:-}" && -n "${DISCORD_BOT_TOKEN:-}" ]]; then
    # Convenience: derive VITE_DISCORD_CLIENT_ID from bot token (does NOT print the token).
    eval "$(node scripts/export_discord_env.mjs)"
  fi

  : "${VITE_DISCORD_CLIENT_ID:?Missing VITE_DISCORD_CLIENT_ID (or set DISCORD_BOT_TOKEN and re-run).}"

  if [[ ! -d node_modules ]]; then
    npm install
  fi
  prepare_dune_font
  npm run build
  verify_dune_font_dist

  popd >/dev/null
fi

if [[ ! -d scenario-weaver/dist ]]; then
  echo "ERROR: scenario-weaver/dist does not exist. Run the build first (or omit SKIP_BUILD)."
  exit 1
fi

echo "[4/4] Upload to S3 and invalidate CloudFront"
aws s3 sync scenario-weaver/dist "s3://${BUCKET_NAME}/" --delete --exclude "uploads/*"
aws cloudfront create-invalidation --distribution-id "${DIST_ID}" --paths "/*" >/dev/null

echo "OK: https://${DOMAIN_NAME}"
