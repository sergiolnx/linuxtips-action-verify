#!/usr/bin/env bash
set -euo pipefail
source "${GITHUB_ACTION_PATH}/scripts/functions.sh"

WORKDIR="$GITHUB_WORKSPACE"

if ! find "$WORKDIR" -name '*.tf' -print -quit | grep -q .; then
  echo "Nenhum arquivo .tf encontrado - pulando verificações Terraform"
  exit 0
fi

########### SCAN TERRASCAN ##############
set +e
terrascan scan \
  -i terraform \
  -t aws \
  --iac-dir "$WORKDIR" \
  -o json > /tmp/terrascan.json
ts_exit=$?
set -e

jq -c '.results.violations[]?' /tmp/terrascan.json | while read -r vio; do
  rule=$(jq -r '.rule_name'      <<<"$vio")
  rid=$(jq -r '.rule_id'         <<<"$vio")
  desc=$(jq -r '.description'    <<<"$vio")
  sev=$(jq -r '.severity'        <<<"$vio")
  catg=$(jq -r '.category'       <<<"$vio")
  res=$(jq -r '.resource_type'   <<<"$vio")
  file=$(jq -r '.file'           <<<"$vio")
  line=$(jq -r '.line'           <<<"$vio")
  rec=$(jq -r '.recommendation // "N/A"' <<<"$vio")

  title="Terrascan [$sev] $rule"
  mark_problem || true

  body=$(cat <<EOF
Regra: \`$rule\` (\`$rid\`)
Descrição: $desc
Severidade: \`$sev\`
Categoria: \`$catg\`
Recurso: \`$res\`
Arquivo: \`$file\` — linha $line
Recomendação: $rec
EOF
  )
  issue_info=$(find_issue "$title" || true)
  if [[ -z "$issue_info" ]]; then
    create_issue "$title" "$body" "terraform-security" || true
  else
    num=${issue_info%%:*}
    state=${issue_info##*:}
    if [[ "$state" == "closed" ]]; then
      reopen_issue "$num" || true
    fi
  fi
done

########### SCAN TRIVY ##############
set +e
trivy config \
  --format json \
  --severity HIGH,CRITICAL \
  --skip-files Dockerfile \
  -o /tmp/trivy_tf.json \
  "$WORKDIR" || true
set -e

mis_count=$(jq '[(.Results // [])[]?.Misconfigurations[]?] | length' /tmp/trivy_tf.json 2>/dev/null || echo 0)
if (( mis_count > 0 )); then
  jq -c '(.Results // [])[]?.Misconfigurations[]?' /tmp/trivy_tf.json | while read -r mis; do
    id=$(jq -r '.ID'             <<<"$mis")
    title_rule=$(jq -r '.Title // .Description | split("\n")[0]' <<<"$mis")
    sev=$(jq -r '.Severity'      <<<"$mis")
    rec=$(jq -r '.Resolution // "N/A"' <<<"$mis")
    file=$(jq -r '.Target'       <<<"$mis")
    line=$(jq -r '.Line'         <<<"$mis")
    url=$(jq -r '.PrimaryURL // (.References[0] // "")' <<<"$mis")

    title="Trivy Config [$sev]: $id"
    mark_problem || true

    body=$(cat <<EOF
ID: \`$id\`
Título: $title_rule
Severidade: \`$sev\`
Arquivo: \`$file\` — linha $line
Recomendação: $rec
Link: $url
EOF
    )
    issue_info=$(find_issue "$title" || true)
    if [[ -z "$issue_info" ]]; then
      create_issue "$title" "$body" "terraform-security" || true
    else
      num=${issue_info%%:*}
      state=${issue_info##*:}
      if [[ "$state" == "closed" ]]; then
        reopen_issue "$num" || true
      fi
    fi
  done
else
  echo "::warning:: Trivy config não gerou /tmp/trivy_tf.json ou não encontrou problemas nos arquivos"
fi