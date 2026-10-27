# Chay toan bo pipeline local tu dau: fixtures -> entity resolution -> Neo4j -> OpenSearch -> risk -> attack path -> (GraphRAG index).
#
# Dung:
#   powershell -ExecutionPolicy Bypass -File scripts/run_pipeline.ps1
#   powershell -ExecutionPolicy Bypass -File scripts/run_pipeline.ps1 -WithGraphRag -SkipAttackPath
#
# Yeu cau:
#   - docker compose up -d da chay xong, Neo4j + OpenSearch "healthy" (xem README.md)
#   - pip install -r requirements.txt
#   - Buoc 1-6: KHONG can bien moi truong LLM.
#   - Buoc 7 (GraphRAG --create-index, tuy chon -WithGraphRag): CAN OPENAI_API_KEY,
#     OPENAI_BASE_URL, EMBEDDING_MODEL (va TEXT2CYPHER_MODEL de hoi dap sau do).
#     Dat trong .env (script tu nap, khong in gia tri) hoac set tay trong shell.
#
# CANH BAO: buoc 3 chay load_graph.py --reset => XOA SACH du lieu Neo4j hien co.
# Dung -SkipReset de nap lai idempotent (khong xoa).

[CmdletBinding()]
param(
    [switch]$SkipRegenerate,   # Bo qua buoc 1-2 neu normalized/ + resolved/ da moi (tranh goi API NVD lau)
    [switch]$SkipReset,        # Buoc 3 chay load_graph.py KHONG co --reset
    [switch]$SkipAttackPath,   # Bo qua buoc 6 (attack path demo)
    [switch]$WithGraphRag,     # Bat buoc 7: tao vector index + embed mo ta CVE (can env LLM/embedding)
    [switch]$DryRun            # Chi in lenh, khong chay
)

# KHONG dung "Stop": PowerShell 5.1 coi moi dong stderr cua native exe (python log INFO,
# neo4j notification warning) la NativeCommandError va se abort du python chay dung.
# Fail-fast da duoc dam bao bang kiem $LASTEXITCODE trong Invoke-Step (dang tin hon).
$ErrorActionPreference = "Continue"

$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot
Write-Host "Working directory: $RepoRoot" -ForegroundColor Cyan

# --- Package secgraph: cai editable de import duoc (het can PYTHONPATH/sys.path) ---
Write-Host "pip install -e . (editable, idempotent)..."
python -m pip install -e . --no-deps -q
$env:PYTHONUTF8 = "1"

# --- Nap .env (neu co) vao bien moi truong tien trinh; khong in gia tri (co the la secret) ---
$envFile = Join-Path $RepoRoot ".env"
if (Test-Path $envFile) {
    foreach ($line in Get-Content $envFile -Encoding UTF8) {
        if ($line -match '^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$') {
            $val = $Matches[2].Trim().Trim('"').Trim("'")
            if ($val -ne "") { Set-Item -Path "Env:$($Matches[1])" -Value $val }
        }
    }
    Write-Host "Da nap .env (khong in gia tri)." -ForegroundColor DarkGray
}

function Invoke-Step {
    param([string]$Description, [scriptblock]$ScriptBlock)
    if ($DryRun) {
        Write-Host "  [DRY-RUN] $Description" -ForegroundColor Gray
        return
    }
    Write-Host "  $Description" -ForegroundColor White
    & $ScriptBlock
    if ($null -ne $LASTEXITCODE -and $LASTEXITCODE -ne 0) {
        Write-Host "  FAILED (exit code $LASTEXITCODE) - dung pipeline" -ForegroundColor Red
        exit $LASTEXITCODE
    }
    Write-Host "  OK" -ForegroundColor Green
}

# ====================================================================
# Buoc 0 — Kiem tra Neo4j + OpenSearch san sang (khong can env LLM)
# ====================================================================
Write-Host "`n[Buoc 0] Kiem tra Neo4j + OpenSearch..." -ForegroundColor Yellow
$checkNeo4j = @'
import os
from neo4j import GraphDatabase
pw = os.environ.get("NEO4J_PASSWORD")
auth = (os.environ.get("NEO4J_USER", "neo4j"), pw) if pw else None
d = GraphDatabase.driver(os.environ.get("NEO4J_URI", "bolt://localhost:7687"), auth=auth)
d.verify_connectivity()
print("Neo4j OK")
'@
# Pipe script qua stdin (python -) thay vi `python -c`: PowerShell 5.1 mangle dau "
# trong here-string khi truyen lam argument cho native exe -> SyntaxError. Stdin ne hoan toan.
Invoke-Step "Neo4j (docker compose ps -> healthy?)" { $checkNeo4j | python - }
$checkOS = @'
from os_client import make_client
print("OpenSearch:", make_client().info()["version"]["number"])
'@
Invoke-Step "OpenSearch" { $checkOS | python - }

# ====================================================================
# Buoc 1-2 — Sinh fixtures, chuan hoa nguon, entity resolution (khong can Neo4j/LLM)
# ====================================================================
if (-not $SkipRegenerate) {
    Write-Host "`n[Buoc 1/7] Sinh fixtures + chuan hoa nguon..." -ForegroundColor Yellow
    # gen_fixtures: sinh du lieu nguon gia (tat dinh). sources: chuan hoa + goi NVD/EPSS/KEV (co cache offline,
    # lan dau khong cache co the mat ~3 phut; dat NVD_API_KEY de nhanh hon).
    Invoke-Step "gen_fixtures.py" { python -m secgraph.ingestion.gen_fixtures }
    Invoke-Step "sources.py" { python -m secgraph.ingestion.sources }

    Write-Host "`n[Buoc 2/7] Entity resolution..." -ForegroundColor Yellow
    Invoke-Step "entity_resolution.py" { python -m secgraph.ingestion.resolution.entity_resolution }
} else {
    Write-Host "`n[Buoc 1-2/7] BO QUA (-SkipRegenerate)." -ForegroundColor DarkYellow
}

# ====================================================================
# Buoc 3 — Nap graph vao Neo4j (Schema v2, khoa MERGE canonical_id)
# ====================================================================
Write-Host "`n[Buoc 3/7] Nap graph vao Neo4j..." -ForegroundColor Yellow
if ($SkipReset) {
    Invoke-Step "load_graph.py (idempotent, khong xoa)" { python -m secgraph.graph.load_graph }
} else {
    Invoke-Step "load_graph.py --reset (XOA du lieu cu)" { python -m secgraph.graph.load_graph --reset }
}

# ====================================================================
# Buoc 4 — Index alert vao OpenSearch (1653 doc, idempotent)
# ====================================================================
Write-Host "`n[Buoc 4/7] Index alert vao OpenSearch..." -ForegroundColor Yellow
Invoke-Step "index_alerts.py" { python -m secgraph.search.index_alerts }

# ====================================================================
# Buoc 5 — Cham rui ro: gan exposure/asset_criticality + ghi CONNECTS_TO.cost
# (phai chay SAU load_graph; attack path doc cost nay)
# ====================================================================
Write-Host "`n[Buoc 5/7] Cham rui ro (risk_scoring)..." -ForegroundColor Yellow
Invoke-Step "risk_scoring.py" { python -m secgraph.analysis.risk.risk_scoring }

# ====================================================================
# Buoc 6 — (tuy chon) Attack path demo. Chi doc graph; dung -SkipAttackPath de bo qua
# ====================================================================
if (-not $SkipAttackPath) {
    Write-Host "`n[Buoc 6/7] Attack path demo..." -ForegroundColor Yellow
    Invoke-Step "attack_path.py" { python -m secgraph.analysis.attack_path.attack_path }
} else {
    Write-Host "`n[Buoc 6/7] BO QUA (-SkipAttackPath)." -ForegroundColor DarkYellow
}

# ====================================================================
# Buoc 7 — (tuy chon, CAN env LLM) GraphRAG: tao vector index + embed mo ta CVE
# ====================================================================
if ($WithGraphRag) {
    Write-Host "`n[Buoc 7/7] GraphRAG --create-index (can OPENAI_API_KEY, OPENAI_BASE_URL, EMBEDDING_MODEL)..." -ForegroundColor Yellow
    foreach ($v in @("OPENAI_API_KEY", "OPENAI_BASE_URL", "EMBEDDING_MODEL")) {
        if (-not (Test-Path "Env:$v") -and -not $DryRun) {
            Write-Host "  Thieu bien moi truong $v - dat trong .env hoac shell roi chay lai voi -WithGraphRag." -ForegroundColor Red
            exit 1
        }
    }
    Invoke-Step "graphrag_demo.py --create-index" { python -m secgraph.llm.graphrag.graphrag_demo --create-index }
} else {
    Write-Host "`n[Buoc 7/7] BO QUA (them -WithGraphRag de bat; can env LLM/embedding)." -ForegroundColor DarkYellow
}

Write-Host "`nPIPELINE XONG" -ForegroundColor Green
Write-Host ""
Write-Host "Buoc tiep theo (xem README.md, can env LLM cho text2cypher/graphrag/eval):" -ForegroundColor Cyan
Write-Host "  python -m secgraph.llm.text2cypher.text2cypher '<cau hoi>'"
Write-Host "  python -m secgraph.llm.graphrag.graphrag_demo '<cau hoi>'"
Write-Host "  python -m pytest                       # unit"
Write-Host "  Neo4j Browser: http://localhost:7474   (khong can dang nhap)"
