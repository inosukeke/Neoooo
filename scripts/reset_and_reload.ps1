# Reset & reload toàn bộ pipeline Neo4j + OpenSearch sau khi merge PR2.
#
# Bối cảnh: commit 2.9 (canonical_id prefix ast-/usr-) trong PR2 đổi format
# canonical_id, đòi hỏi nạp lại toàn bộ graph. Script này tự động 6 bước:
#   1. Verify Neo4j + OpenSearch đang chạy
#   2. Regenerate pipeline (gen_fixtures, sources, entity_resolution)
#   3. --reset Neo4j và nạp lại
#   4. Verify canonical_id format mới (ast-014, usr-003)
#   5. Re-index OpenSearch (1620 doc)
#   6. Chạy unit + integration test (optional)
#
# Dùng:
#   powershell -ExecutionPolicy Bypass -File scripts/reset_and_reload.ps1
#
# Yêu cầu:
#   - Neo4j + OpenSearch Docker đang chạy (xem README.md)
#   - Python deps đã cài: pip install -r requirements.txt
#   - PowerShell 5.1+ (Windows) hoặc PowerShell 7+ (cross-platform)

[CmdletBinding()]
param(
    [switch]$SkipRegenerate,   # Bỏ qua bước 2 nếu normalized/ + resolved/ đã mới
    [switch]$SkipTest,         # Bỏ qua bước 6 (integration test tốn thời gian)
    [switch]$DryRun            # Chỉ in command, không chạy (để review)
)

$ErrorActionPreference = "Stop"

# --- Đường dẫn gốc (chạy từ root repo) ---
$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot
Write-Host "Working directory: $RepoRoot" -ForegroundColor Cyan

# --- Package secgraph: cai editable de import duoc (het can PYTHONPATH/sys.path) ---
Write-Host "pip install -e . (editable, idempotent)..."
python -m pip install -e . --no-deps -q

# ====================================================================
# Helper: in lệnh (DryRun) hoặc chạy thật, fail fast nếu exit != 0
# ====================================================================
function Invoke-Step {
    param(
        [string]$Description,
        [scriptblock]$ScriptBlock
    )
    if ($DryRun) {
        Write-Host "  [DRY-RUN] $Description" -ForegroundColor Gray
        return
    }
    Write-Host "  $Description" -ForegroundColor White
    & $ScriptBlock
    if ($LASTEXITCODE -ne 0 -and $null -ne $LASTEXITCODE) {
        Write-Host "  FAILED (exit code $LASTEXITCODE)" -ForegroundColor Red
        exit $LASTEXITCODE
    }
    Write-Host "  OK" -ForegroundColor Green
}

# ====================================================================
# Bước 1 — Verify Neo4j + OpenSearch đang chạy
# ====================================================================
Write-Host "`n[Buoc 1/6] Verify Neo4j + OpenSearch dang chay..." -ForegroundColor Yellow

$checkNeo4j = @'
from neo4j import GraphDatabase
d = GraphDatabase.driver("bolt://localhost:7687", auth=None)
d.verify_connectivity()
print("Neo4j OK")
'@

Invoke-Step "Kiem tra Neo4j..." {
    python -c $checkNeo4j
    if ($LASTEXITCODE -ne 0) {
        throw "Neo4j khong ket noi duoc. Khoi dong: docker start neo4j-sec"
    }
}

$checkOS = @'
from os_client import make_client
c = make_client()
print("OpenSearch:", c.info()["version"]["number"])
'@

Invoke-Step "Kiem tra OpenSearch..." {
    python -c $checkOS
    if ($LASTEXITCODE -ne 0) {
        throw "OpenSearch khong ket noi duoc. Khoi dong: docker start opensearch-sec"
    }
}

# ====================================================================
# Bước 2 — Regenerate pipeline (chỉ khi normalized/ + resolved/ cũ)
# ====================================================================
if (-not $SkipRegenerate) {
    Write-Host "`n[Buoc 2/6] Regenerate pipeline..." -ForegroundColor Yellow

    Invoke-Step "gen_fixtures.py..." { python -m secgraph.ingestion.gen_fixtures }
    Invoke-Step "sources.py..." { python -m secgraph.ingestion.sources }
    Invoke-Step "entity_resolution.py..." { python -m secgraph.ingestion.resolution.entity_resolution }
} else {
    Write-Host "`n[Buoc 2/6] BO QUA (--SkipRegenerate)." -ForegroundColor DarkYellow
}

# ====================================================================
# Bước 3 — --reset Neo4j và nạp lại
# ====================================================================
Write-Host "`n[Buoc 3/6] --reset Neo4j + nap lai..." -ForegroundColor Yellow

Invoke-Step "load_graph.py --reset..." {
    $env:ALLOW_DESTRUCTIVE_TESTS = "1"
    python -m secgraph.graph.load_graph --reset
    if ($LASTEXITCODE -ne 0) {
        throw "load_graph.py --reset that bai"
    }
}

# ====================================================================
# Bước 4 — Verify canonical_id format mới (ast-014, usr-003)
# ====================================================================
Write-Host "`n[Buoc 4/6] Verify canonical_id format moi..." -ForegroundColor Yellow

$verifyScript = @'
from neo4j import GraphDatabase
d = GraphDatabase.driver("bolt://localhost:7687", auth=None)
with d.session() as s:
    rows = s.run("MATCH (a:Asset) RETURN a.canonical_id AS cid LIMIT 3").data()
    print("Asset:", rows)
    rows = s.run("MATCH (u:User) RETURN u.canonical_id AS cid LIMIT 3").data()
    print("User:", rows)
    rows = s.run(
        'MATCH ()-[r:IN_NETWORK]->(:Network {cidr: "unknown"}) RETURN count(r) AS n'
    ).single()
    print("Unknown network edges:", rows["n"])
'@

Invoke-Step "Query Neo4j: canonical_id phai co prefix ast-/usr-" {
    $out = python -c $verifyScript 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Verify that bai"
    }
    $out | ForEach-Object { Write-Host "  $_" }
    if ($out -notmatch "ast-") {
        throw "Asset canonical_id KHONG co prefix 'ast-' - check lai commit 2.9 hoac chua merge PR2"
    }
    if ($out -notmatch "usr-") {
        throw "User canonical_id KHONG co prefix 'usr-' - check lai commit 2.9 hoac chua merge PR2"
    }
}

# ====================================================================
# Bước 5 — Re-index OpenSearch (1620 doc)
# ====================================================================
Write-Host "`n[Buoc 5/6] Re-index OpenSearch..." -ForegroundColor Yellow

Invoke-Step "index_alerts.py..." { python -m secgraph.search.index_alerts }

# ====================================================================
# Bước 6 — Chạy test (optional)
# ====================================================================
if (-not $SkipTest) {
    Write-Host "`n[Buoc 6/6] Chay unit test..." -ForegroundColor Yellow

    Invoke-Step "Unit test (khong can service that)..." {
        python -m pytest tests/ -v -q
    }
} else {
    Write-Host "`n[Buoc 6/6] BO QUA (--SkipTest)." -ForegroundColor DarkYellow
}

# ====================================================================
# Tổng kết
# ====================================================================
Write-Host "`nRESET & RELOAD XONG" -ForegroundColor Green
Write-Host ""
Write-Host "Da lam:" -ForegroundColor Cyan
Write-Host "  - canonical_id format moi: ast-NNN / usr-NNN"
Write-Host "  - Network 4 (3 zone + 'unknown' cho asset khong IP)"
Write-Host "  - IN_NETWORK 26 canh (21 that + 5 den unknown)"
Write-Host "  - OpenSearch 1620 doc re-indexed"
Write-Host ""
Write-Host "Buoc tiep theo (manual):" -ForegroundColor Cyan
Write-Host "  - Chay e2e Text2Cypher: python -m secgraph.llm.text2cypher.text2cypher '...'"
Write-Host "  - Chay integration test: python -m pytest tests/ -v -m integration"
Write-Host "  - Neu muon visual: mo http://localhost:7474 (Neo4j Browser)"