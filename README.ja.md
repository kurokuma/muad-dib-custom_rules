<p align="center">
  <img src="assets/muaddibLogo.png" alt="MUAD'DIB Logo" width="700">
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/muaddib-scanner"><img src="https://img.shields.io/npm/v/muaddib-scanner" alt="npm version"></a>
  <a href="https://github.com/DNSZLSK/muad-dib/actions/workflows/scan.yml"><img src="https://github.com/DNSZLSK/muad-dib/actions/workflows/scan.yml/badge.svg" alt="CI"></a>
  <a href="https://codecov.io/gh/DNSZLSK/muad-dib"><img src="https://codecov.io/gh/DNSZLSK/muad-dib/branch/master/graph/badge.svg" alt="Coverage"></a>
  <a href="https://scorecard.dev/viewer/?uri=github.com/DNSZLSK/muad-dib"><img src="https://api.scorecard.dev/projects/github.com/DNSZLSK/muad-dib/badge" alt="OpenSSF Scorecard"></a>
  <img src="https://img.shields.io/badge/license-MIT-green" alt="License">
  <img src="https://img.shields.io/badge/node-%3E%3D18-brightgreen" alt="Node">
  <img src="https://img.shields.io/badge/IOCs-225%2C000%2B-red" alt="IOCs">
</p>

<p align="center">
  <a href="#インストール">インストール</a> |
  <a href="#使い方">使い方</a> |
  <a href="#主な機能">主な機能</a> |
  <a href="#vs-code">VS Code</a> |
  <a href="#cicd">CI/CD</a>
</p>

<p align="center">
  <a href="README.md">English</a> |
  <a href="README.ja.md">日本語</a> |
  <a href="docs/README.fr.md">Français</a>
</p>

---

## MUAD'DIBとは？

npm と PyPI のサプライチェーン攻撃は急増しています。2025年には Shai-Hulud が 25,000 以上のリポジトリを侵害しました。既存ツールは脅威を検知できても、対応まで支援しないことが多いです。

MUAD'DIB は **14 個の並列スキャナ**（200 の検知ルール）、**難読化解除エンジン**、**モジュール間データフロー解析**、**複合スコアリング**、**ML 分類器**（XGBoost）、そして gVisor/Docker サンドボックスを組み合わせ、npm と PyPI パッケージに含まれる既知の脅威や不審な挙動パターンを検出します。

---

## 位置づけ

MUAD'DIB は教育目的のツールであり、無料で使える第一防衛線です。**既知の** npm / PyPI 脅威（225,000 件以上の IOC）と、不審な挙動パターンを検知します。

**エンタープライズ用途の防御**には、以下の製品も検討してください。
- [Socket.dev](https://socket.dev) - ML ベースの挙動解析、クラウドサンドボックス
- [Snyk](https://snyk.io) - 大規模な脆弱性データベース、CI/CD 連携
- [Opengrep](https://opengrep.dev) - 高度なデータフロー解析、Semgrep ルール

---

## インストール

### npm（推奨）

```bash
npm install -g muaddib-scanner
```

### ソースから導入

```bash
git clone https://github.com/DNSZLSK/muad-dib
cd muad-dib
npm install
npm link
```

---

## 使い方

### 基本スキャン

```bash
muaddib scan .
muaddib scan /path/to/project
```

npm（`package.json`, `node_modules`）と Python（`requirements.txt`, `setup.py`, `pyproject.toml`）の依存関係を両方スキャンします。

### インタラクティブモード

```bash
muaddib
```

### セーフインストール

```bash
muaddib install <package>
muaddib install lodash axios --save-dev
muaddib install suspicious-pkg --force    # 脅威があっても強制インストール
```

インストール前にパッケージをスキャンします。既知の悪性パッケージはブロックされます。

### リスクスコア

各スキャンでは 0 から 100 のリスクスコアを表示します。

```
[SCORE] 58/100 [***********---------] HIGH
```

### Explain モード

```bash
muaddib scan . --explain
```

各検知について、ルール ID、MITRE ATT&CK テクニック、参照情報、対応プレイブックを表示します。

### エクスポート

```bash
muaddib scan . --json > results.json     # JSON
muaddib scan . --html report.html        # HTML
muaddib scan . --sarif results.sarif     # SARIF (GitHub Security)
```

`--json` は JSON 結果オブジェクトのみを出力します。警告や進捗表示などの非 JSON メッセージは抑制されるため、`muaddib scan . --json > results.json` のようなリダイレクトでも壊れません。

### カスタムルール

```bash
muaddib scan .                           # ./custom-rules があれば自動読込
muaddib scan . --rules-dir ./team-rules  # 追加ルールディレクトリ
muaddib scan . --rules-dir ./custom-rules --rules-dir ./team-rules
```

MUAD'DIB は組み込みスキャナを変更せず、`custom-rules/` から外部定義のパターンマッチルールを読めます。存在しないルールディレクトリは無視されます。
npm 向けの初期サンプルは `custom_rule/` にあります。対象プロジェクトの `custom-rules/` にコピーして利用できます。

### 重大度しきい値

```bash
muaddib scan . --fail-on critical  # CRITICAL のみで失敗
muaddib scan . --fail-on high      # HIGH と CRITICAL で失敗（デフォルト）
```

### Paranoid モード

```bash
muaddib scan . --paranoid
```

より厳格な検知モードです。ネットワークアクセス、サブプロセス実行、動的コード評価、機微ファイルアクセスを強く警戒します。

### Webhook 通知

```bash
muaddib scan . --webhook "https://discord.com/api/webhooks/..."
```

厳格フィルタリング（v2.1.2）では IOC 一致、サンドボックスで確認された脅威、カナリアトークン流出のみ通知します。優先度トリアージ（v2.10.21）では P1（赤, IOC/サンドボックス/カナリア）, P2（橙, 高スコア/複合検知）, P3（黄, その他）を使います。

### 挙動異常検知（v2.0）

```bash
muaddib scan . --temporal-full      # 4 種の時系列特徴をすべて使用
muaddib scan . --temporal           # ライフサイクルスクリプトの急変を検知
muaddib scan . --temporal-ast       # バージョン間 AST 差分
muaddib scan . --temporal-publish   # 公開頻度の異常
muaddib scan . --temporal-maintainer # メンテナ変更検知
```

パッケージのバージョン差分を解析し、IOC データベースへ登録される前のサプライチェーン攻撃を検知します。詳細は [Evaluation Methodology](docs/EVALUATION_METHODOLOGY.md) を参照してください。

### Docker サンドボックス

```bash
muaddib sandbox <package-name>
muaddib sandbox <package-name> --strict
```

隔離された Docker コンテナで動的解析を行います。`strace`、`tcpdump`、ファイルシステム差分、カナリアトークン、CI 風環境、そして時限型ペイロード検知のための preload モンキーパッチを含みます（`0h`, `72h`, `7d` オフセットで複数回実行）。

### その他のコマンド

```bash
muaddib watch .                    # リアルタイム監視
muaddib daemon                     # デーモンモード（npm install を自動スキャン）
muaddib update                     # IOC 更新（高速, 約5秒）
muaddib scrape                     # IOC 全更新（約5分）
muaddib diff HEAD~1                # 直前コミットとの差分比較
muaddib init-hooks                 # Pre-commit フック設定（husky/pre-commit/git）
muaddib scan . --breakdown         # スコア分解の説明
muaddib replay                     # Ground truth 検証（60/64 TPR@3）
```

---

## 主な機能

### 14 個の並列スキャナ

| スキャナ | 検知内容 |
|---------|----------|
| AST Parse (acorn) | `eval`, `Function`, 資格情報窃取, バイナリドロッパ, prototype hook |
| Pattern Matching | シェルコマンド, リバースシェル, dead man's switch |
| Dataflow Analysis | 資格情報読取 + ネットワーク送信（単一ファイル/複数ファイル） |
| Obfuscation Detection | JS 難読化パターン（`.min.js` は除外） |
| Deobfuscation Pre-processing | 文字列連結, charcode, base64, hex array, const 伝播 |
| Inter-module Dataflow | ファイル間 taint 伝播（3-hop chain, class method） |
| Intent Coherence | ファイル内 source-sink ペア（資格情報 + eval/network） |
| Typosquatting | npm + PyPI（Levenshtein distance） |
| Python Scanner | `requirements.txt`, `setup.py`, `pyproject.toml`, 14K+ の PyPI IOC |
| Shannon Entropy | 高エントロピー文字列（5.5 bits 以上かつ 50 文字以上） |
| AI Config Scanner | `.cursorrules`, `CLAUDE.md`, `copilot-instructions.md` への注入 |
| Package/Dependencies | ライフサイクルスクリプト, IOC 一致（225K+ packages） |
| GitHub Actions | Shai-Hulud バックドア検知 |
| Hash Scanner | 既知の悪性ファイルハッシュ |

### 200 の検知ルール

すべてのルールは MITRE ATT&CK テクニックにマッピングされています。完全なルール一覧は [SECURITY.md](SECURITY.md#detection-rules-v21021) を参照してください。

### 検知可能なキャンペーン

| キャンペーン | 状態 |
|-------------|------|
| GlassWorm (2026, 433+ packages) | Detected |
| Shai-Hulud v1/v2/v3 (2025) | Detected |
| event-stream (2018) | Detected |
| eslint-scope (2018) | Detected |
| Protestware (node-ipc, colors, faker) | Detected |
| Typosquats (crossenv, mongose, babelcli) | Detected |

---

## VS Code

VS Code 拡張は npm プロジェクトを自動スキャンできます。

```bash
code --install-extension dnszlsk.muaddib-vscode
```

- `MUAD'DIB: Scan Project` - プロジェクト全体をスキャン
- `MUAD'DIB: Scan Current File` - 現在のファイルをスキャン
- 設定: `muaddib.autoScan`, `muaddib.webhookUrl`, `muaddib.failLevel`

詳細は [vscode-extension/README.md](vscode-extension/README.md) を参照してください。

---

## CI/CD

### GitHub Actions（Marketplace）

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read
    steps:
      - uses: actions/checkout@v4
      - uses: DNSZLSK/muad-dib@v1
        with:
          path: '.'
          fail-on: 'high'
          sarif: 'results.sarif'
```

| 入力 | 説明 | デフォルト |
|------|------|------------|
| `path` | スキャン対象パス | `.` |
| `fail-on` | 失敗扱いにする最小重大度 | `high` |
| `sarif` | SARIF 出力ファイルパス | |
| `paranoid` | 超厳格検知 | `false` |

### Pre-commit フック

```bash
muaddib init-hooks                        # 自動判定（husky/pre-commit/git）
muaddib init-hooks --type husky           # husky を強制
muaddib init-hooks --mode diff            # 新規脅威のみブロック
```

pre-commit フレームワークを使う場合:

```yaml
repos:
  - repo: https://github.com/DNSZLSK/muad-dib
    rev: v2.10.57
    hooks:
      - id: muaddib-scan
```

---

## 評価指標

| 指標 | 結果 | 詳細 |
|------|------|------|
| **ML FPR** | **2.85%** (239/8,393 holdout) | 56,564 サンプル・64 特徴量で再学習した XGBoost、threshold=0.710 |
| **ML TPR** | **99.93%** (2,918/2,920 holdout) | OSSF/GHSA/npm 相関により confirmed_malicious 377 件 |
| **Wild TPR** (Datadog 17K) | **92.8%** (13,538/14,587 in-scope) | 17,922 パッケージ。3,335 は JS なしで除外。カテゴリ別: compromised_lib 97.8%, malicious_intent 92.1% |
| **TPR@3** (検知率) | **93.75%** (60/64) | 実攻撃 66 件中、対象内 64 件。Threshold=3 は何らかのシグナルがあれば検知 |
| **TPR@20** (アラート率) | **85.9%** (55/64) | 運用アラート閾値 20。ADR/FPR と整合 |
| **FPR rules** (良性 curated) | **14.0%** (74/532) | `npm pack` で取得した実ソースの npm パッケージ 532 件 |
| **FPR after ML** | **8.3%** (44/529) | ML が T1 良性 31 件中 30 件を抑制。GT/ADR の抑制は 0 |
| **FPR** (良性 random) | **7.5%** (15/200) | 層化抽出した npm パッケージ 200 件 |
| **ADR** (Adversarial + Holdout) | **96.3%** (103/107) | 67 adversarial + 40 holdout。global threshold=20 |

**3068 tests**、**66 files**、**200 rules**（195 RULES + 5 PARANOID）。

> **ML 再学習手法 (v2.10.51):**
> - Ground truth: auto-labeler により confirmed_malicious と判定された 377 件（OSSF malicious-packages, GitHub Advisory Database, npm registry takedown 相関）
> - Dataset: 56,564 samples（malicious 14,602 / clean 41,962）、層化 80/20 split
> - Grid search: depth=4, estimators=300, lr=0.05。AUC-ROC=0.999, F1=0.960
> - Leaky feature filter: 23 個のリーキー/死んだ特徴量を除去
>
> **静的評価の注意点:**
> - TPR は稼働中の Node.js 攻撃サンプル 64 件で測定（全 66 件中 2 件はスコープ外）
> - TPR@3 は検知率、TPR@20 は運用アラート閾値
> - FPR は人気 npm パッケージ 532 件の curated セットで測定（ランダムサンプルではない）
> - ADR は v2.6.5 時点の global threshold（score >= 20）で測定

実験プロトコル、holdout 履歴、Datadog ベンチマークの詳細は [Evaluation Methodology](docs/EVALUATION_METHODOLOGY.md) を参照してください。

---

## カスタムルール

カスタムルールは、プロジェクト単位またはチーム共有で使える小規模な外部パターンマッチング機構です。

- デフォルトディレクトリ: スキャン対象内の `custom-rules/`
- 追加ディレクトリ: `--rules-dir <path>`（複数指定可）
- 対応ファイル: `*.yaml`, `*.yml`, `*.json`
- 再帰的に読み込み
- 不正なファイルやルールは警告付きでスキップ
- 完全な YARA / Sigma 互換ではない
- v1 は文字列/正規表現マッチのみ
- 検知結果は通常スキャン、explain、スコア、JSON 出力に統合される

### 対応ターゲット

- `file_content`: テキスト系ファイルの内容
- `filename`: 正規化された相対ファイルパス
- `package_json_field`: `package.json` のドット記法フィールド。例: `scripts.postinstall`

### 対応マッチ種別

- `regex`
- `contains`
- `contains_any`
- `contains_all`

### ルールファイル形式

```yaml
rules:
  - id: CUSTOM-STR-001
    name: Suspicious eval with base64
    severity: high
    confidence: medium
    target: file_content
    file_glob:
      - "**/*.js"
    exclude_glob:
      - "**/test/**"
      - "**/docs/**"
    match:
      type: regex
      pattern: "(eval\\s*\\(|Function\\s*\\().{0,200}(atob|Buffer\\.from\\([^\\)]*base64)"
      flags: "is"
    description: "eval/function use near base64 decoding"
    mitre: T1059
    references:
      - "https://attack.mitre.org/techniques/T1059/"

  - id: CUSTOM-PKG-001
    name: Suspicious postinstall downloader
    target: package_json_field
    field: "scripts.postinstall"
    match:
      type: regex
      pattern: "curl|wget|powershell|Invoke-Expression"
      flags: "i"

  - id: CUSTOM-FILE-001
    name: Suspicious filename
    target: filename
    match:
      type: regex
      pattern: "setup_bun\\.js|preinstall\\.js"
      flags: "i"
```

### スキーマ

- `id`: 必須文字列
- `name`: 必須文字列
- `severity`: 任意、デフォルトは `medium`
- `confidence`: 任意、デフォルトは `medium`
- `description`: 任意文字列
- `mitre`: 任意文字列
- `references`: 任意の文字列配列
- `target`: 必須 enum `file_content | filename | package_json_field`
- `file_glob`: 任意の glob 配列
- `exclude_glob`: 任意の glob 配列
- `field`: `package_json_field` の場合のみ必須
- `match`: 必須オブジェクト

`regex` の場合:
- `pattern`: 必須文字列
- `flags`: 任意文字列

`contains` の場合:
- `pattern`: 必須文字列

`contains_any` と `contains_all` の場合:
- `patterns`: 必須の文字列配列

### 例のディレクトリ構成

```text
custom-rules/
  content-rules.yaml
  package-rules.json
  team/
    filename-rules.yaml
```

### npm 用サンプルルール

リポジトリには `custom_rule/` 配下に npm 向けスタータールールが含まれています。

```text
custom_rule/
  npm-content-rules.yaml
  npm-package-rules.json
  npm-filename-rules.yaml
```

典型的なセットアップ:

```bash
mkdir -p custom-rules
cp custom_rule/* custom-rules/
muaddib scan .
```

サンプルファイルは `examples/custom-rules/` にもあります。

### 制限事項

- YARA 互換レイヤーなし
- Sigma 互換レイヤーなし
- v1 には AST DSL / taint DSL / dataflow DSL なし
- `file_content` はテキスト系として妥当なファイルのみ対象
- `package_json_field` は文字列に解決されるフィールドのみ対象

---

## コントリビュート

### IOC の追加

`iocs/` 配下の YAML を編集します。

```yaml
- id: NEW-MALWARE-001
  name: "malicious-package"
  version: "*"
  severity: critical
  confidence: high
  source: community
  description: "Threat description"
  references:
    - https://example.com/article
  mitre: T1195.002
```

### 開発

```bash
git clone https://github.com/DNSZLSK/muad-dib
cd muad-dib
npm install
npm test
```

### テスト

- **3068 tests** / 66 のモジュール化テストファイル
- **56 fuzz tests** - 不正入力、ReDoS、Unicode、バイナリ
- **Datadog 17K benchmark** - 対象内 confirmed malware 14,587 件
- **Ground truth validation** - 実攻撃 66 件（93.75% TPR@3, 85.9% TPR@20）
- **False positive validation** - 532 curated npm で FPR 14.0%、ML 後 8.3%、random 200 件で 7.5%

---

## コミュニティ

- Discord: https://discord.gg/y8zxSmue

---

## ドキュメント

- [Blog](https://dnszlsk.github.io/muad-dib/blog/) - サプライチェーン脅威検知に関する技術記事
- [Carnet de bord](docs/CARNET_DE_BORD_MUADDIB.md) - 開発ジャーナル（フランス語）
- [Documentation Index](docs/INDEX.md) - ドキュメント索引
- [Evaluation Methodology](docs/EVALUATION_METHODOLOGY.md) - 実験プロトコル、holdout スコア
- [Threat Model](docs/threat-model.md) - MUAD'DIB が検知できるもの / できないもの
- [Adversarial Evaluation](ADVERSARIAL.md) - Red team サンプルと ADR 結果
- [Security Policy](SECURITY.md) - 検知ルール参照（200 rules）
- [Security Audit](docs/SECURITY_AUDIT.md) - バイパス検証レポート
- [FP Analysis](docs/EVALUATION.md) - 過去の false positive 分析

---

## ライセンス

MIT
