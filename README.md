# TRPG Discord Bot (AWS Serverless, Python)

Discord上のTRPG運営で発生する情報散逸/日程調整/状態管理を解消するためのAWSサーバレス構成のMVP実装です。サーバレス（API Gateway -> Lambda）で署名検証、状態管理、Embed/UI生成までを最小セットで揃えています。

## リポジトリ構成

```
trpg-discord-bot/
├── scenario-weaver/          # Discord Activity UI (git submodule)
├── activity-ui.yaml          # UI配信用 (S3 + CloudFront) スタック
├── scripts/
│   ├── deploy_backend.py     # Backend(SAM) デプロイ
│   ├── deploy_activity_ui.sh # UI デプロイ
│   ├── register_commands.py  # Discordコマンド登録
│   └── ddb_purge_table.py    # DynamoDBテーブル全消去(開発用)
├── src/
│   └── trpg_bot/
│       ├── __init__.py
│       ├── config.py
│       ├── db.py
│       ├── discord_api.py
│       ├── embeds.py
│       ├── handler.py
│       ├── routes.py
│       └── repositories.py
├── requirements.txt
├── template.yaml
└── README.md
```

## UI (Discord Activity)

UIは `scenario-weaver/` にあります（git submodule）。

```bash
git clone --recurse-submodules https://github.com/yakitori33/trpg-discord-bot.git
# 既にclone済みなら:
git submodule update --init --recursive
```

UI単体リポジトリ: `https://github.com/yakitori33/scenario-weaver.git`

ローカル（モック）: `cd scenario-weaver && npm install && npm run dev:mock`  
Discord（本実装）: `cd scenario-weaver && npm install && npm run dev:live`（※ Activity内でのみ）

## MVP機能
- 署名検証（X-Signature-Ed25519/Timestamp）とInteractionルーティング。Type=1 Pingは即応答、コマンドは3秒以内ACK。
- State machineで`proposed/recruiting/scheduling/confirmed/running/completed/canceled`管理。確定系操作はGM/作成者のみ。
- セッションカード（Embed）をスレッド冒頭に投稿＆ピン留め。参加/回答/確定/完了時に自動更新し、未入力者と次アクションを常に表示。
- シナリオ管理: add/edit/info/search/canrun_add/canrun_remove/who_can_gm/who_played。
- 日程調整: poll create → slotごとのOK/MAYBE/NO、missing検出、status集計Embed、finalize（slot確定でscheduled_start/end反映）。
- 完了処理: セッション参加者をPlayHistoryへ自動記録（PL/GM）、監査ログ記録。
- 催促: `/nudge poll_id` が未入力者を検出しスレッドにメンション投稿（クールダウンはAuditログで管理拡張を想定）。

## State machine（抜粋）
- `recruiting` → 参加受付。`/poll create`で`scheduling`へ。
- `scheduling` → 日程入力待ち。`/poll finalize` で `confirmed` に遷移（slot指定で予定を反映）。
- `confirmed/running` → 当日運用。`/complete` で `completed`。
- `canceled` は将来追加用（操作は禁止）。

## Slash Commands / UI
- `/setup`: #trpg-ops で管制塔パネル(Embed + ボタン)を投稿・ピン留め。ボタンは `handle_component` で案内を返す。
- `/health`: DynamoDBテーブル/GSIの状態をチェック（ephemeral）。
- `/scenario ...`: シナリオ登録/編集/検索/回せるGM管理/履歴参照。
- `/session create title scenario_id? gm_user_id? min_players? max_players?` → 新規スレッド作成 + セッションカードをピン留め。`join/leave` は冪等。
- `/poll create session_id deadline? slots="YYYY-MM-DD HH:MM/YYYY-MM-DD HH:MM;..." timezone_basis?` → statusを`scheduling`へ。
- `/poll avail_input slot_id status=OK|MAYBE|NO comment?` → 最新カードを更新。
- `/poll status poll_id` → 集計Embed（slot番号付き、未入力者表示）。
- `/poll finalize poll_id? session_id? slot_id?` → GM/作成者のみ。slot指定でscheduled_start/endに反映。
- `/nudge poll_id` → 未入力者にメンションして催促（GM/作成者のみ、日程調整中のみ）。
- `/complete session_id scenario_id` → 参加者をPlayHistoryに記録し `completed` に遷移。

## Embeds/Components
- 管制塔パネル: `embeds.ops_panel_embed`
- セッションカード: `embeds.session_card_embed`（状態・予定・未入力者・次アクション・締切）
- 日程集計: `embeds.availability_summary_embed`（slot番号付きで finalize 対応しやすく）
- シナリオ情報: `embeds.scenario_info_embed`

## データストア (DynamoDB 単一テーブル)
- DynamoDB単一テーブル（パーティションキー+ソートキーのみ必須）で、以下のパーティションに格納します。
- BotはテーブルのKeySchemaからキー属性名を自動検出します（例: `PK`/`SK` でも `pk`/`sk` でも動作）。必要なら `DDB_PK_NAME`/`DDB_SK_NAME` で上書きできます。
  - `SCENARIO#{id}`: `META`、`GM#{user}`、`PLAY#{timestamp}#{user}` など
  - `SESSION#{id}`: `META`、`PART#{user}`、`POLL#{created_at}#{poll_id}`、`AUDIT#...`
  - `POLL#{id}`: `META`、`SLOT#{id}`、`RESP#{slot_id}#{user}`
  - `SLOT#{id}`: `META`（slot_id→poll_id の逆引き）
  - `USER#{discord_id}`: `PROFILE`
- GSIは不要です（`/health` はGSIsを表示しますが、存在しなくてもエラーにしません）。
- `POLL#{poll_id}` の `META` に `session_id` を持たせ、`SLOT#{slot_id}` の `META` に `poll_id` を持たせることで、GSIなしで参照を解決します。
- IDはUUID短縮(例: `scn_abcdefgh`)で払い出し、すべて文字列で扱います。
- `migrations/001_init.sql` は旧PostgreSQL版の参考用に残しています（現在は未使用）。

## AWSサーバレス構成 (SAM)

- Discord Interactions Endpoint -> API Gateway (HTTP API) -> Lambda
- DynamoDB（単一テーブル設計）、EventBridge Scheduler(リマインド/催促拡張用)、Secrets Manager/SSM(キー管理)

## VSCode デプロイボタン（Tasks）

- [Run: Deploy Backend (SAM)](vscode://command/workbench.action.tasks.runTask?%22Deploy%3A%20Backend%20%28SAM%29%22)
- [Run: Deploy Activity UI (S3+CloudFront)](vscode://command/workbench.action.tasks.runTask?%22Deploy%3A%20Activity%20UI%20%28S3%2BCloudFront%29%22)

※ `.vscode/tasks.json` は実行前にリポジトリ直下の `.env` を `source` します（`.env` はgitignore済みなので、`DISCORD_BOT_TOKEN` / `DISCORD_CLIENT_SECRET` / `VITE_DISCORD_CLIENT_ID` などを置けます）。

### デプロイ
1. 依存をインストール
   ```bash
   python -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```
2. SAMビルド
   ```bash
   sam build
   ```
3. デプロイ（環境変数を渡す）
   ```bash
   sam deploy --guided \
     --parameter-overrides \
       DiscordApplicationId=YOUR_DISCORD_APPLICATION_ID \
       DiscordClientSecret=YOUR_DISCORD_CLIENT_SECRET \
       DiscordPublicKey=YOUR_DISCORD_PUBLIC_KEY \
       DiscordBotToken=YOUR_BOT_TOKEN \
       TableName=trpg-discord-bot \
       CreateTable=false
   ```
4. デプロイ後、API Gateway URLをDiscord Developer PortalのInteractions Endpoint URLに設定。
   - Discord Activity UI から呼ぶAPIベースURLは `ApiBaseUrl` Output を `VITE_API_BASE_URL` に設定します（`/api/oauth/token`, `/api/sessions/create`）。
5. Discord Activity のOAuthログインを使う場合、Discord Developer Portal の **OAuth2 → Redirects** に `https://discord.com/oauth2/authorized` を追加。
   - `UiApiFunction` のトークン交換はこの `redirect_uri` を送ります（現状は固定/デフォルト）。

## コマンド登録（Discord）
スラッシュコマンドはDiscord側への登録が必要です（ギルドコマンド推奨。反映が速い）。

```bash
export DISCORD_BOT_TOKEN=YOUR_BOT_TOKEN
export DISCORD_GUILD_ID=YOUR_GUILD_ID   # ギルドコマンドにする場合

python scripts/register_commands.py
```

## 注意/補足
- `DISCORD_BOT_TOKEN` が無いとスレッド作成・メッセージ投稿/編集（カード更新）は動きません。
- DynamoDBテーブル名は `TABLE_NAME` 環境変数で渡します（`template.yaml` が自動設定）。ローカルのDynamoDB Localを使う場合は `DYNAMODB_ENDPOINT` を渡してください。
- ボタン/セレクト/モーダルの追加は `routes.py` の `handle_component` を起点に拡張してください。
- 冪等性: 参加/回答/Capability登録はUPSERTで二重押下に耐える設計です。
