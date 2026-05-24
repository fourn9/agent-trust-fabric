# CLAUDE.md — ATF プロジェクト

Claude Code / その他 AI コーディングエージェント向けのプロジェクト指示。

## このプロジェクトは何か

`agent-trust-fabric` (ATF) — 異なる開発者・異なるベンダーが作った AI エージェント
同士が、安全に発見・委任・検証・監査を行うための、中立 OSS substrate。

詳細は [`README.md`](./README.md) と
[`docs/specs/2026-05-23-atf-design.md`](./docs/specs/2026-05-23-atf-design.md) を読む。

## セッション開始時に読むもの

1. `README.md` — プロダクト概要 + quickstart
2. `docs/specs/2026-05-23-atf-design.md` — 設計の source of truth
3. `decisions/0001-design-criteria.md` — 判断基準（trade-off の優先順位）
4. `decisions/` 内の他の ADR — 重い判断の履歴

## 判断に迷ったら

[ADR-0001](./decisions/0001-design-criteria.md) の 8 つの判断基準を必ず参照。
新しい trade-off に直面したら、その判断基準のどれを根拠にしたかを示してから決定する。

## 開発ワークフロー（仕様 → 計画 → 実装 → テスト → レビュー）

1. **仕様明確化** — 曖昧な要求は実装前に設計書で合意する
2. **計画** — タスクを最小単位に分割
3. **段階的実装** — 一度に1スライス、即検証
4. **テスト** — プロトコルロジックはテストを先に書く（TDD）
5. **レビュー** — 品質ゲートを通す
6. **セキュリティ** — ATF はセキュリティ製品なので特に厳格に

## 作業作法

- **設計書の更新は差分提示 → 確認 → 適用**。設計書は仕様の source of truth。
- **仕様変更を伴うコード変更は ADR を先に書く**。
- **コミット・push は明示的許可がない限り行わない**。
- **`spec/` 以下の RFC 風ドキュメントは特に厳格**。breaking change は ADR 必須。

## 進捗管理

- **decisions/** に重い判断を ADR として残す
- GitHub Issues / Projects でロードマップ（設計書 §7）を管理

## してはいけないこと

- 中央 server を前提とした設計（Federation 純度を壊す）
- 単一ベンダー特化機能（Vendor 中立性を壊す）
- 設計書から外れた実装（仕様変更なら設計書を先に更新）
- セキュリティ機能の opt-out 化（判断基準 6 違反）
- breaking change を 2 minor 後方互換せずに入れる（判断基準 7 違反）
