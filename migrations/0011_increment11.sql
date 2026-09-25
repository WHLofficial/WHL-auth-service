-- v3.2.0（PRD P1-4）：解绑确认码复用 bind_code 表，加 kind 区分两类码。
-- 'bind' = 绑定码（网页生成 → QQ 群「绑定 <码>」核销，P0-8 原语义）；
-- 'unbind' = 解绑确认码（网页发起解绑 → QQ 群「解绑 <码>」经
--   /api/identity/unbind/confirm 核销）。存量行全部是绑定码，DEFAULT 'bind' 语义不变。
ALTER TABLE bind_code ADD COLUMN kind TEXT NOT NULL DEFAULT 'bind';
