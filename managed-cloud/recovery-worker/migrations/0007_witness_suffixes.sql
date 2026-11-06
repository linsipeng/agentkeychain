-- Retain bounded verified suffixes to authenticate later revocation boundaries.
-- Old installations retain their heads; absent historical boundary evidence fails closed.
ALTER TABLE roster_witness ADD COLUMN checkpoint_suffix TEXT NOT NULL DEFAULT '[]';
