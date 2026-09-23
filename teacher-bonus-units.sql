-- Apply once to each existing database before deploying worker.js.
-- Existing rewards retain their previous currency interpretation.
ALTER TABLE teacher_bonuses ADD COLUMN bonus_unit TEXT NOT NULL DEFAULT 'ILS' CHECK (bonus_unit IN ('ILS', 'hours', 'units'));
