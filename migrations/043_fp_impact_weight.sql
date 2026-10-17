ALTER TABLE scan_findings ADD COLUMN fp_impact_weight INTEGER
    CHECK (fp_impact_weight IS NULL OR fp_impact_weight IN (1, 3, 9, 27));
