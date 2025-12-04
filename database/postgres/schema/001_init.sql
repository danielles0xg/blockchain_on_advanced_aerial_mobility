-- =============================================================================
-- AAM Security Experiment - PostgreSQL Schema
-- Hash-Chained Audit Log (Tamper-Evident Baseline)
-- =============================================================================

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- =============================================================================
-- SECURITY EVENTS TABLE (Main Audit Log)
-- =============================================================================

CREATE TABLE security_events (
    event_id BIGSERIAL PRIMARY KEY,
    event_timestamp TIMESTAMPTZ NOT NULL,
    event_type SMALLINT NOT NULL CHECK (event_type BETWEEN 1 AND 6),
    -- 1=GPS_SPOOF, 2=DOS, 3=MITM, 4=REPLAY, 5=GPS_JAM, 6=EVIL_TWIN
    confidence SMALLINT NOT NULL CHECK (confidence BETWEEN 0 AND 100),
    vehicle_id BYTEA NOT NULL,
    data_hash BYTEA NOT NULL,
    prev_hash BYTEA NOT NULL,
    record_hash BYTEA NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),

    -- Metrics for experiment
    client_submit_time TIMESTAMPTZ,  -- When client sent the request
    db_receive_time TIMESTAMPTZ DEFAULT NOW()  -- When DB received it
);

-- Indexes for performance
CREATE INDEX idx_events_timestamp ON security_events(event_timestamp);
CREATE INDEX idx_events_vehicle ON security_events(vehicle_id);
CREATE INDEX idx_events_type ON security_events(event_type);
CREATE INDEX idx_events_created ON security_events(created_at);

-- =============================================================================
-- EVENT TYPES LOOKUP
-- =============================================================================

CREATE TABLE event_types (
    type_id SMALLINT PRIMARY KEY,
    type_name VARCHAR(50) NOT NULL,
    description TEXT
);

INSERT INTO event_types (type_id, type_name, description) VALUES
    (1, 'GPS_SPOOF', 'GPS spoofing attack detected'),
    (2, 'DOS', 'Denial of Service attack detected'),
    (3, 'MITM', 'Man-in-the-Middle attack detected'),
    (4, 'REPLAY', 'Replay attack detected'),
    (5, 'GPS_JAM', 'GPS jamming detected'),
    (6, 'EVIL_TWIN', 'Evil twin/rogue access point detected');

-- =============================================================================
-- EXPERIMENT METRICS TABLE
-- =============================================================================

CREATE TABLE experiment_metrics (
    metric_id BIGSERIAL PRIMARY KEY,
    experiment_run_id UUID NOT NULL,
    system_name VARCHAR(50) NOT NULL,  -- 'solana', 'hyperledger', 'postgresql'
    scenario VARCHAR(50) NOT NULL,      -- 'real_time', 'audit_trail'
    event_id BIGINT,

    -- Timing metrics (all in milliseconds)
    submit_time TIMESTAMPTZ NOT NULL,
    confirm_time TIMESTAMPTZ,
    latency_ms DOUBLE PRECISION,

    -- Additional metrics
    tps_at_submission DOUBLE PRECISION,
    batch_size INT,
    success BOOLEAN DEFAULT TRUE,
    error_message TEXT,

    -- Blockchain-specific
    block_number BIGINT,
    tx_hash VARCHAR(128),
    gas_used BIGINT,

    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_metrics_run ON experiment_metrics(experiment_run_id);
CREATE INDEX idx_metrics_system ON experiment_metrics(system_name);
CREATE INDEX idx_metrics_scenario ON experiment_metrics(scenario);

-- =============================================================================
-- EXPERIMENT RUNS TABLE
-- =============================================================================

CREATE TABLE experiment_runs (
    run_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scenario VARCHAR(50) NOT NULL,
    target_tps INT,
    duration_seconds INT,
    start_time TIMESTAMPTZ DEFAULT NOW(),
    end_time TIMESTAMPTZ,
    config JSONB,
    notes TEXT
);

-- =============================================================================
-- HASH CHAIN FUNCTIONS
-- =============================================================================

-- Function to compute record hash
CREATE OR REPLACE FUNCTION compute_record_hash(
    p_event_timestamp TIMESTAMPTZ,
    p_event_type SMALLINT,
    p_confidence SMALLINT,
    p_vehicle_id BYTEA,
    p_data_hash BYTEA,
    p_prev_hash BYTEA
) RETURNS BYTEA AS $$
BEGIN
    RETURN digest(
        EXTRACT(EPOCH FROM p_event_timestamp)::TEXT ||
        p_event_type::TEXT ||
        p_confidence::TEXT ||
        encode(p_vehicle_id, 'hex') ||
        encode(p_data_hash, 'hex') ||
        encode(p_prev_hash, 'hex'),
        'sha256'
    );
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Function to insert security event with automatic hash chaining
CREATE OR REPLACE FUNCTION insert_security_event(
    p_event_timestamp TIMESTAMPTZ,
    p_event_type SMALLINT,
    p_confidence SMALLINT,
    p_vehicle_id BYTEA,
    p_data_hash BYTEA,
    p_client_submit_time TIMESTAMPTZ DEFAULT NULL
) RETURNS TABLE(
    event_id BIGINT,
    latency_ms DOUBLE PRECISION
) AS $$
DECLARE
    v_prev_hash BYTEA;
    v_record_hash BYTEA;
    v_event_id BIGINT;
    v_start_time TIMESTAMPTZ := clock_timestamp();
    v_end_time TIMESTAMPTZ;
BEGIN
    -- Get previous hash (or genesis hash if first record)
    SELECT COALESCE(
        (SELECT se.record_hash FROM security_events se ORDER BY se.event_id DESC LIMIT 1),
        '\x0000000000000000000000000000000000000000000000000000000000000000'::BYTEA
    ) INTO v_prev_hash;

    -- Compute record hash
    v_record_hash := compute_record_hash(
        p_event_timestamp,
        p_event_type,
        p_confidence,
        p_vehicle_id,
        p_data_hash,
        v_prev_hash
    );

    -- Insert the event
    INSERT INTO security_events (
        event_timestamp,
        event_type,
        confidence,
        vehicle_id,
        data_hash,
        prev_hash,
        record_hash,
        client_submit_time
    ) VALUES (
        p_event_timestamp,
        p_event_type,
        p_confidence,
        p_vehicle_id,
        p_data_hash,
        v_prev_hash,
        v_record_hash,
        p_client_submit_time
    ) RETURNING security_events.event_id INTO v_event_id;

    v_end_time := clock_timestamp();

    RETURN QUERY SELECT
        v_event_id,
        (EXTRACT(EPOCH FROM (v_end_time - v_start_time)) * 1000)::DOUBLE PRECISION;
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- HASH CHAIN VERIFICATION
-- =============================================================================

CREATE OR REPLACE FUNCTION verify_hash_chain(
    p_start_id BIGINT DEFAULT 1,
    p_end_id BIGINT DEFAULT NULL
) RETURNS TABLE(
    event_id BIGINT,
    is_valid BOOLEAN,
    error_message TEXT
) AS $$
DECLARE
    v_prev_hash BYTEA := '\x0000000000000000000000000000000000000000000000000000000000000000';
    rec RECORD;
    v_computed_hash BYTEA;
    v_end_id BIGINT;
BEGIN
    -- Set end_id if not provided
    SELECT COALESCE(p_end_id, MAX(se.event_id)) INTO v_end_id FROM security_events se;

    FOR rec IN
        SELECT * FROM security_events se
        WHERE se.event_id >= p_start_id AND se.event_id <= v_end_id
        ORDER BY se.event_id
    LOOP
        -- Compute expected hash
        v_computed_hash := compute_record_hash(
            rec.event_timestamp,
            rec.event_type,
            rec.confidence,
            rec.vehicle_id,
            rec.data_hash,
            v_prev_hash
        );

        event_id := rec.event_id;

        -- Verify prev_hash matches
        IF rec.prev_hash != v_prev_hash THEN
            is_valid := FALSE;
            error_message := 'Previous hash mismatch';
            RETURN NEXT;
            -- Continue checking but flag the break
        ELSIF rec.record_hash != v_computed_hash THEN
            is_valid := FALSE;
            error_message := 'Record hash mismatch';
            RETURN NEXT;
        ELSE
            is_valid := TRUE;
            error_message := NULL;
            RETURN NEXT;
        END IF;

        -- Update prev_hash for next iteration
        v_prev_hash := rec.record_hash;
    END LOOP;
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- METRICS AGGREGATION VIEWS
-- =============================================================================

CREATE OR REPLACE VIEW latency_percentiles AS
SELECT
    system_name,
    scenario,
    COUNT(*) as total_events,
    AVG(latency_ms) as avg_latency_ms,
    PERCENTILE_CONT(0.50) WITHIN GROUP (ORDER BY latency_ms) as p50_ms,
    PERCENTILE_CONT(0.90) WITHIN GROUP (ORDER BY latency_ms) as p90_ms,
    PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY latency_ms) as p95_ms,
    PERCENTILE_CONT(0.99) WITHIN GROUP (ORDER BY latency_ms) as p99_ms,
    MIN(latency_ms) as min_ms,
    MAX(latency_ms) as max_ms,
    STDDEV(latency_ms) as stddev_ms
FROM experiment_metrics
WHERE success = TRUE AND latency_ms IS NOT NULL
GROUP BY system_name, scenario;

CREATE OR REPLACE VIEW throughput_summary AS
SELECT
    experiment_run_id,
    system_name,
    scenario,
    COUNT(*) as total_events,
    COUNT(*) FILTER (WHERE success = TRUE) as successful_events,
    COUNT(*) FILTER (WHERE success = FALSE) as failed_events,
    EXTRACT(EPOCH FROM (MAX(submit_time) - MIN(submit_time))) as duration_seconds,
    COUNT(*) / NULLIF(EXTRACT(EPOCH FROM (MAX(submit_time) - MIN(submit_time))), 0) as actual_tps
FROM experiment_metrics
GROUP BY experiment_run_id, system_name, scenario;

-- =============================================================================
-- SAMPLE DATA FOR TESTING
-- =============================================================================

-- Function to generate test events
CREATE OR REPLACE FUNCTION generate_test_events(
    p_count INT DEFAULT 100
) RETURNS VOID AS $$
DECLARE
    i INT;
    v_vehicle_id BYTEA;
    v_data_hash BYTEA;
BEGIN
    FOR i IN 1..p_count LOOP
        v_vehicle_id := digest('vehicle_' || i::TEXT, 'sha256');
        v_data_hash := digest('test_data_' || i::TEXT || '_' || random()::TEXT, 'sha256');

        PERFORM insert_security_event(
            NOW() - (random() * interval '1 hour'),
            (1 + floor(random() * 6))::SMALLINT,
            (50 + floor(random() * 51))::SMALLINT,
            v_vehicle_id,
            v_data_hash
        );
    END LOOP;
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- GRANTS
-- =============================================================================

-- Grant permissions to aam_user (already created by Docker)
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO aam_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO aam_user;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO aam_user;
