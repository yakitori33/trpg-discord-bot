CREATE TABLE users (
    discord_id TEXT PRIMARY KEY,
    display_name_cache TEXT NOT NULL,
    timezone TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE scenarios (
    scenario_id SERIAL PRIMARY KEY,
    title TEXT NOT NULL,
    system TEXT,
    estimated_time TEXT,
    tags TEXT[] DEFAULT ARRAY[]::TEXT[],
    notes TEXT,
    created_by TEXT REFERENCES users(discord_id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE scenario_capabilities (
    scenario_id INTEGER REFERENCES scenarios(scenario_id) ON DELETE CASCADE,
    gm_user_id TEXT REFERENCES users(discord_id) ON DELETE CASCADE,
    confidence TEXT NOT NULL DEFAULT 'ready',
    PRIMARY KEY (scenario_id, gm_user_id)
);

CREATE TABLE sessions (
    session_id SERIAL PRIMARY KEY,
    scenario_id INTEGER REFERENCES scenarios(scenario_id),
    gm_user_id TEXT REFERENCES users(discord_id),
    status TEXT NOT NULL,
    guild_id TEXT NOT NULL,
    channel_id TEXT NOT NULL,
    thread_id TEXT NOT NULL,
    min_players INTEGER DEFAULT 1,
    max_players INTEGER DEFAULT 5,
    scheduled_start TIMESTAMP WITH TIME ZONE,
    scheduled_end TIMESTAMP WITH TIME ZONE,
    created_by TEXT REFERENCES users(discord_id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE session_participants (
    session_id INTEGER REFERENCES sessions(session_id) ON DELETE CASCADE,
    user_id TEXT REFERENCES users(discord_id) ON DELETE CASCADE,
    role TEXT NOT NULL,
    joined_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    PRIMARY KEY (session_id, user_id)
);

CREATE TABLE availability_polls (
    poll_id SERIAL PRIMARY KEY,
    session_id INTEGER REFERENCES sessions(session_id) ON DELETE CASCADE,
    deadline TIMESTAMP WITH TIME ZONE,
    timezone_basis TEXT NOT NULL
);

CREATE TABLE availability_slots (
    slot_id SERIAL PRIMARY KEY,
    poll_id INTEGER REFERENCES availability_polls(poll_id) ON DELETE CASCADE,
    start_time TIMESTAMP WITH TIME ZONE NOT NULL,
    end_time TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE TABLE availability_responses (
    slot_id INTEGER REFERENCES availability_slots(slot_id) ON DELETE CASCADE,
    user_id TEXT REFERENCES users(discord_id) ON DELETE CASCADE,
    status TEXT NOT NULL,
    comment TEXT,
    PRIMARY KEY (slot_id, user_id)
);

CREATE TABLE play_history (
    play_id SERIAL PRIMARY KEY,
    scenario_id INTEGER REFERENCES scenarios(scenario_id) ON DELETE CASCADE,
    user_id TEXT REFERENCES users(discord_id) ON DELETE CASCADE,
    role TEXT NOT NULL,
    session_id INTEGER REFERENCES sessions(session_id) ON DELETE SET NULL,
    date TIMESTAMP WITH TIME ZONE NOT NULL,
    notes TEXT
);

CREATE TABLE audit_logs (
    audit_id SERIAL PRIMARY KEY,
    session_id INTEGER REFERENCES sessions(session_id) ON DELETE CASCADE,
    action TEXT NOT NULL,
    actor_id TEXT REFERENCES users(discord_id),
    detail JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
