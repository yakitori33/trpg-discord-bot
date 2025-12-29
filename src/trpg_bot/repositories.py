from __future__ import annotations

from datetime import datetime

from trpg_bot.db import get_cursor


def upsert_user(cursor, discord_id: str, display_name: str) -> None:
    cursor.execute(
        """
        INSERT INTO users (discord_id, display_name_cache)
        VALUES (%s, %s)
        ON CONFLICT (discord_id)
        DO UPDATE SET display_name_cache = EXCLUDED.display_name_cache
        """,
        (discord_id, display_name),
    )


def create_scenario(cursor, title: str, system: str, estimated_time: str, tags: list[str], notes: str, created_by: str) -> int:
    cursor.execute(
        """
        INSERT INTO scenarios (title, system, estimated_time, tags, notes, created_by)
        VALUES (%s, %s, %s, %s, %s, %s)
        RETURNING scenario_id
        """,
        (title, system, estimated_time, tags, notes, created_by),
    )
    return cursor.fetchone()[0]


def update_scenario(cursor, scenario_id: int, title: str, system: str, estimated_time: str, tags: list[str], notes: str) -> None:
    cursor.execute(
        """
        UPDATE scenarios
        SET title = %s, system = %s, estimated_time = %s, tags = %s, notes = %s
        WHERE scenario_id = %s
        """,
        (title, system, estimated_time, tags, notes, scenario_id),
    )


def get_scenario(cursor, scenario_id: int) -> dict | None:
    cursor.execute("SELECT * FROM scenarios WHERE scenario_id = %s", (scenario_id,))
    row = cursor.fetchone()
    return dict(row) if row else None


def search_scenarios(cursor, keyword: str) -> list[dict]:
    cursor.execute(
        """
        SELECT * FROM scenarios
        WHERE title ILIKE %s
        ORDER BY created_at DESC
        LIMIT 5
        """,
        (f"%{keyword}%",),
    )
    return [dict(row) for row in cursor.fetchall()]


def add_capability(cursor, scenario_id: int, gm_user_id: str, confidence: str) -> None:
    cursor.execute(
        """
        INSERT INTO scenario_capabilities (scenario_id, gm_user_id, confidence)
        VALUES (%s, %s, %s)
        ON CONFLICT (scenario_id, gm_user_id)
        DO UPDATE SET confidence = EXCLUDED.confidence
        """,
        (scenario_id, gm_user_id, confidence),
    )


def remove_capability(cursor, scenario_id: int, gm_user_id: str) -> None:
    cursor.execute(
        "DELETE FROM scenario_capabilities WHERE scenario_id = %s AND gm_user_id = %s",
        (scenario_id, gm_user_id),
    )


def list_capable_gms(cursor, scenario_id: int) -> list[str]:
    cursor.execute(
        """
        SELECT u.display_name_cache
        FROM scenario_capabilities sc
        JOIN users u ON u.discord_id = sc.gm_user_id
        WHERE sc.scenario_id = %s
        """,
        (scenario_id,),
    )
    return [row[0] for row in cursor.fetchall()]


def list_play_history(cursor, scenario_id: int) -> list[str]:
    cursor.execute(
        """
        SELECT u.display_name_cache
        FROM play_history ph
        JOIN users u ON u.discord_id = ph.user_id
        WHERE ph.scenario_id = %s
        ORDER BY ph.date DESC
        """,
        (scenario_id,),
    )
    return [row[0] for row in cursor.fetchall()]


def create_session(cursor, scenario_id: int | None, gm_user_id: str | None, status: str,
                   guild_id: str, channel_id: str, thread_id: str, min_players: int,
                   max_players: int, created_by: str) -> int:
    cursor.execute(
        """
        INSERT INTO sessions
        (scenario_id, gm_user_id, status, guild_id, channel_id, thread_id,
         min_players, max_players, created_by)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        RETURNING session_id
        """,
        (scenario_id, gm_user_id, status, guild_id, channel_id, thread_id,
         min_players, max_players, created_by),
    )
    return cursor.fetchone()[0]


def get_session(cursor, session_id: int) -> dict | None:
    cursor.execute("SELECT * FROM sessions WHERE session_id = %s", (session_id,))
    row = cursor.fetchone()
    return dict(row) if row else None


def add_participant(cursor, session_id: int, user_id: str, role: str) -> None:
    cursor.execute(
        """
        INSERT INTO session_participants (session_id, user_id, role)
        VALUES (%s, %s, %s)
        ON CONFLICT (session_id, user_id)
        DO UPDATE SET role = EXCLUDED.role
        """,
        (session_id, user_id, role),
    )


def remove_participant(cursor, session_id: int, user_id: str) -> None:
    cursor.execute(
        "DELETE FROM session_participants WHERE session_id = %s AND user_id = %s",
        (session_id, user_id),
    )


def list_participants(cursor, session_id: int) -> list[str]:
    cursor.execute(
        """
        SELECT u.display_name_cache
        FROM session_participants sp
        JOIN users u ON u.discord_id = sp.user_id
        WHERE sp.session_id = %s
        ORDER BY sp.joined_at
        """,
        (session_id,),
    )
    return [row[0] for row in cursor.fetchall()]


def create_poll(cursor, session_id: int, deadline: datetime | None, timezone_basis: str) -> int:
    cursor.execute(
        """
        INSERT INTO availability_polls (session_id, deadline, timezone_basis)
        VALUES (%s, %s, %s)
        RETURNING poll_id
        """,
        (session_id, deadline, timezone_basis),
    )
    return cursor.fetchone()[0]


def add_slot(cursor, poll_id: int, start: datetime, end: datetime) -> int:
    cursor.execute(
        """
        INSERT INTO availability_slots (poll_id, start_time, end_time)
        VALUES (%s, %s, %s)
        RETURNING slot_id
        """,
        (poll_id, start, end),
    )
    return cursor.fetchone()[0]


def upsert_response(cursor, slot_id: int, user_id: str, status: str, comment: str) -> None:
    cursor.execute(
        """
        INSERT INTO availability_responses (slot_id, user_id, status, comment)
        VALUES (%s, %s, %s, %s)
        ON CONFLICT (slot_id, user_id)
        DO UPDATE SET status = EXCLUDED.status, comment = EXCLUDED.comment
        """,
        (slot_id, user_id, status, comment),
    )


def list_availability_summary(cursor, poll_id: int) -> list[dict]:
    cursor.execute(
        """
        SELECT slot_id,
               start_time,
               end_time,
               COUNT(*) FILTER (WHERE status = 'OK') AS ok,
               COUNT(*) FILTER (WHERE status = 'MAYBE') AS maybe,
               COUNT(*) FILTER (WHERE status = 'NO') AS no
        FROM availability_slots s
        LEFT JOIN availability_responses r USING (slot_id)
        WHERE poll_id = %s
        GROUP BY slot_id
        ORDER BY start_time
        """,
        (poll_id,),
    )
    return [
        {
            "slot_id": row[0],
            "start": row[1].isoformat(),
            "end": row[2].isoformat(),
            "ok": row[3],
            "maybe": row[4],
            "no": row[5],
        }
        for row in cursor.fetchall()
    ]


def get_poll_deadline(cursor, poll_id: int) -> datetime | None:
    cursor.execute("SELECT deadline FROM availability_polls WHERE poll_id = %s", (poll_id,))
    row = cursor.fetchone()
    return row[0] if row else None


def mark_session_status(cursor, session_id: int, status: str) -> None:
    cursor.execute(
        "UPDATE sessions SET status = %s WHERE session_id = %s",
        (status, session_id),
    )


def add_play_history(cursor, scenario_id: int, user_id: str, role: str, session_id: int, notes: str) -> None:
    cursor.execute(
        """
        INSERT INTO play_history (scenario_id, user_id, role, session_id, date, notes)
        VALUES (%s, %s, %s, %s, NOW(), %s)
        """,
        (scenario_id, user_id, role, session_id, notes),
    )
