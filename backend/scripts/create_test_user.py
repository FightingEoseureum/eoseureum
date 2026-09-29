import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
import asyncio, aiosqlite, pathlib, bcrypt

async def main():
    pw = b"scantest1234"
    hashed = bcrypt.hashpw(pw, bcrypt.gensalt()).decode()
    db = pathlib.Path("scanner.db")
    async with aiosqlite.connect(db) as conn:
        await conn.execute("DELETE FROM users WHERE username='scantest'")
        await conn.execute(
            "INSERT INTO users (username, password_hash, role, can_scan) VALUES (?, ?, 'admin', 1)",
            ("scantest", hashed),
        )
        await conn.commit()
        print("테스트 계정 생성 완료: scantest / scantest1234")

asyncio.run(main())
