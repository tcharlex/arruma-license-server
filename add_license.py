import sqlite3
from pathlib import Path
import os

# mesmo caminho usado pelo servidor
data_dir = Path(os.getenv("FILEFLOW_DATA_DIR") or Path.home() / ".fileflow_downloads")
db_path = data_dir / "auth.db"

print("DB:", db_path)

conn = sqlite3.connect(db_path)
c = conn.cursor()

c.execute("DELETE FROM licenses")

c.execute(
    "INSERT INTO licenses (license_key, app, device_id) VALUES (?, ?, ?)",
    ("TESTE-1234-AAAA", "fileflow", None),
)

conn.commit()

for row in c.execute("SELECT * FROM licenses"):
    print(row)

conn.close()
print("Licença criada.")
