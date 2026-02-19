import random
from typing import List

import pandas as pd


def generate_authentication_data(rows: int = 200, output_path: str = "auth_logs.csv") -> None:
    """Generate synthetic authentication log data and save to CSV.

    Columns:
    - hour: 0–23
    - failed_attempts: count of consecutive failed logins
    - foreign_ip: 1 = foreign / unusual location, 0 = local / expected
    - login_success: 1 = success, 0 = failure
    - session_duration: session length in minutes
    - data_transfer_mb: approximate MB transferred in session
    """
    records: List[list] = []

    for _ in range(rows):
        hour = random.randint(0, 23)

        # 10% chance: craft clearly suspicious behaviour
        if random.random() < 0.10:
            failed_attempts = random.randint(4, 8)
            foreign_ip = 1
            login_success = 0
            session_duration = random.randint(1, 5)
            data_transfer = random.randint(80, 300)
        else:
            failed_attempts = random.randint(0, 2)
            # mostly local IPs with occasional foreign access
            foreign_ip = random.choice([0, 0, 0, 0, 1])
            login_success = 1 if failed_attempts <= 2 else 0
            session_duration = random.randint(10, 60)
            data_transfer = random.randint(1, 40)

        records.append(
            [
                hour,
                failed_attempts,
                foreign_ip,
                login_success,
                session_duration,
                data_transfer,
            ]
        )

    df = pd.DataFrame(
        records,
        columns=[
            "hour",
            "failed_attempts",
            "foreign_ip",
            "login_success",
            "session_duration",
            "data_transfer_mb",
        ],
    )

    df.to_csv(output_path, index=False)
    print(f"Synthetic authentication dataset written to: {output_path}")


if __name__ == "__main__":
    generate_authentication_data()

