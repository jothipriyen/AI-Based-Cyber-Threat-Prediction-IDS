import random
from typing import List

import pandas as pd


def generate_ip_address(is_foreign: bool = False) -> str:
    """Generate a realistic IP address."""
    if is_foreign:
        # Foreign IPs: various international ranges
        first_octet = random.choice([103, 185, 192, 203, 45, 87, 91, 104, 151, 178])
        return f"{first_octet}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
    else:
        # Local/private IPs: common internal ranges
        network_type = random.choice(["192.168", "10.0", "172.16"])
        if network_type == "192.168":
            return f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)}"
        elif network_type == "10.0":
            return f"10.0.{random.randint(1, 255)}.{random.randint(1, 255)}"
        else:
            return f"172.16.{random.randint(1, 31)}.{random.randint(1, 255)}"


def generate_authentication_data(rows: int = 200, output_path: str = "auth_logs.csv") -> None:
    """Generate synthetic authentication log data with attack types, user roles, and user IDs.

    Columns:
    - hour: 0–23
    - failed_attempts: count of consecutive failed logins
    - foreign_ip: 1 = foreign / unusual location, 0 = local / expected
    - ip_address: actual IP address string
    - user_id: unique user identifier
    - user_role: admin / employee
    - attack_type: BRUTE_FORCE / CREDENTIAL_STUFFING / SUSPICIOUS_LOCATION / DATA_EXFILTRATION / BENIGN
    - login_success: 1 = success, 0 = failure
    - session_duration: session length in minutes
    - data_transfer_mb: approximate MB transferred in session
    """
    records: List[list] = []
    
    # Generate user pool (mix of admins and employees)
    num_users = max(20, rows // 10)  # ~10 events per user on average
    user_pool = []
    for i in range(num_users):
        user_id = f"user_{i+1:03d}"
        # 10% admins, 90% employees
        user_role = "admin" if random.random() < 0.10 else "employee"
        user_pool.append((user_id, user_role))

    for i in range(rows):
        hour = random.randint(0, 23)
        user_id, user_role = random.choice(user_pool)

        # Determine attack type based on behavior patterns
        rand_val = random.random()
        
        if rand_val < 0.05:  # 5% Brute-force attack
            failed_attempts = random.randint(5, 10)
            foreign_ip = random.choice([0, 1])  # Can be local or foreign
            ip_address = generate_ip_address(is_foreign=(foreign_ip == 1))
            attack_type = "BRUTE_FORCE"
            login_success = 0
            session_duration = random.randint(1, 3)
            data_transfer = random.randint(1, 10)
            
        elif rand_val < 0.08:  # 3% Credential stuffing
            failed_attempts = random.randint(3, 6)
            foreign_ip = 1  # Usually from foreign IPs
            ip_address = generate_ip_address(is_foreign=True)
            attack_type = "CREDENTIAL_STUFFING"
            login_success = 0
            session_duration = random.randint(1, 5)
            data_transfer = random.randint(1, 15)
            
        elif rand_val < 0.10:  # 2% Suspicious location login
            failed_attempts = random.randint(0, 2)
            foreign_ip = 1  # Foreign IP
            ip_address = generate_ip_address(is_foreign=True)
            attack_type = "SUSPICIOUS_LOCATION"
            login_success = random.choice([0, 1])  # May succeed
            session_duration = random.randint(5, 30)
            data_transfer = random.randint(10, 50)
            
        elif rand_val < 0.12:  # 2% Data exfiltration pattern
            failed_attempts = random.randint(0, 1)
            foreign_ip = random.choice([0, 1])
            ip_address = generate_ip_address(is_foreign=(foreign_ip == 1))
            attack_type = "DATA_EXFILTRATION"
            login_success = 1  # Usually succeeds (insider threat)
            session_duration = random.randint(30, 120)
            data_transfer = random.randint(200, 500)  # High data transfer
            
        else:  # 88% Benign traffic
            failed_attempts = random.randint(0, 2)
            foreign_ip = random.choice([0, 0, 0, 0, 1])  # Mostly local
            ip_address = generate_ip_address(is_foreign=(foreign_ip == 1))
            attack_type = "BENIGN"
            login_success = 1 if failed_attempts <= 2 else 0
            session_duration = random.randint(10, 60)
            data_transfer = random.randint(1, 40)

        records.append(
            [
                hour,
                failed_attempts,
                foreign_ip,
                ip_address,
                user_id,
                user_role,
                attack_type,
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
            "ip_address",
            "user_id",
            "user_role",
            "attack_type",
            "login_success",
            "session_duration",
            "data_transfer_mb",
        ],
    )

    df.to_csv(output_path, index=False)
    print(f"Synthetic authentication dataset written to: {output_path}")
    print(f"  - Users: {num_users} ({len([u for u in user_pool if u[1]=='admin'])} admins, {len([u for u in user_pool if u[1]=='employee'])} employees)")
    print(f"  - Attack types: {df['attack_type'].value_counts().to_dict()}")


if __name__ == "__main__":
    generate_authentication_data()

