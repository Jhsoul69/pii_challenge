import pandas as pd
import json
import re
import sys

# ---------------------------
# Regex patterns for PII
# ---------------------------
phone_regex = re.compile(r'\b\d{10}\b')
aadhar_regex = re.compile(r'\b\d{12}\b')
passport_regex = re.compile(r'\b[A-Z]\d{7}\b')
upi_regex = re.compile(r'[a-zA-Z0-9._]+@[a-zA-Z]+\b')
email_regex = re.compile(r'[a-zA-Z0-9._]+@[a-zA-Z]+\.[a-z]{2,}')

# ---------------------------
# Masking functions
# ---------------------------
def mask_phone(phone):
    return phone[:2] + "XXXXXX" + phone[-2:]

def mask_aadhar(aadhar):
    return aadhar[:4] + "XXXXXXXX"

def mask_passport(passport):
    return passport[0] + "XXXXXXX"

def mask_upi(upi):
    parts = upi.split("@")
    return parts[0][:2] + "XXX@" + parts[1]

def mask_email(email):
    parts = email.split("@")
    return parts[0][:2] + "XXX@" + parts[1]

def mask_name(name):
    parts = name.split()
    if len(parts) >= 2:
        return parts[0][0] + "XXX " + parts[1][0] + "XXXX"
    else:
        return parts[0][0] + "XXX"

# ---------------------------
# PII detection and redaction
# ---------------------------
def detect_and_redact(record):
    record = str(record).strip()
    # Remove outer quotes if present
    if record.startswith('"') and record.endswith('"'):
        record = record[1:-1].replace('""', '"')

    try:
        data = json.loads(record)
    except Exception:
        return record, False

    pii_detected = False

    # --- Standalone PII ---
    if "phone" in data and phone_regex.fullmatch(str(data["phone"])):
        data["phone"] = mask_phone(str(data["phone"]))
        pii_detected = True

    if "aadhar" in data and aadhar_regex.fullmatch(str(data["aadhar"])):
        data["aadhar"] = mask_aadhar(str(data["aadhar"]))
        pii_detected = True

    if "passport" in data and passport_regex.fullmatch(str(data["passport"])):
        data["passport"] = mask_passport(str(data["passport"]))
        pii_detected = True

    if "upi_id" in data and upi_regex.fullmatch(str(data["upi_id"])):
        data["upi_id"] = mask_upi(str(data["upi_id"]))
        pii_detected = True

    # --- Combinatorial PII ---
    combinatorial_fields = []

    if "name" in data and str(data["name"]).strip():
        combinatorial_fields.append("name")
    if "email" in data and email_regex.fullmatch(str(data["email"])):
        combinatorial_fields.append("email")
    if "address" in data and str(data.get("address", "")).strip() and "pin_code" in data:
        combinatorial_fields.append("address")
    if "device_id" in data or "ip_address" in data:
        combinatorial_fields.append("device_ip")

    if len(combinatorial_fields) >= 2:
        pii_detected = True
        if "name" in combinatorial_fields:
            data["name"] = mask_name(str(data["name"]))
        if "email" in combinatorial_fields:
            data["email"] = mask_email(str(data["email"]))
        if "address" in combinatorial_fields:
            data["address"] = "[REDACTED_ADDRESS]"
        if "device_ip" in combinatorial_fields:
            if "device_id" in data:
                data["device_id"] = "[REDACTED_DEVICE]"
            if "ip_address" in data:
                data["ip_address"] = "[REDACTED_IP]"

    return json.dumps(data), pii_detected

# ---------------------------
# Main execution
# ---------------------------
if len(sys.argv) != 2:
    print("Usage: python detector_full_candidate_name.py iscp_pii_dataset.csv")
    sys.exit(1)

input_file = sys.argv[1]
df = pd.read_csv(input_file)

# Auto-detect JSON column
json_col_candidates = [col for col in df.columns if "json" in col.lower()]
if not json_col_candidates:
    print("Error: No JSON column found in CSV")
    sys.exit(1)

json_col = json_col_candidates[0]

redacted_data = []
is_pii_flags = []

for _, row in df.iterrows():
    redacted_json, pii_flag = detect_and_redact(row[json_col])
    redacted_data.append(redacted_json)
    is_pii_flags.append(pii_flag)

df["redacted_data_json"] = redacted_data
df["is_pii"] = is_pii_flags

df = df[["record_id", "redacted_data_json", "is_pii"]]
df.to_csv("redacted_output_candidate_full_name.csv", index=False)

print("✅ Redacted CSV generated: redacted_output_candidate_full_name.csv")
