import csv
def load_signatures(db_path):
    signatures = {}
    with open(db_path, newline="") as file:
        reader = csv.DictReader(file)
        for row in reader:
            signatures[row["hash"]] = row["name"]
    return signatures
