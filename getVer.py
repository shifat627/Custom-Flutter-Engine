import csv,sys
if len(sys.argv) != 3:
     print(f'Usage {sys.argv[0]} <file.csv> <Snapshot_hash>')

with open(sys.argv[1]) as f_obj:
        
        read = csv.DictReader(f_obj, delimiter=",")
        row_count = sum(1 for _ in read)
        f_obj.seek(0)
        reader = csv.DictReader(f_obj, delimiter=",")
        i = -row_count
        for line in reader:
            i = i + 1
            if sys.argv[2] in line["Snapshot_Hash"]:
                print(f'{line["Engine_commit"]} -> version : {abs(i)}')
                break
